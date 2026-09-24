"""
Tests for the N-BaIoT importer.

Tests:
- Label mapping (benign/mirai/gafgyt/unknown)
- CSV file discovery (directory structure)
- End-to-end import from test fixture
- Provenance preservation
- Manifest generation
- Audit generation
- Security: nonexistent input raises
"""
import json
import sys
from pathlib import Path

import pytest

# Setup paths
REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "model-lab"))
sys.path.insert(0, str(REPO_ROOT / "dashboard" / "ml"))
sys.path.insert(0, str(REPO_ROOT / "shared" / "schemas"))

from model_lab.label_mapping_n_baiot import map_label, get_all_native_labels, get_all_canonical_families
from model_lab.datasets.import_n_baiot import import_n_baiot, discover_nbaiot_files

FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "nbaiot"


@pytest.fixture
def fixture_dir():
    if not FIXTURE_DIR.exists():
        pytest.skip("N-BaIoT test fixture not found")
    return FIXTURE_DIR


@pytest.fixture
def import_result(fixture_dir, tmp_path):
    return import_n_baiot(fixture_dir, tmp_path / "nbaiot" / "v1", "v1")


@pytest.fixture
def output_dir(fixture_dir, tmp_path):
    out = tmp_path / "nbaiot" / "v1"
    import_n_baiot(fixture_dir, out, "v1")
    return out


class TestNBaIoTLabelMapping:
    def test_benign_maps_to_benign(self):
        family, binary, _, conf, _ = map_label("benign")
        assert family == "benign"
        assert binary == "benign"
        assert conf == 1.0

    def test_mirai_maps_to_botnet_mirai(self):
        family, binary, _, conf, _ = map_label("mirai")
        assert family == "botnet_mirai"
        assert binary == "malicious"
        assert conf == 1.0

    def test_gafgyt_maps_to_botnet_gafgyt(self):
        family, binary, _, conf, _ = map_label("gafgyt")
        assert family == "botnet_gafgyt"
        assert binary == "malicious"
        assert conf == 1.0

    def test_unknown_label_maps_to_unknown(self):
        family, binary, _, conf, reason = map_label("NonexistentLabel")
        assert family == "unknown"
        assert binary == "unknown"
        assert conf == 0.0
        assert reason == "unmapped"

    def test_case_insensitive(self):
        family, binary, _, _, _ = map_label("Mirai")
        assert family == "botnet_mirai"
        assert binary == "malicious"

    def test_all_known_labels_mapped(self):
        for label in get_all_native_labels():
            family, binary, _, _, _ = map_label(label)
            assert family != "unknown", f"Known label '{label}' mapped to unknown"
            assert binary in ("malicious", "benign")

    def test_canonical_families_distinct_from_iot23(self):
        """N-BaIoT should have gafgyt family which IoT-23 doesn't."""
        families = get_all_canonical_families()
        assert "botnet_gafgyt" in families
        assert "botnet_mirai" in families
        assert "benign" in families


class TestNBaIoTDiscovery:
    def test_discovers_files(self, fixture_dir):
        files = discover_nbaiot_files(fixture_dir)
        assert len(files) > 0
        # Should find benign and mirai files
        conditions = [c for _, c, _ in files]
        assert "benign" in conditions
        assert "mirai" in conditions

    def test_discovers_device_name(self, fixture_dir):
        files = discover_nbaiot_files(fixture_dir)
        devices = set(d for d, _, _ in files)
        assert "test-device" in devices


class TestNBaIoTImportEndToEnd:
    def test_import_produces_output(self, import_result):
        assert import_result["dataset_id"] == "nbaiot"
        assert import_result["records_imported"] > 0
        assert import_result["devices"] == 1

    def test_manifests_generated(self, output_dir):
        assert (output_dir / "dataset_manifest.json").exists()
        assert (output_dir / "raw_manifest.json").exists()
        assert (output_dir / "provenance.json").exists()
        assert (output_dir / "label_mapping.json").exists()
        assert (output_dir / "audit.json").exists()
        assert (output_dir / "schema.json").exists()

    def test_dataset_manifest_fields(self, output_dir):
        manifest = json.loads((output_dir / "dataset_manifest.json").read_text())
        assert manifest["dataset_id"] == "nbaiot"
        assert manifest["dataset_name"] == "N-BaIoT"
        assert manifest["source_format"] == "csv_statistical_features"
        assert manifest["record_count"] > 0
        assert manifest["source_checksum"] != ""

    def test_audit_has_correct_data_type(self, output_dir):
        audit = json.loads((output_dir / "audit.json").read_text())
        assert audit["data_type"] == "external_real"
        assert "benign" in audit["label_distribution"]
        assert "malicious" in audit["label_distribution"]

    def test_audit_warns_about_feature_incompatibility(self, output_dir):
        audit = json.loads((output_dir / "audit.json").read_text())
        # Should warn about feature incompatibility with IoT-23
        feature_warnings = [w for w in audit["warnings"] if "comparable" in w.lower() or "feature" in w.lower()]
        assert len(feature_warnings) > 0

    def test_normalized_data_exists(self, output_dir):
        normalized_dir = output_dir / "normalized"
        parquet = normalized_dir / "flows.parquet"
        jsonl = normalized_dir / "flows.jsonl"
        assert parquet.exists() or jsonl.exists()

    def test_provenance_preserved(self, output_dir):
        jsonl = output_dir / "normalized" / "flows.jsonl"
        if jsonl.exists():
            records = [json.loads(line) for line in jsonl.read_text().strip().split("\n")]
        else:
            import pandas as pd
            df = pd.read_parquet(output_dir / "normalized" / "flows.parquet")
            records = df.to_dict("records")

        assert len(records) > 0
        first = records[0]
        assert "dataset_id" in first
        assert first["dataset_id"] == "nbaiot"
        assert "source_scenario" in first
        assert "native_label" in first
        assert "canonical_attack_family" in first
        assert "binary_label" in first
        assert "nbaiot_features" in first  # 115 features preserved


class TestNBaIoTSecurity:
    def test_nonexistent_input_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            import_n_baiot(Path("/nonexistent/path"), tmp_path / "out")

    def test_output_dir_created(self, fixture_dir, tmp_path):
        out = tmp_path / "deep" / "nested" / "output"
        import_n_baiot(fixture_dir, out, "v1")
        assert out.exists()
        assert (out / "dataset_manifest.json").exists()
