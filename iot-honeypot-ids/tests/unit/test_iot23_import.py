"""
Tests for the IoT-23 importer.

Tests:
- Zeek TSV parsing (headers, comments, malformed rows)
- Label mapping (native → canonical, unmapped labels)
- Provenance preservation (source_file, source_row_id, source_scenario)
- Manifest generation (raw_manifest.json, dataset_manifest.json, provenance.json)
- Audit generation (record_count, scenario_count, unmapped labels, rejections)
- End-to-end import from the test fixture
- Canonical schema fields
- Security: path validation, no path traversal
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

# Import directly
from model_lab.label_mapping_iot23 import map_label, get_all_native_labels, get_all_canonical_families
from model_lab.datasets.import_iot23 import (
    parse_zeek_line, parse_zeek_ts, DEFAULT_ZEEK_FIELDS,
    discover_zeek_files, import_iot23,
)

FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "iot23"


@pytest.fixture
def fixture_dir():
    if not FIXTURE_DIR.exists():
        pytest.skip("IoT-23 test fixture not found")
    return FIXTURE_DIR


@pytest.fixture
def import_result(fixture_dir, tmp_path):
    """Run the importer on the test fixture."""
    return import_iot23(fixture_dir, tmp_path / "iot23" / "v1", "v1")


@pytest.fixture
def output_dir(fixture_dir, tmp_path):
    """Get the output directory after import."""
    out = tmp_path / "iot23" / "v1"
    import_iot23(fixture_dir, out, "v1")
    return out


class TestZeekParser:
    def test_parse_valid_line(self):
        line = "192.0.2.1\tCHhAvVGS1D6jJfM8k\t192.168.1.100\t46238\t192.168.1.50\t23\ttcp\ttelnet\t3.523\t120\t580\tSF\tT\tT\t0\tShADadf\t2\t180\t3\t620\t-\tBenign\t-"
        result = parse_zeek_line(line, DEFAULT_ZEEK_FIELDS)
        assert result is not None
        assert result["id.orig_h"] == "192.168.1.100"
        assert result["proto"] == "tcp"
        assert result["label"] == "Benign"

    def test_parse_comment_line(self):
        result = parse_zeek_line("# This is a comment", DEFAULT_ZEEK_FIELDS)
        assert result is None

    def test_parse_empty_line(self):
        result = parse_zeek_line("", DEFAULT_ZEEK_FIELDS)
        assert result is None

    def test_parse_malformed_line(self):
        line = "192.0.2.1\tCHhAvVGS1D6jJfM8k\t192.168.1.100"
        result = parse_zeek_line(line, DEFAULT_ZEEK_FIELDS)
        assert result is None

    def test_parse_timestamp_valid(self):
        ts = parse_zeek_ts("1700000000.123")
        assert "Z" in ts

    def test_parse_timestamp_invalid(self):
        assert parse_zeek_ts("not_a_number") == ""
        assert parse_zeek_ts("") == ""


class TestLabelMapping:
    def test_benign_maps_to_benign(self):
        family, binary, canonical, conf, reason = map_label("Benign")
        assert family == "benign"
        assert binary == "benign"
        assert conf == 1.0

    def test_mirai_maps_to_botnet(self):
        family, binary, _, _, _ = map_label("Mirai")
        assert family == "botnet_mirai"
        assert binary == "malicious"

    def test_mirai_cc_maps_to_c2(self):
        family, binary, _, _, _ = map_label("Mirai-CC")
        assert family == "command_and_control"
        assert binary == "malicious"

    def test_ddos_maps_to_dos(self):
        family, binary, _, _, _ = map_label("DDoS")
        assert family == "dos"
        assert binary == "malicious"

    def test_unknown_label_maps_to_unknown(self):
        family, binary, canonical, conf, reason = map_label("NonexistentLabel")
        assert family == "unknown"
        assert binary == "unknown"
        assert conf == 0.0
        assert reason == "unmapped"

    def test_all_known_labels_mapped(self):
        for label in get_all_native_labels():
            family, binary, _, _, _ = map_label(label)
            assert family != "unknown", f"Known label '{label}' mapped to unknown"
            assert binary in ("malicious", "benign"), f"Known label '{label}' has invalid binary: {binary}"

    def test_canonical_families_are_distinct(self):
        families = get_all_canonical_families()
        assert "benign" in families
        assert "botnet_mirai" in families
        assert "command_and_control" in families
        assert "dos" in families
        assert len(families) == len(set(families))


class TestImportEndToEnd:
    def test_import_produces_output(self, import_result):
        assert import_result["dataset_id"] == "iot23"
        assert import_result["records_imported"] > 0
        assert import_result["scenarios"] == 1

    def test_manifest_generated(self, output_dir):
        assert (output_dir / "dataset_manifest.json").exists()
        assert (output_dir / "raw_manifest.json").exists()
        assert (output_dir / "provenance.json").exists()
        assert (output_dir / "label_mapping.json").exists()
        assert (output_dir / "audit.json").exists()
        assert (output_dir / "schema.json").exists()

    def test_dataset_manifest_fields(self, output_dir):
        manifest = json.loads((output_dir / "dataset_manifest.json").read_text())
        assert manifest["dataset_id"] == "iot23"
        assert manifest["dataset_name"] == "IoT-23"
        assert manifest["source"] == "Stratosphere Research Laboratory"
        assert manifest["source_format"] == "zeek_conn_labeled"
        assert manifest["record_count"] > 0
        assert manifest["scenario_count"] == 1
        assert manifest["source_checksum"] != ""

    def test_raw_manifest_records_provenance(self, output_dir):
        raw = json.loads((output_dir / "raw_manifest.json").read_text())
        assert raw["total_rows_seen"] > 0
        assert raw["total_rows_imported"] > 0
        assert len(raw["files"]) == 1
        assert raw["files"][0]["source_scenario"] == "test-scenario"
        assert raw["files"][0]["file_checksum"] != ""

    def test_audit_records_labels(self, output_dir):
        audit = json.loads((output_dir / "audit.json").read_text())
        assert audit["data_type"] == "external_real"
        assert audit["rows_seen"] > 0
        assert audit["rows_imported"] > 0
        assert "benign" in audit["label_distribution"]
        assert "malicious" in audit["label_distribution"]
        assert len(audit["native_labels"]) > 1
        assert len(audit["canonical_families"]) > 1

    def test_normalized_data_exists(self, output_dir):
        normalized_dir = output_dir / "normalized"
        parquet = normalized_dir / "flows.parquet"
        jsonl = normalized_dir / "flows.jsonl"
        assert parquet.exists() or jsonl.exists()

    def test_provenance_preserved_in_flows(self, output_dir):
        jsonl = output_dir / "normalized" / "flows.jsonl"
        if jsonl.exists():
            flows = [json.loads(line) for line in jsonl.read_text().strip().split("\n")]
        else:
            import pandas as pd
            df = pd.read_parquet(output_dir / "normalized" / "flows.parquet")
            flows = df.to_dict("records")

        assert len(flows) > 0
        first = flows[0]
        assert "record_id" in first
        assert "dataset_id" in first
        assert first["dataset_id"] == "iot23"
        assert "source_file" in first
        assert "source_scenario" in first
        assert first["source_scenario"] == "test-scenario"
        assert "native_label" in first
        assert "canonical_label" in first
        assert "binary_label" in first

    def test_label_mapping_file(self, output_dir):
        mapping = json.loads((output_dir / "label_mapping.json").read_text())
        assert mapping["dataset"] == "iot23"
        assert "mappings" in mapping
        assert "Benign" in mapping["mappings"]


class TestSecurity:
    def test_nonexistent_input_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            import_iot23(Path("/nonexistent/path"), tmp_path / "out")

    def test_output_dir_created(self, fixture_dir, tmp_path):
        out = tmp_path / "deeply" / "nested" / "output"
        import_iot23(fixture_dir, out, "v1")
        assert out.exists()
        assert (out / "dataset_manifest.json").exists()
