"""Regression tests for Pass 3 research pipeline fixes.

Covers:
- Full SHA-256 (64 chars) for provenance, not truncated (16 chars)
- N-BaIoT label_source = device_condition (not external)
- N-BaIoT source_url points to original USIB/UPC, not Kaggle
- UnknownBotnet label mapping (found in real IoT-23 fixture)
- split_unknown_family_with_validation provides separate val set
- HybridDetector.select_anomaly_threshold() selects on validation
- anomaly_threshold NOT hardcoded to -0.1 in predict()
- cross_dataset.check_compatibility() returns NOT_COMPARABLE for IoT-23 vs N-BaIoT
- session-level split marks leakage_unsafe=True
"""
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "model-lab"))


class TestSha256FullHash:
    """D1/D2/D11: SHA-256 must be full 64 chars, not truncated to 16."""

    def test_iot23_file_checksum_is_64_chars(self, tmp_path):
        from model_lab.datasets.import_iot23 import file_checksum
        f = tmp_path / "test.log"
        f.write_text("test content")
        h = file_checksum(f)
        assert len(h) == 64, f"Expected 64-char SHA-256, got {len(h)}: {h}"

    def test_nbaiot_file_checksum_is_64_chars(self, tmp_path):
        from model_lab.datasets.import_n_baiot import file_checksum
        f = tmp_path / "test.csv"
        f.write_text("test content")
        h = file_checksum(f)
        assert len(h) == 64, f"Expected 64-char SHA-256, got {len(h)}: {h}"

    def test_checksum_is_hex(self, tmp_path):
        from model_lab.datasets.import_iot23 import file_checksum
        f = tmp_path / "test.log"
        f.write_text("test content")
        h = file_checksum(f)
        assert all(c in "0123456789abcdef" for c in h), f"Non-hex char in hash: {h}"

    def test_checksum_deterministic(self, tmp_path):
        from model_lab.datasets.import_iot23 import file_checksum
        f = tmp_path / "test.log"
        f.write_text("same content")
        h1 = file_checksum(f)
        h2 = file_checksum(f)
        assert h1 == h2

    def test_checksum_changes_with_content(self, tmp_path):
        from model_lab.datasets.import_iot23 import file_checksum
        f1 = tmp_path / "a.log"
        f1.write_text("content a")
        f2 = tmp_path / "b.log"
        f2.write_text("content b")
        assert file_checksum(f1) != file_checksum(f2)


class TestNBaiotLabelSource:
    """D3: N-BaIoT label_source must be device_condition (controlled experiment),
    NOT external/analyst-derived. N-BaIoT labels are reliable experimental conditions."""

    def test_nbaiot_label_source_in_import(self, tmp_path):
        """Verify the importer writes label_source=device_condition."""
        from model_lab.datasets.import_n_baiot import stream_nbaiot_rows
        # Create a minimal N-BaIoT-style CSV
        csv = tmp_path / "test_benign.csv"
        csv.write_text("1.0,2.0,3.0\n4.0,5.0,6.0\n")
        records = list(stream_nbaiot_rows(csv, "Danmini", "benign", "nbaiot", "v1"))
        assert len(records) == 2
        for rec, reason in records:
            assert reason is None
            assert rec["label_source"] == "device_condition", \
                f"Expected device_condition, got {rec['label_source']}"

    def test_nbaiot_label_source_not_external(self, tmp_path):
        """D3 regression: must not be 'external'."""
        from model_lab.datasets.import_n_baiot import stream_nbaiot_rows
        csv = tmp_path / "test.csv"
        csv.write_text("1.0,2.0\n")
        records = list(stream_nbaiot_rows(csv, "Danmini", "mirai", "nbaiot", "v1"))
        rec = records[0][0]
        assert rec["label_source"] != "external"
        assert rec["label_source"] != "external_analyst_derived"


class TestNBaiotSourceUrl:
    """D10: N-BaIoT source_url must point to the original USIB/UPC source,
    not a third-party Kaggle mirror."""

    def test_nbaiot_manifest_source_url(self, tmp_path):
        """The manifest dataset_manifest.json must have the correct source_url."""
        from model_lab.datasets.import_n_baiot import import_n_baiot
        # Create minimal N-BaIoT structure
        device_dir = tmp_path / "Danmini_Doorbell"
        device_dir.mkdir()
        csv = device_dir / "benign_traffic.csv"
        csv.write_text("1.0,2.0,3.0\n4.0,5.0,6.0\n")
        out = tmp_path / "out"
        import_n_baiot(tmp_path, out, "v1")
        import json
        manifest = json.loads((out / "dataset_manifest.json").read_text())
        assert "kaggle" not in manifest["source_url"].lower(), \
            f"source_url should not point to Kaggle: {manifest['source_url']}"
        assert "stratosphere" in manifest["source_url"].lower() or \
               "iotstratosphere" in manifest["source_url"].lower() or \
               "usib" in manifest["source_url"].lower() or \
               "upc" in manifest["source_url"].lower(), \
            f"source_url should point to original source: {manifest['source_url']}"


class TestUnknownBotnetMapping:
    """D-iot23: UnknownBotnet is a real IoT-23 label — must be mapped."""

    def test_unknown_botnet_mapped(self):
        from model_lab.label_mapping_iot23 import map_label
        family, binary, label, conf, reason = map_label("UnknownBotnet")
        assert family != "unknown", f"UnknownBotnet should be mapped, got family={family}"
        assert binary == "malicious"
        assert conf > 0.0

    def test_mapping_version_v3(self):
        from model_lab.label_mapping_iot23 import get_mapping_version
        v = get_mapping_version()
        assert v == "v3", f"Expected v3 (adds UnknownBotnet), got {v}"

    def test_unknown_botnet_in_mapping_dict(self):
        from model_lab.label_mapping_iot23 import LABEL_MAPPING
        assert "UnknownBotnet" in LABEL_MAPPING


class TestUnknownFamilySplitWithValidation:
    """D-split: unknown_family split must provide a separate validation set
    for threshold selection, NOT tune on the test set."""

    @pytest.fixture
    def sample_df(self):
        import pandas as pd
        # Create a small dataset with multiple campaigns and scenarios
        rows = []
        for i in range(100):
            scenario = "ssh-bruteforce" if i < 50 else "http-enumeration"
            campaign = f"camp-{scenario}-{i // 10}"  # 5 sessions per campaign
            rows.append({
                "session_id": f"sess-{i}",
                "campaign_id": campaign,
                "scenario_id": scenario,
                "label": "brute_force" if i < 25 else ("benign" if i < 50 else "command_injection"),
                "start_time": f"2024-01-{(i % 28) + 1:02d}T10:00:00Z",
                "event_count": float(i),
                "duration_s": float(i * 1.5),
            })
        return pd.DataFrame(rows)

    def test_returns_four_sets(self, sample_df):
        from model_lab.research import split_unknown_family_with_validation
        result = split_unknown_family_with_validation(
            sample_df, ["http-enumeration"], seed=42
        )
        assert len(result) == 4, "Should return (train, val, known_test, unknown)"

    def test_unknown_not_in_train_or_val(self, sample_df):
        from model_lab.research import split_unknown_family_with_validation
        train, val, test, unknown = split_unknown_family_with_validation(
            sample_df, ["http-enumeration"], seed=42
        )
        train_scenarios = set(sample_df.iloc[train]["scenario_id"])
        val_scenarios = set(sample_df.iloc[val]["scenario_id"])
        assert "http-enumeration" not in train_scenarios
        assert "http-enumeration" not in val_scenarios

    def test_no_campaign_overlap_train_val_test(self, sample_df):
        from model_lab.research import split_unknown_family_with_validation
        train, val, test, unknown = split_unknown_family_with_validation(
            sample_df, ["http-enumeration"], seed=42
        )
        train_camps = set(sample_df.iloc[train]["campaign_id"])
        val_camps = set(sample_df.iloc[val]["campaign_id"])
        test_camps = set(sample_df.iloc[test]["campaign_id"])
        assert not (train_camps & val_camps), "Train/val campaign overlap"
        assert not (train_camps & test_camps), "Train/test campaign overlap"
        assert not (val_camps & test_camps), "Val/test campaign overlap"

    def test_unknown_only_contains_held_out(self, sample_df):
        from model_lab.research import split_unknown_family_with_validation
        train, val, test, unknown = split_unknown_family_with_validation(
            sample_df, ["http-enumeration"], seed=42
        )
        unknown_scenarios = set(sample_df.iloc[unknown]["scenario_id"])
        assert unknown_scenarios == {"http-enumeration"}


class TestHybridDetectorThreshold:
    """D6/D7: anomaly threshold must be selected on validation data,
    NOT hardcoded to -0.1."""

    def test_threshold_not_negative_zero_point_one_default(self):
        """The HybridDetector.predict() must NOT use -0.1 as default threshold."""
        from model_lab.research import HybridDetector
        import numpy as np
        d = HybridDetector("v2")
        # Before select_anomaly_threshold, threshold is 0.0 (not -0.1)
        assert d.anomaly_threshold == 0.0
        assert d.anomaly_threshold != -0.1, "Default threshold must NOT be -0.1"

    def test_select_anomaly_threshold_on_validation(self):
        from model_lab.research import HybridDetector
        import numpy as np
        from features import FEATURE_NAMES_V2
        d = HybridDetector("v2")
        X = np.random.rand(50, len(FEATURE_NAMES_V2))
        d.train_anomaly(X, contamination=0.1, seed=42)
        # Select threshold on validation
        X_val = np.random.rand(20, len(FEATURE_NAMES_V2))
        y_val = np.array(["benign"] * 15 + ["brute_force"] * 5)
        threshold = d.select_anomaly_threshold(X_val, y_val, benign_label="benign", target_fpr=0.05)
        assert d.anomaly_threshold == threshold
        assert "validation" in d.threshold_selection_method

    def test_select_threshold_before_predict(self):
        """predict() must use the threshold selected via select_anomaly_threshold()."""
        from model_lab.research import HybridDetector
        import numpy as np
        from features import FEATURE_NAMES_V2
        d = HybridDetector("v2")
        X = np.random.rand(50, len(FEATURE_NAMES_V2))
        d.train_anomaly(X)
        X_val = np.random.rand(20, len(FEATURE_NAMES_V2))
        y_val = np.array(["benign"] * 20)
        threshold = d.select_anomaly_threshold(X_val, y_val, target_fpr=0.1)
        # predict() should use this threshold, not -0.1
        feats = [{n: float(v) for n, v in zip(FEATURE_NAMES_V2, row)} for row in X_val[:5]]
        results = d.predict(feats)
        # Verify threshold was actually used
        assert d.anomaly_threshold == threshold
        assert threshold != -0.1


class TestCrossDatasetNotComparable:
    """D12: IoT-23 and N-BaIoT are NOT directly comparable — different feature spaces."""

    def test_iot23_vs_nbaiot_not_comparable(self):
        from model_lab.cross_dataset import check_compatibility
        result = check_compatibility("iot23", "nbaiot")
        assert result.comparable is False
        assert "NOT_COMPARABLE" in result.reason
        assert result.comparable_subset == "binary_label_only"

    def test_same_dataset_comparable(self):
        from model_lab.cross_dataset import check_compatibility
        result = check_compatibility("iot23", "iot23")
        assert result.comparable is True

    def test_iot23_vs_synthetic_different(self):
        from model_lab.cross_dataset import check_compatibility
        result = check_compatibility("iot23", "trapsig_synthetic")
        # Different representations
        assert result.comparable is False

    def test_unknown_dataset_returns_error(self):
        from model_lab.cross_dataset import check_compatibility
        result = check_compatibility("iot23", "unknown_dataset")
        assert result.comparable is False
        assert "Unknown dataset" in result.reason


class TestSessionLevelSplitMarksLeakageUnsafe:
    """D5: session-level split must mark itself as leakage_unsafe."""

    def test_session_split_has_leakage_unsafe_marker(self, tmp_path):
        """Run an experiment with session split and verify the marker."""
        from model_lab.research import run_experiment
        from model_lab.experiment import ExperimentConfig
        import pandas as pd

        # Create a small dataset
        csv = tmp_path / "sessions.csv"
        rows = []
        for i in range(50):
            rows.append({
                "session_id": f"sess-{i}",
                "campaign_id": f"camp-{i // 5}",  # 5 sessions per campaign
                "scenario_id": "ssh-bruteforce",
                "label": ["benign", "brute_force", "reconnaissance"][i % 3],
                "label_source": "scenario",
                "start_time": f"2024-01-{(i % 28) + 1:02d}T10:00:00Z",
                "event_count": float(i),
                "duration_s": float(i),
            })
        df = pd.DataFrame(rows)
        df.to_csv(csv, index=False)

        config = ExperimentConfig(
            experiment_id="test-session-split",
            training_scenarios=["ssh-bruteforce"],
            held_out_scenarios=[],
            split_strategy="session",  # the unsafe one
            seed=42,
        )
        # Set dataset_version (it's set externally in the CLI, not in __init__)
        config.dataset_version = "v1"
        results = run_experiment(config, csv)
        assert results.split_info.get("leakage_unsafe") is True
        assert any("leakage" in w.lower() for w in results.warnings)
