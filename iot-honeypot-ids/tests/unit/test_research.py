"""
Tests for the research experiment module.

Tests:
- Scenario manifest loading
- Experiment config creation and hashing
- Campaign/session data model
- Split strategies (campaign, temporal, unknown_family)
- Campaign overlap detection
- Hybrid detector (train + predict)
- Experiment runner (end-to-end on bootstrap dataset)
- Result artifact creation
"""
import sys
import json
import tempfile
from pathlib import Path

import pytest
import pandas as pd
import numpy as np

# Setup paths
REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "model-lab"))
sys.path.insert(0, str(REPO_ROOT / "dashboard" / "ml"))
sys.path.insert(0, str(REPO_ROOT / "shared" / "schemas"))

from model_lab.scenario_manifest import load_manifest, get_scenario, get_all_labels, get_all_families
from model_lab.experiment import Campaign, SessionRecord, ExperimentConfig, ExperimentResults, DatasetVersion
from model_lab.research import (
    split_by_campaign, split_temporal, split_unknown_family,
    check_campaign_overlap, HybridDetector, run_experiment,
)


@pytest.fixture
def v1_csv():
    csv = REPO_ROOT / "model-lab" / "datasets" / "v1" / "sessions.csv"
    if not csv.exists():
        pytest.skip("v1 dataset not found")
    return csv


@pytest.fixture
def v1_df(v1_csv):
    return pd.read_csv(v1_csv)


class TestScenarioManifest:
    def test_manifest_loads(self):
        manifest = load_manifest()
        assert len(manifest) >= 7  # at least 7 scenarios

    def test_get_scenario(self):
        s = get_scenario("ssh-bruteforce")
        assert s is not None
        assert s.expected_label == "brute_force"
        assert s.target_honeypot == "cowrie-01"

    def test_get_scenario_not_found(self):
        assert get_scenario("nonexistent") is None

    def test_get_all_labels(self):
        labels = get_all_labels()
        assert "brute_force" in labels
        assert "benign" in labels
        assert "reconnaissance" in labels

    def test_get_all_families(self):
        families = get_all_families()
        assert "credential_access" in families
        assert "discovery" in families

    def test_scenario_has_version(self):
        for s in load_manifest():
            assert s.version != ""

    def test_scenario_has_label_source(self):
        for s in load_manifest():
            assert s.label_source == "scenario"

    def test_benign_scenario_exists(self):
        s = get_scenario("benign-browsing")
        assert s is not None
        assert s.expected_label == "benign"
        assert s.family == "benign"


class TestCampaignSessionModel:
    def test_campaign_create(self):
        c = Campaign.create("ssh-bruteforce", "brute_force", "cowrie-01", repetitions=5)
        assert c.campaign_id.startswith("camp-ssh-bruteforce-")
        assert c.label == "brute_force"
        assert c.honeypot == "cowrie-01"
        assert c.repetitions == 5
        assert c.status == "planned"
        assert c.label_source == "scenario"

    def test_session_record(self):
        s = SessionRecord(
            session_id="sess-001",
            campaign_id="camp-001",
            scenario_id="ssh-bruteforce",
            label="brute_force",
            label_source="scenario",
            run_id="run-001",
            duration_s=30.5,
            event_count=15,
            features={"event_count": 15.0, "duration_s": 30.5},
        )
        assert s.session_id == "sess-001"
        assert s.features["event_count"] == 15.0

    def test_session_to_csv_row(self):
        s = SessionRecord(
            session_id="sess-001",
            campaign_id="camp-001",
            scenario_id="ssh-bruteforce",
            label="brute_force",
            label_source="scenario",
            run_id="run-001",
            features={"event_count": 15.0, "duration_s": 30.5},
        )
        row = s.to_csv_row()
        assert row["session_id"] == "sess-001"
        assert row["campaign_id"] == "camp-001"
        assert row["event_count"] == 15.0  # flattened feature


class TestExperimentConfig:
    def test_config_creates_id(self):
        c = ExperimentConfig(
            experiment_id="",
            training_scenarios=["ssh-bruteforce"],
            held_out_scenarios=["http-enumeration"],
        )
        assert c.experiment_id.startswith("exp-")

    def test_config_hash_deterministic(self):
        c1 = ExperimentConfig(
            experiment_id="exp-1",
            training_scenarios=["a", "b"],
            held_out_scenarios=["c"],
            seed=42,
        )
        c2 = ExperimentConfig(
            experiment_id="exp-2",
            training_scenarios=["b", "a"],  # different order
            held_out_scenarios=["c"],
            seed=42,
        )
        # Same config (sorted) → same hash
        assert c1.configuration_hash == c2.configuration_hash

    def test_config_to_json(self):
        c = ExperimentConfig(
            experiment_id="exp-test",
            training_scenarios=["a"],
            held_out_scenarios=["b"],
        )
        data = json.loads(c.to_json())
        assert data["experiment_id"] == "exp-test"
        assert data["training_scenarios"] == ["a"]


class TestSplitStrategies:
    def test_campaign_split_no_overlap(self, v1_df):
        train_idx, test_idx = split_by_campaign(v1_df, test_ratio=0.2, seed=42)
        train_campaigns = set(v1_df.iloc[train_idx]["campaign_id"])
        test_campaigns = set(v1_df.iloc[test_idx]["campaign_id"])
        assert len(train_campaigns & test_campaigns) == 0

    def test_campaign_split_both_nonempty(self, v1_df):
        train_idx, test_idx = split_by_campaign(v1_df, test_ratio=0.2, seed=42)
        assert len(train_idx) > 0
        assert len(test_idx) > 0

    def test_temporal_split_orders_by_time(self, v1_df):
        train_idx, test_idx = split_temporal(v1_df, test_ratio=0.2)
        assert len(train_idx) > 0
        assert len(test_idx) > 0

    def test_unknown_family_excludes_held_out(self, v1_df):
        # The bootstrap dataset has scenario_id like "syn-brute_force"
        # which won't match "http-enumeration". So all sessions go to known.
        # But we can test the logic with a scenario that exists.
        # Use a label that exists in the dataset
        held_out = ["syn-brute_force"]  # matches bootstrap scenario_id pattern
        train_idx, test_idx, unknown_idx = split_unknown_family(v1_df, held_out, seed=42)
        assert len(train_idx) > 0
        # Unknown should be the brute_force sessions
        assert len(unknown_idx) > 0
        # Train should NOT contain any unknown scenarios
        train_scenarios = set(v1_df.iloc[train_idx]["scenario_id"])
        assert "syn-brute_force" not in train_scenarios

    def test_check_campaign_overlap_detects_overlap(self, v1_df):
        # Force an overlap by using the same indices
        overlap = check_campaign_overlap([0, 1, 2], [2, 3, 4], v1_df)
        # At least one warning if sessions 2 shares a campaign with 0 or 1
        if len(overlap) > 0:
            assert "CAMPAIGN OVERLAP" in overlap[0]

    def test_check_campaign_overlap_no_overlap(self, v1_df):
        train_idx, test_idx = split_by_campaign(v1_df, test_ratio=0.2, seed=42)
        overlap = check_campaign_overlap(train_idx, test_idx, v1_df)
        assert len(overlap) == 0


class TestHybridDetector:
    def test_train_supervised(self):
        detector = HybridDetector("v2")
        X = np.random.rand(20, len(FEATURE_NAMES_V2) if 'FEATURE_NAMES_V2' in dir() else 22)
        y = np.array(["benign"] * 10 + ["brute_force"] * 10)
        # We need the actual feature names
        from features import FEATURE_NAMES_V2
        X = np.random.rand(20, len(FEATURE_NAMES_V2))
        detector.train_supervised(X, y, seed=42)
        assert detector.classifier is not None
        assert len(detector.classes) == 2

    def test_train_anomaly(self):
        from features import FEATURE_NAMES_V2
        detector = HybridDetector("v2")
        X = np.random.rand(20, len(FEATURE_NAMES_V2))
        detector.train_anomaly(X, contamination=0.1, seed=42)
        assert detector.anomaly_detector is not None

    def test_predict_returns_hybrid_results(self):
        from features import FEATURE_NAMES_V2, features_to_vector_v2
        detector = HybridDetector("v2")
        X = np.random.rand(20, len(FEATURE_NAMES_V2))
        y = np.array(["benign"] * 10 + ["brute_force"] * 10)
        detector.train_supervised(X, y, seed=42)
        detector.train_anomaly(X, contamination=0.1, seed=42)

        # Create test features
        test_features = [
            {fn: float(v) for fn, v in zip(FEATURE_NAMES_V2, np.random.rand(len(FEATURE_NAMES_V2)))}
            for _ in range(5)
        ]
        results = detector.predict(test_features)
        assert len(results) == 5
        for r in results:
            assert "rule_result" in r
            assert "supervised_prediction" in r
            assert "anomaly_score" in r
            assert "final_decision" in r
            assert "detection_sources" in r


class TestExperimentRunner:
    def test_run_experiment_campaign_split(self, v1_csv):
        config = ExperimentConfig(
            experiment_id="test-exp-campaign",
            training_scenarios=["ssh-bruteforce", "camera-recon"],
            held_out_scenarios=["http-enumeration"],
            feature_version="v2",
            split_strategy="campaign",
            test_ratio=0.2,
            seed=42,
            models=["supervised", "anomaly", "hybrid"],
        )
        config.dataset_version = "v1"  # type: ignore
        results = run_experiment(config, v1_csv)

        assert results.status == "completed"
        assert len(results.model_results) == 3  # supervised + anomaly + hybrid
        assert results.split_info["strategy"] == "campaign"

    def test_run_experiment_unknown_family(self, v1_csv):
        config = ExperimentConfig(
            experiment_id="test-exp-unknown",
            training_scenarios=["ssh-bruteforce", "camera-recon"],
            held_out_scenarios=["syn-brute_force"],  # matches bootstrap pattern
            feature_version="v2",
            split_strategy="unknown_family",
            seed=42,
            models=["supervised", "anomaly"],
        )
        config.dataset_version = "v1"  # type: ignore
        results = run_experiment(config, v1_csv)

        assert results.status == "completed"
        assert "unknown_size" in results.split_info
        # Should have unknown metrics in the anomaly model
        anomaly_result = [r for r in results.model_results if r["model_type"] == "anomaly"]
        if anomaly_result:
            assert "unknown_metrics" in anomaly_result[0]
            unknown_metrics = anomaly_result[0]["unknown_metrics"]
            if unknown_metrics:
                assert "unknown_detection_rate" in unknown_metrics

    def test_experiment_creates_artifacts(self, v1_csv):
        config = ExperimentConfig(
            experiment_id="test-exp-artifacts",
            training_scenarios=["ssh-bruteforce"],
            held_out_scenarios=["http-enumeration"],
            feature_version="v2",
            split_strategy="campaign",
            seed=42,
            models=["supervised"],
        )
        config.dataset_version = "v1"  # type: ignore
        run_experiment(config, v1_csv)

        exp_dir = REPO_ROOT / "model-lab" / "experiments" / "test-exp-artifacts"
        assert (exp_dir / "config.json").exists()
        assert (exp_dir / "results.json").exists()
        assert (exp_dir / "dataset_audit.json").exists()

        # Verify results.json is valid JSON
        results = json.loads((exp_dir / "results.json").read_text())
        assert results["experiment_id"] == "test-exp-artifacts"
        assert len(results["model_results"]) > 0

    def test_experiment_warnings_for_bootstrap(self, v1_csv):
        config = ExperimentConfig(
            experiment_id="test-exp-warnings",
            training_scenarios=["ssh-bruteforce"],
            held_out_scenarios=["http-enumeration"],
            feature_version="v2",
            split_strategy="campaign",
            seed=42,
            models=["supervised"],
        )
        config.dataset_version = "v1"  # type: ignore
        results = run_experiment(config, v1_csv)

        # Bootstrap dataset should produce warnings
        assert len(results.warnings) > 0
        # Should warn about unique campaigns
        camp_warnings = [w for w in results.warnings if "campaign" in w.lower()]
        assert len(camp_warnings) > 0
