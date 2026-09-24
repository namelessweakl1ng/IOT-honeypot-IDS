"""
Tests for the dataset audit module.

Tests:
- Audit on the existing v1 bootstrap dataset
- Leakage detection (contains_* features flagged)
- Campaign count / unique campaign ratio
- Duplicate session detection
- Class distribution
- Label provenance
- Warning generation for small/synthetic datasets
"""
import sys
from pathlib import Path

import pytest

# Setup paths
REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "model-lab"))
sys.path.insert(0, str(REPO_ROOT / "dashboard" / "ml"))
sys.path.insert(0, str(REPO_ROOT / "shared" / "schemas"))

from model_lab.dataset_audit import audit_dataset, DatasetAuditReport, LEAKY_FEATURES


@pytest.fixture
def v1_csv():
    csv = REPO_ROOT / "model-lab" / "datasets" / "v1" / "sessions.csv"
    if not csv.exists():
        pytest.skip("v1 dataset not found")
    return csv


@pytest.fixture
def audit_report(v1_csv):
    return audit_dataset(v1_csv, "v1")


class TestDatasetAudit:
    def test_audit_returns_report(self, audit_report):
        assert isinstance(audit_report, DatasetAuditReport)

    def test_session_count_positive(self, audit_report):
        assert audit_report.session_count > 0
        assert audit_report.session_count == 210  # known bootstrap size

    def test_campaign_count(self, audit_report):
        # The bootstrap dataset has unique campaign_id per row — this is a KNOWN issue
        assert audit_report.campaign_count > 0

    def test_unique_campaign_ratio_is_low_with_campaign_grouping(self, audit_report):
        # The fixed bootstrap dataset has 5 sessions per campaign
        # unique_campaign_ratio should be ~0.20 (42 campaigns / 210 sessions)
        assert audit_report.unique_campaign_ratio < 0.5
        assert audit_report.unique_campaign_ratio > 0.1  # not too few campaigns either

    def test_class_distribution_has_expected_labels(self, audit_report):
        expected_labels = {"brute_force", "default_credentials", "reconnaissance",
                           "command_injection", "path_traversal", "anomaly", "benign"}
        assert set(audit_report.class_distribution.keys()) == expected_labels

    def test_classes_are_balanced(self, audit_report):
        # Bootstrap dataset is balanced: 30 per class
        counts = list(audit_report.class_distribution.values())
        assert min(counts) == 30
        assert max(counts) == 30

    def test_label_sources_all_synthetic(self, audit_report):
        # Bootstrap dataset is all SYNTHETIC
        assert audit_report.label_sources.get("SYNTHETIC", 0) == 210

    def test_leaky_features_detected(self, audit_report):
        assert "contains_path_traversal" in audit_report.leaky_features
        assert "contains_command_injection" in audit_report.leaky_features
        assert "contains_default_credentials" in audit_report.leaky_features

    def test_leaky_feature_exposure(self, audit_report):
        # Each leaky feature should have some non-zero exposure
        for lf in audit_report.leaky_features:
            exposure = audit_report.leaky_feature_exposure.get(lf, 0)
            assert exposure > 0, f"{lf} should have non-zero exposure in the dataset"

    def test_no_duplicates_in_bootstrap(self, audit_report):
        # Bootstrap dataset should have unique session IDs
        assert audit_report.duplicate_count == 0

    def test_warnings_generated(self, audit_report):
        # Bootstrap dataset should trigger warnings
        assert len(audit_report.warnings) > 0

    def test_warning_about_unique_campaigns(self, audit_report):
        # Should warn about ~1 session per campaign
        camp_warning = [w for w in audit_report.warnings if "campaign" in w.lower()]
        assert len(camp_warning) > 0

    def test_warning_about_synthetic(self, audit_report):
        # Should warn about synthetic data
        synth_warning = [w for w in audit_report.warnings if "synthetic" in w.lower()]
        assert len(synth_warning) > 0

    def test_warning_about_leaky_features(self, audit_report):
        # Should warn about leaky features
        leaky_warning = [w for w in audit_report.warnings if "leaky" in w.lower() or "leak" in w.lower()]
        assert len(leaky_warning) > 0

    def test_hash_is_computed(self, audit_report):
        assert audit_report.hash != ""
        # Full SHA-256 = 64 hex chars (was 16 in pre-Pass-3 versions — that
        # was a truncation defect corrected in Pass 3 for research provenance).
        assert len(audit_report.hash) == 64

    def test_summary_is_readable(self, audit_report):
        summary = audit_report.summary()
        assert "DATASET AUDIT" in summary
        assert "Sessions:" in summary
        assert "Campaigns:" in summary
        assert "Leaky features:" in summary

    def test_to_json_serializable(self, audit_report):
        import json
        data = json.loads(audit_report.to_json())
        assert "dataset_version" in data
        assert "session_count" in data
        assert "warnings" in data

    def test_feature_categories_classified(self, audit_report):
        # All features should be classified as either behavioral or label_derived
        assert "behavioral" in audit_report.feature_categories
        assert "label_derived" in audit_report.feature_categories
        # The 3 leaky features should be in label_derived
        for lf in LEAKY_FEATURES:
            assert lf in audit_report.feature_categories.get("label_derived", [])
