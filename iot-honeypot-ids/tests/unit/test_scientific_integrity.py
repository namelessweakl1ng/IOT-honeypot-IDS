"""Tests for label provenance + leakage audit — scientific integrity."""
import pytest
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "shared"))

from schemas.label_provenance import (
    LabelSource, LabelProvenance, LabelProvenanceError,
    validate_label_for_training, audit_dataset_labels,
)
from schemas.leakage_audit import (
    audit_feature, audit_feature_set, validate_features_for_training,
    LeakageClassification,
)


class TestLabelProvenance:
    """Verify rule engine output CANNOT silently become ground truth."""

    def test_rule_engine_is_not_ground_truth(self):
        """RULE_ENGINE is a detector output — NOT ground truth."""
        assert not LabelSource.RULE_ENGINE.is_ground_truth
        assert LabelSource.RULE_ENGINE.is_detector_output

    def test_scenario_ground_truth_is_ground_truth(self):
        assert LabelSource.SCENARIO_GROUND_TRUTH.is_ground_truth

    def test_analyst_labeled_is_ground_truth(self):
        assert LabelSource.ANALYST_LABELED.is_ground_truth

    def test_synthetic_is_ground_truth(self):
        """SYNTHETIC labels can be used for development training."""
        assert LabelSource.SYNTHETIC.is_ground_truth

    def test_unlabeled_is_not_ground_truth(self):
        assert not LabelSource.UNLABELED.is_ground_truth

    def test_validate_rejects_rule_engine_for_training(self):
        """Training on RULE_ENGINE labels must FAIL."""
        with pytest.raises(LabelProvenanceError, match="circular evaluation"):
            validate_label_for_training("brute_force", "rule_engine")

    def test_validate_rejects_unlabeled_for_training(self):
        with pytest.raises(LabelProvenanceError, match="unlabeled"):
            validate_label_for_training("unknown", "unlabeled")

    def test_validate_accepts_scenario_ground_truth(self):
        result = validate_label_for_training("brute_force", "scenario_ground_truth")
        assert result == LabelSource.SCENARIO_GROUND_TRUTH

    def test_validate_accepts_synthetic(self):
        result = validate_label_for_training("brute_force", "synthetic")
        assert result == LabelSource.SYNTHETIC

    def test_rule_engine_confidence_capped(self):
        """RULE_ENGINE confidence is capped at 0.9 — it's a detector output."""
        lp = LabelProvenance(
            label="brute_force",
            label_source=LabelSource.RULE_ENGINE,
            labeling_confidence=1.0,  # try to set 1.0
        )
        assert lp.labeling_confidence == 0.9  # capped

    def test_scenario_confidence_not_capped(self):
        lp = LabelProvenance(
            label="brute_force",
            label_source=LabelSource.SCENARIO_GROUND_TRUTH,
            labeling_confidence=1.0,
        )
        assert lp.labeling_confidence == 1.0  # not capped


class TestDatasetLabelAudit:
    """Verify dataset label auditing catches circular evaluation."""

    def test_safe_dataset_passes_audit(self):
        rows = [
            {"label": "brute_force", "label_source": "scenario_ground_truth"},
            {"label": "recon", "label_source": "scenario_ground_truth"},
        ]
        report = audit_dataset_labels(rows)
        assert report["is_safe_for_training"] is True
        assert report["rule_engine_labeled_rows"] == 0
        assert report["ground_truth_rows"] == 2

    def test_rule_engine_labels_detected_as_circular(self):
        rows = [
            {"label": "brute_force", "label_source": "rule_engine"},
            {"label": "recon", "label_source": "rule_engine"},
        ]
        report = audit_dataset_labels(rows)
        assert report["is_safe_for_training"] is False
        assert report["circular_evaluation_risk"] is True
        assert report["rule_engine_labeled_rows"] == 2
        assert report["ground_truth_rows"] == 0

    def test_mixed_dataset_detected(self):
        rows = [
            {"label": "brute_force", "label_source": "scenario_ground_truth"},
            {"label": "recon", "label_source": "rule_engine"},
            {"label": "unknown", "label_source": "unlabeled"},
        ]
        report = audit_dataset_labels(rows)
        assert report["is_safe_for_training"] is False
        assert report["rule_engine_labeled_rows"] == 1
        assert report["unlabeled_rows"] == 1
        assert report["ground_truth_rows"] == 1

    def test_missing_label_source_detected(self):
        rows = [
            {"label": "brute_force"},  # no label_source
        ]
        report = audit_dataset_labels(rows)
        assert report["missing_label_source_rows"] == 1
        assert report["is_safe_for_training"] is False


class TestLeakageAudit:
    """Verify feature leakage audit correctly classifies features."""

    def test_leaky_feature_detected(self):
        report = audit_feature("contains_path_traversal")
        assert report.classification == LeakageClassification.LEAKY
        assert "circular" in report.reason.lower()

    def test_leaky_command_injection_detected(self):
        report = audit_feature("contains_command_injection")
        assert report.classification == LeakageClassification.LEAKY

    def test_leaky_default_credentials_detected(self):
        report = audit_feature("contains_default_credentials")
        assert report.classification == LeakageClassification.LEAKY

    def test_safe_feature_classified(self):
        report = audit_feature("auth_attempts")
        assert report.classification == LeakageClassification.SAFE

    def test_safe_duration_classified(self):
        report = audit_feature("duration_s")
        assert report.classification == LeakageClassification.SAFE

    def test_label_feature_rejected(self):
        report = audit_feature("label")
        assert report.classification == LeakageClassification.LEAKY

    def test_scenario_id_rejected(self):
        report = audit_feature("scenario_id")
        assert report.classification == LeakageClassification.LEAKY
        assert report.leakage_type in ("scenario_id_leakage", "identity_leakage")

    def test_source_ip_rejected(self):
        report = audit_feature("source_ip")
        assert report.classification == LeakageClassification.LEAKY

    def test_feature_set_audit(self):
        features = ["auth_attempts", "duration_s", "contains_path_traversal", "event_count"]
        audit = audit_feature_set(features)
        assert audit["total_features"] == 4
        assert audit["leaky_count"] == 1
        assert audit["safe_count"] == 3
        assert audit["is_safe_for_training"] is False
        assert "contains_path_traversal" in audit["leaky_features"]

    def test_clean_feature_set_passes(self):
        features = ["auth_attempts", "duration_s", "event_count", "uri_count"]
        audit = audit_feature_set(features)
        assert audit["is_safe_for_training"] is True
        assert audit["leaky_count"] == 0

    def test_validate_rejects_leaky_features(self):
        features = ["auth_attempts", "contains_path_traversal"]
        with pytest.raises(ValueError, match="LEAKY features"):
            validate_features_for_training(features, allow_leaky=False)

    def test_validate_allows_leaky_when_explicit(self):
        features = ["auth_attempts", "contains_path_traversal"]
        result = validate_features_for_training(features, allow_leaky=True)
        assert len(result) == 2  # both returned

    def test_validate_strips_leaky_by_default(self):
        """validate_features_for_training REJECTS leaky features by default
        (raises ValueError). The caller must use feature_version='v2' which
        already excludes them, or pass allow_leaky=True for experimental runs."""
        features = ["auth_attempts", "contains_path_traversal", "event_count"]
        with pytest.raises(ValueError, match="LEAKY features"):
            validate_features_for_training(features, allow_leaky=False)
        # With allow_leaky=True, all features are returned (experimental)
        result = validate_features_for_training(features, allow_leaky=True)
        assert len(result) == 3
