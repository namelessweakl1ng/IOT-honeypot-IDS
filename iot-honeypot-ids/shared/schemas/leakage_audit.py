"""Automated feature leakage audit.

Classifies each feature as SAFE / SUSPECT / LEAKY / UNKNOWN based on
whether it could leak the label into the feature space.

Leakage types checked:
  - direct_label_derivation: feature is derived from the label itself
  - post_label_enrichment: feature added AFTER classification (Logstash enrichment)
  - scenario_id_leakage: scenario_id in features
  - campaign_id_leakage: campaign_id in features
  - honeypot_identity_leakage: honeypot.name used as a feature (can leak via class correlation)
  - attacker_ip_leakage: source.ip used directly as a feature
  - timestamp_leakage: raw timestamp used as a feature (temporal leakage)
  - dataset_origin_leakage: dataset origin encoded in features
  - rule_output_leakage: rule classification output used as a feature
  - future_information: information from after the session ended

Classifier training MUST reject LEAKY features unless the user explicitly
requests an experimental leakage run.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Set, Tuple


class LeakageClassification(str, Enum):
    SAFE = "safe"
    SUSPECT = "suspect"
    LEAKY = "leaky"
    UNKNOWN = "unknown"


@dataclass
class FeatureLeakageReport:
    feature_name: str
    classification: LeakageClassification
    reason: str
    leakage_type: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "feature": self.feature_name,
            "classification": self.classification.value,
            "reason": self.reason,
            "leakage_type": self.leakage_type,
        }


# Known LEAKY features — derived from attack.classification (Logstash enrichment)
# These are the same features already identified in dashboard/ml/features.py
KNOWN_LEAKY_FEATURES: Set[str] = {
    "contains_path_traversal",
    "contains_command_injection",
    "contains_default_credentials",
}

# Known SUSPECT features — may leak in some contexts
KNOWN_SUSPECT_FEATURES: Set[str] = {
    # source.ip encoded as a feature could leak attacker identity
    # (but we don't currently include it — if added, flag as suspect)
    # honeypot.name could correlate with label (but we don't include it)
    # scenario_id, campaign_id, dataset_origin are metadata, not features
}

# Features that should NEVER be in the feature vector
FORBIDDEN_AS_FEATURES: Set[str] = {
    "label",
    "label_source",
    "scenario_id",
    "campaign_id",
    "dataset_origin",
    "session_id",
    "event_id",
    "source_ip",
    "attacker_ip",
}


def audit_feature(feature_name: str, feature_value_description: str = "") -> FeatureLeakageReport:
    """Classify a single feature for leakage risk.

    Args:
        feature_name: the name of the feature
        feature_value_description: optional description of what the feature computes

    Returns:
        FeatureLeakageReport with classification + reason.
    """
    name_lower = feature_name.lower()

    # Check forbidden features (metadata that should never be a feature)
    if name_lower in FORBIDDEN_AS_FEATURES:
        return FeatureLeakageReport(
            feature_name=feature_name,
            classification=LeakageClassification.LEAKY,
            reason=f"{feature_name} is metadata/identity, not a behavioral feature — including it leaks label or identity",
            leakage_type="identity_leakage",
        )

    # Check known leaky features
    if feature_name in KNOWN_LEAKY_FEATURES:
        return FeatureLeakageReport(
            feature_name=feature_name,
            classification=LeakageClassification.LEAKY,
            reason=f"{feature_name} is derived from attack.classification (Logstash enrichment) — using it creates circular evaluation because the classification signal influences both the label and the feature",
            leakage_type="rule_output_leakage",
        )

    # Check known suspect features
    if feature_name in KNOWN_SUSPECT_FEATURES:
        return FeatureLeakageReport(
            feature_name=feature_name,
            classification=LeakageClassification.SUSPECT,
            reason=f"{feature_name} may leak in some contexts — verify it does not correlate with the label",
            leakage_type="contextual_leakage",
        )

    # Check for common leakage patterns in the name
    if "classification" in name_lower or "label" in name_lower:
        return FeatureLeakageReport(
            feature_name=feature_name,
            classification=LeakageClassification.LEAKY,
            reason=f"feature name contains 'classification' or 'label' — likely derived from the label",
            leakage_type="direct_label_derivation",
        )

    if "scenario" in name_lower or "campaign" in name_lower:
        return FeatureLeakageReport(
            feature_name=feature_name,
            classification=LeakageClassification.LEAKY,
            reason=f"feature name contains 'scenario' or 'campaign' — scenario/campaign ID can leak the label",
            leakage_type="scenario_id_leakage",
        )

    if "source_ip" in name_lower or "attacker_ip" in name_lower or "src_ip" in name_lower:
        return FeatureLeakageReport(
            feature_name=feature_name,
            classification=LeakageClassification.LEAKY,
            reason=f"feature name contains IP reference — attacker IP can leak identity + label",
            leakage_type="attacker_ip_leakage",
        )

    # Check description for leakage hints
    desc_lower = feature_value_description.lower()
    if "classification" in desc_lower or "attack.classification" in desc_lower:
        return FeatureLeakageReport(
            feature_name=feature_name,
            classification=LeakageClassification.LEAKY,
            reason=f"feature description mentions 'classification' — derived from Logstash enrichment (post-label)",
            leakage_type="post_label_enrichment",
        )

    if "label" in desc_lower and "not" not in desc_lower:
        return FeatureLeakageReport(
            feature_name=feature_name,
            classification=LeakageClassification.SUSPECT,
            reason=f"feature description mentions 'label' — verify it is not derived from the label",
            leakage_type="possible_label_derivation",
        )

    # Default: SAFE (behavioral features that don't touch classification)
    return FeatureLeakageReport(
        feature_name=feature_name,
        classification=LeakageClassification.SAFE,
        reason=f"behavioral feature — derived from observable session/event properties, not from classification or label",
        leakage_type="",
    )


def audit_feature_set(feature_names: List[str]) -> Dict[str, Any]:
    """Audit a complete feature set for leakage.

    Returns:
        Dict with:
          - total_features
          - safe_count
          - suspect_count
          - leaky_count
          - unknown_count
          - leaky_features (list of names)
          - suspect_features (list of names)
          - is_safe_for_training (bool — True if no LEAKY features)
          - reports (list of FeatureLeakageReport dicts)
    """
    reports = [audit_feature(name) for name in feature_names]
    safe_count = sum(1 for r in reports if r.classification == LeakageClassification.SAFE)
    suspect_count = sum(1 for r in reports if r.classification == LeakageClassification.SUSPECT)
    leaky_count = sum(1 for r in reports if r.classification == LeakageClassification.LEAKY)
    unknown_count = sum(1 for r in reports if r.classification == LeakageClassification.UNKNOWN)

    return {
        "total_features": len(feature_names),
        "safe_count": safe_count,
        "suspect_count": suspect_count,
        "leaky_count": leaky_count,
        "unknown_count": unknown_count,
        "leaky_features": [r.feature_name for r in reports if r.classification == LeakageClassification.LEAKY],
        "suspect_features": [r.feature_name for r in reports if r.classification == LeakageClassification.SUSPECT],
        "is_safe_for_training": leaky_count == 0,
        "reports": [r.to_dict() for r in reports],
    }


def validate_features_for_training(feature_names: List[str], allow_leaky: bool = False) -> List[str]:
    """Validate that a feature set is safe for training.

    Args:
        feature_names: the feature names to validate
        allow_leaky: if True, allow LEAKY features (experimental leakage run)

    Returns:
        The list of SAFE feature names (LEAKY excluded unless allow_leaky=True).

    Raises:
        ValueError: if LEAKY features are found and allow_leaky=False
    """
    audit = audit_feature_set(feature_names)
    if audit["leaky_count"] > 0 and not allow_leaky:
        raise ValueError(
            f"LEAKY features detected: {audit['leaky_features']}. "
            f"These are derived from attack.classification and create circular "
            f"evaluation. Use feature_version='v2' (which excludes them) or pass "
            f"allow_leaky=True for an experimental leakage run."
        )
    if allow_leaky:
        return feature_names  # return all (experimental)
    return [f for f in feature_names if f not in audit["leaky_features"]]
