"""Label provenance — formal distinction between ground truth and detector output.

SCIENTIFIC INTEGRITY (Section 1-2 of the research hardening spec):
  Rule engine output is a DETECTOR OUTPUT, not ground truth. Using rule output
  as training labels creates circular evaluation: the same classification signal
  influences both the label and the feature space.

  This module enforces:
    1. A formal enum of label sources
    2. A validation function that rejects rule_output as ground truth
    3. A LabelProvenance dataclass that carries provenance metadata

Label source hierarchy (most reliable → least reliable):
  SCENARIO_GROUND_TRUTH — controlled attacker scenario metadata (highest reliability)
  ANALYST_LABELED       — human analyst annotation
  EXTERNAL_DATASET      — labels from IoT-23, N-BaIoT, or other external datasets
  SYNTHETIC             — programmatically generated labels (for development only)
  RULE_ENGINE           — rule detector output (NEVER ground truth)
  UNLABELED             — no label available

CRITICAL INVARIANT:
  RULE_ENGINE labels can NEVER be used as ground truth for supervised training.
  If label_source == RULE_ENGINE, the label is a PREDICTION, not ground truth.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional


class LabelSource(str, Enum):
    """Formal label provenance enum.

    The ordering reflects reliability (highest first). RULE_ENGINE is
    explicitly the LEAST reliable because it's a detector output — using
    it as ground truth creates circular evaluation.
    """
    SCENARIO_GROUND_TRUTH = "scenario_ground_truth"
    ANALYST_LABELED = "analyst_labeled"
    EXTERNAL_DATASET = "external_dataset"
    SYNTHETIC = "synthetic"
    RULE_ENGINE = "rule_engine"
    UNLABELED = "unlabeled"

    @property
    def is_ground_truth(self) -> bool:
        """Whether this label source can be used as ground truth for
        supervised training. RULE_ENGINE and UNLABELED CANNOT."""
        return self in (
            LabelSource.SCENARIO_GROUND_TRUTH,
            LabelSource.ANALYST_LABELED,
            LabelSource.EXTERNAL_DATASET,
            LabelSource.SYNTHETIC,  # for development only
        )

    @property
    def is_detector_output(self) -> bool:
        """Whether this label source is a detector output (NOT ground truth)."""
        return self == LabelSource.RULE_ENGINE


class LabelProvenanceError(Exception):
    """Raised when a label provenance violation is detected.

    Examples:
      - Attempting to train on RULE_ENGINE labels
      - Attempting to use classifier output as ground truth
      - Missing label_source on a labeled dataset row
    """


@dataclass
class LabelProvenance:
    """Carries label provenance metadata for a dataset row or session.

    This ensures every label can be traced back to its source, and
    detector outputs can never silently become ground truth.
    """
    label: str
    label_source: LabelSource
    labeling_method: str = ""  # e.g. "scenario_manifest", "analyst_review", "rule_classify_session"
    labeling_confidence: float = 1.0  # 1.0 for ground truth, <1.0 for uncertain
    labeler_id: str = ""  # who/what produced the label (e.g. "campaign-001", "analyst-alice")

    def __post_init__(self) -> None:
        if not isinstance(self.label_source, LabelSource):
            self.label_source = LabelSource(self.label_source)
        # RULE_ENGINE confidence is capped at 0.9 — it's a detector output
        if self.label_source == LabelSource.RULE_ENGINE and self.labeling_confidence > 0.9:
            self.labeling_confidence = 0.9

    @property
    def is_ground_truth(self) -> bool:
        """Whether this label can be used as ground truth for supervised training."""
        return self.label_source.is_ground_truth

    def to_dict(self) -> Dict[str, Any]:
        return {
            "label": self.label,
            "label_source": self.label_source.value,
            "labeling_method": self.labeling_method,
            "labeling_confidence": self.labeling_confidence,
            "labeler_id": self.labeler_id,
            "is_ground_truth": self.is_ground_truth,
        }


def validate_label_for_training(
    label: str,
    label_source: str | LabelSource,
) -> LabelSource:
    """Validate that a label can be used for supervised training.

    Raises LabelProvenanceError if:
      - label_source is RULE_ENGINE (circular evaluation)
      - label_source is UNLABELED (no label to train on)

    Returns the validated LabelSource enum.
    """
    if not isinstance(label_source, LabelSource):
        try:
            label_source = LabelSource(label_source)
        except ValueError:
            raise LabelProvenanceError(
                f"unknown label_source: {label_source!r}. "
                f"Must be one of: {[ls.value for ls in LabelSource]}"
            )

    if label_source == LabelSource.RULE_ENGINE:
        raise LabelProvenanceError(
            f"REFUSED: label_source=RULE_ENGINE for label={label!r}. "
            f"Rule engine output is a DETECTOR OUTPUT, not ground truth. "
            f"Using it as a training label creates circular evaluation. "
            f"Use SCENARIO_GROUND_TRUTH, ANALYST_LABELED, or EXTERNAL_DATASET instead."
        )

    if label_source == LabelSource.UNLABELED:
        raise LabelProvenanceError(
            f"REFUSED: label_source=UNLABELED for label={label!r}. "
            f"Cannot train on unlabeled data."
        )

    return label_source


def audit_dataset_labels(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Audit a dataset for label provenance issues.

    Returns a report with:
      - total_rows
      - labeled_rows
      - unlabeled_rows
      - label_source_distribution
      - ground_truth_rows (excludes RULE_ENGINE + UNLABELED)
      - rule_engine_labeled_rows (circular risk)
      - missing_label_source_rows
      - is_safe_for_training (bool)
    """
    total = len(rows)
    label_source_dist: Dict[str, int] = {}
    ground_truth_count = 0
    rule_engine_count = 0
    unlabeled_count = 0
    missing_source_count = 0

    for row in rows:
        label = row.get("label", "")
        source_str = row.get("label_source", "")

        if not label or label == "unknown":
            unlabeled_count += 1
            label_source_dist["unlabeled"] = label_source_dist.get("unlabeled", 0) + 1
            continue

        if not source_str:
            missing_source_count += 1
            label_source_dist["missing"] = label_source_dist.get("missing", 0) + 1
            continue

        try:
            source = LabelSource(source_str)
        except ValueError:
            missing_source_count += 1
            label_source_dist["unknown"] = label_source_dist.get("unknown", 0) + 1
            continue

        label_source_dist[source.value] = label_source_dist.get(source.value, 0) + 1

        if source.is_ground_truth:
            ground_truth_count += 1
        if source == LabelSource.RULE_ENGINE:
            rule_engine_count += 1

    return {
        "total_rows": total,
        "labeled_rows": total - unlabeled_count,
        "unlabeled_rows": unlabeled_count,
        "label_source_distribution": label_source_dist,
        "ground_truth_rows": ground_truth_count,
        "rule_engine_labeled_rows": rule_engine_count,
        "missing_label_source_rows": missing_source_count,
        "is_safe_for_training": rule_engine_count == 0 and missing_source_count == 0,
        "circular_evaluation_risk": rule_engine_count > 0,
    }
