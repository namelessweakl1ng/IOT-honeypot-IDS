"""Compatibility exports for the canonical IoT-23 feature contract."""
from pathlib import Path
import sys

MODEL_LAB = Path(__file__).resolve().parents[3] / "model-lab"
if str(MODEL_LAB) not in sys.path:
    sys.path.insert(0, str(MODEL_LAB))

from model_lab.datasets.iot23_features import (  # noqa: E402,F401
    FEATURE_MAP,
    FEATURE_VERSION,
    FORBIDDEN_FEATURES,
    NUMERIC_FEATURES,
    audit_feature_names,
    feature_vector,
    scenario_split,
    temporal_split,
)

__all__ = ["FEATURE_MAP", "FEATURE_VERSION", "FORBIDDEN_FEATURES", "NUMERIC_FEATURES",
           "audit_feature_names", "feature_vector", "scenario_split", "temporal_split"]
