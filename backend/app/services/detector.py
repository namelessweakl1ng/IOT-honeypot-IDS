"""Compatibility facade for learned behavioural detection; no signature rules."""
from typing import Any

from .adaptive import (
    AdaptiveEngine,
    DETECTION_TYPE,
    MODEL_VERSION,
    POLICY_VERSION,
    SUPPORTED_DETECTION_TYPES,
)


def detect(session: dict[str, Any], engine: AdaptiveEngine | None = None) -> list[dict[str, Any]]:
    """Return zero or one learned anomaly, using a cold model when none is supplied."""
    result = (engine or AdaptiveEngine()).evaluate(session)
    detection = result["detection"]
    return [detection] if detection else []
