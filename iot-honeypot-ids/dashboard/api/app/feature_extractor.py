"""Runtime feature extraction service.

Wraps dashboard/ml/features.py extract_features() with a thin service
that loads a session's events from ES and extracts the v2 feature vector.
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import es_client

log = logging.getLogger("feature_extractor")

FEATURE_SCHEMA_VERSION = "v2"

_ROOT = Path(__file__).resolve().parents[2]
_ML_PATH = _ROOT / "dashboard" / "ml"
if str(_ML_PATH) not in sys.path:
    sys.path.insert(0, str(_ML_PATH))

try:
    from features import (  # type: ignore
        FEATURE_NAMES, FEATURE_NAMES_V2, LEAKY_FEATURES,
        extract_features, features_to_vector, features_to_vector_v2,
    )
except ImportError as exc:
    log.error("failed to import dashboard.ml.features: %s", exc)
    FEATURE_NAMES = []
    FEATURE_NAMES_V2 = []
    LEAKY_FEATURES = []

    def extract_features(session_events: List[Dict[str, Any]]) -> Dict[str, float]:  # type: ignore
        return {}

    def features_to_vector(features: Dict[str, float]) -> List[float]:  # type: ignore
        return []

    def features_to_vector_v2(features: Dict[str, float]) -> List[float]:  # type: ignore
        return []


def get_schema() -> Dict[str, Any]:
    return {
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "feature_names": FEATURE_NAMES_V2,
        "feature_count": len(FEATURE_NAMES_V2),
        "leaky_features_excluded": LEAKY_FEATURES,
    }


def extract_for_session(session_id: str) -> Optional[Dict[str, Any]]:
    try:
        session = es_client.get_session(session_id)
        if not session:
            return None
        events: List[Dict[str, Any]] = session.get("events") or []
        if not events:
            return None
        features = extract_features(events)
        vector = features_to_vector_v2(features)
        from datetime import datetime, timezone
        return {
            "session_id": session_id,
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "feature_names": list(FEATURE_NAMES_V2),
            "features": features,
            "feature_vector": vector,
            "extracted_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "source": "live_es",
        }
    except Exception as exc:
        log.error("feature extraction for session %s failed: %s", session_id, exc, exc_info=True)
        return None
