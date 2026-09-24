"""Runtime rule detector — deterministic detection on materialized sessions.

Wraps dashboard/ml/rules.py classify_session() with persistence to ES.
"""
from __future__ import annotations

import hashlib
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import es_client

log = logging.getLogger("rule_detector")

_ROOT = Path(__file__).resolve().parents[2]
_ML_PATH = _ROOT / "dashboard" / "ml"
if str(_ML_PATH) not in sys.path:
    sys.path.insert(0, str(_ML_PATH))

try:
    from rules import classify_session  # type: ignore
except ImportError:
    def classify_session(events: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:  # type: ignore
        return None

RULE_SEVERITY: Dict[str, str] = {
    "rule_brute_force_v1": "high",
    "rule_default_credentials_v1": "critical",
    "rule_command_injection_v1": "high",
    "rule_path_traversal_v1": "medium",
    "rule_recon_v1": "low",
}

DETECTOR_VERSION = "rule_engine_v1"
DETECTION_INDEX_PREFIX = "honeypot-detections"


def _detection_id(session_id: str, rule_id: str) -> str:
    h = hashlib.sha1()
    h.update(session_id.encode("utf-8"))
    h.update(b"|")
    h.update(rule_id.encode("utf-8"))
    return "det-" + h.hexdigest()[:16]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def detect_for_session(session_id: str) -> Optional[Dict[str, Any]]:
    try:
        session = es_client.get_session(session_id)
        if not session:
            return None
        events: List[Dict[str, Any]] = session.get("events") or []
        if not events:
            return None
        result = classify_session(events)
        if not result:
            return None

        rule_id = result["rule_id"]
        label = result["label"]
        confidence = float(result.get("confidence", 0.0))
        explanation = result.get("explanation", "")
        severity = RULE_SEVERITY.get(rule_id, "medium")
        detection_id = _detection_id(session_id, rule_id)

        evidence = {
            "rule_id": rule_id,
            "label": label,
            "confidence": confidence,
            "explanation": explanation,
            "event_count": len(events),
        }
        auth_attempts = sum(1 for e in events if (e.get("authentication") or {}).get("attempted"))
        if auth_attempts:
            evidence["auth_attempts"] = auth_attempts
        unique_uris = {(e.get("http") or {}).get("uri") for e in events if (e.get("http") or {}).get("uri")}
        if unique_uris:
            evidence["unique_uris"] = len(unique_uris)

        detection = {
            "detection_id": detection_id,
            "session_id": session_id,
            "campaign_id": session.get("campaign_id"),
            "@timestamp": _now_iso(),
            "engine": "rule_engine",
            "detector_version": DETECTOR_VERSION,
            "rule_id": rule_id,
            "label": label,
            "classification": label,
            "confidence": confidence,
            "severity": severity,
            "explanation": explanation,
            "evidence": evidence,
            "model_id": None,
            "model_version": None,
            "feature_schema_version": None,
            "source": session.get("source", {}),
            "device": session.get("device", {}),
        }

        persisted = False
        persistence_error = None
        try:
            index_name = DETECTION_INDEX_PREFIX + "-" + datetime.now(timezone.utc).strftime("%Y.%m.%d")
            es_client.get_client().index(index=index_name, id=detection_id, document=detection)
            persisted = True
        except Exception as exc:
            log.error("failed to persist detection %s: %s", detection_id, exc)
            persistence_error = f"{exc.__class__.__name__}: {exc}"
        detection["persisted"] = persisted
        if persistence_error:
            detection["persistence_error"] = persistence_error

        return detection
    except Exception as exc:
        log.error("rule detection for session %s failed: %s", session_id, exc, exc_info=True)
        return None
