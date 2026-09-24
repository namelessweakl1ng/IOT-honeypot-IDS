"""Hybrid detector — combines rule + supervised + anomaly signals.

Each layer contributes INDEPENDENTLY. The hybrid decision preserves
which layer(s) contributed. Detections are NOT collapsed into one
unexplained number.

NEVER collapses anomaly=malicious — anomaly is a signal, not a final
malicious verdict. The hybrid policy uses anomaly as one input; it
does NOT collapse anomaly → malicious.

Decision policy:
  KNOWN_ATTACK: strong rule (confidence >= 0.85) OR supervised (prob >= 0.7)
  NOVEL_BEHAVIOR: anomaly signal + no rule + no supervised
  HYBRID_AGREEMENT: multiple independent signals agree → severity=high
  NO_SIGNAL: no detection (no fabrication)
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from . import anomaly_detector, es_client, feature_extractor, rule_detector

log = logging.getLogger("hybrid_detector")

DETECTOR_VERSION = "hybrid_v1"
RULE_CONFIDENCE_THRESHOLD = 0.85
SUPERVISED_PROBABILITY_THRESHOLD = 0.7


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _compute_config_fingerprint(*, supervised_model_id, supervised_model_version,
                                 feature_schema_version, anomaly_threshold,
                                 rule_confidence_threshold, supervised_probability_threshold) -> str:
    h = hashlib.sha1()
    h.update(DETECTOR_VERSION.encode("utf-8"))
    h.update(b"|")
    h.update((supervised_model_id or "none").encode("utf-8"))
    h.update(b"|")
    h.update((supervised_model_version or "none").encode("utf-8"))
    h.update(b"|")
    h.update((feature_schema_version or "none").encode("utf-8"))
    h.update(b"|")
    h.update(f"{anomaly_threshold:.6f}".encode("utf-8") if anomaly_threshold is not None else b"none")
    h.update(b"|")
    h.update(f"{rule_confidence_threshold:.2f}".encode("utf-8"))
    h.update(b"|")
    h.update(f"{supervised_probability_threshold:.2f}".encode("utf-8"))
    return "fp-" + h.hexdigest()[:16]


def _detection_id(session_id: str, contributed: List[str], config_fingerprint: str) -> str:
    h = hashlib.sha1()
    h.update(session_id.encode("utf-8"))
    h.update(b"|")
    for sig in sorted(contributed):
        h.update(sig.encode("utf-8"))
        h.update(b"|")
    h.update(b"|")
    h.update(config_fingerprint.encode("utf-8"))
    return "det-hyb-" + h.hexdigest()[:16]


def evaluate_session(session_id: str) -> Optional[Dict[str, Any]]:
    try:
        session = es_client.get_session(session_id)
    except Exception as exc:
        log.error("hybrid: failed to load session %s: %s", session_id, exc)
        return None
    if not session:
        return None

    contributed: List[str] = []
    rule_signal: Optional[Dict[str, Any]] = None
    supervised_signal: Optional[Dict[str, Any]] = None
    anomaly_signal: Optional[Dict[str, Any]] = None

    try:
        rule_signal = rule_detector.detect_for_session(session_id)
        if rule_signal and rule_signal.get("confidence", 0.0) >= RULE_CONFIDENCE_THRESHOLD:
            contributed.append("rule_engine")
    except Exception as exc:
        log.warning("hybrid: rule layer error for %s: %s", session_id, exc)

    try:
        anomaly_signal = anomaly_detector.detect_for_session(session_id)
        if anomaly_signal:
            contributed.append("anomaly_detector")
    except Exception as exc:
        log.warning("hybrid: anomaly layer error for %s: %s", session_id, exc)

    try:
        supervised_signal = _run_supervised(session_id)
        if supervised_signal and supervised_signal.get("probability", 0.0) >= SUPERVISED_PROBABILITY_THRESHOLD:
            contributed.append("supervised_model")
    except Exception as exc:
        log.warning("hybrid: supervised layer error for %s: %s", session_id, exc)

    if not contributed:
        return None

    label: str = "unknown"
    severity: str = "medium"
    confidence: float = 0.0
    explanation_parts: List[str] = []

    if "rule_engine" in contributed and rule_signal:
        label = rule_signal.get("label", "unknown")
        severity = rule_signal.get("severity", "medium")
        confidence = max(confidence, float(rule_signal.get("confidence", 0.0)))
        explanation_parts.append(f"rule_engine: {rule_signal.get('rule_id')} ({label}, conf={rule_signal.get('confidence'):.2f})")

    if "supervised_model" in contributed and supervised_signal:
        s_label = supervised_signal.get("label", "unknown")
        s_prob = float(supervised_signal.get("probability", 0.0))
        if "rule_engine" not in contributed:
            label = s_label
        confidence = max(confidence, s_prob)
        explanation_parts.append(f"supervised_model: {s_label} (prob={s_prob:.2f})")

    if "anomaly_detector" in contributed and anomaly_signal:
        if len(contributed) == 1 and "anomaly_detector" in contributed:
            label = "anomaly"
            severity = "medium"
        explanation_parts.append(f"anomaly_detector: score={anomaly_signal.get('anomaly_score'):.4f} < threshold={anomaly_signal.get('threshold'):.4f}")

    if len(contributed) >= 2:
        severity = "high"

    supervised_model_id = supervised_signal.get("model_id") if supervised_signal else None
    supervised_model_version = supervised_signal.get("model_version") if supervised_signal else None
    feature_schema_version = feature_extractor.FEATURE_SCHEMA_VERSION

    config_fingerprint = _compute_config_fingerprint(
        supervised_model_id=supervised_model_id,
        supervised_model_version=supervised_model_version,
        feature_schema_version=feature_schema_version,
        anomaly_threshold=anomaly_signal.get("threshold") if anomaly_signal else None,
        rule_confidence_threshold=RULE_CONFIDENCE_THRESHOLD,
        supervised_probability_threshold=SUPERVISED_PROBABILITY_THRESHOLD,
    )
    detection_id = _detection_id(session_id, contributed, config_fingerprint)

    detection = {
        "detection_id": detection_id,
        "session_id": session_id,
        "campaign_id": session.get("campaign_id"),
        "@timestamp": _now_iso(),
        "engine": "hybrid",
        "detector_version": DETECTOR_VERSION,
        "label": label,
        "classification": label,
        "confidence": round(confidence, 4),
        "severity": severity,
        "explanation": " | ".join(explanation_parts),
        "evidence": {
            "contributed_signals": contributed,
            "rule_signal": _slim_rule(rule_signal),
            "supervised_signal": _slim_supervised(supervised_signal),
            "anomaly_signal": _slim_anomaly(anomaly_signal),
            "policy": {
                "rule_confidence_threshold": RULE_CONFIDENCE_THRESHOLD,
                "supervised_probability_threshold": SUPERVISED_PROBABILITY_THRESHOLD,
            },
            "rule_engine_version": "rule_engine_v1" if rule_signal else None,
            "anomaly_detector_version": "anomaly_detector_v1" if anomaly_signal else None,
            "supervised_model_id": supervised_model_id,
            "supervised_model_version": supervised_model_version,
        },
        "model_id": supervised_model_id,
        "model_version": supervised_model_version,
        "feature_schema_version": feature_schema_version,
        "thresholds": {
            "rule_confidence_threshold": RULE_CONFIDENCE_THRESHOLD,
            "supervised_probability_threshold": SUPERVISED_PROBABILITY_THRESHOLD,
            "anomaly_threshold": anomaly_signal.get("threshold") if anomaly_signal else None,
        },
        "detector_config_fingerprint": config_fingerprint,
        "source": session.get("source", {}),
        "device": session.get("device", {}),
    }

    persisted = False
    persistence_error = None
    try:
        index_name = "honeypot-detections-" + datetime.now(timezone.utc).strftime("%Y.%m.%d")
        es_client.get_client().index(index=index_name, id=detection_id, document=detection)
        persisted = True
    except Exception as exc:
        log.error("failed to persist hybrid detection %s: %s", detection_id, exc)
        persistence_error = f"{exc.__class__.__name__}: {exc}"
    detection["persisted"] = persisted
    if persistence_error:
        detection["persistence_error"] = persistence_error

    return detection


def _run_supervised(session_id: str) -> Optional[Dict[str, Any]]:
    try:
        from . import model_registry, feature_extractor
        active = model_registry.get_active_model()
        if not active:
            return None
        model_fv = active.get("feature_version", "v1")
        runtime_fv = feature_extractor.FEATURE_SCHEMA_VERSION
        if model_fv != runtime_fv:
            log.warning("supervised model %s has feature_version=%s but runtime schema is %s — skipping",
                        active.get("model_id"), model_fv, runtime_fv)
            return None
        import sys as _sys
        from pathlib import Path as _Path
        _ml_root = _Path(settings.model_path).parent
        if str(_ml_root) not in _sys.path:
            _sys.path.insert(0, str(_ml_root))
        from models import predict  # type: ignore
        features = feature_extractor.extract_for_session(session_id)
        if not features:
            return None
        model_id = active["model_id"]
        preds = predict(_Path(settings.model_path), model_id, [features["features"]])
        if not preds:
            return None
        p = preds[0]
        return {
            "label": p.get("label", "unknown"),
            "probability": float(p.get("probability", 0.0)),
            "model_id": model_id,
            "model_version": active.get("version", "unknown"),
            "feature_schema_version": model_fv,
        }
    except Exception as exc:
        log.warning("supervised prediction failed: %s", exc)
        return None


def _slim_rule(d):
    if not d: return None
    return {"rule_id": d.get("rule_id"), "label": d.get("label"), "confidence": d.get("confidence")}

def _slim_supervised(d):
    if not d: return None
    return {"label": d.get("label"), "probability": d.get("probability"), "model_id": d.get("model_id"), "model_version": d.get("model_version")}

def _slim_anomaly(d):
    if not d: return None
    return {"anomaly_score": d.get("anomaly_score"), "threshold": d.get("threshold"), "is_anomaly": d.get("is_anomaly")}

try:
    from .config import settings
except ImportError:
    settings = None
