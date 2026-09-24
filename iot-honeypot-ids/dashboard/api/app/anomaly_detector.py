"""Anomaly detector service — IsolationForest + threshold calibration."""
from __future__ import annotations

import hashlib
import logging
import pickle
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from . import es_client, feature_extractor
from .config import settings

log = logging.getLogger("anomaly_detector")

DETECTOR_VERSION = "anomaly_detector_v1"
DETECTOR_ARTIFACT_NAME = "anomaly_detector.pkl"


def _models_dir() -> Path:
    p = Path(settings.model_path) / "anomaly"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _artifact_path() -> Path:
    return _models_dir() / DETECTOR_ARTIFACT_NAME


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _detection_id(session_id: str) -> str:
    h = hashlib.sha1()
    h.update(session_id.encode("utf-8"))
    h.update(b"|")
    h.update(DETECTOR_VERSION.encode("utf-8"))
    return "det-anom-" + h.hexdigest()[:16]


class AnomalyDetectorService:
    def __init__(self) -> None:
        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self.threshold: float = 0.0
        self.threshold_selection_method: str = "none"
        self.target_fpr: float = 0.05
        self.feature_schema_version: str = feature_extractor.FEATURE_SCHEMA_VERSION
        self.trained_at: Optional[str] = None
        self.training_session_count: int = 0

    def train(self, feature_vectors: List[List[float]], contamination: float = 0.1, seed: int = 42) -> None:
        if not feature_vectors:
            raise ValueError("cannot train on empty feature matrix")
        X = np.array(feature_vectors, dtype=float)
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        contamination = max(0.01, min(float(contamination), 0.5))
        self.model = IsolationForest(n_estimators=100, contamination=contamination, random_state=seed)
        self.model.fit(X_scaled)
        self.training_session_count = len(feature_vectors)
        self.trained_at = _now_iso()

    def select_threshold_for_fpr(self, benign_feature_vectors: List[List[float]], target_fpr: float = 0.05) -> float:
        if self.model is None or self.scaler is None:
            raise RuntimeError("train() must be called before select_threshold_for_fpr()")
        if not benign_feature_vectors:
            raise ValueError("cannot calibrate on empty validation set")
        X = np.array(benign_feature_vectors, dtype=float)
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
        X_scaled = self.scaler.transform(X)
        scores = self.model.decision_function(X_scaled)
        threshold = float(np.quantile(scores, target_fpr))
        self.threshold = threshold
        self.target_fpr = target_fpr
        self.threshold_selection_method = f"benign_validation_fpr_{target_fpr:.2f}_quantile"
        return threshold

    def score_session(self, feature_vector: List[float]) -> Dict[str, Any]:
        if self.model is None or self.scaler is None:
            raise RuntimeError("train() must be called before score_session()")
        X = np.array([feature_vector], dtype=float)
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
        X_scaled = self.scaler.transform(X)
        score = float(self.model.decision_function(X_scaled)[0])
        is_anomaly = score < self.threshold
        return {
            "anomaly_score": score,
            "threshold": self.threshold,
            "is_anomaly": bool(is_anomaly),
            "threshold_selection_method": self.threshold_selection_method,
            "detector_version": DETECTOR_VERSION,
        }

    def save(self) -> None:
        artifact = {
            "model": self.model, "scaler": self.scaler, "threshold": self.threshold,
            "threshold_selection_method": self.threshold_selection_method,
            "target_fpr": self.target_fpr, "feature_schema_version": self.feature_schema_version,
            "trained_at": self.trained_at, "training_session_count": self.training_session_count,
            "detector_version": DETECTOR_VERSION,
        }
        with open(_artifact_path(), "wb") as f:
            pickle.dump(artifact, f)

    def load(self) -> bool:
        if not _artifact_path().exists():
            return False
        try:
            with open(_artifact_path(), "rb") as f:
                artifact = pickle.load(f)
            self.model = artifact.get("model")
            self.scaler = artifact.get("scaler")
            self.threshold = artifact.get("threshold", 0.0)
            self.threshold_selection_method = artifact.get("threshold_selection_method", "none")
            self.target_fpr = artifact.get("target_fpr", 0.05)
            self.feature_schema_version = artifact.get("feature_schema_version", feature_extractor.FEATURE_SCHEMA_VERSION)
            self.trained_at = artifact.get("trained_at")
            self.training_session_count = artifact.get("training_session_count", 0)
            return self.model is not None
        except Exception as exc:
            log.error("failed to load anomaly detector: %s", exc)
            return False

    def is_ready(self) -> bool:
        return self.model is not None and self.scaler is not None


_service: Optional[AnomalyDetectorService] = None


def get_service() -> AnomalyDetectorService:
    global _service
    if _service is None:
        _service = AnomalyDetectorService()
        _service.load()
    return _service


def detect_for_session(session_id: str) -> Optional[Dict[str, Any]]:
    svc = get_service()
    if not svc.is_ready():
        return None
    features = feature_extractor.extract_for_session(session_id)
    if not features:
        return None
    score_result = svc.score_session(features["feature_vector"])
    if not score_result["is_anomaly"]:
        return None
    try:
        session = es_client.get_session(session_id) or {}
    except Exception:
        session = {}

    detection_id = _detection_id(session_id)
    detection = {
        "detection_id": detection_id,
        "session_id": session_id,
        "campaign_id": session.get("campaign_id"),
        "@timestamp": _now_iso(),
        "engine": "anomaly_detector",
        "detector_version": DETECTOR_VERSION,
        "label": "anomaly",
        "classification": "anomaly",
        "anomaly_score": score_result["anomaly_score"],
        "threshold": score_result["threshold"],
        "threshold_selection_method": score_result["threshold_selection_method"],
        "confidence": min(1.0, abs(score_result["threshold"] - score_result["anomaly_score"]) * 2),
        "severity": "medium",
        "explanation": (
            f"anomaly_score {score_result['anomaly_score']:.4f} < threshold "
            f"{score_result['threshold']:.4f} (calibration: "
            f"{score_result['threshold_selection_method']})"
        ),
        "evidence": {
            "anomaly_score": score_result["anomaly_score"],
            "threshold": score_result["threshold"],
            "method": score_result["threshold_selection_method"],
            "feature_schema_version": features["feature_schema_version"],
        },
        "model_id": None,
        "model_version": None,
        "feature_schema_version": features["feature_schema_version"],
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
        log.error("failed to persist anomaly detection %s: %s", detection_id, exc)
        persistence_error = f"{exc.__class__.__name__}: {exc}"
    detection["persisted"] = persisted
    if persistence_error:
        detection["persistence_error"] = persistence_error

    return detection
