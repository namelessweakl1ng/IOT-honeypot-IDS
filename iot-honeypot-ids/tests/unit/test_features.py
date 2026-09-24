"""Unit tests for the feature extraction module."""
import sys
from pathlib import Path

# Make dashboard/ml importable
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "dashboard" / "ml"))

from features import (  # type: ignore  # noqa: E402
    FEATURE_NAMES,
    extract_features,
    features_to_vector,
    reconstruct_sessions,
)


def _camera_event(method="GET", uri="/", status=200, **extra):
    base = {
        "@timestamp": "2025-01-01T12:00:00.000Z",
        "event_id": "evt-1",
        "session_id": "sess-1",
        "source": {"ip": "192.168.1.20", "port": 54321},
        "destination": {"ip": "192.168.1.50", "port": 8080},
        "device": {"id": "camera-01", "type": "camera", "hostname": "iot-bridge-01", "container": "pi-camera"},
        "protocol": "http",
        "event": {"type": "http_request", "category": "network", "action": "get_root"},
        "authentication": {"attempted": False, "username": None, "success": False},
        "http": {"method": method, "uri": uri, "status": status, "user_agent": "test", "bytes_in": 0, "bytes_out": 100},
        "honeypot": {"name": "camera", "container": "pi-camera"},
        "attack": {"session_id": "sess-1", "stage": None, "classification": None, "confidence": 0.0},
    }
    base.update(extra)
    return base


def test_empty_session_returns_zero_features():
    feats = extract_features([])
    for name in FEATURE_NAMES:
        assert feats[name] == 0.0, f"{name} should be 0 for empty session"


def test_single_event_session_has_event_count_1():
    feats = extract_features([_camera_event()])
    assert feats["event_count"] == 1.0
    assert feats["http_request_count"] == 1.0


def test_brute_force_features():
    events = []
    for i in range(10):
        ev = _camera_event(method="POST", uri="/login", status=401)
        ev["authentication"] = {"attempted": True, "username": f"user{i:02d}", "success": False}
        ev["@timestamp"] = f"2025-01-01T12:00:{i:02d}.000Z"
        events.append(ev)
    feats = extract_features(events)
    assert feats["auth_attempts"] == 10.0
    assert feats["auth_successes"] == 0.0
    assert feats["auth_failure_ratio"] == 1.0
    assert feats["unique_usernames"] == 10.0


def test_recon_features():
    events = []
    for i, uri in enumerate(["/", "/admin", "/config", "/system", "/status", "/network"]):
        ev = _camera_event(method="GET", uri=uri, status=200)
        ev["@timestamp"] = f"2025-01-01T12:00:{i:02d}.000Z"
        events.append(ev)
    feats = extract_features(events)
    assert feats["http_uri_diversity"] == 6.0
    assert feats["is_recon_only"] == 1.0
    assert feats["auth_attempts"] == 0.0


def test_path_traversal_flag():
    ev = _camera_event(uri="/../../etc/passwd")
    ev["attack"] = {"session_id": "sess-1", "stage": "path_traversal",
                     "classification": "path_traversal", "confidence": 0.85}
    feats = extract_features([ev])
    assert feats["contains_path_traversal"] == 1.0


def test_features_to_vector_correct_order():
    feats = extract_features([_camera_event()])
    vec = features_to_vector(feats)
    assert len(vec) == len(FEATURE_NAMES)
    # event_count is first
    assert vec[0] == feats["event_count"]


def test_reconstruct_sessions_groups_by_session_id():
    events = [
        _camera_event(),
        {**_camera_event(), "session_id": "sess-2"},
        {**_camera_event(), "session_id": "sess-1", "@timestamp": "2025-01-01T12:00:01.000Z"},
        {"event_id": "x", "@timestamp": "2025-01-01T12:00:02.000Z"},  # no session_id
    ]
    sessions = reconstruct_sessions(events)
    assert "sess-1" in sessions
    assert "sess-2" in sessions
    assert len(sessions["sess-1"]) == 2
    assert len(sessions["sess-2"]) == 1
    # The event without session_id should be counted as dropped
    assert sessions.get("_dropped_count", 0) == 1
