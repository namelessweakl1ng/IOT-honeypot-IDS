"""Unit tests for the rule engine."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "dashboard" / "ml"))

from rules import classify_session  # type: ignore  # noqa: E402


def _event(action="http_request", **extra):
    base = {
        "@timestamp": "2025-01-01T12:00:00.000Z",
        "event_id": "evt-1",
        "session_id": "sess-1",
        "source": {"ip": "192.168.1.20", "port": 54321},
        "device": {"id": "camera-01", "type": "camera"},
        "event": {"type": action, "category": "network"},
        "authentication": {"attempted": False, "username": None, "success": False},
        "http": {"method": "GET", "uri": "/", "status": 200},
        "honeypot": {"name": "camera"},
        "attack": {"session_id": "sess-1", "stage": None, "classification": None, "confidence": 0.0},
    }
    base.update(extra)
    return base


def test_no_events_returns_none():
    assert classify_session([]) is None


def test_benign_session_returns_none():
    events = [_event() for _ in range(2)]
    assert classify_session(events) is None


def test_brute_force_detection():
    events = []
    for i in range(6):
        ev = _event(action="authentication_attempt")
        ev["authentication"] = {"attempted": True, "username": f"user{i:02d}", "success": False}
        events.append(ev)
    result = classify_session(events)
    assert result is not None
    assert result["label"] == "brute_force"
    assert result["confidence"] >= 0.9


def test_default_credentials_detection():
    events = [
        {**_event(), "attack": {"session_id": "s1", "stage": "initial_access",
                                  "classification": "default_credentials", "confidence": 0.9}},
    ]
    result = classify_session(events)
    assert result is not None
    assert result["label"] == "default_credentials"


def test_command_injection_detection():
    events = [
        {**_event(), "attack": {"session_id": "s1", "stage": "execution",
                                  "classification": "command_injection", "confidence": 0.7}},
    ]
    result = classify_session(events)
    assert result is not None
    assert result["label"] == "command_injection"


def test_path_traversal_detection():
    events = [
        {**_event(), "attack": {"session_id": "s1", "stage": "collection",
                                  "classification": "path_traversal", "confidence": 0.8}},
    ]
    result = classify_session(events)
    assert result is not None
    assert result["label"] == "path_traversal"


def test_recon_only_detection():
    events = []
    for i, uri in enumerate(["/", "/admin", "/config", "/system", "/status"]):
        ev = _event()
        ev["http"] = {"method": "GET", "uri": uri, "status": 200}
        events.append(ev)
    result = classify_session(events)
    assert result is not None
    assert result["label"] == "reconnaissance"
