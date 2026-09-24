"""Unit tests for the common event schema."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "shared"))

from schemas.event_schema import (  # type: ignore  # noqa: E402
    KNOWN_CLASSIFICATIONS,
    KNOWN_EVENT_TYPES,
    MITRE_MAPPING,
    mitre_for,
    validate,
)


def _valid_event():
    return {
        "@timestamp": "2025-01-01T12:00:00.000Z",
        "event_id": "evt-1",
        "session_id": "sess-1",
        "source": {"ip": "192.168.1.20", "port": 54321},
        "device": {"id": "camera-01", "type": "camera"},
        "event": {"type": "http_request"},
        "honeypot": {"name": "camera"},
    }


def test_valid_event_passes():
    assert validate(_valid_event()) == []


def test_missing_required_field_reports():
    for field in ["@timestamp", "event_id", "session_id", "source.ip",
                   "device.id", "event.type", "honeypot.name"]:
        ev = _valid_event()
        # navigate and delete
        parts = field.split(".")
        cur = ev
        for p in parts[:-1]:
            cur = cur[p]
        del cur[parts[-1]]
        errs = validate(ev)
        assert any(f in e for e in errs for f in [field]), \
            f"missing field {field} should produce a validation error, got {errs}"


def test_mitre_mapping_has_all_classifications():
    # Every classification the platform uses for known attacks should have a MITRE mapping
    for c in ["brute_force", "default_credentials", "reconnaissance",
              "command_abuse", "command_injection", "path_traversal",
              "web_enumeration", "file_retrieval"]:
        assert c in MITRE_MAPPING, f"{c} should have a MITRE mapping"


def test_mitre_for_unknown_returns_none():
    assert mitre_for("not_a_real_classification") is None


def test_mitre_for_known_returns_dict():
    m = mitre_for("brute_force")
    assert m is not None
    assert "tactic" in m and "technique" in m


def test_known_event_types_contains_core_types():
    for t in ["http_request", "authentication_attempt", "command_execution",
              "session_start", "session_end"]:
        assert t in KNOWN_EVENT_TYPES


def test_known_classifications_includes_anomaly_and_unknown():
    assert "anomaly" in KNOWN_CLASSIFICATIONS
    assert "unknown" in KNOWN_CLASSIFICATIONS
    assert "benign" in KNOWN_CLASSIFICATIONS
