"""Unit tests for session reconstruction."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "dashboard" / "ml"))

from features import reconstruct_sessions  # type: ignore  # noqa: E402


def test_reconstruct_groups_by_session_id():
    events = [
        {"session_id": "s1", "@timestamp": "2025-01-01T12:00:00Z"},
        {"session_id": "s2", "@timestamp": "2025-01-01T12:00:01Z"},
        {"session_id": "s1", "@timestamp": "2025-01-01T12:00:02Z"},
    ]
    sessions = reconstruct_sessions(events)
    assert "s1" in sessions
    assert "s2" in sessions
    assert len(sessions["s1"]) == 2
    assert len(sessions["s2"]) == 1


def test_reconstruct_handles_nested_session_id():
    events = [
        {"attack": {"session_id": "nested-1"}, "@timestamp": "2025-01-01T12:00:00Z"},
        {"session_id": "top-1", "@timestamp": "2025-01-01T12:00:01Z"},
    ]
    sessions = reconstruct_sessions(events)
    assert "nested-1" in sessions
    assert "top-1" in sessions


def test_reconstruct_drops_events_without_session_id():
    events = [
        {"session_id": "s1", "@timestamp": "2025-01-01T12:00:00Z"},
        {"no_session": True},
        {"no_session": True},
    ]
    sessions = reconstruct_sessions(events)
    assert "s1" in sessions
    assert sessions.get("_dropped_count", 0) == 2


def test_reconstruct_empty_input():
    sessions = reconstruct_sessions([])
    # Empty dict (no sessions, no dropped count since there were no events to drop)
    assert sessions == {} or sessions == {"_dropped_count": 0}
