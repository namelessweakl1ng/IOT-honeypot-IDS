from backend.app.services.sessionizer import reconstruct_sessions


def event(identifier, time, source="10.0.0.2", service="camera"):
    return {
        "@timestamp": time,
        "event": {"id": identifier, "category": "network", "outcome": "unknown"},
        "source": {"ip": source},
        "honeypot": {"id": service + "-01"},
        "service": {"name": service},
        "network": {"protocol": "http"},
    }


def test_same_source_cross_honeypot_and_deterministic():
    events = [event("b", "2026-01-01T00:01:00Z", service="router"), event("a", "2026-01-01T00:00:00Z")]
    first = reconstruct_sessions(events)
    second = reconstruct_sessions(list(reversed(events)))
    assert first == second
    assert first[0]["event_count"] == 2
    assert first[0]["honeypots_touched"] == ["camera-01", "router-01"]


def test_timeout_and_sources_split():
    events = [event("a", "2026-01-01T00:00:00Z"), event("b", "2026-01-01T00:06:00Z"), event("c", "2026-01-01T00:00:01Z", "10.0.0.3")]
    assert len(reconstruct_sessions(events, 300)) == 3
