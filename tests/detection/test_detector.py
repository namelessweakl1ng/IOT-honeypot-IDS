import pytest

from backend.app.services.detector import detect


def make(events, services=None, commands=None, urls=None):
    return {
        "session_id": "SES-one",
        "end_time": "2026-01-01T00:00:00Z",
        "event_ids": [e["event"]["id"] for e in events],
        "events": events,
        "services_touched": services or ["cowrie"],
        "commands": commands or [],
        "urls": urls or [],
    }


def ev(i, category="network", outcome="unknown", protocol="ssh", auth=None):
    return {"event": {"id": str(i), "category": category, "outcome": outcome}, "network": {"protocol": protocol}, **({"authentication": auth} if auth else {})}


@pytest.mark.parametrize(
    "session,kind",
    [
        (make([ev(i, "authentication", "failure") for i in range(5)]), "BRUTE_FORCE"),
        (make([ev(1, "authentication", "failure", auth={"username": "admin", "password": "admin"})]), "DEFAULT_CREDENTIALS"),
        (make([ev(1)], urls=["/a", "/b", "/c", "/d"]), "WEB_ENUMERATION"),
        (make([ev(1)], commands=["id"]), "COMMAND_INTERACTION"),
        (make([ev(1, protocol="mqtt")]), "MQTT_PROBING"),
        (make([ev(1)], services=["camera", "router", "mqtt"]), "MULTI_SERVICE_ACTIVITY"),
        (make([ev(1, "authentication", "failure"), ev(2)], services=["cowrie", "router"], urls=["/admin"]), "MULTI_STAGE_ATTACK"),
        (make([ev(1), ev(2), ev(3)]), "RECONNAISSANCE"),
    ],
)
def test_rules_are_explainable(session, kind):
    result = detect(session)
    found = next(d for d in result if d["type"] == kind)
    assert found["reason"] and found["evidence_event_ids"] and found["rule_id"]


def test_bruteforce_boundary():
    assert not any(d["type"] == "BRUTE_FORCE" for d in detect(make([ev(i, "authentication", "failure") for i in range(4)])))
