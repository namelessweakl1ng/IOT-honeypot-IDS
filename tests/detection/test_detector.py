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


def ev(i, category="network", outcome="unknown", protocol="ssh", auth=None, action="observe", service=None, mqtt=None):
    return {
        "event": {"id": str(i), "category": category, "outcome": outcome, "action": action},
        "network": {"protocol": protocol},
        "service": {"name": service or ("mqtt" if protocol == "mqtt" else "cowrie")},
        **({"authentication": auth} if auth else {}),
        **({"mqtt": mqtt} if mqtt else {}),
    }


@pytest.mark.parametrize(
    "session,kind",
    [
        (make([ev(i, "authentication", "failure") for i in range(5)]), "BRUTE_FORCE"),
        (make([ev(1, "authentication", "failure", auth={"username": "admin", "password": "admin"})]), "DEFAULT_CREDENTIALS"),
        (make([ev(1)], urls=["/a", "/b", "/c", "/d"]), "WEB_ENUMERATION"),
        (make([ev(1)], commands=["id"]), "COMMAND_INTERACTION"),
        (make([ev(1, protocol="mqtt", mqtt={"operation": "connect"}), ev(2, protocol="mqtt", mqtt={"operation": "connect"})]), "MQTT_PROBING"),
        (make([ev(1)], services=["camera", "router", "mqtt"]), "MULTI_SERVICE_ACTIVITY"),
        (make([ev(1, "authentication", "failure"), ev(2)], services=["cowrie", "router"], urls=["/admin"]), "MULTI_STAGE_ATTACK"),
        (
            make(
                [ev(1, protocol="tcp", service="iot-service"), ev(2, protocol="tcp", service="iot-service"), ev(3, protocol="tcp", service="iot-service")],
                services=["iot-service"],
            ),
            "RECONNAISSANCE",
        ),
    ],
)
def test_rules_are_explainable(session, kind):
    result = detect(session)
    found = next(d for d in result if d["type"] == kind)
    assert found["reason"] and found["evidence_event_ids"] and found["rule_id"]


def test_bruteforce_boundary():
    assert not any(d["type"] == "BRUTE_FORCE" for d in detect(make([ev(i, "authentication", "failure") for i in range(4)])))


def detection_types(events, services):
    return {item["type"] for item in detect(make(events, services=services))}


def test_routine_ssh_chatter_is_not_reconnaissance():
    events = [ev(1, action="connect"), ev(2, action="version"), ev(3, action="kex"), ev(4, action="close")]
    assert "RECONNAISSANCE" not in detection_types(events, ["cowrie"])


def test_iot_control_is_negative_but_repeated_iot_probes_are_reconnaissance():
    one = [ev(1, protocol="tcp", service="iot-service")]
    three = [ev(i, protocol="tcp", service="iot-service") for i in range(1, 4)]
    assert detection_types(one, ["iot-service"]) == set()
    assert "RECONNAISSANCE" in detection_types(three, ["iot-service"])


def test_mqtt_control_is_negative_but_active_or_repeated_operations_are_probing():
    connect = ev(1, protocol="mqtt", service="mqtt", mqtt={"operation": "connect"})
    repeated = [connect, ev(2, protocol="mqtt", service="mqtt", mqtt={"operation": "connect"})]
    recon = [
        connect,
        ev(2, protocol="mqtt", service="mqtt", mqtt={"operation": "subscribe"}),
        ev(3, protocol="mqtt", service="mqtt", mqtt={"operation": "ping"}),
    ]
    assert detection_types([connect], ["mqtt"]) == set()
    assert "MQTT_PROBING" in detection_types(repeated, ["mqtt"])
    assert "MQTT_PROBING" in detection_types(recon, ["mqtt"])
