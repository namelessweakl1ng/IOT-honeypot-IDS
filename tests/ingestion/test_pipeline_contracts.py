from backend.app.services.detector import detect
from backend.app.services.normalizer import normalize
from backend.app.services.sessionizer import reconstruct_sessions


def cowrie(identifier: str, username: str = "user", password: str = "wrong", second: int = 0):
    return normalize({"timestamp": f"2026-01-01T00:00:{second:02d}Z", "eventid": "cowrie.login.failed", "session": identifier, "src_ip": "192.168.50.20", "src_port": 40000 + second, "dst_port": 2222, "username": username, "password": password}, "ssh_telnet", "cowrie-01", "pi-01")


def custom(identifier: str, service: str, protocol: str, second: int, **extra):
    raw = {"timestamp": f"2026-01-01T00:00:{second:02d}Z", "event_id": identifier, "category": "network", "type": "info", "action": "request", "outcome": "unknown", "source_ip": "192.168.50.20", "source_port": 41000 + second, "destination_port": 80, "protocol": protocol, "service": service, **extra}
    return normalize(raw, service, f"{service}-01", "pi-01")


def test_cowrie_failure_to_brute_force_pipeline():
    events = [cowrie(str(i), second=i) for i in range(5)]
    assert events[0]["event"]["id"].startswith("cowrie.login.failed-")
    assert {k: v for k, v in events[0]["event"].items() if k != "ingested"} | {"id": "ignored"} == {"id": "ignored", "category": "authentication", "type": "info", "action": "login_attempt", "outcome": "failure"}
    assert any(item["type"] == "BRUTE_FORCE" for item in detect(reconstruct_sessions(events)[0]))


def test_default_credentials_survive_normalization():
    detection = detect(reconstruct_sessions([cowrie("one", "admin", "admin")])[0])
    assert any(item["type"] == "DEFAULT_CREDENTIALS" for item in detection)


def test_distinct_paths_and_mqtt_and_multiple_services():
    paths = [custom(str(i), "camera", "http", i, category="web", url={"path": path}) for i, path in enumerate(["/admin", "/login", "/config", "/setup"])]
    mqtt = custom("mqtt", "mqtt", "mqtt", 5, mqtt={"operation": "connect", "packet_type": 1})
    router = custom("router", "router", "http", 6, url={"path": "/"})
    detections = detect(reconstruct_sessions(paths + [mqtt, router])[0])
    kinds = {item["type"] for item in detections}
    assert {"WEB_ENUMERATION", "MQTT_PROBING", "MULTI_SERVICE_ACTIVITY"} <= kinds
