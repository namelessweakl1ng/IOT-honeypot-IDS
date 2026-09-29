from pathlib import Path

import yaml


def load(name: str) -> dict:
    return yaml.safe_load(Path(f"attacks/scenarios/{name}.yaml").read_text())


def test_bruteforce_uses_password_authentication():
    scenario = load("ssh-bruteforce")
    assert len(scenario["steps"]) >= 5
    assert all(step["service"] == "ssh" and step["username"] and step["password"] for step in scenario["steps"])


def test_default_credentials_are_submitted():
    for name in ["camera-default-creds", "router-default-creds"]:
        step = load(name)["steps"][0]
        assert (step["username"], step["password"]) == ("admin", "admin")


def test_web_enumeration_paths_are_distinct():
    paths = [step["path"] for step in load("http-enumeration")["steps"]]
    assert paths == ["/admin", "/login", "/config", "/setup", "/system"]


def test_mqtt_scenario_has_protocol_operations():
    operations = {step["operation"] for step in load("mqtt-recon")["steps"]}
    assert operations == {"connect", "subscribe", "ping"}


def test_mqtt_auth_probe_uses_repeated_connects_expected_by_detector():
    scenario = load("mqtt-auth-probe")
    assert scenario["expected_detection"] == "MQTT_PROBING"
    assert [step["operation"] for step in scenario["steps"]] == ["connect", "connect"]
