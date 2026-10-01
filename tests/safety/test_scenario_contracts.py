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
        assert step["auth_mode"] == "form"


def test_web_enumeration_paths_are_distinct():
    paths = [step["path"] for step in load("http-enumeration")["steps"]]
    assert paths == ["/admin", "/login", "/config", "/setup", "/system"]


def test_mqtt_scenario_has_protocol_operations():
    scenario = load("mqtt-recon")
    operations = {step["operation"] for step in scenario["steps"]}
    assert operations == {"connect", "subscribe", "ping"}
    assert scenario["steps"][0]["client_id"] == "mqtt-explorer"
    assert scenario["steps"][1]["topic"] == "#"


def test_mqtt_auth_probe_uses_repeated_connects_expected_by_detector():
    scenario = load("mqtt-auth-probe")
    assert scenario["expected_detection"] == "MQTT_PROBING"
    assert [step["operation"] for step in scenario["steps"]] == ["connect", "connect"]
    assert [step["client_id"] for step in scenario["steps"]] == ["mqtt-client-1", "mqtt-client-2"]


def test_iot_scenarios_are_bounded_to_final_persona_commands():
    assert [step["payload"] for step in load("iot-probe")["steps"]] == ["STATUS\\r\\n", "VERSION\\r\\n", "INFO\\r\\n"]
    default = load("iot-default-creds")
    assert default["target_services"] == ["iot"]
    assert default["expected_detection"] == "DEFAULT_CREDENTIALS"
    assert default["steps"] == [{"service": "iot", "payload": "AUTH admin admin\\r\\n"}]


def test_ssh_interaction_is_one_harmless_enumeration_session():
    steps = load("ssh-interaction")["steps"]
    assert len(steps) == 1
    assert steps[0]["commands"] == ["hostname", "uname -a", "id", "cat /etc/os-release"]


def test_every_manifest_has_a_consistent_basic_contract():
    known_services = {"ssh", "telnet", "camera", "http", "iot", "mqtt", "router"}
    detections = {
        "RECONNAISSANCE",
        "BRUTE_FORCE",
        "DEFAULT_CREDENTIALS",
        "WEB_ENUMERATION",
        "COMMAND_INTERACTION",
        "MQTT_PROBING",
        "MULTI_SERVICE_ACTIVITY",
        "MULTI_STAGE_ATTACK",
    }
    for path in Path("attacks/scenarios").glob("*.yaml"):
        scenario = yaml.safe_load(path.read_text())
        assert scenario["id"] == path.stem
        assert scenario["trial_kind"] in {"attack", "control"}
        assert scenario["target_services"] and set(scenario["target_services"]) <= known_services
        assert scenario["steps"] and all(step["service"] in known_services for step in scenario["steps"])
        assert scenario["expected_detection"] in detections if scenario["trial_kind"] == "attack" else scenario["expected_detection"] is None
