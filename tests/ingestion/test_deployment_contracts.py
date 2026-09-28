import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[2]


def load_compose(path: str):
    return yaml.safe_load((ROOT / path).read_text())


def test_analysis_deployment_contracts():
    text = (ROOT / "docker-compose.yml").read_text()
    compose = load_compose("docker-compose.yml")
    for mount in (
        "elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml:ro,Z",
        "logstash/config:/usr/share/logstash/config:ro,Z",
        "logstash/pipelines:/usr/share/logstash/pipeline:ro,Z",
        "kibana.yml:/usr/share/kibana/config/kibana.yml:ro,Z",
        "trapsig.ndjson:/assets/trapsig.ndjson:ro,Z",
        "pi_ssh_key}:/run/trapsig-secrets/pi_ssh_key:ro,Z",
        "known_hosts}:/run/trapsig-secrets/known_hosts:ro,Z",
    ):
        assert mount in text
    assert compose["services"]["frontend"]["environment"]["HOSTNAME"] == "0.0.0.0"
    assert "127.0.0.1:3000" in compose["services"]["frontend"]["healthcheck"]["test"][-1]
    kibana = compose["services"]["kibana"]
    assert kibana["environment"]["NODE_OPTIONS"] == "--max-old-space-size=768"
    assert kibana["mem_limit"] == "1536m"


def test_sensor_health_and_permissions_contracts():
    compose = load_compose("sensor/docker-compose.yml")
    services = compose["services"]
    assert services["custom-logs-init"]["command"] == ["chown", "-R", "10001:10001", "/logs"]
    for name in ("camera", "iot-service", "mqtt", "router"):
        service = services[name]
        assert service["build"]
        assert service["read_only"] is True
        assert service["cap_drop"] == ["ALL"]
        assert service["depends_on"]["custom-logs-init"]["condition"] == "service_completed_successfully"
        assert service["healthcheck"]["test"] == ["CMD", "python", "/usr/local/bin/healthcheck.py"]
    assert services["cowrie"]["healthcheck"]["test"][0] == "CMD"
    assert services["cowrie"]["healthcheck"]["test"][1] == "/cowrie/cowrie-env/bin/python"
    assert services["filebeat"]["healthcheck"]["test"][0] == "CMD"
    assert "--strict.perms=false" in services["filebeat"]["healthcheck"]["test"]


def test_ssh_wrapper_is_an_exact_whitelist():
    wrapper = ROOT / "sensor/scripts/ssh-manage-wrapper.sh"
    text = wrapper.read_text()
    assert "eval" not in text
    assert "sh -c" not in text
    assert 'MANAGER=/opt/trapsig/sensor/scripts/manage.sh' in text
    assert "${SSH_ORIGINAL_COMMAND:-}" in text
    for service in ("cowrie", "camera", "iot-service", "mqtt", "router"):
        for action in ("start", "stop", "restart"):
            assert f'"{action} {service}")' in text
    denied = subprocess.run(
        [str(wrapper)], env={"SSH_ORIGINAL_COMMAND": "uname -a"}, text=True, capture_output=True, check=False
    )
    assert denied.returncode != 0
    assert "Denied" in denied.stderr
