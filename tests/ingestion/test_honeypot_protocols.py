import importlib
import json
import sys
from base64 import b64encode
from pathlib import Path

import pytest

HONEYPOTS = Path("sensor/honeypots").resolve()
sys.path.insert(0, str(HONEYPOTS))

app = importlib.import_module("app")
from camera.persona import CameraPersona  # noqa: E402
from common.protocols import mqtt_details  # noqa: E402
from common.telemetry import base_event, write_jsonl  # noqa: E402
from iot_service.persona import IoTServicePersona  # noqa: E402
from mqtt.persona import MQTTPersona  # noqa: E402
from router.persona import RouterPersona  # noqa: E402


@pytest.mark.parametrize(
    ("service", "persona_type"),
    [("camera", CameraPersona), ("router", RouterPersona), ("iot-service", IoTServicePersona), ("mqtt", MQTTPersona)],
)
def test_service_selects_its_own_persona(service, persona_type):
    assert isinstance(app.select_persona(service), persona_type)


def test_unknown_service_fails_clearly():
    with pytest.raises(ValueError, match="unknown SERVICE 'printer'"):
        app.select_persona("printer")


@pytest.mark.parametrize("persona", [CameraPersona(), RouterPersona()])
def test_http_personas_parse_requests_and_preserve_authentication(persona):
    token = b64encode(b"admin:admin").decode()
    details = persona.parse(f"GET /admin?tab=network HTTP/1.1\r\nAuthorization: Basic {token}\r\nUser-Agent: test\r\n\r\n".encode())
    event = base_event("camera", "http", 8081, ("192.0.2.1", 4321), details)
    persona.enrich(event, details)

    assert details["path"] == "/admin"
    assert event["authentication"] == {"username": "admin", "password": "admin"}
    assert persona.response(details).startswith(b"HTTP/1.1 401 Unauthorized")


def test_iot_tcp_records_payload_interaction():
    persona = IoTServicePersona()
    assert persona.parse(b"status\xff") == {"payload": "status�"}
    assert persona.response({}) == b"TRAPSIG-IOT READY\r\n"


def test_mqtt_packets_are_classified_and_enriched():
    assert mqtt_details(b"\x10\x00")["operation"] == "connect"
    assert mqtt_details(b"\x82\x00")["operation"] == "subscribe"
    event = {}
    MQTTPersona().enrich(event, mqtt_details(b"\x10\x00"))
    assert event["mqtt"]["packet_type"] == 1


@pytest.mark.parametrize("service", ["camera", "router", "mqtt", "iot-service"])
def test_base_event_preserves_required_fields_and_service_identity(service):
    event = base_event(service, "tcp", 9000, ("192.0.2.1", 4321), {"payload": "hello"})
    required = {
        "timestamp",
        "event_id",
        "category",
        "type",
        "action",
        "outcome",
        "source_ip",
        "source_port",
        "destination_port",
        "protocol",
        "service",
        "honeypot_id",
        "honeypot_type",
        "summary",
    }
    assert required <= event.keys()
    assert event["honeypot_id"] == f"{service}-01"
    assert event["honeypot_type"] == service.replace("-", "_")


def test_log_output_is_json_lines(tmp_path):
    path = tmp_path / "events.jsonl"
    write_jsonl(str(path), {"event_id": "one"})
    write_jsonl(str(path), {"event_id": "two"})
    assert [json.loads(line)["event_id"] for line in path.read_text().splitlines()] == ["one", "two"]


def test_app_is_dispatcher_not_monolithic_protocol_implementation():
    source = Path("sensor/honeypots/app.py").read_text()
    assert "socketserver" not in source
    assert "def http_details" not in source
    assert "def mqtt_details" not in source
    for module in ("camera/persona.py", "router/persona.py", "iot_service/persona.py", "mqtt/persona.py"):
        assert (HONEYPOTS / module).is_file()
