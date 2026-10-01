import sys
from pathlib import Path

import pytest

HONEYPOTS = Path("sensor/honeypots").resolve()
sys.path.insert(0, str(HONEYPOTS))

from mqtt.persona import MQTTPersona  # noqa: E402
from mqtt.protocol import parse_packet  # noqa: E402

CONNECT = b"\x10\x10\x00\x04MQTT\x04\x02\x00\x0a\x00\x04test"
SUBSCRIBE = b"\x82\x09\x00\x01\x00\x04test\x00"


def test_connect_parsing_and_accepted_connack():
    persona = MQTTPersona()
    details = persona.parse(CONNECT)
    assert details == {
        "packet_type": 1,
        "flags": 0,
        "operation": "connect",
        "remaining_length": 16,
        "protocol_name": "MQTT",
        "protocol_level": 4,
        "connect_flags": 2,
        "keep_alive": 10,
        "username_present": False,
        "password_present": False,
        "client_id": "test",
    }
    assert persona.response(details) == b"\x20\x02\x00\x00"


def test_subscribe_parsing_and_matching_suback_without_session():
    persona = MQTTPersona()
    details = persona.parse(SUBSCRIBE)
    assert details["operation"] == "subscribe"
    assert details["packet_id"] == 1 and details["topic"] == "test"
    assert persona.response(details) == b"\x90\x03\x00\x01\x00"


def test_ping_disconnect_and_publish_behavior():
    persona = MQTTPersona()
    assert persona.response(persona.parse(b"\xc0\x00")) == b"\xd0\x00"
    assert persona.response(persona.parse(b"\xe0\x00")) == b""
    publish = persona.parse(b"\x30\x07\x00\x04testx")
    assert (publish["operation"], publish["topic"], publish["qos"]) == ("publish", "test", 0)
    assert persona.response(publish) == b""


@pytest.mark.parametrize(
    "packet,error",
    [
        (b"", "empty packet"),
        (b"\x10", "truncated remaining length"),
        (b"\x10\x80\x80\x80\x80", "malformed remaining length"),
        (b"\x10\x10\x00", "truncated payload"),
    ],
)
def test_malformed_fixed_headers_never_raise(packet, error):
    details = parse_packet(packet)
    assert details["malformed"] is True and details["error"] == error
    assert MQTTPersona().response(details) == b""


def test_multibyte_remaining_length_is_decoded_without_declared_allocation():
    payload = b"x" * 128
    details = parse_packet(b"\xf0\x80\x01" + payload)
    assert details["packet_type"] == 15
    assert details["operation"] == "unknown"
    assert details["remaining_length"] == 128


def test_unsupported_packet_is_identified_without_ping_response():
    persona = MQTTPersona()
    details = persona.parse(b"\x40\x02\x00\x01")
    event = {}
    persona.enrich(event, details)
    assert details["operation"] == "puback"
    assert event["mqtt"]["operation"] == "puback"
    assert persona.response(details) == b""


def test_detector_compatible_operations_for_recon_and_auth_probe():
    persona = MQTTPersona()
    recon = [persona.parse(packet)["operation"] for packet in (CONNECT, SUBSCRIBE, b"\xc0\x00")]
    repeated = [persona.parse(CONNECT)["operation"] for _ in range(2)]
    assert recon == ["connect", "subscribe", "ping"]
    assert repeated == ["connect", "connect"]


@pytest.mark.parametrize("packet", [bytes(range(size)) for size in range(20)])
def test_arbitrary_short_binary_input_never_crashes(packet):
    details = parse_packet(packet)
    assert isinstance(details, dict)
