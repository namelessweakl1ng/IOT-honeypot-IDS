import sys
from pathlib import Path

HONEYPOTS = Path("sensor/honeypots").resolve()
sys.path.insert(0, str(HONEYPOTS))

from common.telemetry import base_event  # noqa: E402
from iot_service.persona import IoTServicePersona  # noqa: E402


class Clock:
    now = 100.0

    def __call__(self):
        return self.now


def interact(persona, command):
    details = persona.parse(command)
    return details, persona.response(details)


def test_supported_commands_are_distinct_and_case_insensitive():
    persona = IoTServicePersona()
    status = interact(persona, b"  status\r\n")[1]
    version = interact(persona, b"VERSION\n")[1]
    info = interact(persona, b"Info")[1]
    help_response = interact(persona, b"HELP")[1]
    assert b"STATE=ONLINE" in status
    assert b"FIRMWARE=3.2.1" in version
    assert b"HOSTNAME=VE-EDGE-01" in info
    assert b"STATUS VERSION INFO HELP AUTH" in help_response
    assert len({status, version, info, help_response}) == 4


def test_authentication_response_and_normalized_telemetry():
    persona = IoTServicePersona()
    valid, valid_response = interact(persona, b"AUTH admin admin")
    invalid, invalid_response = interact(persona, b"auth guest wrong")
    assert valid_response == b"230 AUTH OK\r\n"
    assert invalid_response == b"530 AUTH FAILED\r\n"
    for details, outcome in ((valid, "success"), (invalid, "failure")):
        event = base_event("iot-service", "tcp", 9000, ("192.0.2.1", 1), details)
        persona.enrich(event, details)
        assert event["iot"]["operation"] == "auth"
        assert event["authentication"] == {"username": details["username"], "password": details["password"]}
        assert (event["category"], event["action"], event["outcome"]) == ("authentication", "login_attempt", outcome)


def test_operation_telemetry_and_dynamic_synthetic_uptime():
    clock = Clock()
    persona = IoTServicePersona(clock)
    details, first = interact(persona, b"STATUS")
    clock.now += 7
    second = interact(persona, b"STATUS")[1]
    event = {}
    persona.enrich(event, details)
    assert b"UPTIME=18420" in first and b"UPTIME=18427" in second
    assert event["iot"] == {"operation": "status"}


def test_unknown_and_malformed_inputs_are_bounded_and_fingerprint_free():
    persona = IoTServicePersona()
    samples = [b"NOPE", b"", b"\xff\xfe", b"\x00binary", b"AUTH admin", b"A" * 1025, b" \t\r\n"]
    responses = [interact(persona, sample)[1] for sample in samples]
    assert responses[0] == b"400 UNKNOWN COMMAND\r\n"
    assert all(response.startswith(b"400 ") for response in responses)
    forbidden = (b"TRAPSIG", b"honeypot", b"decoy", b"Python")
    assert not any(word.lower() in response.lower() for response in responses for word in forbidden)


def test_iot_probe_events_retain_three_network_interactions():
    persona = IoTServicePersona()
    events = []
    for command in (b"STATUS", b"VERSION", b"INFO"):
        details = persona.parse(command)
        event = base_event("iot-service", "tcp", 9000, ("192.0.2.1", 1), details)
        persona.enrich(event, details)
        events.append(event)
    assert [event["action"] for event in events] == ["status", "version", "info"]
    assert all(event["category"] == "network" for event in events)
