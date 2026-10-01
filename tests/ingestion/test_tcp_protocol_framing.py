import json
import socket
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path("sensor/honeypots").resolve()))

from common.server import MAX_IOT_COMMAND_BYTES, MAX_MQTT_FRAME_BYTES, Server, handler_for  # noqa: E402
from iot_service.persona import IoTServicePersona  # noqa: E402
from mqtt.persona import MQTTPersona  # noqa: E402

CONNECT = b"\x10\x10\x00\x04MQTT\x04\x02\x00\x0a\x00\x04test"
SUBSCRIBE = b"\x82\x09\x00\x01\x00\x04test\x00"


def exchange(tmp_path, persona, service, protocol, chunks, shutdown_write=False):
    log_path = tmp_path / f"{service}.jsonl"
    server = Server(("127.0.0.1", 0), handler_for(persona, service, protocol, 1883, str(log_path)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with socket.create_connection(server.server_address, timeout=2) as client:
            for chunk in chunks:
                client.sendall(chunk)
            if shutdown_write:
                client.shutdown(socket.SHUT_WR)
            response = bytearray()
            while part := client.recv(4096):
                response.extend(part)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)
    events = [json.loads(line) for line in log_path.read_text().splitlines()] if log_path.exists() else []
    return bytes(response), events


@pytest.mark.parametrize(
    ("packet", "chunks", "expected"),
    [
        (CONNECT, (1, 3, 8), b"\x20\x02\x00\x00"),
        (SUBSCRIBE, (1, 2, 7), b"\x90\x03\x00\x01\x00"),
    ],
)
def test_mqtt_handler_assembles_frames_split_across_tcp_writes(tmp_path, packet, chunks, expected):
    offsets = (0, *chunks, len(packet))
    writes = [packet[start:end] for start, end in zip(offsets, offsets[1:])]
    response, events = exchange(tmp_path, MQTTPersona(), "mqtt", "mqtt", writes)
    assert response == expected
    assert len(events) == 1


@pytest.mark.parametrize(
    ("writes", "response_fragment", "outcome"),
    [
        ([b"STA", b"TUS\r\n"], b"STATE=ONLINE", "unknown"),
        ([b"AUTH ad", b"min admin\r\n"], b"230 AUTH OK", "success"),
    ],
)
def test_iot_handler_assembles_split_lines_and_writes_telemetry(tmp_path, writes, response_fragment, outcome):
    response, events = exchange(tmp_path, IoTServicePersona(), "iot-service", "tcp", writes)
    assert response_fragment in response
    assert len(events) == 1
    assert events[0]["iot"]["operation"] in {"status", "auth"}
    assert events[0]["outcome"] == outcome
    if outcome == "success":
        assert events[0]["authentication"] == {"username": "admin", "password": "admin"}


def test_oversized_mqtt_frame_is_closed_without_reading_payload(tmp_path):
    remaining = MAX_MQTT_FRAME_BYTES
    encoded = bytes([remaining % 128 | 0x80, remaining // 128])
    response, events = exchange(tmp_path, MQTTPersona(), "mqtt", "mqtt", [b"\x30" + encoded])
    assert response == b"" and events == []


def test_maximum_bounded_mqtt_frame_is_read_safely(tmp_path):
    payload_length = MAX_MQTT_FRAME_BYTES - 3
    encoded = bytes([payload_length % 128 | 0x80, payload_length // 128])
    response, events = exchange(tmp_path, MQTTPersona(), "mqtt", "mqtt", [b"\xf0" + encoded, b"x" * payload_length])
    assert response == b""
    assert len(events) == 1 and events[0]["mqtt"]["remaining_length"] == payload_length


def test_incomplete_mqtt_frame_closes_safely(tmp_path):
    response, events = exchange(tmp_path, MQTTPersona(), "mqtt", "mqtt", [b"\x10\x10partial"], shutdown_write=True)
    assert response == b"" and events == []


def test_oversized_iot_line_closes_safely(tmp_path):
    response, events = exchange(tmp_path, IoTServicePersona(), "iot-service", "tcp", [b"A" * MAX_IOT_COMMAND_BYTES])
    assert response == b"" and events == []
