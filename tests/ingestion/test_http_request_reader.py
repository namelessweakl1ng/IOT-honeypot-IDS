import json
import socket
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path("sensor/honeypots").resolve()))

from camera.persona import CameraPersona
from common.server import MAX_HTTP_BODY_BYTES, HTTPRequestReadError, Server, handler_for, read_http_request
from router.persona import RouterPersona


class ScriptedSocket:
    def __init__(self, reads):
        self.reads = list(reads)
        self.timeout = None

    def settimeout(self, timeout):
        self.timeout = timeout

    def recv(self, size):
        if not self.reads:
            return b""
        data = self.reads.pop(0)
        self.reads.insert(0, data[size:]) if len(data) > size else None
        return data[:size]


class TimingOutSocket(ScriptedSocket):
    def recv(self, size):
        raise socket.timeout


def form_request(service, body=b"username=admin&password=admin"):
    headers = (
        b"POST /login HTTP/1.1\r\n"
        + f"Host: {service}\r\n".encode()
        + b"User-Agent: split-request-test\r\n"
        + b"Content-Type: application/x-www-form-urlencoded\r\n"
        + f"Content-Length: {len(body)}\r\n\r\n".encode()
    )
    return headers, body


def exchange(tmp_path, persona, service, chunks, shutdown_write=False):
    log_path = tmp_path / f"{service}.jsonl"
    server = Server(("127.0.0.1", 0), handler_for(persona, service, "http", 8080, str(log_path)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with socket.create_connection(server.server_address, timeout=1) as client:
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


def test_reader_assembles_header_and_body_from_separate_reads():
    headers, body = form_request("router")
    connection = ScriptedSocket([headers, body])
    assert read_http_request(connection) == headers + body
    assert connection.timeout is not None


def test_reader_accepts_normal_single_read_request():
    headers, body = form_request("router")
    assert read_http_request(ScriptedSocket([headers + body])) == headers + body


@pytest.mark.parametrize(
    ("content_length", "expected_status"),
    [(b"not-a-number", 400), (b"-1", 400), (str(MAX_HTTP_BODY_BYTES + 1).encode(), 413)],
)
def test_reader_rejects_malformed_and_oversized_content_lengths(content_length, expected_status):
    request = b"POST /login HTTP/1.1\r\nContent-Length: " + content_length + b"\r\n\r\n"
    with pytest.raises(HTTPRequestReadError) as caught:
        read_http_request(ScriptedSocket([request]))
    assert caught.value.status == expected_status


def test_reader_rejects_incomplete_body_without_crashing():
    request = b"POST /login HTTP/1.1\r\nContent-Length: 10\r\n\r\nshort"
    with pytest.raises(HTTPRequestReadError) as caught:
        read_http_request(ScriptedSocket([request]))
    assert caught.value.status == 400


def test_reader_converts_socket_timeout_to_bounded_http_failure():
    with pytest.raises(HTTPRequestReadError) as caught:
        read_http_request(TimingOutSocket([]))
    assert caught.value.status == 408


@pytest.mark.parametrize(("service", "persona"), [("router", RouterPersona()), ("camera", CameraPersona())])
def test_shared_handler_supports_split_form_login_and_preserves_telemetry(tmp_path, service, persona):
    headers, body = form_request(service)
    response, events = exchange(tmp_path, persona, service, [headers, body])
    assert response.startswith(b"HTTP/1.1 302 Found")
    assert b"Set-Cookie: session=" in response
    assert len(events) == 1
    event = events[0]
    assert event["category"] == "authentication"
    assert event["action"] == "login_attempt"
    assert event["outcome"] == "success"
    assert event["http"] == {"request": {"method": "POST"}, "user_agent": "split-request-test"}
    assert event["url"]["path"] == "/login"
    assert event["authentication"] == {"username": "admin", "password": "admin"}


def test_shared_handler_returns_bounded_failure_for_incomplete_body(tmp_path):
    headers, _ = form_request("router")
    response, events = exchange(tmp_path, RouterPersona(), "router", [headers, b"short"], shutdown_write=True)
    assert response.startswith(b"HTTP/1.1 400 Bad Request")
    assert len(response) < 512
    assert events == []
