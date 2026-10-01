"""Shared bounded socket lifecycle for every custom persona."""

import socket
import socketserver
from typing import Protocol

from common.telemetry import base_event, write_jsonl

MAX_HTTP_HEADER_BYTES = 16 * 1024
MAX_HTTP_BODY_BYTES = 64 * 1024
MAX_HTTP_REQUEST_BYTES = MAX_HTTP_HEADER_BYTES + MAX_HTTP_BODY_BYTES
HTTP_READ_TIMEOUT = 2.0
TCP_READ_TIMEOUT = 1.0
MAX_MQTT_FRAME_BYTES = 4096
MAX_IOT_COMMAND_BYTES = 1024


class HTTPRequestReadError(Exception):
    """A client sent an HTTP request that cannot be assembled safely."""

    def __init__(self, status: int, reason: str) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason


class ProtocolReadError(Exception):
    """A bounded non-HTTP frame could not be read safely."""


def _recv_exact(connection: socket.socket, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = connection.recv(length - len(data))
        if not chunk:
            raise ProtocolReadError("incomplete frame")
        data.extend(chunk)
    return bytes(data)


def read_mqtt_frame(connection: socket.socket) -> bytes:
    """Read exactly one bounded MQTT frame from a TCP stream."""
    connection.settimeout(TCP_READ_TIMEOUT)
    try:
        frame = bytearray(_recv_exact(connection, 1))
        remaining_length = 0
        multiplier = 1
        for _ in range(4):
            encoded = _recv_exact(connection, 1)[0]
            frame.append(encoded)
            remaining_length += (encoded & 0x7F) * multiplier
            if not encoded & 0x80:
                break
            multiplier *= 128
        else:
            raise ProtocolReadError("malformed remaining length")
        if len(frame) + remaining_length > MAX_MQTT_FRAME_BYTES:
            raise ProtocolReadError("frame too large")
        frame.extend(_recv_exact(connection, remaining_length))
        return bytes(frame)
    except socket.timeout as exc:
        raise ProtocolReadError("frame read timeout") from exc


def read_iot_command(connection: socket.socket) -> bytes:
    """Read one newline-terminated, bounded IoT command."""
    connection.settimeout(TCP_READ_TIMEOUT)
    data = bytearray()
    try:
        while b"\n" not in data:
            remaining = MAX_IOT_COMMAND_BYTES - len(data)
            if remaining <= 0:
                raise ProtocolReadError("command too large")
            chunk = connection.recv(min(256, remaining))
            if not chunk:
                raise ProtocolReadError("incomplete command")
            data.extend(chunk)
        line_end = data.index(b"\n") + 1
        if line_end != len(data):
            raise ProtocolReadError("multiple commands are not supported")
        return bytes(data)
    except socket.timeout as exc:
        raise ProtocolReadError("command read timeout") from exc


def read_http_request(connection: socket.socket) -> bytes:
    """Read one Content-Length-framed HTTP request within strict size bounds."""
    connection.settimeout(HTTP_READ_TIMEOUT)
    data = bytearray()
    try:
        while b"\r\n\r\n" not in data:
            remaining = MAX_HTTP_HEADER_BYTES - len(data)
            if remaining <= 0:
                raise HTTPRequestReadError(431, "Request Header Fields Too Large")
            chunk = connection.recv(min(4096, remaining))
            if not chunk:
                raise HTTPRequestReadError(400, "Bad Request")
            data.extend(chunk)

        header, separator, initial_body = bytes(data).partition(b"\r\n\r\n")
        content_lengths = []
        for line in header.split(b"\r\n")[1:]:
            name, colon, value = line.partition(b":")
            if colon and name.strip().lower() == b"content-length":
                content_lengths.append(value.strip())
        if len(content_lengths) > 1 or (content_lengths and not content_lengths[0].isdigit()):
            raise HTTPRequestReadError(400, "Bad Request")
        if content_lengths and len(content_lengths[0]) > len(str(MAX_HTTP_BODY_BYTES)):
            raise HTTPRequestReadError(413, "Payload Too Large")

        content_length = int(content_lengths[0]) if content_lengths else 0
        if content_length > MAX_HTTP_BODY_BYTES:
            raise HTTPRequestReadError(413, "Payload Too Large")

        body = bytearray(initial_body[:content_length])
        while len(body) < content_length:
            chunk = connection.recv(min(4096, content_length - len(body)))
            if not chunk:
                raise HTTPRequestReadError(400, "Bad Request")
            body.extend(chunk)
    except socket.timeout as exc:
        raise HTTPRequestReadError(408, "Request Timeout") from exc

    request = header + separator + body
    if len(request) > MAX_HTTP_REQUEST_BYTES:
        raise HTTPRequestReadError(413, "Payload Too Large")
    return request


def http_error_response(error: HTTPRequestReadError) -> bytes:
    body = f"{error.status} {error.reason}\n".encode()
    return (
        f"HTTP/1.1 {error.status} {error.reason}\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Cache-Control: no-store\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode() + body


class Persona(Protocol):
    def parse(self, data: bytes) -> dict: ...
    def enrich(self, event: dict, details: dict) -> None: ...
    def response(self, details: dict) -> bytes: ...


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def handler_for(persona: Persona, service: str, protocol: str, port: int, log_path: str):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            if protocol == "http":
                try:
                    data = read_http_request(self.request)
                except HTTPRequestReadError as error:
                    self.request.sendall(http_error_response(error))
                    return
            elif protocol == "mqtt":
                try:
                    data = read_mqtt_frame(self.request)
                except ProtocolReadError:
                    return
            elif service == "iot-service" and protocol == "tcp":
                try:
                    data = read_iot_command(self.request)
                except ProtocolReadError:
                    return
            else:
                data = self.request.recv(4096)
            details = persona.parse(data)
            event = base_event(service, protocol, port, self.client_address, details, bool(data))
            persona.enrich(event, details)
            write_jsonl(log_path, event)
            self.request.sendall(persona.response(details))

    return Handler


def serve(persona: Persona, service: str, protocol: str, port: int, log_path: str) -> None:
    Server(("0.0.0.0", port), handler_for(persona, service, protocol, port, log_path)).serve_forever()
