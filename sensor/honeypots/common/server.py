"""Shared bounded socket lifecycle for every custom persona."""

import socketserver
from typing import Protocol

from common.telemetry import base_event, write_jsonl


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
            data = self.request.recv(4096)
            details = persona.parse(data)
            event = base_event(service, protocol, port, self.client_address, details, bool(data))
            persona.enrich(event, details)
            write_jsonl(log_path, event)
            self.request.sendall(persona.response(details))

    return Handler


def serve(persona: Persona, service: str, protocol: str, port: int, log_path: str) -> None:
    Server(("0.0.0.0", port), handler_for(persona, service, protocol, port, log_path)).serve_forever()
