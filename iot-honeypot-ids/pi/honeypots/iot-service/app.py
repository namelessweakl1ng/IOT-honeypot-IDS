"""
Lightweight IoT management service honeypot.

A minimal TCP service that pretends to be a small IoT device management daemon.
Captures banner-grabs, malformed payloads, and "command" attempts.

Each connection produces one or more structured JSON events in
`/app/logs/iot.jsonl`.

Protocol (deliberately trivial, looks like cheap IoT firmwares):

  On connect, server greets:
    `HELLO <device-id> IoT-MGMT-1.0\n`

  Client may send commands terminated by `\n`:
    PING                       -> `PONG\n`
    STAT                       -> `OK cpu=14 mem=96\n`
    LIST                       -> `OK devices=1\n`
    AUTH <user> <pass>         -> `AUTH-OK` or `AUTH-FAIL` (we always accept
                                  admin/admin and record everything)
    CMD <command>              -> `EXEC-OK` (but we never execute anything)
    QUIT                       -> closes the connection

Any unrecognized input is recorded and answered with `ERROR\n`.
"""
from __future__ import annotations

import json
import logging
import os
import socket
import socketserver
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEVICE_ID = os.environ.get("DEVICE_ID", "iot-01")
HOSTNAME = os.environ.get("HOSTNAME", "iot-bridge-01")
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
LOG_PATH = os.environ.get("IOT_LOG_PATH", "/var/log/iot/iot.jsonl")
LISTEN_PORT = int(os.environ.get("IOT_SERVICE_PORT", "9000"))

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s %(levelname)s %(name)s | %(message)s",
)
log = logging.getLogger("iot-service")

_lock = threading.Lock()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _emit(event: dict[str, Any]) -> None:
    try:
        Path(LOG_PATH).parent.mkdir(parents=True, exist_ok=True)
        with _lock, open(LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, ensure_ascii=False) + "\n")
    except Exception as exc:
        log.error("failed to write event: %s", exc)


def _event(
    *,
    session_id: str,
    src_ip: str,
    src_port: int,
    action: str,
    stage: str | None = None,
    classification: str | None = None,
    confidence: float = 0.0,
    raw: str | None = None,
    note: str | None = None,
) -> dict[str, Any]:
    ev = {
        "@timestamp": _now_iso(),
        "event_id": str(uuid.uuid4()),
        "session_id": session_id,
        "device": {
            "id": DEVICE_ID,
            "type": "iot_service",
            "hostname": HOSTNAME,
            "container": "pi-iot-service",
        },
        "protocol": "tcp_iot",
        "source": {"ip": src_ip, "port": src_port},
        "destination": {"ip": "0.0.0.0", "port": LISTEN_PORT},
        "event": {
            "type": action,
            "category": "network",
            "action": action,
        },
        "honeypot": {"name": "iot-service", "container": "pi-iot-service"},
        "attack": {
            "session_id": session_id,
            "stage": stage,
            "classification": classification,
            "confidence": confidence,
        },
    }
    if raw is not None:
        sanitized_raw = _redact_iot_credentials(raw)
        ev["iot"] = {"raw": sanitized_raw[:512]}
    if note:
        ev["event"]["note"] = note
    return ev


def _redact_iot_credentials(raw: str) -> str:
    """Redact passwords from IoT protocol commands before persistence."""
    import re
    raw = re.sub(r'(AUTH\s+\S+)\s+\S+', r'\1 <redacted>', raw, flags=re.IGNORECASE)
    raw = re.sub(r'(AUTH\s+)(\S+):(\S+)', r'\1\2:<redacted>', raw, flags=re.IGNORECASE)
    return raw


class Handler(socketserver.StreamRequestHandler):
    """One handler per connection."""

    def handle(self) -> None:  # noqa: C901 - simple flat protocol
        src_ip, src_port = self.client_address[0], self.client_address[1]
        session_id = str(uuid.uuid4())
        try:
            self.wfile.write(f"HELLO {DEVICE_ID} IoT-MGMT-1.0\n".encode())
            self.wfile.flush()
        except Exception:
            return

        _emit(_event(
            session_id=session_id, src_ip=src_ip, src_port=src_port,
            action="connect", stage="reconnaissance", confidence=0.2,
            note="banner-grab",
        ))

        bytes_in = 0
        bytes_out = 0
        cmd_count = 0
        auth_attempts = 0
        auth_user = None

        while True:
            try:
                line = self.rfile.readline()
            except (ConnectionResetError, BrokenPipeError):
                break
            if not line:
                break
            bytes_in += len(line)
            text = line.decode("utf-8", "ignore").strip()
            if not text:
                continue

            response = b"ERROR\n"
            action = "command"
            stage = None
            classification = None
            confidence = 0.0

            if text.upper() == "PING":
                response = b"PONG\n"
                action = "ping"
            elif text.upper() == "STAT":
                response = b"OK cpu=14 mem=96\n"
                action = "stat_query"
                stage = "discovery"
                confidence = 0.3
            elif text.upper() == "LIST":
                response = b"OK devices=1\n"
                action = "list_query"
                stage = "discovery"
                confidence = 0.3
            elif text.upper().startswith("AUTH "):
                parts = text.split(" ", 2)
                auth_user = parts[1] if len(parts) > 1 else ""
                # We never log the password value, only that an attempt happened.
                accepted = (auth_user, parts[2] if len(parts) > 2 else "") in {
                    ("admin", "admin"), ("root", "root")
                }
                auth_attempts += 1
                response = b"AUTH-OK\n" if accepted else b"AUTH-FAIL\n"
                action = "authentication_attempt"
                stage = "credential_access"
                classification = "default_credentials" if accepted else None
                confidence = 0.9 if accepted else 0.5
            elif text.upper().startswith("CMD "):
                cmd_count += 1
                response = b"EXEC-OK\n"
                action = "command_execution"
                stage = "execution"
                classification = "command_abuse"
                confidence = 0.7
            elif text.upper() == "QUIT":
                _emit(_event(
                    session_id=session_id, src_ip=src_ip, src_port=src_port,
                    action="disconnect", raw=text,
                ))
                break
            else:
                # Unrecognized input — could be probing, fuzzing, or junk.
                action = "unknown_input"
                stage = "reconnaissance"
                classification = "malformed_payload" if any(
                    c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 _-.:/"
                    for c in text
                ) else None
                confidence = 0.4

            _emit(_event(
                session_id=session_id, src_ip=src_ip, src_port=src_port,
                action=action, stage=stage, classification=classification,
                confidence=confidence, raw=text,
            ))

            try:
                self.wfile.write(response)
                self.wfile.flush()
                bytes_out += len(response)
            except (ConnectionResetError, BrokenPipeError):
                break

        # Final session summary event — helps PC1 reconstruct sessions.
        _emit(_event(
            session_id=session_id, src_ip=src_ip, src_port=src_port,
            action="session_end",
            stage="exfiltration" if bytes_out > 4096 else None,
            note=(
                f"bytes_in={bytes_in} bytes_out={bytes_out} "
                f"commands={cmd_count} auth_attempts={auth_attempts} "
                f"auth_user={auth_user}"
            ),
        ))


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> None:
    log.info(
        "starting iot-service honeypot device_id=%s port=%d log=%s",
        DEVICE_ID, LISTEN_PORT, LOG_PATH,
    )
    server = ThreadingTCPServer(("0.0.0.0", LISTEN_PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("shutting down")
    finally:
        server.shutdown()


if __name__ == "__main__":
    main()
