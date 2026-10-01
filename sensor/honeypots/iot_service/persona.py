"""Bounded, fictional Velora Edge Controller command persona."""

import time
from collections.abc import Callable

MAX_COMMAND_BYTES = 1024


class IoTServicePersona:
    """Emulate a small line-oriented controller without touching host state."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._started = clock()

    def parse(self, data: bytes) -> dict:
        details = {"operation": "unknown", "payload": data[:MAX_COMMAND_BYTES].decode("utf-8", errors="replace")}
        if not data or len(data) > MAX_COMMAND_BYTES or b"\x00" in data:
            details["malformed"] = True
            return details
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            details["malformed"] = True
            return details

        parts = text.strip(" \t\r\n").split()
        if not parts:
            details["malformed"] = True
            return details
        command = parts[0].upper()
        if command in {"STATUS", "VERSION", "INFO", "HELP"}:
            details["operation"] = command.lower()
            details["malformed"] = len(parts) != 1
        elif command == "AUTH":
            details["operation"] = "auth"
            details["malformed"] = len(parts) != 3
            if len(parts) >= 2:
                details["username"] = parts[1][:128]
            if len(parts) >= 3:
                details["password"] = parts[2][:128]
            details["auth_success"] = parts[1:] == ["admin", "admin"]
        return details

    def enrich(self, event: dict, details: dict) -> None:
        event["iot"] = {"operation": details["operation"]}
        if details["operation"] == "auth":
            event["authentication"] = {
                "username": details.get("username"),
                "password": details.get("password"),
            }
            event["category"] = "authentication"
            event["action"] = "login_attempt"
            event["outcome"] = "success" if details.get("auth_success") and not details.get("malformed") else "failure"

    def response(self, details: dict) -> bytes:
        if details.get("malformed"):
            return b"400 BAD REQUEST\r\n"
        operation = details.get("operation", "unknown")
        if operation == "status":
            uptime = max(0, int(self._clock() - self._started)) + 18420
            return (
                "200 OK\r\nMODEL=VEC-100\r\nSTATE=ONLINE\r\n"
                f"UPTIME={uptime}\r\nINPUTS=4\r\nOUTPUTS=2\r\nTEMP=24.8\r\n"
            ).encode()
        if operation == "version":
            return (
                b"200 OK\r\nPRODUCT=Velora Edge Controller\r\nMODEL=VEC-100\r\n"
                b"FIRMWARE=3.2.1\r\nHARDWARE=VEC1-R2\r\nPROTOCOL=VCP/1.0\r\n"
            )
        if operation == "info":
            return (
                b"200 OK\r\nHOSTNAME=VE-EDGE-01\r\nSERIAL=VE10-42A8-1031\r\n"
                b"IP=192.168.10.42\r\nMAC=02:56:45:10:42:31\r\nMODE=edge-controller\r\n"
            )
        if operation == "help":
            return b"200 OK\r\nCOMMANDS=STATUS VERSION INFO HELP AUTH <username> <password>\r\n"
        if operation == "auth":
            return b"230 AUTH OK\r\n" if details.get("auth_success") else b"530 AUTH FAILED\r\n"
        return b"400 UNKNOWN COMMAND\r\n"
