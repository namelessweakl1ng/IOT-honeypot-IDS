"""High-fidelity, bounded AsterView CV-210 camera persona."""

# ruff: noqa: E501 -- embedded device markup is intentionally kept in this module.

import json
import secrets
import threading
import time
from datetime import datetime, timezone
from http import HTTPStatus

from common.protocols import add_http_fields, http_details

from camera.pages import info_table, login_page, shell

SESSION_TTL = 30 * 60


class CameraPersona:
    def __init__(self, clock=time.monotonic) -> None:
        self._clock = clock
        self._started = clock()
        self._sessions: dict[str, float] = {}
        self._lock = threading.Lock()

    def parse(self, data: bytes) -> dict:
        details = http_details(data)
        details["basic_supplied"] = details["authorization"].lower().startswith("basic ")
        return details

    def enrich(self, event: dict, details: dict) -> None:
        add_http_fields(event, details)
        if details.get("username") is not None:
            event["outcome"] = "success" if self._valid_credentials(details) else "failure"

    @staticmethod
    def _valid_credentials(details: dict) -> bool:
        return details.get("username") == "admin" and details.get("password") == "admin"

    def _token(self, details: dict) -> str | None:
        for item in details.get("cookie", "").split(";"):
            key, separator, value = item.strip().partition("=")
            if separator and key == "session":
                return value
        return None

    def _authenticated(self, details: dict) -> bool:
        token = self._token(details)
        if not token:
            return False
        now = self._clock()
        with self._lock:
            expiry = self._sessions.get(token, 0)
            if expiry <= now:
                self._sessions.pop(token, None)
                return False
            return True

    def _new_session(self) -> str:
        token = secrets.token_urlsafe(24)
        with self._lock:
            self._sessions[token] = self._clock() + SESSION_TTL
        return token

    @staticmethod
    def _response(status: HTTPStatus, body: str | bytes = b"", content_type="text/html; charset=utf-8", headers=()) -> bytes:
        payload = body.encode() if isinstance(body, str) else body
        lines = [f"HTTP/1.1 {status.value} {status.phrase}", "Server: AsterView-Embedded/2.4", f"Content-Type: {content_type}", "Cache-Control: no-store", "X-Content-Type-Options: nosniff", f"Content-Length: {len(payload)}", "Connection: close"]
        lines.extend(f"{key}: {value}" for key, value in headers)
        return ("\r\n".join(lines) + "\r\n\r\n").encode() + payload

    def _challenge(self) -> bytes:
        body = login_page(False)
        return self._response(HTTPStatus.UNAUTHORIZED, body, headers=(("WWW-Authenticate", 'Basic realm="AsterView Camera"'),))

    def _now(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    def _page(self, path: str) -> str:
        now = self._now()
        if path == "/live":
            details = info_table((("Camera", "Front Entrance"), ("Resolution", "1920 × 1080"), ("Frame Rate", "25 FPS"), ("Codec", "H.264"), ("Stream", "Main Stream"), ("Status", "Online")))
            body = f'<div class="heading"><h1>Live View</h1><a class="button secondary" href="/live">Refresh</a></div><div class="grid"><section class="panel"><div class="viewer"><img src="/snapshot" alt="Front Entrance camera preview"><div class="overlay"><span>CAM 01 · FRONT ENTRANCE</span><span class="rec">● REC</span></div></div></section><aside class="panel"><h1>Stream Information</h1>{details}<p class="muted">Device time: {now}</p></aside></div>'
        elif path == "/device":
            rows = (("Product Name", "AsterView Network Camera"), ("Model", "CV-210"), ("Firmware", "2.4.7"), ("Hardware", "CV210-R2"), ("Device Name", "Front Entrance"), ("Serial Number", "AV21-FC38-1042"), ("Hostname", "AV-CAM-01"), ("MAC Address", "02:41:56:21:10:42"), ("Video Standard", "PAL"), ("Timezone", "UTC+05:30"))
            body = f'<div class="heading"><h1>Device Information</h1></div><section class="panel">{info_table(rows)}</section>'
        elif path == "/network":
            rows = (("Mode", "Static"), ("IPv4 Address", "192.168.1.64"), ("Subnet Mask", "255.255.255.0"), ("Gateway", "192.168.1.1"), ("DNS", "192.168.1.1"), ("HTTP Port", "80"), ("RTSP Port", "554"))
            body = f'<div class="heading"><h1>Network Settings</h1></div><section class="panel">{info_table(rows)}<p class="muted">Settings are managed by the device administrator.</p></section>'
        elif path == "/maintenance":
            body = '<div class="heading"><h1>System Maintenance</h1></div><div class="cards"><section class="panel"><h1>Device Operations</h1><p class="muted">Manage startup and configuration tasks.</p><div class="actions"><button>Reboot Device</button><button class="secondary">Restore Settings</button></div></section><section class="panel"><h1>Configuration</h1><p>Export Configuration</p><p>System Log</p><p>Time Synchronization <span class="status">Synchronized</span></p></section></div>'
        else:
            rows = (("Current Firmware", "2.4.7"), ("Build Date", "2025-11-18"), ("Hardware Revision", "CV210-R2"), ("Firmware Status", "Up to date"))
            body = f'<div class="heading"><h1>Firmware</h1></div><section class="panel">{info_table(rows)}<form method="post" action="/firmware" enctype="multipart/form-data"><p><label>Firmware package <input type="file" name="firmware"></label></p><button>Upload Firmware</button></form><p class="muted">Packages must be signed for this hardware revision.</p></section>'
        return shell(path[1:].title(), path[1:], body, now)

    def _snapshot(self) -> bytes:
        stamp = self._now()
        svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="960" height="540" viewBox="0 0 960 540"><defs><linearGradient id="g" x2="0" y2="1"><stop stop-color="#182d3b"/><stop offset="1" stop-color="#060c12"/></linearGradient></defs><rect width="960" height="540" fill="url(#g)"/><path d="M0 390L180 270l120 72 180-170 210 205 100-75 170 114v124H0z" fill="#10202b"/><rect x="80" y="120" width="260" height="220" fill="#142937" stroke="#34566b"/><rect x="120" y="165" width="75" height="100" fill="#07141e"/><path d="M35 65h65M35 65v65M925 65h-65M925 65v65M35 475h65M35 475v-65M925 475h-65M925 475v-65" stroke="#54cce0" stroke-width="3"/><g fill="#e8f5fa" font-family="monospace"><text x="35" y="38" font-size="19">CAM 01  FRONT ENTRANCE</text><text x="35" y="515" font-size="17">1920x1080  H.264  {stamp}</text><text x="840" y="38" font-size="19" fill="#ff6570">● REC</text></g></svg>'''
        return self._response(HTTPStatus.OK, svg, "image/svg+xml")

    def response(self, details: dict) -> bytes:
        path, method = details["path"], details["method"].upper()
        if path in ("/", "/login") and method == "GET" and not details.get("basic_supplied"):
            return self._response(HTTPStatus.OK, login_page(False))
        if path == "/login" and details.get("username") is not None:
            if self._valid_credentials(details):
                token = self._new_session()
                return self._response(HTTPStatus.FOUND, headers=(("Location", "/live"), ("Set-Cookie", f"session={token}; Max-Age={SESSION_TTL}; HttpOnly; SameSite=Lax; Path=/")))
            return self._response(HTTPStatus.UNAUTHORIZED, login_page(True), headers=(("WWW-Authenticate", 'Basic realm="AsterView Camera"'),))
        if path == "/logout":
            token = self._token(details)
            with self._lock:
                self._sessions.pop(token, None)
            return self._response(HTTPStatus.FOUND, headers=(("Location", "/login"), ("Set-Cookie", "session=; Max-Age=0; HttpOnly; SameSite=Lax; Path=/")))
        if not self._authenticated(details):
            return self._challenge()
        if path == "/status":
            payload = json.dumps({"device": "CV-210", "status": "online", "recording": True, "stream": "main", "uptime": int(self._clock() - self._started), "sessions": len(self._sessions)}, separators=(",", ":"))
            return self._response(HTTPStatus.OK, payload, "application/json")
        if path == "/snapshot":
            return self._snapshot()
        if path == "/stream":
            return self._response(HTTPStatus.SERVICE_UNAVAILABLE, '{"status":"temporarily_unavailable","viewer":"/live"}', "application/json", (("Retry-After", "10"),))
        if path == "/firmware" and method != "GET":
            return self._response(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "Firmware package rejected: signature verification failed.", "text/plain; charset=utf-8")
        if path in ("/live", "/device", "/network", "/maintenance", "/firmware"):
            return self._response(HTTPStatus.OK, self._page(path))
        return self._response(HTTPStatus.NOT_FOUND, "Resource not found.", "text/plain; charset=utf-8")
