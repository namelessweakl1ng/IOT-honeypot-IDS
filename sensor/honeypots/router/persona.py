"""High-fidelity, safely simulated Nexora NR-1800 router persona."""

# ruff: noqa: E501 -- embedded device markup and stable synthetic tables are intentionally contiguous.

import json
import secrets
import threading
import time
from datetime import datetime, timezone
from http import HTTPStatus

from common.protocols import add_http_fields, http_details

from router.pages import device_table, login_page, shell, table

SESSION_TTL = 30 * 60
MAX_SESSIONS = 128

CLIENTS = (
    ("Device", "Type", "LAN IP", "MAC Address", "Connection", "Signal", "Lease"),
    ("home-laptop", "Laptop", "192.168.0.118", "02:52:18:30:11:8A", "Wi-Fi 5 GHz", "-48 dBm", "21h 14m"),
    ("phone-01", "Phone", "192.168.0.111", "02:31:74:20:65:11", "Wi-Fi 5 GHz", "-55 dBm", "17h 42m"),
    ("living-room-tv", "Smart TV", "192.168.0.104", "02:18:42:64:10:04", "Ethernet", "—", "19h 08m"),
    ("family-tablet", "Tablet", "192.168.0.121", "02:27:63:40:12:1B", "Wi-Fi 2.4 GHz", "-61 dBm", "12h 35m"),
    ("camera-front", "IP Camera", "192.168.0.126", "02:41:56:21:10:7E", "Wi-Fi 2.4 GHz", "-67 dBm", "22h 51m"),
    ("kitchen-speaker", "Smart Speaker", "192.168.0.132", "02:66:28:15:09:84", "Wi-Fi 2.4 GHz", "-58 dBm", "15h 03m"),
)


class RouterPersona:
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

    @staticmethod
    def _token(details: dict) -> str | None:
        for item in details.get("cookie", "").split(";"):
            key, separator, value = item.strip().partition("=")
            if separator and key == "session":
                return value
        return None

    def _purge_expired_sessions(self, now: float) -> None:
        for token in [token for token, expiry in self._sessions.items() if expiry <= now]:
            del self._sessions[token]

    def _authenticated(self, details: dict) -> bool:
        token = self._token(details)
        if not token:
            return False
        with self._lock:
            now = self._clock()
            self._purge_expired_sessions(now)
            return token in self._sessions

    def _new_session(self) -> str:
        token = secrets.token_urlsafe(24)
        with self._lock:
            now = self._clock()
            self._purge_expired_sessions(now)
            if len(self._sessions) >= MAX_SESSIONS:
                del self._sessions[min(self._sessions, key=self._sessions.get)]
            self._sessions[token] = now + SESSION_TTL
        return token

    @staticmethod
    def _response(status: HTTPStatus, body: str | bytes = b"", content_type="text/html; charset=utf-8", headers=()) -> bytes:
        payload = body.encode() if isinstance(body, str) else body
        lines = [f"HTTP/1.1 {status.value} {status.phrase}", "Server: Nexora-Web/1.8", f"Content-Type: {content_type}", "Cache-Control: no-store", "X-Content-Type-Options: nosniff", f"Content-Length: {len(payload)}", "Connection: close"]
        lines.extend(f"{key}: {value}" for key, value in headers)
        return ("\r\n".join(lines) + "\r\n\r\n").encode() + payload

    def _challenge(self) -> bytes:
        return self._response(HTTPStatus.UNAUTHORIZED, login_page(False), headers=(("WWW-Authenticate", 'Basic realm="Nexora Router"'),))

    def _now(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    def _uptime(self) -> int:
        return max(0, int(self._clock() - self._started))

    def _page(self, path: str, message: str = "") -> str:
        notice = f'<div class="notice">{message}</div>' if message else ""
        if path == "/dashboard":
            body = f'''<h1>Dashboard</h1>{notice}<div class="cards"><div class="card">Internet Status<b class="status">Connected</b></div><div class="card">WAN Address<b>198.51.100.24</b></div><div class="card">Connected Devices<b>6</b></div></div><div class="grid"><section class="panel"><h2>Internet</h2><div class="inside">{table((("Connection Type", "DHCP"), ("Gateway", "198.51.100.1"), ("Lease Time", "18h 42m")))}</div></section><section class="panel"><h2>Local Network</h2><div class="inside">{table((("LAN Address", "192.168.0.1"), ("Wi-Fi 2.4 GHz", "Enabled"), ("Wi-Fi 5 GHz", "Enabled"), ("Uptime", f"{self._uptime()} seconds"), ("Firmware", "1.8.3")))}</div></section></div>'''
        elif path == "/internet":
            body = '<h1>Internet / WAN</h1><section class="panel"><h2>IPv4 Connection</h2><div class="inside">' + table((("Connection Type", "DHCP"), ("Status", "Connected"), ("WAN IPv4", "198.51.100.24"), ("Gateway", "198.51.100.1"), ("DNS 1", "203.0.113.53"), ("DNS 2", "203.0.113.54"), ("MTU", "1500"), ("Lease Time", "18h 42m"))) + "</div></section>"
        elif path == "/lan":
            body = '<h1>LAN Settings</h1><section class="panel"><h2>Local Network</h2><div class="inside">' + table((("Router Address", "192.168.0.1"), ("Subnet Mask", "255.255.255.0"), ("DHCP Server", "Enabled"), ("DHCP Start", "192.168.0.100"), ("DHCP End", "192.168.0.199"), ("Lease Time", "24 hours"))) + "</div></section>"
        elif path == "/wifi":
            radio24 = table((("SSID", "NexoraHome"), ("Status", "Enabled"), ("Channel", "6"), ("Bandwidth", "20 MHz"), ("Security", "WPA2-Personal"), ("Network Key", "••••••••••••")))
            radio5 = table((("SSID", "NexoraHome_5G"), ("Status", "Enabled"), ("Channel", "44"), ("Bandwidth", "80 MHz"), ("Security", "WPA2/WPA3-Personal"), ("Network Key", "••••••••••••")))
            body = f'<h1>Wireless Settings</h1><div class="grid"><section class="panel"><h2>2.4 GHz Radio</h2><div class="inside">{radio24}</div></section><section class="panel"><h2>5 GHz Radio</h2><div class="inside">{radio5}</div></section></div>'
        elif path == "/dhcp":
            rows = (("Device", "IP Address", "MAC Address", "Lease Remaining"),) + tuple((row[0], row[2], row[3], row[6]) for row in CLIENTS[1:])
            body = f'<h1>DHCP Server</h1><section class="panel"><h2>Active Leases</h2><div class="inside">{device_table(rows)}</div></section>'
        elif path == "/clients":
            body = f'<h1>Connected Devices</h1><section class="panel"><h2>6 Active Clients</h2><div class="inside">{device_table(CLIENTS)}</div></section>'
        elif path == "/network":
            body = '<h1>Network Overview</h1><div class="grid"><section class="panel"><h2>WAN</h2><div class="inside">' + table((("Status", "Connected"), ("Address", "198.51.100.24"), ("DNS", "203.0.113.53, 203.0.113.54"))) + '</div></section><section class="panel"><h2>LAN &amp; Wireless</h2><div class="inside">' + table((("Router", "192.168.0.1/24"), ("DHCP", "Enabled · 100–199"), ("2.4 GHz", "NexoraHome · Channel 6"), ("5 GHz", "NexoraHome_5G · Channel 44"))) + "</div></section></div>"
        elif path == "/system":
            identity = table((("Product", "Nexora Wireless Router"), ("Model", "NR-1800"), ("Firmware", "1.8.3"), ("Hardware", "NR18-R3"), ("Hostname", "NEXORA-GW"), ("Serial", "NX18-74A2-0184"), ("LAN MAC", "02:18:00:74:A2:18"), ("WAN MAC", "02:18:00:74:A2:19"), ("System Time", self._now()), ("Uptime", f"{self._uptime()} seconds")))
            body = f'''<h1>System</h1>{notice}<section class="panel"><h2>Device Information</h2><div class="inside">{identity}</div></section><section class="panel"><h2>System Operations</h2><div class="inside actions"><form method="post" action="/system/reboot"><button>Reboot</button></form><form method="post" action="/system/restore"><button class="secondary">Restore Defaults</button></form><a class="button secondary" href="/system/export">Export Configuration</a></div></section>'''
        elif path == "/firmware":
            body = f'''<h1>Firmware Update</h1>{notice}<section class="panel"><h2>Installed Firmware</h2><div class="inside">{table((("Current Version", "1.8.3"), ("Build Date", "2026-04-16"), ("Hardware Revision", "NR18-R3"), ("Update Status", "No update pending")))}<form method="post" action="/firmware" enctype="multipart/form-data"><p><label>Firmware image &nbsp; <input type="file" name="firmware"></label></p><button>Validate and Update</button></form></div></section>'''
        else:
            rows = (("Time", "Level", "Event"), ("08:01:12", "Info", "WAN link established"), ("08:01:14", "Info", "NTP synchronization completed"), ("08:16:42", "Info", "DHCP lease issued to living-room-tv"), ("09:03:08", "Info", "Wireless client connected on 5 GHz"), ("09:17:31", "Info", "Configuration login successful"))
            body = f'<h1>System Log</h1><section class="panel"><h2>Recent Events</h2><div class="inside">{device_table(rows)}</div></section>'
        return shell(path.strip("/").replace("network", "Network Overview").title(), path.strip("/"), body, self._now())

    def response(self, details: dict) -> bytes:
        path, method = details["path"], details["method"].upper()
        if path in ("/", "/login") and method == "GET" and not details.get("basic_supplied"):
            return self._response(HTTPStatus.OK, login_page(False))
        if path == "/login" and details.get("username") is not None:
            if self._valid_credentials(details):
                token = self._new_session()
                cookie = f"session={token}; Max-Age={SESSION_TTL}; HttpOnly; SameSite=Lax; Path=/"
                return self._response(HTTPStatus.FOUND, headers=(("Location", "/dashboard"), ("Set-Cookie", cookie)))
            return self._response(HTTPStatus.UNAUTHORIZED, login_page(True), headers=(("WWW-Authenticate", 'Basic realm="Nexora Router"'),))
        if path == "/logout":
            token = self._token(details)
            with self._lock:
                self._sessions.pop(token, None)
            return self._response(HTTPStatus.FOUND, headers=(("Location", "/login"), ("Set-Cookie", "session=; Max-Age=0; HttpOnly; SameSite=Lax; Path=/")))
        if path == "/status":
            payload = json.dumps({"model": "NR-1800", "status": "online", "internet": "connected", "uptime": self._uptime(), "clients": 6}, separators=(",", ":"))
            return self._response(HTTPStatus.OK, payload, "application/json")
        if path in ("/network", "/system") and method == "GET":
            return self._response(HTTPStatus.OK, self._page(path))
        if not self._authenticated(details):
            return self._challenge()
        if path == "/firmware" and method == "POST":
            return self._response(HTTPStatus.UNPROCESSABLE_ENTITY, self._page(path, "Firmware validation failed. The image was not accepted."))
        if path == "/system/reboot" and method == "POST":
            return self._response(HTTPStatus.OK, self._page("/system", "Restart scheduled. Device will be available shortly."))
        if path == "/system/restore" and method == "POST":
            return self._response(HTTPStatus.OK, self._page("/system", "Restore request recorded. No settings were changed."))
        if path == "/system/export" and method == "GET":
            config = "NEXORA-CONFIG\nmodel=NR-1800\nlan_address=192.168.0.1\ndhcp=enabled\n"
            return self._response(HTTPStatus.OK, config, "text/plain; charset=utf-8", (("Content-Disposition", 'attachment; filename="nr1800-config.txt"'),))
        if path in ("/dashboard", "/internet", "/lan", "/wifi", "/dhcp", "/clients", "/firmware", "/logs") and method == "GET":
            return self._response(HTTPStatus.OK, self._page(path))
        return self._response(HTTPStatus.NOT_FOUND, "Resource not found.", "text/plain; charset=utf-8")
