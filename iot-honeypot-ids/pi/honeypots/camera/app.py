"""
Camera HTTP honeypot — simulates a cheap network camera / DVR.

Records every request as a structured JSON event into /var/log/camera/camera.jsonl.
Filebeat on the Pi tails that file and ships events to PC1 Logstash.

Endpoints mimic a believable but cheap IP camera / DVR:
  /  /login  /admin  /config  /system  /status  /network  /users
  /device  /firmware  /snapshot  /video  /api/  /health

The interface looks believable externally but it is unambiguously a honeypot
internally: no real credentials are stored, no real video exists, and any
"authentication success" is purely simulated.
"""
from __future__ import annotations

import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask, Response, jsonify, request

# --------------------------------------------------------------------------- #
# Config (env-driven)
# --------------------------------------------------------------------------- #
DEVICE_ID = os.environ.get("DEVICE_ID", "camera-01")
HOSTNAME = os.environ.get("HOSTNAME", "iot-bridge-01")
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
LOG_PATH = os.environ.get("CAMERA_LOG_PATH", "/var/log/camera/camera.jsonl")

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s %(levelname)s %(name)s | %(message)s",
)
log = logging.getLogger("camera")

# --------------------------------------------------------------------------- #
# App
# --------------------------------------------------------------------------- #
app = Flask(__name__)

# Track simple sessions per source IP for telemetry richness.
SESSIONS: dict[str, dict[str, Any]] = {}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _session_id_for(src_ip: str) -> str:
    """Return a session id for the source IP.

    A new session is started if the previous one for that IP has been idle
    for more than SESSION_IDLE_SECONDS.
    """
    SESSION_IDLE_SECONDS = 300
    now = time.time()
    sess = SESSIONS.get(src_ip)
    if sess is None or (now - sess["last_seen"]) > SESSION_IDLE_SECONDS:
        sess = {
            "id": str(uuid.uuid4()),
            "started_at": _now_iso(),
            "last_seen": now,
            "requests": 0,
        }
        SESSIONS[src_ip] = sess
    sess["last_seen"] = now
    sess["requests"] += 1
    return sess["id"]


def _log_event(payload: dict[str, Any]) -> None:
    """Append a structured event to the JSONL log."""
    try:
        Path(LOG_PATH).parent.mkdir(parents=True, exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, ensure_ascii=False) + "\n")
    except Exception as exc:  # never crash the honeypot on logging errors
        log.error("failed to write event: %s", exc)


def _record(
    *,
    method: str,
    path: str,
    status: int,
    body_preview: str | None = None,
    note: str | None = None,
) -> None:
    """Record a request as a structured JSON event."""
    src_ip = request.remote_addr or "0.0.0.0"
    src_port = request.environ.get("REMOTE_PORT")
    session_id = _session_id_for(src_ip)

    auth_user = None
    auth_attempted = False
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Basic "):
        auth_attempted = True
        # Intentionally never store the password. We only record that an
        # attempt happened and which username (decoded for telemetry only).
        try:
            import base64

            decoded = base64.b64decode(auth_header[6:]).decode("utf-8", "ignore")
            auth_user = decoded.split(":", 1)[0] if ":" in decoded else decoded
        except Exception:
            auth_user = "<malformed>"

    payload_size = request.content_length or 0

    event = {
        "@timestamp": _now_iso(),
        "event_id": str(uuid.uuid4()),
        "session_id": session_id,
        "device": {
            "id": DEVICE_ID,
            "type": "camera",
            "hostname": HOSTNAME,
            "container": "pi-camera",
        },
        "protocol": "http",
        "source": {"ip": src_ip, "port": int(src_port) if src_port else 0},
        "destination": {"ip": "0.0.0.0", "port": 8080},
        "http": {
            "method": method,
            "uri": path,
            "status": status,
            "user_agent": request.headers.get("User-Agent", ""),
            "bytes_in": payload_size,
            "bytes_out": 0,
            "headers": {
                "authorization": "<redacted>" if auth_attempted else None,
                "content_type": request.headers.get("Content-Type"),
                "accept": request.headers.get("Accept"),
            },
        },
        "authentication": {
            "attempted": auth_attempted,
            "username": auth_user,
            "success": False,  # default — overridden on /login POST
        },
        "honeypot": {"name": "camera", "container": "pi-camera"},
        "event": {
            "type": "http_request",
            "category": "network",
            "action": f"{method.lower()}_{path.strip('/').lower() or 'root'}",
        },
        "attack": {
            "session_id": session_id,
            "stage": None,
            "classification": None,
            "confidence": 0.0,
        },
    }

    if body_preview:
        event["http"]["body_preview"] = body_preview[:512]
    if note:
        event["event"]["note"] = note

    # Simple rule-engine enrichment — these tags help the rule engine on PC1.
    uri_lower = path.lower()
    if "admin" in uri_lower or "config" in uri_lower:
        event["event"]["category"] = "discovery"
        event["attack"]["stage"] = "reconnaissance"
    if "login" in uri_lower and method == "POST":
        event["event"]["category"] = "authentication"
        event["attack"]["stage"] = "credential_access"
    if ".." in path or "%2e%2e" in uri_lower:
        event["event"]["category"] = "intrusion_attempt"
        event["attack"]["stage"] = "path_traversal"
        event["attack"]["classification"] = "path_traversal"
        event["attack"]["confidence"] = 0.8
    if "exec" in uri_lower or "shell" in uri_lower:
        event["event"]["category"] = "intrusion_attempt"
        event["attack"]["stage"] = "execution"
        event["attack"]["classification"] = "command_injection"
        event["attack"]["confidence"] = 0.7

    _log_event(event)


# --------------------------------------------------------------------------- #
# Routes — every endpoint records telemetry then returns a believable response.
# --------------------------------------------------------------------------- #
HTML_INDEX = """<!doctype html>
<html>
<head><title>IP Camera</title><meta name='viewport' content='width=device-width,initial-scale=1'></head>
<body style='font-family:sans-serif'>
<h2>IPCAM-{device}</h2>
<p>Web Interface</p>
<form method='POST' action='/login'>
  User: <input name='user'><br>
  Pass: <input name='pass' type='password'><br>
  <button>Sign in</button>
</form>
</body></html>
""".replace("{device}", DEVICE_ID)


@app.route("/")
def index():
    _record(method="GET", path="/", status=200)
    return HTML_INDEX


@app.route("/health")
def health():
    """Used by Docker healthcheck."""
    return jsonify({"status": "ok", "device": DEVICE_ID})


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        _record(method="GET", path="/login", status=200)
        return HTML_INDEX
    # POST — pretend to accept some credentials, record the attempt.
    form = request.form or {}
    user = form.get("user", "")
    pwd = form.get("pass", "")
    # Fake "weak default" credentials that succeed on cheap cameras.
    accepted = (user, pwd) in {("admin", "admin"), ("admin", "12345"), ("root", "root")}
    body_preview = f"user={user}&pass=<redacted>"
    _record(
        method="POST",
        path="/login",
        status=302 if accepted else 401,
        body_preview=body_preview,
        note="login_attempt",
    )
    # The last event recorded has success=False by default; re-emit with truth.
    if accepted:
        # Append a success event so PC1 has a clean signal.
        _log_event({
            "@timestamp": _now_iso(),
            "event_id": str(uuid.uuid4()),
            "session_id": SESSIONS.get(request.remote_addr, {}).get("id"),
            "device": {"id": DEVICE_ID, "type": "camera", "hostname": HOSTNAME, "container": "pi-camera"},
            "protocol": "http",
            "source": {"ip": request.remote_addr, "port": 0},
            "destination": {"ip": "0.0.0.0", "port": 8080},
            "authentication": {"attempted": True, "username": user, "success": True},
            "event": {"type": "authentication_success", "category": "authentication", "action": "login_success"},
            "honeypot": {"name": "camera", "container": "pi-camera"},
            "attack": {"session_id": SESSIONS.get(request.remote_addr, {}).get("id"), "stage": "initial_access", "classification": "default_credentials", "confidence": 0.9},
        })
        return Response("Redirecting...", 302, headers={"Location": "/admin"})
    return Response("Unauthorized", 401)


@app.route("/admin")
def admin():
    _record(method="GET", path="/admin", status=200)
    return "<html><body><h2>Admin Console</h2><p>System settings</p><a href='/config'>config</a></body></html>"


@app.route("/config")
def config():
    _record(method="GET", path="/config", status=200)
    return jsonify({"device": DEVICE_ID, "ip": "0.0.0.0", "gateway": "0.0.0.0", "dns": "8.8.8.8"})


@app.route("/system")
def system():
    _record(method="GET", path="/system", status=200)
    return jsonify({"hostname": HOSTNAME, "uptime_s": 123456, "fw": "1.0.4-iot"})


@app.route("/status")
def status():
    _record(method="GET", path="/status", status=200)
    return jsonify({"cpu": 14, "mem_mb": 96, "temp_c": 41, "sd_free_mb": 512})


@app.route("/network")
def network():
    _record(method="GET", path="/network", status=200)
    return jsonify({"ssid": "<redacted>", "ip": "0.0.0.0", "mac": "00:11:22:33:44:55"})


@app.route("/users")
def users():
    _record(method="GET", path="/users", status=200)
    return jsonify({"users": ["admin", "operator"]})


@app.route("/device")
def device():
    _record(method="GET", path="/device", status=200)
    return jsonify({"model": "IPCAM-X100", "vendor": "Generic", "fw": "1.0.4"})


@app.route("/firmware")
def firmware():
    _record(method="GET", path="/firmware", status=200)
    return jsonify({"version": "1.0.4-iot", "build": "20240101", "channel": "stable"})


@app.route("/snapshot")
def snapshot():
    _record(method="GET", path="/snapshot", status=200)
    # Return a single 1x1 transparent PNG so crawlers get *something*.
    transparent_png = bytes.fromhex(
        "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4"
        "890000000d49444154789c63000100000005000100"
        "0d0a2db4000000004945"
        "4e44ae426082"
    )
    return Response(transparent_png, mimetype="image/png")


@app.route("/video")
def video():
    _record(method="GET", path="/video", status=200)
    return Response("stream unavailable", 200, mimetype="text/plain")


@app.route("/api/<path:subpath>")
def api_catchall(subpath: str):
    _record(method="GET", path=f"/api/{subpath}", status=200)
    return jsonify({"ok": True, "endpoint": subpath, "device": DEVICE_ID})


@app.route("/<path:catchall>", methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"])
def catchall(catchall: str):
    """Catch-all so every probe is recorded, even unknown endpoints."""
    _record(
        method=request.method,
        path=f"/{catchall}",
        status=200,
        body_preview=request.get_data(as_text=True)[:512] if request.data else None,
    )
    return Response("ok", 200)


@app.errorhandler(404)
def not_found(e):  # noqa: ANN001
    _record(method=request.method, path=request.path, status=404)
    return Response("Not Found", 404)


if __name__ == "__main__":
    log.info("starting camera honeypot device_id=%s hostname=%s", DEVICE_ID, HOSTNAME)
    # Flask dev server is fine for honeypot telemetry on the Pi — it is light
    # enough and we do not need production concurrency here.
    app.run(host="0.0.0.0", port=8080, threaded=True)
