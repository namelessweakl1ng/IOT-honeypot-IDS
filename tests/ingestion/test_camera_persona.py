import json
import re
import sys
from base64 import b64encode
from pathlib import Path

import pytest

from backend.app.services.detector import detect

sys.path.insert(0, str(Path("sensor/honeypots").resolve()))

from camera.persona import MAX_SESSIONS, SESSION_TTL, CameraPersona
from common.telemetry import base_event


def request(persona, path="/", method="GET", headers=None, body=""):
    headers = headers or {}
    raw_headers = "".join(f"{key}: {value}\r\n" for key, value in headers.items())
    details = persona.parse(f"{method} {path} HTTP/1.1\r\nHost: camera\r\n{raw_headers}\r\n{body}".encode())
    return details, persona.response(details)


def status(response):
    return int(response.split(b" ", 2)[1])


def body(response):
    return response.partition(b"\r\n\r\n")[2]


def login(persona):
    _, response = request(persona, "/login", "POST", body="username=admin&password=admin")
    token = re.search(rb"Set-Cookie: session=([^;]+)", response).group(1).decode()
    return token, response


@pytest.mark.parametrize("path", ["/", "/login"])
def test_public_login_routes_present_fictional_identity(path):
    _, response = request(CameraPersona(), path)
    assert status(response) == 200
    assert b"AsterView" in response and b"CV-210" in response


@pytest.mark.parametrize("path", ["/live", "/status", "/snapshot", "/stream", "/device", "/network", "/maintenance", "/firmware"])
def test_protected_camera_routes_require_authentication(path):
    _, response = request(CameraPersona(), path)
    assert status(response) == 401
    assert b'Basic realm="AsterView Camera"' in response


def test_form_login_session_routes_and_logout():
    persona = CameraPersona()
    token, response = login(persona)
    assert status(response) == 302 and b"Location: /live" in response
    assert b"HttpOnly; SameSite=Lax; Path=/" in response
    headers = {"Cookie": f"session={token}"}

    expected = {
        "/live": b"Front Entrance",
        "/status": b'"device":"CV-210"',
        "/snapshot": b"image/svg+xml",
        "/stream": b"temporarily_unavailable",
        "/device": b"CV210-R2",
        "/network": b"192.168.1.64",
        "/maintenance": b"Reboot Device",
        "/firmware": b"Current Firmware",
    }
    for path, marker in expected.items():
        _, result = request(persona, path, headers=headers)
        assert status(result) in (200, 503)
        assert marker in result

    _, logout = request(persona, "/logout", headers=headers)
    assert status(logout) == 302 and b"Max-Age=0" in logout
    assert status(request(persona, "/live", headers=headers)[1]) == 401


def test_invalid_and_expired_sessions_are_rejected():
    current = [100.0]
    persona = CameraPersona(clock=lambda: current[0])
    assert status(request(persona, "/live", headers={"Cookie": "session=invalid"})[1]) == 401
    token, _ = login(persona)
    current[0] += 1801
    assert status(request(persona, "/live", headers={"Cookie": f"session={token}"})[1]) == 401


def test_new_session_purges_all_expired_sessions():
    current = [100.0]
    persona = CameraPersona(clock=lambda: current[0])
    old_tokens = {login(persona)[0] for _ in range(3)}

    current[0] += SESSION_TTL + 1
    new_token, response = login(persona)

    assert status(response) == 302
    assert persona._sessions == {new_token: current[0] + SESSION_TTL}
    assert old_tokens.isdisjoint(persona._sessions)


def test_sessions_are_bounded_without_rejecting_valid_logins():
    persona = CameraPersona(clock=lambda: 100.0)

    tokens = [login(persona)[0] for _ in range(MAX_SESSIONS + 1)]

    assert len(persona._sessions) <= MAX_SESSIONS
    assert tokens[-1] in persona._sessions


def test_status_counts_only_active_sessions():
    current = [100.0]
    persona = CameraPersona(clock=lambda: current[0])
    login(persona)
    login(persona)
    current[0] += 1
    active_token, _ = login(persona)
    current[0] += SESSION_TTL - 1

    _, response = request(persona, "/status", headers={"Cookie": f"session={active_token}"})

    assert status(response) == 200
    assert json.loads(body(response))["sessions"] == 1
    assert len(persona._sessions) == 1


def test_basic_auth_success_failure_and_malformed_input():
    persona = CameraPersona()
    good = b64encode(b"admin:admin").decode()
    bad = b64encode(b"admin:wrong").decode()
    details, success = request(persona, "/login", headers={"Authorization": f"Basic {good}"})
    assert status(success) == 302
    event = base_event("camera", "http", 8081, ("192.0.2.1", 1234), details)
    persona.enrich(event, details)
    assert event["outcome"] == "success"
    assert event["authentication"] == {"username": "admin", "password": "admin"}
    assert event["service"] == "camera" and event["honeypot_id"] == "camera-01"

    details, failure = request(persona, "/login", headers={"Authorization": f"Basic {bad}"})
    event = base_event("camera", "http", 8081, ("192.0.2.1", 1234), details)
    persona.enrich(event, details)
    assert status(failure) == 401 and event["outcome"] == "failure"
    assert event["url"]["path"] == "/login" and event["http"]["request"]["method"] == "GET"

    details, malformed = request(persona, "/login", headers={"Authorization": "Basic !!!not-base64!!!"})
    assert status(malformed) == 401
    assert details["username"] is None


def test_failed_form_authentication_telemetry():
    persona = CameraPersona()
    details, response = request(persona, "/login", "POST", body="username=viewer&password=guess")
    event = base_event("camera", "http", 8081, ("192.0.2.1", 1234), details)
    persona.enrich(event, details)
    assert status(response) == 401
    assert event["category"] == "authentication" and event["action"] == "login_attempt"
    assert event["outcome"] == "failure"
    assert event["authentication"] == {"username": "viewer", "password": "guess"}


def test_all_camera_responses_hide_internal_identity():
    persona = CameraPersona()
    token, login_response = login(persona)
    private_paths = ("/live", "/status", "/snapshot", "/stream", "/device", "/network", "/maintenance", "/firmware")
    responses = [request(persona, path, headers={"Cookie": f"session={token}"})[1] for path in private_paths]
    responses.extend((request(persona, "/")[1], login_response))
    forbidden = (b"trapsig", b"honeypot", b"decoy")
    for response in responses:
        lowered = response.lower()
        assert all(word not in lowered for word in forbidden)


def test_recon_paths_and_default_credentials_remain_detector_compatible():
    persona = CameraPersona()
    paths = ["/", "/status", "/snapshot", "/stream"]
    recorded = [persona.parse(f"GET {path} HTTP/1.1\r\n\r\n".encode())["path"] for path in paths]
    assert recorded == paths

    normalized = {"event": {"id": "one", "category": "authentication", "outcome": "success"}, "authentication": {"username": "admin", "password": "admin"}}
    session = {
        "session_id": "camera",
        "end_time": "2026-01-01T00:00:00Z",
        "event_ids": ["one"],
        "events": [normalized],
        "services_touched": ["camera"],
        "commands": [],
        "urls": recorded,
    }
    kinds = {item["type"] for item in detect(session)}
    assert {"DEFAULT_CREDENTIALS", "WEB_ENUMERATION"} <= kinds


def test_status_is_compact_json_with_dynamic_uptime():
    current = [10.0]
    persona = CameraPersona(clock=lambda: current[0])
    token, _ = login(persona)
    current[0] += 42
    _, response = request(persona, "/status", headers={"Cookie": f"session={token}"})
    assert json.loads(body(response))["uptime"] == 42


def test_firmware_submission_is_safely_rejected():
    persona = CameraPersona()
    token, _ = login(persona)
    _, response = request(persona, "/firmware", "POST", {"Cookie": f"session={token}"}, "untrusted bytes")
    assert status(response) == 415
