import json
import re
import sys
from base64 import b64encode
from pathlib import Path

import pytest

from backend.app.services.detector import detect

sys.path.insert(0, str(Path("sensor/honeypots").resolve()))

from common.telemetry import base_event
from router.persona import MAX_SESSIONS, SESSION_TTL, RouterPersona


def request(persona, path="/", method="GET", headers=None, body=""):
    headers = headers or {}
    raw_headers = "".join(f"{key}: {value}\r\n" for key, value in headers.items())
    details = persona.parse(f"{method} {path} HTTP/1.1\r\nHost: router\r\n{raw_headers}\r\n{body}".encode())
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
def test_public_login_routes_present_nexora_identity_without_project_fingerprints(path):
    _, response = request(RouterPersona(), path)
    assert status(response) == 200
    assert b"Nexora" in response and b"NR-1800" in response
    assert all(value not in response.lower() for value in (b"trapsig", b"honeypot", b"decoy", b"research"))


def test_form_login_session_access_and_logout():
    persona = RouterPersona()
    token, response = login(persona)
    assert status(response) == 302 and b"Location: /dashboard" in response
    assert b"HttpOnly; SameSite=Lax; Path=/" in response
    headers = {"Cookie": f"session={token}"}
    assert status(request(persona, "/dashboard", headers=headers)[1]) == 200

    _, logout = request(persona, "/logout", headers=headers)
    assert status(logout) == 302 and b"Max-Age=0" in logout
    assert status(request(persona, "/dashboard", headers=headers)[1]) == 401


def test_basic_auth_success_failure_and_telemetry_contract():
    persona = RouterPersona()
    good = b64encode(b"admin:admin").decode()
    bad = b64encode(b"admin:wrong").decode()

    details, success = request(persona, "/login", headers={"Authorization": f"Basic {good}", "User-Agent": "scenario-runner"})
    event = base_event("router", "http", 8080, ("192.0.2.4", 31337), details)
    persona.enrich(event, details)
    assert status(success) == 302
    assert event["category"] == "authentication" and event["action"] == "login_attempt"
    assert event["outcome"] == "success"
    assert event["authentication"] == {"username": "admin", "password": "admin"}
    assert event["http"] == {"request": {"method": "GET"}, "user_agent": "scenario-runner"}
    assert event["url"]["path"] == "/login"
    assert event["service"] == "router" and event["honeypot_id"] == "router-01"

    details, failure = request(persona, "/login", headers={"Authorization": f"Basic {bad}"})
    event = base_event("router", "http", 8080, ("192.0.2.4", 31337), details)
    persona.enrich(event, details)
    assert status(failure) == 401 and event["outcome"] == "failure"
    assert b'Basic realm="Nexora Router"' in failure


def test_failed_form_authentication_records_failure():
    persona = RouterPersona()
    details, response = request(persona, "/login", "POST", body="username=admin&password=nope")
    event = base_event("router", "http", 8080, ("192.0.2.4", 31337), details)
    persona.enrich(event, details)
    assert status(response) == 401
    assert event["outcome"] == "failure"
    assert event["authentication"] == {"username": "admin", "password": "nope"}


def test_invalid_and_expired_sessions_are_rejected_and_purged():
    current = [100.0]
    persona = RouterPersona(clock=lambda: current[0])
    assert status(request(persona, "/dashboard", headers={"Cookie": "session=invalid"})[1]) == 401
    old_tokens = {login(persona)[0] for _ in range(3)}
    current[0] += SESSION_TTL + 1
    assert status(request(persona, "/dashboard", headers={"Cookie": f"session={next(iter(old_tokens))}"})[1]) == 401
    new_token, response = login(persona)
    assert status(response) == 302
    assert persona._sessions == {new_token: current[0] + SESSION_TTL}


def test_session_table_is_bounded_and_valid_login_succeeds_at_capacity():
    persona = RouterPersona(clock=lambda: 100.0)
    tokens = [login(persona)[0] for _ in range(MAX_SESSIONS + 1)]
    assert len(persona._sessions) == MAX_SESSIONS
    assert tokens[-1] in persona._sessions
    assert status(request(persona, "/dashboard", headers={"Cookie": f"session={tokens[-1]}"})[1]) == 200


def test_recon_routes_are_meaningful_and_distinct():
    persona = RouterPersona(clock=lambda: 42.0)
    responses = {path: request(persona, path)[1] for path in ("/", "/status", "/network", "/system")}
    assert all(status(response) == 200 for response in responses.values())
    assert json.loads(body(responses["/status"])) == {"model": "NR-1800", "status": "online", "internet": "connected", "uptime": 0, "clients": 6}
    assert b"Network Overview" in responses["/network"]
    assert b"NX18-74A2-0184" in responses["/system"]
    assert [persona.parse(f"GET {path} HTTP/1.1\r\n\r\n".encode())["path"] for path in responses] == list(responses)


def test_authenticated_router_pages_have_representative_content():
    persona = RouterPersona()
    token, _ = login(persona)
    headers = {"Cookie": f"session={token}"}
    markers = {
        "/dashboard": b"198.51.100.24",
        "/internet": b"203.0.113.53",
        "/lan": b"192.168.0.199",
        "/wifi": b"NexoraHome_5G",
        "/dhcp": b"living-room-tv",
        "/clients": b"Smart Speaker",
        "/firmware": b"NR18-R3",
        "/logs": b"WAN link established",
    }
    for path, marker in markers.items():
        response = request(persona, path, headers=headers)[1]
        assert status(response) == 200 and marker in response


def test_firmware_submission_is_safely_rejected():
    persona = RouterPersona()
    token, _ = login(persona)
    _, response = request(persona, "/firmware", "POST", {"Cookie": f"session={token}"}, "arbitrary bytes")
    assert status(response) == 422
    assert b"Firmware validation failed" in response


def test_every_representative_response_hides_internal_identity():
    persona = RouterPersona()
    token, login_response = login(persona)
    headers = {"Cookie": f"session={token}"}
    paths = ("/", "/login", "/status", "/network", "/system", "/dashboard", "/internet", "/lan", "/wifi", "/dhcp", "/clients", "/firmware", "/logs")
    responses = [request(persona, path, headers=headers)[1] for path in paths] + [login_response]
    forbidden = (b"trapsig", b"honeypot", b"decoy", b"research", b"controlled lab", b"python")
    assert all(all(word not in response.lower() for word in forbidden) for response in responses)


def test_existing_router_scenarios_remain_detector_compatible():
    paths = ["/", "/status", "/network", "/system"]
    normalized = {"event": {"id": "one", "category": "authentication", "outcome": "success"}, "authentication": {"username": "admin", "password": "admin"}}
    session = {
        "session_id": "router",
        "end_time": "2026-01-01T00:00:00Z",
        "event_ids": ["one"],
        "events": [normalized],
        "services_touched": ["router"],
        "commands": [],
        "urls": paths,
    }
    kinds = {item["type"] for item in detect(session)}
    assert {"DEFAULT_CREDENTIALS", "WEB_ENUMERATION"} <= kinds
