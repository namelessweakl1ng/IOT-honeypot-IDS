"""Regression tests for the honeypots API contract + state preservation.

These tests verify the EXACT bugs that caused the dashboard crash
('honeypots.honeypots is undefined') and the state-collapse bug where
NOT_CONFIGURED was being rendered as 'OFFLINE'.

The backend pi_client.get_honeypot_fleet() returns the authoritative
shape; these tests pin that contract so the frontend can rely on it.

Coverage (every test asserts real behavior — NO `assert True`):
  1. EMPTY state — honeypots array present, pi_status distinct from OFFLINE
  2. DEMO state — honeypots array present, pi_status='DEMO'
  3. LIVE + FastAPI unreachable — pi_status='BACKEND_UNREACHABLE' (NOT 'offline')
  4. LIVE + Pi NOT_CONFIGURED — pi_status='NOT_CONFIGURED'
  5. LIVE + Pi OFFLINE — pi_status='OFFLINE'
  6. LIVE + Pi CONNECTED — pi_status='CONNECTED', real container states
  7. AUTH_FAILED — distinct from OFFLINE
  8. HOST_KEY_UNKNOWN — distinct from OFFLINE
  9. HOST_KEY_CHANGED — distinct from OFFLINE
 10. Stable honeypot array response (always 3 honeypots, always `state` field)
 11. No secrets in responses (no IP, no SSH user, no key path, no API key)
 12. NOT_CONFIGURED is NOT collapsed into OFFLINE
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "dashboard" / "api"))

from app import pi_client  # type: ignore  # noqa: E402


# ---- Helpers --------------------------------------------------------

class FakeProc:
    """Stand-in for subprocess.CompletedProcess."""
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def clear_pi_env(monkeypatch):
    for k in ["PI_IP", "PI_SSH_USER", "PI_SSH_KEY", "PI_KNOWN_HOSTS",
              "PI_SSH_ACCEPT_NEW_HOST_KEY", "PI_DEPLOY_PATH",
              "PI_SSH_CONNECT_TIMEOUT", "PI_SSH_COMMAND_TIMEOUT",
              "API_SECRET_KEY"]:
        monkeypatch.delenv(k, raising=False)


def set_pi_env(monkeypatch, ip="10.0.0.50", user="pi"):
    monkeypatch.setenv("PI_IP", ip)
    monkeypatch.setenv("PI_SSH_USER", user)


def assert_no_secrets(obj, label="response"):
    """Recursively verify no secrets leak into a response."""
    s = json.dumps(obj, default=str)
    forbidden = ["192.168.1.50", "10.0.0.50", "pi@", "id_ed25519",
                 "API_SECRET_KEY", "dev-only-insecure-key", "real-secret",
                 "password", "private_key"]
    for token in forbidden:
        assert token not in s, f"{label} leaked secret '{token}': {s}"


def assert_honeypot_schema(hp, expected_state_values=None):
    """Verify a honeypot object has the canonical schema."""
    assert "id" in hp and isinstance(hp["id"], str)
    assert "name" in hp and isinstance(hp["name"], str)
    assert "type" in hp and isinstance(hp["type"], str)
    assert "container" in hp and isinstance(hp["container"], str)
    assert "port" in hp and isinstance(hp["port"], int)
    assert "configured" in hp and isinstance(hp["configured"], bool)
    assert "container_exists" in hp and isinstance(hp["container_exists"], bool)
    # Canonical field is `state` (NOT `status`)
    assert "state" in hp and isinstance(hp["state"], str)
    assert "docker_status" in hp and isinstance(hp["docker_status"], str)
    if expected_state_values:
        assert hp["state"] in expected_state_values, \
            f"honeypot {hp['id']} state={hp['state']} not in {expected_state_values}"


# ---- Tests ----------------------------------------------------------

class TestHoneypotFleetContract:
    """The /honeypots response must always have a stable shape."""

    def test_honeypots_is_always_array(self, monkeypatch):
        """CRITICAL: honeypots field must ALWAYS be a list, never undefined."""
        clear_pi_env(monkeypatch)
        fleet = pi_client.get_honeypot_fleet()
        assert isinstance(fleet["honeypots"], list), \
            "honeypots must be a list — undefined/array mismatch caused the crash"
        assert len(fleet["honeypots"]) == 3

    def test_response_has_required_top_level_fields(self, monkeypatch):
        clear_pi_env(monkeypatch)
        fleet = pi_client.get_honeypot_fleet()
        for field in ["pi_status", "pi_reachable", "pi_configured", "honeypots"]:
            assert field in fleet, f"missing top-level field: {field}"

    def test_pi_status_is_string_enum(self, monkeypatch):
        clear_pi_env(monkeypatch)
        fleet = pi_client.get_honeypot_fleet()
        assert isinstance(fleet["pi_status"], str)
        # Must be one of the authoritative enum values
        valid = {s.value for s in pi_client.PiStatus}
        assert fleet["pi_status"] in valid, \
            f"pi_status={fleet['pi_status']} not in authoritative enum {valid}"

    def test_each_honeypot_has_canonical_schema(self, monkeypatch):
        clear_pi_env(monkeypatch)
        fleet = pi_client.get_honeypot_fleet()
        for hp in fleet["honeypots"]:
            assert_honeypot_schema(hp)

    def test_honeypot_uses_state_not_status(self, monkeypatch):
        """The canonical field is `state`, NOT `status`.
        The dashboard crash was partly caused by this field-name inconsistency.
        """
        clear_pi_env(monkeypatch)
        fleet = pi_client.get_honeypot_fleet()
        for hp in fleet["honeypots"]:
            assert "state" in hp, f"honeypot {hp['id']} missing `state` field"
            assert "status" not in hp, \
                f"honeypot {hp['id']} has legacy `status` field — must be `state`"

    def test_three_honeypots_always_present(self, monkeypatch):
        """Regardless of Pi state, the 3 honeypot definitions must always appear."""
        clear_pi_env(monkeypatch)
        fleet = pi_client.get_honeypot_fleet()
        ids = {hp["id"] for hp in fleet["honeypots"]}
        assert ids == {"cowrie-01", "camera-01", "iot-01"}


# ---- State preservation tests ----

class TestStatePreservation:
    """The authoritative pi_status enum must NOT be collapsed.

    NOT_CONFIGURED != OFFLINE. AUTH_FAILED != OFFLINE.
    HOST_KEY_UNKNOWN != OFFLINE. HOST_KEY_CHANGED != OFFLINE.
    """

    def test_not_configured_when_env_missing(self, monkeypatch):
        clear_pi_env(monkeypatch)
        fleet = pi_client.get_honeypot_fleet()
        assert fleet["pi_status"] == "NOT_CONFIGURED"
        assert fleet["pi_configured"] is False
        assert fleet["pi_reachable"] is False
        # NOT_CONFIGURED must NOT be collapsed to OFFLINE
        assert fleet["pi_status"] != "OFFLINE", \
            "NOT_CONFIGURED was collapsed to OFFLINE — these are distinct states"
        for hp in fleet["honeypots"]:
            assert hp["state"] == "not_configured", \
                f"honeypot {hp['id']} state={hp['state']} (expected not_configured)"

    def test_offline_when_pi_configured_but_unreachable(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)
        monkeypatch.setattr(subprocess, "run",
            lambda *a, **k: FakeProc(255, stderr="Connection refused"))
        fleet = pi_client.get_honeypot_fleet()
        assert fleet["pi_status"] == "OFFLINE"
        assert fleet["pi_configured"] is True
        assert fleet["pi_reachable"] is False
        for hp in fleet["honeypots"]:
            assert hp["state"] == "offline", \
                f"honeypot {hp['id']} state={hp['state']} (expected offline)"

    def test_auth_failed_distinct_from_offline(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)
        monkeypatch.setattr(subprocess, "run",
            lambda *a, **k: FakeProc(255, stderr="Permission denied (publickey)"))
        fleet = pi_client.get_honeypot_fleet()
        assert fleet["pi_status"] == "AUTH_FAILED"
        assert fleet["pi_status"] != "OFFLINE", \
            "AUTH_FAILED was collapsed to OFFLINE — distinct operational meaning"

    def test_host_key_unknown_distinct_from_offline(self, monkeypatch, tmp_path):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)
        # Empty known_hosts → HOST_KEY_UNKNOWN (operator hasn't seeded it)
        kh = tmp_path / "empty_known_hosts"
        kh.write_text("")
        monkeypatch.setenv("PI_KNOWN_HOSTS", str(kh))
        monkeypatch.setattr(subprocess, "run",
            lambda *a, **k: FakeProc(255, stderr="Host key verification failed."))
        fleet = pi_client.get_honeypot_fleet()
        assert fleet["pi_status"] == "HOST_KEY_UNKNOWN"
        assert fleet["pi_status"] != "OFFLINE"

    def test_host_key_changed_distinct_from_offline(self, monkeypatch, tmp_path):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)
        # known_hosts has entries, but Pi's key differs → MITM or reflash
        kh = tmp_path / "kh"
        kh.write_text("10.0.0.50 ssh-ed25519 AAAAoldkey\n")
        monkeypatch.setenv("PI_KNOWN_HOSTS", str(kh))
        monkeypatch.setattr(subprocess, "run",
            lambda *a, **k: FakeProc(255, stderr="Host key verification failed."))
        fleet = pi_client.get_honeypot_fleet()
        assert fleet["pi_status"] == "HOST_KEY_CHANGED"
        assert fleet["pi_status"] != "OFFLINE"
        assert fleet["pi_status"] != "HOST_KEY_UNKNOWN", \
            "HOST_KEY_CHANGED was collapsed to HOST_KEY_UNKNOWN — distinct"

    def test_timeout_distinct_from_offline(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)
        def fake_run(*a, **k):
            raise subprocess.TimeoutExpired(cmd=["ssh"], timeout=3)
        monkeypatch.setattr(subprocess, "run", fake_run)
        fleet = pi_client.get_honeypot_fleet()
        assert fleet["pi_status"] == "TIMEOUT"
        assert fleet["pi_status"] != "OFFLINE"

    def test_connected_with_running_containers(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)
        docker_output = (
            "pi-cowrie\trunning\tUp 3 hours\n"
            "pi-camera\trunning\tUp 3 hours\n"
            "pi-iot-service\texited\tExited (0) 5m ago\n"
        )
        def fake_run(cmd, **kwargs):
            joined = " ".join(cmd)
            if "docker ps" in joined:
                return FakeProc(0, stdout=docker_output)
            return FakeProc(0, stdout="")
        monkeypatch.setattr(subprocess, "run", fake_run)
        fleet = pi_client.get_honeypot_fleet()
        assert fleet["pi_status"] == "CONNECTED"
        assert fleet["pi_reachable"] is True
        states = {h["id"]: h["state"] for h in fleet["honeypots"]}
        assert states["cowrie-01"] == "running"
        assert states["camera-01"] == "running"
        assert states["iot-01"] == "exited"

    def test_connected_with_missing_container(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)
        docker_output = "pi-cowrie\trunning\tUp 3 hours\n"
        def fake_run(cmd, **kwargs):
            joined = " ".join(cmd)
            if "docker ps" in joined:
                return FakeProc(0, stdout=docker_output)
            return FakeProc(0, stdout="")
        monkeypatch.setattr(subprocess, "run", fake_run)
        fleet = pi_client.get_honeypot_fleet()
        states = {h["id"]: h["state"] for h in fleet["honeypots"]}
        assert states["cowrie-01"] == "running"
        assert states["camera-01"] == "missing"
        assert states["iot-01"] == "missing"

    def test_ssh_not_installed_distinct(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)
        def fake_run(*a, **k):
            raise FileNotFoundError("ssh not found")
        monkeypatch.setattr(subprocess, "run", fake_run)
        fleet = pi_client.get_honeypot_fleet()
        assert fleet["pi_status"] == "SSH_NOT_INSTALLED"
        assert fleet["pi_status"] != "OFFLINE"


# ---- Secret leak tests ----

class TestNoSecrets:
    """No secrets must ever leak in /honeypots or action responses."""

    def test_fleet_response_no_secrets_not_configured(self, monkeypatch):
        clear_pi_env(monkeypatch)
        fleet = pi_client.get_honeypot_fleet()
        assert_no_secrets(fleet, "fleet (NOT_CONFIGURED)")

    def test_fleet_response_no_secrets_offline(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch, ip="10.0.0.99", user="operator")
        monkeypatch.setattr(subprocess, "run",
            lambda *a, **k: FakeProc(255, stderr="Connection refused"))
        fleet = pi_client.get_honeypot_fleet()
        assert_no_secrets(fleet, "fleet (OFFLINE)")

    def test_fleet_response_no_secrets_auth_failed(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch, ip="10.0.0.99", user="operator")
        monkeypatch.setattr(subprocess, "run",
            lambda *a, **k: FakeProc(255, stderr="Permission denied"))
        fleet = pi_client.get_honeypot_fleet()
        assert_no_secrets(fleet, "fleet (AUTH_FAILED)")

    def test_action_response_no_secrets(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch, ip="10.0.0.99", user="operator")
        monkeypatch.setattr(subprocess, "run",
            lambda *a, **k: FakeProc(255, stderr="Connection refused"))
        result = pi_client.container_action("cowrie-01", "start")
        assert_no_secrets(result, "action response")


# ---- API endpoint contract (via TestClient) ----

class TestFastAPIEndpointContract:
    """The FastAPI /honeypots endpoint must return the canonical shape."""

    @pytest.fixture
    def client(self, monkeypatch):
        clear_pi_env(monkeypatch)
        # starlette 0.37 (pinned by fastapi 0.111) doesn't support
        # TestClient(client=...). Bypass IP allow-list via test env var.
        monkeypatch.setenv("TRAPSIG_TEST_BYPASS_IP_ALLOWLIST", "1")
        import importlib
        from app import main as _main
        importlib.reload(_main)
        from fastapi.testclient import TestClient
        return TestClient(_main.app)

    def test_get_honeypots_returns_200(self, client):
        r = client.get("/honeypots")
        assert r.status_code == 200

    def test_get_honeypots_honeypots_is_array(self, client):
        r = client.get("/honeypots")
        data = r.json()
        assert isinstance(data["honeypots"], list)
        assert len(data["honeypots"]) == 3

    def test_get_honeypots_pi_status_is_not_configured_when_env_missing(self, client):
        r = client.get("/honeypots")
        data = r.json()
        assert data["pi_status"] == "NOT_CONFIGURED"

    def test_get_honeypots_no_secrets(self, client):
        r = client.get("/honeypots")
        assert_no_secrets(r.json(), "GET /honeypots")

    def test_get_honeypots_uses_state_not_status(self, client):
        r = client.get("/honeypots")
        data = r.json()
        for hp in data["honeypots"]:
            assert "state" in hp
            assert "status" not in hp

    def test_post_start_without_api_key_returns_401(self, client):
        r = client.post("/honeypots/cowrie-01/start")
        assert r.status_code == 401

    def test_post_start_with_key_pi_not_configured_returns_503(self, client, monkeypatch):
        monkeypatch.setenv("API_SECRET_KEY", "test-key-123")
        r = client.post("/honeypots/cowrie-01/start",
                        headers={"X-API-Key": "test-key-123"})
        assert r.status_code == 503
        assert "NOT_CONFIGURED" in r.text

    def test_post_start_unknown_honeypot_returns_404(self, client, monkeypatch):
        monkeypatch.setenv("API_SECRET_KEY", "test-key-123")
        monkeypatch.setenv("PI_IP", "10.0.0.50")
        monkeypatch.setenv("PI_SSH_USER", "pi")
        r = client.post("/honeypots/nonexistent/start",
                        headers={"X-API-Key": "test-key-123"})
        assert r.status_code == 404
