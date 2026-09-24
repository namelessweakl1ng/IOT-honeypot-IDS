"""Tests for the FastAPI honeypot endpoints.

Covers:
- GET /honeypots returns deterministic pi_status (NOT_CONFIGURED when env missing)
- GET /honeypots never exposes secrets (no IP, no user, no key path)
- POST /honeypots/{id}/start|stop|restart require API key (401 without)
- 404 for unknown honeypot id
- 503 when Pi not configured / unreachable
- 200 only when success=true (verified state)
- /stats endpoint behavior when ES unavailable
- /health endpoint behavior
"""
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "dashboard" / "api"))

from app.main import app  # type: ignore  # noqa: E402
from app import pi_client  # type: ignore  # noqa: E402


@pytest.fixture
def client(monkeypatch):
    # starlette 0.37 (pinned by fastapi 0.111) doesn't support the
    # TestClient(client=...) kwarg. We bypass the IP allow-list in tests
    # via TRAPSIG_TEST_BYPASS_IP_ALLOWLIST=1. This still tests the real
    # require_api_key + real pi_client + real endpoint logic — we only
    # skip the network-level IP filter, which is irrelevant for API tests.
    monkeypatch.setenv("TRAPSIG_TEST_BYPASS_IP_ALLOWLIST", "1")
    import importlib
    from app import main as _main
    importlib.reload(_main)
    return TestClient(_main.app)


@pytest.fixture(autouse=True)
def clear_pi_env(monkeypatch):
    """Each test starts with Pi NOT_CONFIGURED unless explicitly set."""
    for k in ["PI_IP", "PI_SSH_USER", "PI_SSH_KEY", "PI_KNOWN_HOSTS",
              "PI_SSH_ACCEPT_NEW_HOST_KEY", "PI_DEPLOY_PATH",
              "PI_SSH_CONNECT_TIMEOUT", "PI_SSH_COMMAND_TIMEOUT",
              "API_SECRET_KEY"]:
        monkeypatch.delenv(k, raising=False)


# ---- GET /honeypots ------------------------------------------------

class TestGetHoneypots:
    def test_returns_not_configured_when_env_missing(self, client):
        r = client.get("/honeypots")
        assert r.status_code == 200
        data = r.json()
        assert data["pi_status"] == "NOT_CONFIGURED"
        assert data["pi_reachable"] is False
        assert data["pi_configured"] is False
        for hp in data["honeypots"]:
            assert hp["state"] == "not_configured"

    def test_response_contains_no_secrets(self, client):
        r = client.get("/honeypots")
        body = r.text
        # No IP, no SSH user, no key path, no API key
        assert "192.168.1.50" not in body
        assert "pi@" not in body
        assert "id_ed25519" not in body
        assert "API_SECRET_KEY" not in body
        assert "dev-only-insecure-key" not in body

    def test_returns_offline_when_pi_configured_but_unreachable(self, client, monkeypatch):
        monkeypatch.setenv("PI_IP", "10.0.0.99")
        monkeypatch.setenv("PI_SSH_USER", "pi")

        import subprocess
        def fake_run(cmd, **kwargs):
            return subprocess.CompletedProcess(cmd, returncode=255, stdout="", stderr="Connection refused")
        monkeypatch.setattr(subprocess, "run", fake_run)

        r = client.get("/honeypots")
        data = r.json()
        assert data["pi_status"] == "OFFLINE"
        assert data["pi_configured"] is True
        for hp in data["honeypots"]:
            assert hp["state"] == "offline"

    def test_returns_connected_with_running_state(self, client, monkeypatch):
        monkeypatch.setenv("PI_IP", "10.0.0.99")
        monkeypatch.setenv("PI_SSH_USER", "pi")

        import subprocess
        docker_output = "pi-cowrie\trunning\tUp 3 hours\npi-camera\trunning\tUp 3 hours\n"
        def fake_run(cmd, **kwargs):
            joined = " ".join(cmd)
            if "docker ps" in joined:
                return subprocess.CompletedProcess(cmd, returncode=0, stdout=docker_output, stderr="")
            return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")
        monkeypatch.setattr(subprocess, "run", fake_run)

        r = client.get("/honeypots")
        data = r.json()
        assert data["pi_status"] == "CONNECTED"
        assert data["pi_reachable"] is True
        states = {h["id"]: h["state"] for h in data["honeypots"]}
        assert states["cowrie-01"] == "running"
        assert states["camera-01"] == "running"
        assert states["iot-01"] == "missing"

    def test_honeypot_definitions_consistent(self, client):
        """All 3 honeypots should always appear, regardless of Pi state."""
        r = client.get("/honeypots")
        ids = {h["id"] for h in r.json()["honeypots"]}
        assert ids == {"cowrie-01", "camera-01", "iot-01"}


# ---- POST /honeypots/{id}/{start,stop,restart} ---------------------

class TestHoneypotActions:
    def test_action_requires_api_key(self, client):
        """Without API key, mutating endpoints must return 401."""
        r = client.post("/honeypots/cowrie-01/start")
        assert r.status_code == 401
        r = client.post("/honeypots/cowrie-01/stop")
        assert r.status_code == 401
        r = client.post("/honeypots/cowrie-01/restart")
        assert r.status_code == 401

    def test_action_with_invalid_api_key(self, client, monkeypatch):
        monkeypatch.setenv("API_SECRET_KEY", "real-secret-123")
        r = client.post("/honeypots/cowrie-01/start",
                        headers={"X-API-Key": "wrong-key"})
        assert r.status_code == 401

    def test_action_with_valid_api_key_when_pi_not_configured(self, client, monkeypatch):
        """API key OK, but Pi not configured → 503."""
        monkeypatch.setenv("API_SECRET_KEY", "real-secret-123")
        r = client.post("/honeypots/cowrie-01/start",
                        headers={"X-API-Key": "real-secret-123"})
        assert r.status_code == 503
        assert "NOT_CONFIGURED" in r.text

    def test_action_unknown_honeypot(self, client, monkeypatch):
        monkeypatch.setenv("API_SECRET_KEY", "real-secret-123")
        monkeypatch.setenv("PI_IP", "10.0.0.99")
        monkeypatch.setenv("PI_SSH_USER", "pi")
        r = client.post("/honeypots/nonexistent-01/start",
                        headers={"X-API-Key": "real-secret-123"})
        assert r.status_code == 404

    def test_action_when_pi_offline_returns_503(self, client, monkeypatch):
        monkeypatch.setenv("API_SECRET_KEY", "real-secret-123")
        monkeypatch.setenv("PI_IP", "10.0.0.99")
        monkeypatch.setenv("PI_SSH_USER", "pi")

        import subprocess
        def fake_run(cmd, **kwargs):
            return subprocess.CompletedProcess(cmd, returncode=255, stdout="", stderr="Connection refused")
        monkeypatch.setattr(subprocess, "run", fake_run)

        r = client.post("/honeypots/cowrie-01/start",
                        headers={"X-API-Key": "real-secret-123"})
        assert r.status_code == 503
        assert "OFFLINE" in r.text

    def test_action_auth_failed_returns_503(self, client, monkeypatch):
        monkeypatch.setenv("API_SECRET_KEY", "real-secret-123")
        monkeypatch.setenv("PI_IP", "10.0.0.99")
        monkeypatch.setenv("PI_SSH_USER", "pi")

        import subprocess
        def fake_run(cmd, **kwargs):
            return subprocess.CompletedProcess(cmd, returncode=255, stdout="", stderr="Permission denied (publickey)")
        monkeypatch.setattr(subprocess, "run", fake_run)

        r = client.post("/honeypots/cowrie-01/start",
                        headers={"X-API-Key": "real-secret-123"})
        assert r.status_code == 503
        assert "AUTH_FAILED" in r.text

    def test_action_succeeded_and_verified_returns_200(self, client, monkeypatch):
        monkeypatch.setenv("API_SECRET_KEY", "real-secret-123")
        monkeypatch.setenv("PI_IP", "10.0.0.99")
        monkeypatch.setenv("PI_SSH_USER", "pi")

        import subprocess
        def fake_run(cmd, **kwargs):
            joined = " ".join(cmd)
            if "docker compose" in joined:
                return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")
            elif "docker ps" in joined:
                return subprocess.CompletedProcess(cmd, returncode=0,
                    stdout="pi-cowrie\trunning\tUp 1 second\n", stderr="")
            return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")
        monkeypatch.setattr(subprocess, "run", fake_run)

        r = client.post("/honeypots/cowrie-01/start",
                        headers={"X-API-Key": "real-secret-123"})
        assert r.status_code == 200
        data = r.json()
        assert data["success"] is True
        assert data["verified_state"] == "running"

    def test_action_failed_verification_returns_500(self, client, monkeypatch):
        """Command exited 0 but state not verified → 500."""
        monkeypatch.setenv("API_SECRET_KEY", "real-secret-123")
        monkeypatch.setenv("PI_IP", "10.0.0.99")
        monkeypatch.setenv("PI_SSH_USER", "pi")

        import subprocess
        def fake_run(cmd, **kwargs):
            joined = " ".join(cmd)
            if "docker compose" in joined:
                return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")
            elif "docker ps" in joined:
                # Container still exited after start
                return subprocess.CompletedProcess(cmd, returncode=0,
                    stdout="pi-cowrie\texited\tExited (137)\n", stderr="")
            return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")
        monkeypatch.setattr(subprocess, "run", fake_run)

        r = client.post("/honeypots/cowrie-01/start",
                        headers={"X-API-Key": "real-secret-123"})
        assert r.status_code == 500
        assert "did not yield expected state" in r.text

    def test_action_compose_nonzero_returns_500(self, client, monkeypatch):
        """docker compose returned non-zero → 500 with compose error message.
        Pass 4: pre-action probe must show container exists (so we reach the action)."""
        monkeypatch.setenv("API_SECRET_KEY", "real-secret-123")
        monkeypatch.setenv("PI_IP", "10.0.0.99")
        monkeypatch.setenv("PI_SSH_USER", "pi")

        import subprocess
        def fake_run(cmd, **kwargs):
            joined = " ".join(cmd)
            if "docker ps" in joined:
                # Pre-action probe: container exists, is stopped
                return subprocess.CompletedProcess(cmd, returncode=0,
                    stdout="pi-cowrie\texited\tExited (0)\n", stderr="")
            if "docker compose" in joined:
                return subprocess.CompletedProcess(cmd, returncode=1, stdout="", stderr="no such service: cowrie")
            return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")
        monkeypatch.setattr(subprocess, "run", fake_run)

        r = client.post("/honeypots/cowrie-01/start",
                        headers={"X-API-Key": "real-secret-123"})
        assert r.status_code == 500
        assert "docker compose start failed" in r.text

    def test_response_never_exposes_secrets(self, client, monkeypatch):
        monkeypatch.setenv("API_SECRET_KEY", "real-secret-123")
        monkeypatch.setenv("PI_IP", "10.0.0.99")
        monkeypatch.setenv("PI_SSH_USER", "operator")

        import subprocess
        def fake_run(cmd, **kwargs):
            return subprocess.CompletedProcess(cmd, returncode=255, stdout="", stderr="Connection refused")
        monkeypatch.setattr(subprocess, "run", fake_run)

        r = client.post("/honeypots/cowrie-01/start",
                        headers={"X-API-Key": "real-secret-123"})
        body = r.text
        # No PI_IP, no SSH user, no key path, no API key value
        assert "10.0.0.99" not in body
        assert "operator@" not in body
        assert "id_ed25519" not in body
        assert "real-secret-123" not in body


# ---- GET endpoints never require API key (read-only) --------------

class TestReadOnlyAccess:
    def test_get_honeypots_no_auth(self, client):
        """GET /honeypots should work without API key (read-only)."""
        r = client.get("/honeypots")
        assert r.status_code == 200

    def test_get_stats_no_auth(self, client):
        r = client.get("/stats")
        # Either ok (if ES reachable) or degraded — but not 401
        assert r.status_code != 401

    def test_get_health_no_auth(self, client):
        r = client.get("/health")
        assert r.status_code == 200


# ---- /honeypots/{id}/start vs /training vs /replay auth -----------

class TestMutatingEndpointAuth:
    def test_training_requires_api_key(self, client):
        r = client.post("/training", json={"algorithm": "random_forest"})
        assert r.status_code == 401

    def test_replay_requires_api_key(self, client):
        r = client.post("/replay", json={"scenario_id": "ssh-bruteforce", "target": "192.168.1.50"})
        assert r.status_code == 401

    def test_replay_rejects_non_lab_target(self, client, monkeypatch):
        """Target outside lab subnet must be rejected even with valid API key."""
        monkeypatch.setenv("API_SECRET_KEY", "real-secret-123")
        r = client.post("/replay",
                        headers={"X-API-Key": "real-secret-123"},
                        json={"scenario_id": "ssh-bruteforce", "target": "8.8.8.8"})
        # 8.8.8.8 is outside the lab subnet 192.168.1.0/24
        assert r.status_code == 400
