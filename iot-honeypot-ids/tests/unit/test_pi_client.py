"""Tests for the Pi control-plane client.

Covers:
- Pi config resolution (NOT_CONFIGURED when env missing)
- SSH option construction (NO StrictHostKeyChecking=no)
- Failure classification (auth / timeout / offline / host-key)
- Honeypot fleet status (deterministic states when Pi unreachable)
- Container action mapping (success / 503 / 404 / verify failure)
- No secrets leak in responses

These tests use monkeypatch to control environment variables and to
replace subprocess.run with deterministic fakes — no real SSH is performed.
"""
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "dashboard" / "api"))

from app import pi_client  # type: ignore  # noqa: E402


# ---- Test helpers --------------------------------------------------

class FakeProc:
    """Minimal stand-in for subprocess.CompletedProcess / TimeoutExpired."""
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def clear_pi_env(monkeypatch):
    """Strip every Pi-related env var so defaults kick in (empty = NOT_CONFIGURED)."""
    for k in ["PI_IP", "PI_SSH_USER", "PI_SSH_KEY", "PI_KNOWN_HOSTS",
              "PI_SSH_ACCEPT_NEW_HOST_KEY", "PI_DEPLOY_PATH",
              "PI_SSH_CONNECT_TIMEOUT", "PI_SSH_COMMAND_TIMEOUT"]:
        monkeypatch.delenv(k, raising=False)


def set_pi_env(monkeypatch, ip="10.0.0.50", user="pi"):
    monkeypatch.setenv("PI_IP", ip)
    monkeypatch.setenv("PI_SSH_USER", user)


# ---- Pi config resolution -----------------------------------------

class TestPiConfig:
    def test_missing_env_yields_not_configured(self, monkeypatch):
        clear_pi_env(monkeypatch)
        cfg = pi_client.load_pi_config()
        assert cfg.is_configured is False
        assert cfg.pi_ip == ""
        assert cfg.pi_user == ""

    def test_no_silent_default_ip(self, monkeypatch):
        """Critical: pi_ip MUST NOT default to 192.168.1.50."""
        clear_pi_env(monkeypatch)
        cfg = pi_client.load_pi_config()
        assert cfg.pi_ip != "192.168.1.50"
        assert cfg.pi_ip == ""

    def test_no_silent_default_user(self, monkeypatch):
        clear_pi_env(monkeypatch)
        cfg = pi_client.load_pi_config()
        assert cfg.pi_user != "pi"
        assert cfg.pi_user == ""

    def test_configured_when_both_set(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)
        cfg = pi_client.load_pi_config()
        assert cfg.is_configured is True
        assert cfg.ssh_target == "pi@10.0.0.50"

    def test_ssh_key_path_optional(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)
        cfg = pi_client.load_pi_config()
        # No PI_SSH_KEY set — should be None, not fail
        assert cfg.ssh_key_path is None


# ---- SSH options hardening -----------------------------------------

class TestSshOptions:
    def test_no_strict_host_key_checking_no(self, monkeypatch):
        """Critical: NEVER emit StrictHostKeyChecking=no."""
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)
        cfg = pi_client.load_pi_config()
        opts = pi_client._ssh_options(cfg)
        joined = " ".join(opts)
        assert "StrictHostKeyChecking=no" not in joined
        assert "StrictHostKeyChecking=yes" in joined or \
               "StrictHostKeyChecking=accept-new" in joined

    def test_password_authentication_disabled(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)
        cfg = pi_client.load_pi_config()
        opts = pi_client._ssh_options(cfg)
        joined = " ".join(opts)
        assert "PasswordAuthentication=no" in joined

    def test_batch_mode_yes(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)
        cfg = pi_client.load_pi_config()
        opts = pi_client._ssh_options(cfg)
        assert "BatchMode=yes" in opts

    def test_known_hosts_file_set(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)
        cfg = pi_client.load_pi_config()
        opts = pi_client._ssh_options(cfg)
        joined = " ".join(opts)
        assert "UserKnownHostsFile=" in joined

    def test_accept_new_only_when_explicitly_opted_in(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)
        monkeypatch.setenv("PI_SSH_ACCEPT_NEW_HOST_KEY", "1")
        cfg = pi_client.load_pi_config()
        opts = pi_client._ssh_options(cfg)
        joined = " ".join(opts)
        assert "StrictHostKeyChecking=accept-new" in joined
        assert "StrictHostKeyChecking=yes" not in joined

    def test_strict_by_default(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)
        cfg = pi_client.load_pi_config()
        opts = pi_client._ssh_options(cfg)
        joined = " ".join(opts)
        assert "StrictHostKeyChecking=yes" in joined


# ---- Failure classification ---------------------------------------

class TestFailureClassification:
    def test_permission_denied_is_auth_failed(self):
        err = subprocess.CalledProcessError(255, ["ssh"], stderr="Permission denied (publickey).")
        s = pi_client._classify_ssh_failure(err, "Permission denied (publickey).")
        assert s == pi_client.PiStatus.AUTH_FAILED

    def test_connection_refused_is_offline(self):
        err = subprocess.CalledProcessError(255, ["ssh"], stderr="Connection refused")
        s = pi_client._classify_ssh_failure(err, "Connection refused")
        assert s == pi_client.PiStatus.OFFLINE

    def test_connection_timed_out_is_timeout(self):
        err = subprocess.CalledProcessError(255, ["ssh"], stderr="Connection timed out")
        s = pi_client._classify_ssh_failure(err, "Connection timed out")
        assert s == pi_client.PiStatus.TIMEOUT

    def test_unknown_host_is_offline(self):
        err = subprocess.CalledProcessError(255, ["ssh"], stderr="Could not resolve hostname")
        s = pi_client._classify_ssh_failure(err, "Could not resolve hostname")
        assert s == pi_client.PiStatus.OFFLINE

    def test_host_key_not_in_known_hosts_is_unknown(self, monkeypatch, tmp_path):
        # Empty known_hosts file → HOST_KEY_UNKNOWN (operator hasn't seeded)
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)
        monkeypatch.setenv("PI_KNOWN_HOSTS", str(tmp_path / "empty_known_hosts"))
        # Need to write empty file so exists() returns True but size is 0
        (tmp_path / "empty_known_hosts").write_text("")
        err = subprocess.CalledProcessError(255, ["ssh"], stderr="Host key verification failed.")
        s = pi_client._classify_ssh_failure(err, "Host key verification failed.")
        assert s == pi_client.PiStatus.HOST_KEY_UNKNOWN

    def test_host_key_mismatch_is_changed(self, monkeypatch, tmp_path):
        # known_hosts has entries, but Pi's key differs → HOST_KEY_CHANGED
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)
        kh = tmp_path / "kh"
        kh.write_text("10.0.0.50 ssh-ed25519 AAAAoldkey\n")
        monkeypatch.setenv("PI_KNOWN_HOSTS", str(kh))
        err = subprocess.CalledProcessError(255, ["ssh"], stderr="Host key verification failed.")
        s = pi_client._classify_ssh_failure(err, "Host key verification failed.")
        assert s == pi_client.PiStatus.HOST_KEY_CHANGED

    def test_file_not_found_is_ssh_not_installed(self):
        err = FileNotFoundError("[Errno 2] No such file or directory: 'ssh'")
        s = pi_client._classify_ssh_failure(err, "")
        assert s == pi_client.PiStatus.SSH_NOT_INSTALLED

    def test_timeout_expired_is_timeout(self):
        err = subprocess.TimeoutExpired(cmd=["ssh"], timeout=5)
        s = pi_client._classify_ssh_failure(err, "")
        assert s == pi_client.PiStatus.TIMEOUT

    def test_unknown_error_is_error(self):
        err = subprocess.CalledProcessError(1, ["ssh"], stderr="weird unknown failure")
        s = pi_client._classify_ssh_failure(err, "weird unknown failure")
        assert s == pi_client.PiStatus.ERROR


# ---- Fleet status --------------------------------------------------

class TestHoneypotFleet:
    def test_not_configured_when_env_missing(self, monkeypatch):
        clear_pi_env(monkeypatch)
        fleet = pi_client.get_honeypot_fleet()
        assert fleet["pi_status"] == "NOT_CONFIGURED"
        assert fleet["pi_reachable"] is False
        assert fleet["pi_configured"] is False
        for hp in fleet["honeypots"]:
            assert hp["state"] == "not_configured"
            assert hp["container_exists"] is False

    def test_not_configured_response_has_no_secrets(self, monkeypatch):
        clear_pi_env(monkeypatch)
        fleet = pi_client.get_honeypot_fleet()
        import json
        serialized = json.dumps(fleet)
        # No IP / user / key path should appear
        assert "192.168.1.50" not in serialized
        assert "pi@" not in serialized
        assert "id_ed25519" not in serialized

    def test_offline_when_pi_configured_but_unreachable(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)

        def fake_run(cmd, **kwargs):
            return FakeProc(returncode=255, stderr="Connection refused")

        monkeypatch.setattr(subprocess, "run", fake_run)
        fleet = pi_client.get_honeypot_fleet()
        assert fleet["pi_status"] == "OFFLINE"
        assert fleet["pi_reachable"] is False
        assert fleet["pi_configured"] is True
        for hp in fleet["honeypots"]:
            assert hp["state"] == "offline"

    def test_connected_with_running_containers(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)

        docker_output = (
            "pi-cowrie\trunning\tUp 3 hours\n"
            "pi-camera\trunning\tUp 3 hours\n"
            "pi-iot-service\texited\tExited (0) 5 minutes ago\n"
        )

        def fake_run(cmd, **kwargs):
            if "docker ps" in " ".join(cmd):
                return FakeProc(returncode=0, stdout=docker_output)
            return FakeProc(returncode=0, stdout="")

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

        # Only cowrie exists on Pi
        docker_output = "pi-cowrie\trunning\tUp 3 hours\n"

        def fake_run(cmd, **kwargs):
            if "docker ps" in " ".join(cmd):
                return FakeProc(returncode=0, stdout=docker_output)
            return FakeProc(returncode=0, stdout="")

        monkeypatch.setattr(subprocess, "run", fake_run)
        fleet = pi_client.get_honeypot_fleet()
        states = {h["id"]: h["state"] for h in fleet["honeypots"]}
        assert states["cowrie-01"] == "running"
        assert states["camera-01"] == "missing"
        assert states["iot-01"] == "missing"


# ---- Container action ---------------------------------------------

class TestContainerAction:
    def test_invalid_honeypot_id(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)
        result = pi_client.container_action("nonexistent-01", "start")
        assert result["success"] is False
        assert "unknown honeypot" in result["message"]

    def test_invalid_action(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)
        result = pi_client.container_action("cowrie-01", "destroy")
        assert result["success"] is False
        assert "invalid action" in result["message"]

    def test_not_configured_returns_503_cause(self, monkeypatch):
        clear_pi_env(monkeypatch)
        result = pi_client.container_action("cowrie-01", "start")
        assert result["success"] is False
        assert result["pi_status"] == "NOT_CONFIGURED"
        assert "PI_IP/PI_SSH_USER" in result["message"]

    def test_offline_returns_503_cause(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)

        def fake_run(cmd, **kwargs):
            return FakeProc(returncode=255, stderr="Connection refused")

        monkeypatch.setattr(subprocess, "run", fake_run)
        result = pi_client.container_action("cowrie-01", "start")
        assert result["success"] is False
        assert result["pi_status"] == "OFFLINE"
        # Pass 4: pre-action probe now catches OFFLINE before attempting the action
        assert "pre-action probe failed: OFFLINE" in result["message"]

    def test_start_verified_running(self, monkeypatch):
        """Successful start: command exit 0, then docker ps reports running."""
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)

        call_count = {"n": 0}

        def fake_run(cmd, **kwargs):
            call_count["n"] += 1
            joined = " ".join(cmd)
            if "docker compose" in joined:
                # The actual action — pretend success
                return FakeProc(returncode=0, stdout="", stderr="")
            elif "docker ps" in joined:
                # Pre-action probe AND post-action verification — cowrie is stopped before, running after.
                # Return stopped on first probe (so action proceeds), running on subsequent (verification).
                if call_count["n"] == 1:
                    return FakeProc(returncode=0, stdout="pi-cowrie\texited\tExited (0)\n")
                return FakeProc(returncode=0, stdout="pi-cowrie\trunning\tUp 1 second\n")
            return FakeProc(returncode=0, stdout="")

        monkeypatch.setattr(subprocess, "run", fake_run)
        result = pi_client.container_action("cowrie-01", "start")
        assert result["success"] is True
        assert result["verified_state"] == "running"
        assert "verified" in result["message"].lower() or "succeeded" in result["message"].lower()

    def test_stop_verified_exited(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)

        call_count = {"n": 0}
        def fake_run(cmd, **kwargs):
            call_count["n"] += 1
            joined = " ".join(cmd)
            if "docker compose" in joined:
                return FakeProc(returncode=0)
            elif "docker ps" in joined:
                # Pre-probe: running. Post-action: exited.
                if call_count["n"] == 1:
                    return FakeProc(returncode=0, stdout="pi-cowrie\trunning\tUp 3 hours\n")
                return FakeProc(returncode=0, stdout="pi-cowrie\texited\tExited (0)\n")
            return FakeProc(returncode=0)

        monkeypatch.setattr(subprocess, "run", fake_run)
        result = pi_client.container_action("cowrie-01", "stop")
        assert result["success"] is True
        assert result["verified_state"] == "exited"

    def test_start_fails_when_state_does_not_match(self, monkeypatch):
        """start succeeded (exit 0) but docker still reports exited — must fail."""
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)

        call_count = {"n": 0}
        def fake_run(cmd, **kwargs):
            call_count["n"] += 1
            joined = " ".join(cmd)
            if "docker compose" in joined:
                return FakeProc(returncode=0)
            elif "docker ps" in joined:
                # Pre-probe: exited (so action proceeds). Post-action: STILL exited (start failed to make it running).
                return FakeProc(returncode=0, stdout="pi-cowrie\texited\tExited (137)\n")
            return FakeProc(returncode=0)

        monkeypatch.setattr(subprocess, "run", fake_run)
        result = pi_client.container_action("cowrie-01", "start")
        assert result["success"] is False
        assert "did not yield expected state" in result["message"]

    def test_action_fails_when_compose_returns_nonzero(self, monkeypatch):
        """docker compose returns non-zero → 500 with compose error message.
        Pre-action probe must show container exists (so we reach the action)."""
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)

        def fake_run(cmd, **kwargs):
            joined = " ".join(cmd)
            if "docker ps" in joined:
                # Pre-action probe: container exists, is stopped
                return FakeProc(returncode=0, stdout="pi-cowrie\texited\tExited (0)\n")
            if "docker compose" in joined:
                return FakeProc(returncode=1, stderr="no such service: cowrie")
            return FakeProc(returncode=0)

        monkeypatch.setattr(subprocess, "run", fake_run)
        result = pi_client.container_action("cowrie-01", "start")
        assert result["success"] is False
        assert "docker compose start failed" in result["message"]

    def test_no_secrets_in_action_response(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch, ip="10.0.0.99")

        def fake_run(cmd, **kwargs):
            return FakeProc(returncode=255, stderr="Connection refused")

        monkeypatch.setattr(subprocess, "run", fake_run)
        result = pi_client.container_action("cowrie-01", "start")
        import json
        s = json.dumps(result)
        assert "10.0.0.99" not in s
        assert "pi@" not in s


# ---- check_pi -----------------------------------------------------

class TestCheckPi:
    def test_not_configured(self, monkeypatch):
        clear_pi_env(monkeypatch)
        assert pi_client.check_pi() == pi_client.PiStatus.NOT_CONFIGURED

    def test_connected(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)
        monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeProc(0))
        assert pi_client.check_pi() == pi_client.PiStatus.CONNECTED

    def test_auth_failed(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)
        monkeypatch.setattr(subprocess, "run",
                            lambda *a, **k: FakeProc(255, stderr="Permission denied (publickey)"))
        assert pi_client.check_pi() == pi_client.PiStatus.AUTH_FAILED

    def test_timeout(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)
        def fake_run(*a, **k):
            raise subprocess.TimeoutExpired(cmd=["ssh"], timeout=3)
        monkeypatch.setattr(subprocess, "run", fake_run)
        assert pi_client.check_pi() == pi_client.PiStatus.TIMEOUT

    def test_offline(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)
        monkeypatch.setattr(subprocess, "run",
                            lambda *a, **k: FakeProc(255, stderr="Connection refused"))
        assert pi_client.check_pi() == pi_client.PiStatus.OFFLINE

    def test_ssh_not_installed(self, monkeypatch):
        clear_pi_env(monkeypatch)
        set_pi_env(monkeypatch)
        def fake_run(*a, **k):
            raise FileNotFoundError("ssh not found")
        monkeypatch.setattr(subprocess, "run", fake_run)
        assert pi_client.check_pi() == pi_client.PiStatus.SSH_NOT_INSTALLED


# ---- Container state classification ------------------------------

class TestContainerState:
    def test_running(self):
        assert pi_client._classify_container_state("running Up 3 hours") == pi_client.ContainerState.RUNNING

    def test_exited(self):
        assert pi_client._classify_container_state("exited Exited (0)") == pi_client.ContainerState.EXITED

    def test_created(self):
        assert pi_client._classify_container_state("created") == pi_client.ContainerState.CREATED

    def test_empty_is_unknown(self):
        assert pi_client._classify_container_state("") == pi_client.ContainerState.UNKNOWN
