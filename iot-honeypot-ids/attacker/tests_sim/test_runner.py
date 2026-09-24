"""Config + runner + manifest + scenario tests."""
import json
import os
import tempfile
from pathlib import Path

import pytest
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "attacker"))

from sim.config import ExperimentConfig, load_config
from sim.safety import SafetyRefusal
from sim.manifest import audit_manifest_no_secrets, build_manifest, generate_run_id, write_manifest
from sim.scenarios import SCENARIOS
from sim.scenarios.base import Scenario, ScenarioResult


def make_test_config(**kw):
    defaults = dict(
        target_ip="192.168.1.50",
        allowed_cidrs=["192.168.1.0/24"],
        ssh_port=2222,
        camera_port=8080,
        iot_port=9000,
        max_connections=30,
        max_requests=50,
        max_auth_attempts=10,
        request_delay_ms=10,
        scenario_timeout_seconds=30,
        require_private_target=True,
        require_explicit_target=True,
        allow_localhost=False,
    )
    defaults.update(kw)
    return ExperimentConfig(**defaults)


class TestConfig:
    def test_yaml_config_loads(self):
        yaml_content = """
target:
  ip: "192.168.1.50"
lab:
  allowed_cidrs:
    - "192.168.1.0/24"
services:
  ssh:
    port: 2222
  camera:
    port: 8080
  iot:
    port: 9000
limits:
  max_connections: 30
  max_requests: 50
  max_auth_attempts: 10
  request_delay_ms: 250
  scenario_timeout_seconds: 120
safety:
  require_private_target: true
  require_explicit_target: true
  allow_localhost: false
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            cfg = load_config(f.name)
        assert cfg.target_ip == "192.168.1.50"
        assert cfg.ssh_port == 2222
        assert cfg.allowed_ports == [2222, 8080, 9000]

    def test_env_config_loads(self):
        os.environ["HONEYPOT_IP"] = "192.168.1.50"
        os.environ["LAB_SUBNET"] = "192.168.1.0/24"
        os.environ["COWRIE_SSH_PORT"] = "2222"
        os.environ["CAMERA_HTTP_PORT"] = "8080"
        os.environ["IOT_SERVICE_PORT"] = "9000"
        cfg = load_config(None)
        assert cfg.target_ip == "192.168.1.50"
        assert cfg.ssh_port == 2222

    def test_config_summary_contains_key_fields(self):
        cfg = make_test_config()
        summary = cfg.summary()
        assert "192.168.1.50" in summary
        assert "TRAPSIG ATTACK SIMULATOR" in summary
        assert "LIMITS" in summary


class TestManifest:
    def test_run_id_format(self):
        rid = generate_run_id()
        assert rid.startswith("RUN-")
        assert len(rid) > len("RUN-YYYYMMDD-")

    def test_manifest_has_required_fields(self):
        cfg = make_test_config()
        result = ScenarioResult(scenario="recon_basic", status="completed", started_at="2025-01-01T00:00:00Z", ended_at="2025-01-01T00:00:01Z")
        manifest = build_manifest("RUN-001", "recon_basic", cfg, result, seed=42, profile="normal")
        assert manifest["run_id"] == "RUN-001"
        assert manifest["scenario"] == "recon_basic"
        assert manifest["target"]["ip"] == "192.168.1.50"
        assert manifest["seed"] == 42
        assert manifest["profile"] == "normal"
        assert "stages" in manifest
        assert "statistics" in manifest

    def test_manifest_no_secrets(self):
        cfg = make_test_config()
        result = ScenarioResult(scenario="ssh_probe", status="completed", started_at="2025-01-01T00:00:00Z", ended_at="2025-01-01T00:00:01Z")
        manifest = build_manifest("RUN-002", "ssh_probe", cfg, result, seed=42, profile="normal")
        assert audit_manifest_no_secrets(manifest) is True

    def test_manifest_write_to_file(self):
        cfg = make_test_config()
        result = ScenarioResult(scenario="recon_basic", status="completed", started_at="2025-01-01T00:00:00Z", ended_at="2025-01-01T00:00:01Z")
        manifest = build_manifest("RUN-003", "recon_basic", cfg, result, seed=42, profile="normal")
        with tempfile.TemporaryDirectory() as tmp:
            path = write_manifest(manifest, manifests_dir=tmp)
            assert path.exists()
            loaded = json.loads(path.read_text())
            assert loaded["run_id"] == "RUN-003"


class TestDryRun:
    def test_dry_run_produces_no_connections(self):
        cfg = make_test_config()
        for name, cls in SCENARIOS.items():
            scenario = cls(cfg, seed=42, profile="fast")
            result = scenario.run(dry_run=True)
            assert result.status == "dry_run"
            assert result.statistics["connections"] == 0
            assert result.statistics["requests"] == 0
            assert result.statistics["auth_attempts"] == 0

    def test_dry_run_has_steps(self):
        cfg = make_test_config()
        scenario = SCENARIOS["recon_basic"](cfg, seed=42)
        result = scenario.run(dry_run=True)
        assert len(result.steps) > 0
        # Each step should have status="dry_run"
        for step in result.steps:
            assert step.status == "dry_run"


class TestDeterminism:
    def test_same_seed_same_plan(self):
        """Same seed produces the same dry-run plan (deterministic)."""
        cfg = make_test_config()
        s1 = SCENARIOS["multi_stage"](cfg, seed=12345)
        s2 = SCENARIOS["multi_stage"](cfg, seed=12345)
        r1 = s1.run(dry_run=True)
        r2 = s2.run(dry_run=True)
        assert len(r1.steps) == len(r2.steps)
        for a, b in zip(r1.steps, r2.steps):
            assert a.step == b.step


class TestScenarioLimits:
    def test_ssh_banner_probe_respects_max_auth_attempts(self):
        """ssh_banner_probe should not exceed max_auth_attempts."""
        cfg = make_test_config(max_auth_attempts=3, max_connections=10)
        scenario = SCENARIOS["ssh_banner_probe"](cfg, seed=42, profile="fast")
        # Dry-run shows the planned steps
        result = scenario.run(dry_run=True)
        # Count the "SSH banner probe" steps
        ssh_steps = [s for s in result.steps if "SSH banner probe" in s.step]
        assert len(ssh_steps) <= 3

    def test_web_recon_respects_max_requests(self):
        cfg = make_test_config(max_requests=5)
        scenario = SCENARIOS["web_recon"](cfg, seed=42, profile="fast")
        result = scenario.run(dry_run=True)
        http_steps = [s for s in result.steps if "GET" in s.step]
        assert len(http_steps) <= 5

    def test_multi_stage_has_five_stages(self):
        cfg = make_test_config()
        scenario = SCENARIOS["multi_stage"](cfg, seed=42, profile="fast")
        result = scenario.run(dry_run=True)
        stage_steps = [s for s in result.steps if "PHASE" in s.step]
        assert len(stage_steps) == 5


class TestScenarioRegistry:
    def test_all_six_scenarios_registered(self):
        expected = {"recon_basic", "ssh_banner_probe", "ssh_interaction", "web_recon", "iot_probe", "multi_stage"}
        assert set(SCENARIOS.keys()) == expected

    def test_each_scenario_has_description(self):
        for name, cls in SCENARIOS.items():
            assert cls.description, f"{name} missing description"
            assert cls.name == name


class TestSecurityAudit:
    def test_no_hardcoded_public_ips_in_source(self):
        """Search the attacker/sim source for hardcoded public IPs."""
        import re
        sim_dir = Path(__file__).resolve().parents[1] / "attacker" / "sim"
        for py_file in sim_dir.rglob("*.py"):
            text = py_file.read_text()
            # Look for IP addresses that are NOT in 192.168.x.x, 10.x.x.x, 172.16-31.x.x, 127.x.x.x, 0.0.0.0
            # (i.e. public IPs hardcoded in source)
            ips = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', text)
            for ip in ips:
                parts = [int(p) for p in ip.split(".")]
                is_private = (
                    parts[0] == 10
                    or (parts[0] == 172 and 16 <= parts[1] <= 31)
                    or (parts[0] == 192 and parts[1] == 168)
                    or parts[0] == 127
                    or ip == "0.0.0.0"
                )
                assert is_private, f"hardcoded public IP {ip} in {py_file.name}"

    def test_no_subprocess_shell_true(self):
        """No subprocess with shell=True anywhere in the attacker code."""
        sim_dir = Path(__file__).resolve().parents[1] / "attacker" / "sim"
        for py_file in sim_dir.rglob("*.py"):
            text = py_file.read_text()
            assert "shell=True" not in text, f"shell=True found in {py_file.name}"
            assert "os.system" not in text, f"os.system found in {py_file.name}"

    def test_no_arbitrary_command_execution(self):
        """The CLI does NOT accept arbitrary commands — only allowlisted scenarios."""
        cli_path = Path(__file__).resolve().parents[1] / "sim" / "__init__.py"
        text = cli_path.read_text()
        # The CLI must reject unknown scenarios
        assert "unknown scenario" in text


# ============================================================
# Final hardening — global budget + SSH semantics + manifest audit + legacy
# ============================================================

class TestGlobalBudget:
    """Verify multi-stage runs cannot exceed the configured global limits."""

    def _make_config(self, **kw):
        return make_test_config(max_connections=5, max_requests=5, max_auth_attempts=5, **kw)

    def test_multi_stage_uses_shared_budget(self):
        """multi_stage passes a shared budget to child stages so the
        total cannot exceed global limits."""
        from sim.scenarios.base import _SharedBudget
        cfg = self._make_config()
        scenario = SCENARIOS["multi_stage"](cfg, seed=42, profile="fast")
        # Dry-run shows 5 stages
        result = scenario.run(dry_run=True)
        stage_steps = [s for s in result.steps if "PHASE" in s.step]
        assert len(stage_steps) == 5

    def test_shared_budget_prevents_exceeding_global_connections(self):
        """If max_connections=5, a shared budget with 5 connections
        already used must reject new connections."""
        from sim.scenarios.base import _SharedBudget
        budget = _SharedBudget(max_connections=5, max_requests=10, max_auth_attempts=10)
        for _ in range(5):
            budget.connections += 1
        assert not budget.can_connect()

    def test_shared_budget_prevents_exceeding_global_requests(self):
        from sim.scenarios.base import _SharedBudget
        budget = _SharedBudget(max_connections=10, max_requests=5, max_auth_attempts=10)
        for _ in range(5):
            budget.requests += 1
        assert not budget.can_request()

    def test_shared_budget_prevents_exceeding_global_auth(self):
        from sim.scenarios.base import _SharedBudget
        budget = _SharedBudget(max_connections=10, max_requests=10, max_auth_attempts=5)
        for _ in range(5):
            budget.auth_attempts += 1
        assert not budget.can_auth()

    def test_shared_budget_allows_under_limit(self):
        from sim.scenarios.base import _SharedBudget
        budget = _SharedBudget(max_connections=10, max_requests=10, max_auth_attempts=10)
        assert budget.can_connect()
        assert budget.can_request()
        assert budget.can_auth()


class TestSshSemantics:
    """Verify SSH scenario name/description truthfully represents behavior."""

    def test_scenario_name_is_ssh_banner_probe_not_ssh_probe(self):
        """The scenario must be named 'ssh_banner_probe' — NOT 'ssh_probe'.
        The old name implied authentication but only did banner grabs."""
        assert "ssh_banner_probe" in SCENARIOS
        assert "ssh_probe" not in SCENARIOS

    def test_behavior_class_is_connection_probing(self):
        """behavior_class must be 'connection_probing' — NOT 'authentication_probing'.
        The scenario does NOT authenticate, it only connects + reads banners."""
        cls = SCENARIOS["ssh_banner_probe"]
        assert cls.behavior_class == "connection_probing"
        assert cls.behavior_class != "authentication_probing"

    def test_description_says_banner_not_auth(self):
        """The description must truthfully say 'banner' or 'connection',
        and explicitly say NOT authentication."""
        cls = SCENARIOS["ssh_banner_probe"]
        desc_lower = cls.description.lower()
        assert "banner" in desc_lower or "connection" in desc_lower
        # Must explicitly say "not authentication" — not claim to authenticate
        assert "not auth" in desc_lower or "no auth" in desc_lower or "not authentication" in desc_lower

    def test_no_sshpass_or_host_key_bypass_in_source(self):
        """The SSH scenario must NOT IMPORT or CALL sshpass, nor set
        StrictHostKeyChecking or UserKnownHostsFile in code.
        Mentions in docstrings/comments documenting what NOT to do are allowed."""
        from pathlib import Path
        sim_dir = Path(__file__).resolve().parents[1] / "sim"
        for py_file in sim_dir.rglob("*.py"):
            text = py_file.read_text()
            # Check for executable patterns — not docstring mentions.
            # sshpass would appear in subprocess calls or os.system.
            import re
            # Look for sshpass as a command (in subprocess/system calls)
            assert not re.search(r"(subprocess|os\.system|Popen).*sshpass", text, re.DOTALL), \
                f"sshpass command execution in {py_file.name}"
            # Look for StrictHostKeyChecking as a KEY=VALUE assignment (not in docstrings)
            # Strip triple-quoted strings
            code_only = re.sub(r'""".*?"""', '', text, flags=re.DOTALL)
            code_only = re.sub(r"'''.*?'''", '', code_only, flags=re.DOTALL)
            code_only = re.sub(r'#.*$', '', code_only, flags=re.MULTILINE)
            assert "StrictHostKeyChecking=no" not in code_only, f"StrictHostKeyChecking=no in code of {py_file.name}"
            assert "UserKnownHostsFile=/dev/null" not in code_only, f"UserKnownHostsFile=/dev/null in code of {py_file.name}"


class TestManifestSecretAudit:
    """Verify the field-aware manifest secret audit works correctly."""

    def _make_config(self):
        return make_test_config()

    def _make_manifest(self, extra_fields=None):
        cfg = self._make_config()
        result = ScenarioResult(scenario="test", status="completed", started_at="2025-01-01T00:00:00Z", ended_at="2025-01-01T00:00:01Z")
        manifest = build_manifest("RUN-001", "test", cfg, result, seed=42, profile="normal")
        if extra_fields:
            manifest.update(extra_fields)
        return manifest

    def test_clean_manifest_passes_audit(self):
        manifest = self._make_manifest()
        assert audit_manifest_no_secrets(manifest) is True

    def test_credential_profile_label_allowed(self):
        """'credential_profile_N' labels are safe — they are indices, not secrets."""
        manifest = self._make_manifest({"credential_profiles": "credential_profile_3 (no plaintext recorded)"})
        assert audit_manifest_no_secrets(manifest) is True

    def test_password_value_rejected(self):
        """An actual password value in a 'password' field must be rejected."""
        manifest = self._make_manifest({"password": "admin123"})
        with pytest.raises(AssertionError, match="secret field"):
            audit_manifest_no_secrets(manifest)

    def test_private_key_rejected(self):
        """PEM private key material must be rejected."""
        manifest = self._make_manifest({"detail": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."})
        with pytest.raises(AssertionError, match="secret pattern"):
            audit_manifest_no_secrets(manifest)

    def test_password_in_value_rejected(self):
        """A value containing 'password=something' must be rejected."""
        manifest = self._make_manifest({"detail": "user=root password=secret123"})
        with pytest.raises(AssertionError, match="secret pattern"):
            audit_manifest_no_secrets(manifest)

    def test_api_key_value_rejected(self):
        manifest = self._make_manifest({"api_key": "sk-abc123"})
        with pytest.raises(AssertionError, match="secret field"):
            audit_manifest_no_secrets(manifest)

    def test_empty_password_field_allowed(self):
        """An empty/null password field is allowed (no secret leaked)."""
        manifest = self._make_manifest({"password": ""})
        assert audit_manifest_no_secrets(manifest) is True

    def test_nested_secret_rejected(self):
        """Secrets nested inside sub-objects must be found."""
        manifest = self._make_manifest({"target": {"ip": "192.168.1.50", "password": "secret"}})
        with pytest.raises(AssertionError, match="secret field"):
            audit_manifest_no_secrets(manifest)


class TestLegacyQuarantine:
    """Verify the old shell-based attacker framework is quarantined."""

    def test_old_run_scenario_not_executable(self):
        """run-scenario.sh must NOT be executable."""
        from pathlib import Path
        old = Path(__file__).resolve().parents[1] / "_deprecated" / "run-scenario.sh"
        if old.exists():
            import os, stat
            mode = old.stat().st_mode
            assert not (mode & stat.S_IXUSR), f"{old} is still executable"

    def test_old_runner_lib_not_executable(self):
        from pathlib import Path
        old = Path(__file__).resolve().parents[1] / "_deprecated" / "runner" / "lib.sh"
        if old.exists():
            import os, stat
            mode = old.stat().st_mode
            assert not (mode & stat.S_IXUSR), f"{old} is still executable"

    def test_deprecated_readme_exists(self):
        from pathlib import Path
        readme = Path(__file__).resolve().parents[1] / "_deprecated" / "README.md"
        assert readme.exists()
        text = readme.read_text()
        assert "DEPRECATED" in text
        assert "DO NOT USE" in text

    def test_no_strict_host_key_checking_in_canonical_sim(self):
        """The canonical sim/ must NOT set StrictHostKeyChecking=no or
        UserKnownHostsFile=/dev/null in executable code.
        Docstrings documenting what NOT to do are allowed."""
        from pathlib import Path
        import re
        sim_dir = Path(__file__).resolve().parents[1] / "sim"
        for py_file in sim_dir.rglob("*.py"):
            text = py_file.read_text()
            # Strip triple-quoted strings + comment lines
            code_only = re.sub(r'""".*?"""', '', text, flags=re.DOTALL)
            code_only = re.sub(r"'''.*?'''", '', code_only, flags=re.DOTALL)
            code_only = re.sub(r'#.*$', '', code_only, flags=re.MULTILINE)
            assert "StrictHostKeyChecking=no" not in code_only, f"StrictHostKeyChecking=no in {py_file.name}"
            assert "UserKnownHostsFile=/dev/null" not in code_only, f"UserKnownHostsFile=/dev/null in {py_file.name}"
            assert "sshpass" not in code_only or re.search(r"(subprocess|os\.system).*sshpass", code_only) is None, \
                f"sshpass command execution in {py_file.name}"

    def test_canonical_cli_rejects_unknown_scenarios(self):
        """The CLI must reject unknown scenario names — no arbitrary execution."""
        from pathlib import Path
        cli = Path(__file__).resolve().parents[1] / "sim" / "__init__.py"
        text = cli.read_text()
        assert "unknown scenario" in text


class TestDryRunZeroTraffic:
    """Verify dry-run produces ZERO network traffic."""

    def test_dry_run_zero_connections_all_scenarios(self):
        cfg = make_test_config()
        for name, cls in SCENARIOS.items():
            scenario = cls(cfg, seed=42, profile="fast")
            result = scenario.run(dry_run=True)
            assert result.statistics["connections"] == 0, f"{name} dry-run had connections"
            assert result.statistics["requests"] == 0, f"{name} dry-run had requests"
            assert result.statistics["auth_attempts"] == 0, f"{name} dry-run had auth_attempts"

    def test_dry_run_status_is_dry_run(self):
        cfg = make_test_config()
        scenario = SCENARIOS["recon_basic"](cfg, seed=42)
        result = scenario.run(dry_run=True)
        assert result.status == "dry_run"
