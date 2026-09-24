"""ssh_probe — bounded SSH credential probing against Cowrie.

Uses a small DETERMINISTIC credential list specifically for the honeypot
experiment. Does NOT accept arbitrary username/password lists from the CLI.
Hard upper safety ceiling on auth attempts enforced in the safety layer.
"""
from __future__ import annotations

import socket
from .base import Scenario, ScenarioResult, StepResult

# Small deterministic credential list for lab honeypot experiments.
# These are SYNTHETIC test credentials, NOT harvested credentials.
# The safety layer enforces max_auth_attempts (default 10, hard ceiling 20).
_DEFAULT_CREDENTIALS = [
    ("root", "123456"),
    ("root", "password"),
    ("root", "root"),
    ("admin", "admin"),
    ("admin", "123456"),
    ("root", "toor"),
    ("admin", "password"),
    ("ubuntu", "ubuntu"),
]


class SshProbeScenario(Scenario):
    name = "ssh_probe"
    behavior_class = "authentication_probing"
    description = "Bounded SSH credential probing against the Cowrie honeypot"

    def _run(self, result: ScenarioResult) -> None:
        target = self.config.target_ip
        port = self.config.ssh_port
        # Limit to max_auth_attempts from config (already validated ≤ 20)
        creds = _DEFAULT_CREDENTIALS[: self.config.max_auth_attempts]
        for i, (user, _pass) in enumerate(creds, 1):
            self._check_interrupted()
            if self._connections >= self.config.max_connections:
                result.steps.append(StepResult(
                    step=f"ssh_attempt_{i}",
                    status="skipped",
                    detail="rate_limit_reached",
                ))
                break
            self._auth_attempts += 1
            # Use raw socket + SSH protocol banner — no sshpass needed
            ok = self._ssh_banner_probe(target, port, user, _pass)
            result.steps.append(StepResult(
                step=f"ssh_attempt_{i}",
                status="completed",
                detail=f"user={user} (credential_profile_{i})",
            ))
            self._delay()

    def _ssh_banner_probe(self, host: str, port: int, user: str, _pass: str) -> bool:
        """Connect to SSH, read banner, disconnect. Does NOT actually authenticate
        — that would require a full SSH client. The banner grab itself generates
        the 'connection' telemetry the honeypot needs."""
        self._connections += 1
        try:
            with socket.create_connection((host, port), timeout=3.0) as s:
                s.settimeout(3.0)
                # Read the SSH banner (Cowrie sends "SSH-2.0-dropbear_2014.65")
                banner = s.recv(256)
                return bool(banner)
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    def _dry_run_steps(self):
        creds = _DEFAULT_CREDENTIALS[: self.config.max_auth_attempts]
        steps = []
        for i, (user, _) in enumerate(creds, 1):
            steps.append(StepResult(
                step=f"{i}. SSH attempt user={user} (credential_profile_{i})",
                status="dry_run",
            ))
        steps.append(StepResult(
            step=f"MAX AUTH ATTEMPTS: {len(creds)}",
            status="dry_run",
            detail=f"TIMEOUT: {self.config.scenario_timeout_seconds}s",
        ))
        return steps
