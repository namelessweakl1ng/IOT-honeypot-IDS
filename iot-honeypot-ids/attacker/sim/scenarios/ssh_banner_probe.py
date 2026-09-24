"""ssh_banner_probe — bounded SSH banner/connection probing against Cowrie.

TRUTHFUL SEMANTICS (final hardening):
  This scenario does NOT perform SSH authentication. It performs bounded
  TCP connections to the Cowrie SSH port and reads the SSH banner. This
  generates connection-level telemetry (cowrie.session.connect events) that
  TRAPSIG can observe.

  The previous implementation called itself "ssh_probe" with behavior_class
  "authentication_probing" but only did banner grabs — a semantic lie. The
  name has been changed to truthfully represent what actually happens.

  If genuine SSH authentication is needed in the future, it must:
    - use a maintained SSH client library (paramiko)
    - enforce strict host-key verification (NEVER StrictHostKeyChecking=no)
    - NEVER use UserKnownHostsFile=/dev/null
    - NEVER use sshpass
    - use only the synthetic credential set
    - be bounded by max_auth_attempts

  For now, this banner-probe scenario generates the connection telemetry
  the honeypot needs without requiring SSH client libraries or host-key bypass.

  The manifest records credential_profile identifiers (by index) for research
  comparison — these represent the INTENDED credential profile, not actual
  authentication attempts. The scenario itself only connects + reads banners.
"""
from __future__ import annotations

import socket
from .base import Scenario, ScenarioResult, StepResult

# Small deterministic credential PROFILE list for lab honeypot experiments.
# These are SYNTHETIC test credentials, NOT harvested credentials.
# The safety layer enforces max_auth_attempts (default 10, hard ceiling 20).
# NOTE: these profiles are recorded in the manifest by INDEX ONLY (e.g.
# "credential_profile_3") — never as plaintext credentials.
_CREDENTIAL_PROFILES = [
    ("root", "123456"),
    ("root", "password"),
    ("root", "root"),
    ("admin", "admin"),
    ("admin", "123456"),
    ("root", "toor"),
    ("admin", "password"),
    ("ubuntu", "ubuntu"),
]


class SshBannerProbeScenario(Scenario):
    """Bounded SSH banner/connection probing.

    Connects to the Cowrie SSH port and reads the SSH banner. Each connection
    is associated with a credential profile (by index) for research comparison,
    but NO actual SSH authentication is performed.

    behavior_class = "connection_probing" (truthful, NOT "authentication_probing")
    """
    name = "ssh_banner_probe"
    behavior_class = "connection_probing"
    description = "Bounded SSH banner/connection probing (NOT authentication — connects + reads banner only)"

    def _run(self, result: ScenarioResult) -> None:
        target = self.config.target_ip
        port = self.config.ssh_port
        # Limit to max_auth_attempts from config (already validated ≤ 20).
        # This is the number of CONNECTION attempts (one per credential profile).
        profiles = _CREDENTIAL_PROFILES[: self.config.max_auth_attempts]
        for i, (user, _pass) in enumerate(profiles, 1):
            self._check_interrupted()
            if self._connections >= self.config.max_connections:
                result.steps.append(StepResult(
                    step=f"ssh_banner_probe_{i}",
                    status="skipped",
                    detail="rate_limit_reached",
                ))
                break
            self._auth_attempts += 1  # count as an auth-profile association
            ok = self._ssh_banner_probe(target, port)
            result.steps.append(StepResult(
                step=f"ssh_banner_probe_{i}",
                status="completed" if ok else "failed",
                detail=f"credential_profile_{i} (banner grab only, no auth)",
            ))
            self._delay()

    def _ssh_banner_probe(self, host: str, port: int) -> bool:
        """Connect to SSH, read banner, disconnect. Does NOT authenticate."""
        self._connections += 1
        try:
            with socket.create_connection((host, port), timeout=3.0) as s:
                s.settimeout(3.0)
                banner = s.recv(256)
                return bool(banner)
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    def _dry_run_steps(self):
        profiles = _CREDENTIAL_PROFILES[: self.config.max_auth_attempts]
        steps = []
        for i, (user, _) in enumerate(profiles, 1):
            steps.append(StepResult(
                step=f"{i}. SSH banner probe (credential_profile_{i})",
                status="dry_run",
            ))
        steps.append(StepResult(
            step=f"MAX AUTH PROFILES: {len(profiles)}",
            status="dry_run",
            detail=f"TIMEOUT: {self.config.scenario_timeout_seconds}s",
        ))
        return steps
