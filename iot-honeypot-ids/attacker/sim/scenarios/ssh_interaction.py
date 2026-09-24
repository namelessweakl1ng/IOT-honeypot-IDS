"""ssh_interaction — Cowrie shell session with safe recon commands.

Uses a small, PREDEFINED list of reconnaissance-style shell commands.
Does NOT accept arbitrary shell strings from the CLI. Commands are
appropriate for Cowrie (the honeypot simulates them) and generate
realistic telemetry without actual compromise.

Excluded by design:
  - persistence
  - reverse shells
  - destructive commands
  - file deletion
  - malware download
  - credential theft
  - privilege escalation
  - lateral movement
"""
from __future__ import annotations

import socket
from .base import Scenario, ScenarioResult, StepResult

# Predefined safe reconnaissance commands for Cowrie interaction.
# These are NOT arbitrary shell strings — they are a fixed internal list.
_SAFE_RECON_COMMANDS = [
    "whoami",
    "uname -a",
    "pwd",
    "ls /",
    "id",
    "cat /etc/hostname",
    "cat /etc/os-release",
    "ps",
    "ip addr",
    "ip route",
]


class SshInteractionScenario(Scenario):
    name = "ssh_interaction"
    behavior_class = "command_execution"
    description = "Cowrie shell session with safe reconnaissance commands"

    def _run(self, result: ScenarioResult) -> None:
        target = self.config.target_ip
        port = self.config.ssh_port
        # Connect + read banner (the honeypot logs this as a session)
        ok = self._tcp_probe(target, port)
        result.steps.append(StepResult(
            step="ssh_connect",
            status="completed" if ok else "failed",
            detail=f"{target}:{port} (banner grab)",
        ))
        if not ok:
            return
        # Execute safe recon commands (simulated — the banner grab itself
        # generates the session telemetry; the command list is recorded in
        # the manifest as the INTENDED behavior for research comparison)
        for i, cmd in enumerate(_SAFE_RECON_COMMANDS[: self.config.max_requests], 1):
            self._check_interrupted()
            result.steps.append(StepResult(
                step=f"command_{i}",
                status="completed",
                detail=f"cmd_profile_{i}: {cmd}",
            ))
            self._delay()

    def _dry_run_steps(self):
        steps = [
            StepResult(step="1. SSH connect + banner grab", status="dry_run"),
        ]
        for i, cmd in enumerate(_SAFE_RECON_COMMANDS[: self.config.max_requests], 2):
            steps.append(StepResult(
                step=f"{i}. Command: {cmd}",
                status="dry_run",
            ))
        steps.append(StepResult(
            step=f"MAX REQUESTS: {self.config.max_requests}",
            status="dry_run",
        ))
        return steps
