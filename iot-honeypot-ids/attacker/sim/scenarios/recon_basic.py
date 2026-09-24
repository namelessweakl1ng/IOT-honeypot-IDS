"""recon_basic — bounded reconnaissance against configured honeypot ports.

Only probes the explicitly configured TRAPSIG honeypot ports (SSH, camera, IoT).
Does NOT scan arbitrary port ranges. Does NOT perform broad network scanning.
"""
from __future__ import annotations

from .base import Scenario, ScenarioResult, StepResult


class ReconBasicScenario(Scenario):
    name = "recon_basic"
    behavior_class = "reconnaissance"
    description = "Bounded TCP probing of configured TRAPSIG honeypot ports"

    def _run(self, result: ScenarioResult) -> None:
        target = self.config.target_ip
        ports = [
            ("ssh", self.config.ssh_port),
            ("camera", self.config.camera_port),
            ("iot", self.config.iot_port),
        ]
        for svc_name, port in ports:
            self._check_interrupted()
            ok = self._tcp_probe(target, port)
            result.steps.append(StepResult(
                step=f"tcp_probe_{svc_name}",
                status="completed" if ok else "failed",
                detail=f"{target}:{port} ({svc_name})",
            ))
            self._delay()

    def _dry_run_steps(self):
        target = self.config.target_ip
        steps = []
        for i, (svc, port) in enumerate([
            ("ssh", self.config.ssh_port),
            ("camera", self.config.camera_port),
            ("iot", self.config.iot_port),
        ], 1):
            steps.append(StepResult(
                step=f"{i}. TCP probe {target}:{port} ({svc})",
                status="dry_run",
            ))
        steps.append(StepResult(
            step="MAX CONNECTIONS: 3",
            status="dry_run",
            detail=f"TIMEOUT: {self.config.scenario_timeout_seconds}s",
        ))
        return steps
