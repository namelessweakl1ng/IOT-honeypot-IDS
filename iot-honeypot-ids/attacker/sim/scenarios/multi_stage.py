"""multi_stage — orchestrates all safe scenarios in a deterministic order.

Produces multiple sessions/events from one attacker source, allowing TRAPSIG's
campaign correlator to reconstruct a campaign. Uses predefined scenario profiles
— NOT infinitely configurable.

GLOBAL BUDGET (final hardening):
  All child stages share a single _SharedBudget so the total run cannot
  exceed the configured global limits. Without this, each child would reset
  its own counters and the total could exceed the ceiling.
"""
from __future__ import annotations

from .base import Scenario, ScenarioResult, StepResult, _SharedBudget
from .recon_basic import ReconBasicScenario
from .ssh_banner_probe import SshBannerProbeScenario
from .web_recon import WebReconScenario
from .iot_probe import IotProbeScenario
from .ssh_interaction import SshInteractionScenario


# Predefined stage order — NOT configurable via CLI
_STAGES = [
    ("recon_basic", ReconBasicScenario),
    ("ssh_banner_probe", SshBannerProbeScenario),
    ("web_recon", WebReconScenario),
    ("iot_probe", IotProbeScenario),
    ("ssh_interaction", SshInteractionScenario),
]


class MultiStageScenario(Scenario):
    name = "multi_stage"
    behavior_class = "multi_stage_campaign"
    description = "Multi-stage campaign: recon -> ssh_banner_probe -> web_recon -> iot_probe -> ssh_interaction"

    def _run(self, result: ScenarioResult) -> None:
        # Create a SHARED budget — all child stages check against this
        # so the total cannot exceed the configured global limits.
        shared_budget = _SharedBudget(
            max_connections=self.config.max_connections,
            max_requests=self.config.max_requests,
            max_auth_attempts=self.config.max_auth_attempts,
        )
        for stage_name, stage_cls in _STAGES:
            self._check_interrupted()
            # Pass the shared budget to each child scenario
            stage = stage_cls(self.config, seed=self.seed, profile=self.profile, budget=shared_budget)
            stage_result = stage.run(dry_run=False)
            result.steps.append(StepResult(
                step=f"stage_{stage_name}",
                status=stage_result.status,
                detail=f"{len(stage_result.steps)} sub-steps",
            ))
            # Accumulate statistics from child stage
            for k in result.statistics:
                result.statistics[k] += stage_result.statistics.get(k, 0)
            # Update our local counters from the shared budget
            self._connections = shared_budget.connections
            self._requests = shared_budget.requests
            self._auth_attempts = shared_budget.auth_attempts
            self._delay()

    def _dry_run_steps(self):
        steps = []
        for i, (stage_name, _) in enumerate(_STAGES, 1):
            steps.append(StepResult(
                step=f"PHASE {i}: {stage_name}",
                status="dry_run",
            ))
        steps.append(StepResult(
            step=f"TOTAL STAGES: {len(_STAGES)}",
            status="dry_run",
            detail=f"TIMEOUT: {self.config.scenario_timeout_seconds}s",
        ))
        return steps
