"""Attack simulator runner — orchestrates scenario execution + manifest writing."""
from __future__ import annotations

import sys
from typing import Optional

from .config import ExperimentConfig, load_config
from .manifest import build_manifest, generate_run_id, write_manifest
from .safety import SafetyRefusal, validate_limits, validate_scenario, validate_target
from .scenarios import SCENARIOS
from .scenarios.base import Scenario


def run_scenario(
    scenario_name: str,
    config: ExperimentConfig,
    seed: int = 42,
    profile: str = "normal",
    dry_run: bool = False,
    manifests_dir: str = "manifests",
    yes: bool = False,
) -> dict:
    """Run a scenario with full pre-flight validation.

    Returns the manifest dict.
    """
    # Pre-flight validation
    safety = config.to_safety_config()
    validate_limits(safety)
    validate_target(config.target_ip, safety)
    validate_scenario(scenario_name, safety)

    # Display summary + require confirmation (unless --yes or --dry-run)
    print(config.summary())
    print()
    print(f"SCENARIO: {scenario_name}")
    print()

    # Compute max operations for display
    if scenario_name == "ssh_probe":
        max_ops = min(config.max_auth_attempts, 8)
        print(f"MAX AUTH ATTEMPTS: {max_ops}")
    elif scenario_name == "multi_stage":
        max_ops = 5  # 5 stages
        print(f"MAX STAGES: {max_ops}")
    else:
        max_ops = min(config.max_requests, 14)
        print(f"MAX OPERATIONS: {max_ops}")
    print(f"TIMEOUT: {config.scenario_timeout_seconds} seconds")
    print()
    print("This traffic is restricted to the configured TRAPSIG lab target.")
    print()

    if not yes and not dry_run:
        resp = input("Continue? [y/N] ").strip().lower()
        if resp != "y":
            print("ABORTED by user.")
            return {"status": "aborted", "scenario": scenario_name}

    # Execute the scenario
    scenario_cls = SCENARIOS[scenario_name]
    scenario = scenario_cls(config, seed=seed, profile=profile)
    result = scenario.run(dry_run=dry_run)

    # Build + write manifest
    run_id = generate_run_id()
    manifest = build_manifest(run_id, scenario_name, config, result, seed, profile)

    # Write manifest (even for dry-run, so the operator can inspect the plan)
    manifest_path = write_manifest(manifest, manifests_dir)
    print(f"\nManifest: {manifest_path}")
    print(f"Status:   {result.status}")
    return manifest
