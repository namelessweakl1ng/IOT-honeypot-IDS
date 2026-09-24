"""TRAPSIG Attack Simulator — CLI entry point.

Usage:
  ./trapsig_attack.py list
  ./trapsig_attack.py validate
  ./trapsig_attack.py recon_basic --config config.yaml --dry-run
  ./trapsig_attack.py multi_stage --config config.yaml --seed 12345 --profile normal

Safety:
  - Target must be inside configured lab CIDR
  - Ports must be in the allowlisted set
  - Scenarios must be in the allowlisted set
  - All limits bounded with hard safety ceilings
  - SIGINT/SIGTERM stops execution cleanly
"""
from __future__ import annotations

import argparse
import sys

from .config import load_config
from .runner import run_scenario
from .safety import SafetyRefusal
from .scenarios import SCENARIOS


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="trapsig_attack.py",
        description="TRAPSIG Attack Simulator — controlled honeypot experiments",
    )
    parser.add_argument("command", help="scenario name, 'list', or 'validate'")
    parser.add_argument("--config", default=None, help="YAML config file path")
    parser.add_argument("--dry-run", action="store_true", help="validate + show planned actions, no traffic")
    parser.add_argument("--seed", type=int, default=42, help="random seed for reproducibility")
    parser.add_argument("--profile", choices=["fast", "normal", "slow"], default="normal")
    parser.add_argument("--yes", action="store_true", help="skip confirmation prompt")
    args = parser.parse_args(argv)

    if args.command == "list":
        print("Available scenarios:")
        for name, cls in sorted(SCENARIOS.items()):
            print(f"  {name:20s}  {cls.description}")
        return 0

    if args.command == "validate":
        try:
            cfg = load_config(args.config)
            print(cfg.summary())
            print("\nVALIDATION: OK")
            return 0
        except SafetyRefusal as exc:
            print(f"VALIDATION FAILED: {exc}", file=sys.stderr)
            return 1

    if args.command not in SCENARIOS:
        print(f"ERROR: unknown scenario {args.command!r}", file=sys.stderr)
        print(f"Available: {', '.join(sorted(SCENARIOS.keys()))}", file=sys.stderr)
        return 2

    try:
        cfg = load_config(args.config)
        run_scenario(
            scenario_name=args.command,
            config=cfg,
            seed=args.seed,
            profile=args.profile,
            dry_run=args.dry_run,
            yes=args.yes,
        )
        return 0
    except SafetyRefusal as exc:
        print(f"\n{exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nINTERRUPTED by user.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
