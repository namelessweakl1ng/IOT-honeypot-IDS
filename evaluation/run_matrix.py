"""Plan, then explicitly execute repeated bounded scenarios through the API."""

import argparse
import json
import random
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from attacks.runner.run import run
from backend.app.services.scenarios import ScenarioCatalog

from .http import request_json

RESULTS = Path(__file__).parent / "results"


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description="Plan or execute a bounded TRAPSIG evaluation matrix")
    value.add_argument("--api-url", required=True)
    value.add_argument("--attacker-ip", required=True)
    value.add_argument("--target-ip", required=True)
    value.add_argument("--repetitions", type=int, default=5, choices=range(1, 21), metavar="1..20")
    value.add_argument("--scenario", action="append", default=[])
    group = value.add_mutually_exclusive_group()
    group.add_argument("--all-attacks", action="store_true")
    group.add_argument("--all-controls", action="store_true")
    group.add_argument("--all-evaluation", action="store_true")
    value.add_argument("--shuffle", action="store_true")
    value.add_argument("--seed", type=int)
    value.add_argument("--execute", action="store_true", help="required to perform network actions")
    return value


def make_plan(args) -> list[dict]:
    catalog = ScenarioCatalog().load()
    selected = list(args.scenario)
    if args.all_attacks:
        selected += [item.id for item in catalog.values() if item.trial_kind == "attack"]
    if args.all_controls:
        selected += [item.id for item in catalog.values() if item.trial_kind == "control"]
    if args.all_evaluation:
        selected += list(catalog)
    selected = list(dict.fromkeys(selected))
    if not selected:
        raise ValueError("select --scenario or an --all-* option")
    unknown = set(selected) - set(catalog)
    if unknown:
        raise ValueError(f"unknown scenarios: {', '.join(sorted(unknown))}")
    plan = [
        {"scenario_id": scenario_id, "trial_kind": catalog[scenario_id].trial_kind, "replicate": replicate}
        for replicate in range(1, args.repetitions + 1)
        for scenario_id in selected
    ]
    if args.shuffle:
        if args.seed is None:
            raise ValueError("--shuffle requires --seed so ordering is reproducible")
        random.Random(args.seed).shuffle(plan)
    return plan


def execute(args, plan: list[dict]) -> Path:
    identifier = "EVAL-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    directory = RESULTS / identifier
    directory.mkdir(parents=True, exist_ok=False)
    manifest = {
        "evaluation_run_id": identifier,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "finished_at": None,
        "target": args.target_ip,
        "attacker_ip": args.attacker_ip,
        "requested_repetitions": args.repetitions,
        "scenario_ids": list(dict.fromkeys(entry["scenario_id"] for entry in plan)),
        "scenario_order": plan,
        "shuffle_seed": args.seed if args.shuffle else None,
        "software_revision": subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=False).stdout.strip() or None,
        "experiments": [],
    }
    path = directory / "evaluation-session.json"
    for number, entry in enumerate(plan, 1):
        scenario_id = entry["scenario_id"]
        created = request_json(
            f"{args.api_url.rstrip('/')}/experiments",
            "POST",
            {
                "name": f"Evaluation {number}: {scenario_id}",
                "description": f"Controlled evaluation run {identifier}",
                "scenario_id": scenario_id,
                "attacker_ip": args.attacker_ip,
                "target_ip": args.target_ip,
                "evaluation_batch_id": identifier,
                "replicate": entry["replicate"],
            },
        )
        experiment_id = created["experiment_id"]
        try:
            request_json(f"{args.api_url.rstrip('/')}/experiments/{experiment_id}/start", "POST")
            run(scenario_id, args.target_ip, args.attacker_ip, experiment_id, args.api_url)
            final = request_json(f"{args.api_url.rstrip('/')}/experiments/{experiment_id}/finish", "POST")
        except Exception as exc:
            try:
                final = request_json(f"{args.api_url.rstrip('/')}/experiments/{experiment_id}/cancel", "POST")
            except Exception:
                final = {"experiment_id": experiment_id, "status": "error", "result": "INCONCLUSIVE"}
            final["local_error"] = str(exc)
        (directory / f"{experiment_id}.json").write_text(json.dumps(final, indent=2) + "\n")
        manifest["experiments"].append({"experiment_id": experiment_id, **entry, "status": final.get("status"), "result": final.get("result")})
        path.write_text(json.dumps(manifest, indent=2) + "\n")
    manifest["finished_at"] = datetime.now(timezone.utc).isoformat()
    path.write_text(json.dumps(manifest, indent=2) + "\n")
    return path


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    try:
        plan = make_plan(args)
    except ValueError as exc:
        parser().error(str(exc))
    print(json.dumps({"mode": "EXECUTE" if args.execute else "PLAN ONLY", "scenario_order": plan}, indent=2))
    if not args.execute:
        print("No network actions performed. Add --execute to run this plan.")
        return 0
    print(execute(args, plan))
    return 0


if __name__ == "__main__":
    sys.exit(main())
