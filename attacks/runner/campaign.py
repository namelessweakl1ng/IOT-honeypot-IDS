"""Run a small, single-target behavioural test campaign against TRAPSIG."""

import argparse
import json
import random
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .run import run
from .safety import validate_target

DEFAULT_SCENARIOS = (
    "iot-controller-discovery",
    "mqtt-topic-enumeration",
    "multi-stage-pivot",
    "slow-cross-service",
)
MAX_SCENARIOS = 4


def run_campaign(target: str, scenarios: tuple[str, ...] = DEFAULT_SCENARIOS) -> dict:
    lab_subnet = __import__("os").environ.get("LAB_SUBNET", "")
    target = validate_target(target, lab_subnet)
    selected = tuple(scenarios)
    if not selected or len(selected) > MAX_SCENARIOS:
        raise ValueError(f"campaign must contain between 1 and {MAX_SCENARIOS} scenarios")
    if len(set(selected)) != len(selected):
        raise ValueError("scenario names must be unique")

    started = datetime.now(timezone.utc)
    results = []
    for index, scenario_id in enumerate(selected):
        results.append(run(scenario_id, target))
        if index + 1 < len(selected):
            # A short, bounded pause creates distinct temporal signatures without
            # flooding the target or escaping the fixed service/port allowlist.
            time.sleep(random.uniform(1.0, 2.5))

    summary = {
        "campaign_id": "CMP-" + uuid.uuid4().hex[:12],
        "target": target,
        "scenarios": list(selected),
        "start_time": started.isoformat(),
        "end_time": datetime.now(timezone.utc).isoformat(),
        "overall_status": "completed" if all(item["overall_status"] == "completed" for item in results) else "partial",
        "runs": results,
    }
    output = Path(__file__).parents[1] / "runs"
    output.mkdir(exist_ok=True)
    path = output / f"{summary['campaign_id']}.json"
    path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    summary["result_path"] = str(path)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a bounded TRAPSIG multi-stage lab campaign")
    parser.add_argument("--target", required=True, help="one honeypot IP inside LAB_SUBNET")
    parser.add_argument("--scenarios", nargs="+", choices=sorted(DEFAULT_SCENARIOS), default=list(DEFAULT_SCENARIOS))
    args = parser.parse_args()
    print(json.dumps(run_campaign(args.target, tuple(args.scenarios)), indent=2))


if __name__ == "__main__":
    main()
