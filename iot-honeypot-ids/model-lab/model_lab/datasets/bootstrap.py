"""Bootstrap a clearly-labeled SYNTHETIC dataset for offline development.

Usage:
    python -m model_lab.datasets.bootstrap --out datasets/v1/sessions.csv

The generated sessions all carry label_source='SYNTHETIC' so the platform
can never confuse them with real captures.
"""
from __future__ import annotations

import argparse
import csv
import random
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List

# Import feature names from the shared ML package
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "dashboard" / "ml"))
from features import FEATURE_NAMES  # type: ignore  # noqa: E402


def _make_session(label: str, seed: int) -> dict:
    rng = random.Random(seed)
    base = {n: 0.0 for n in FEATURE_NAMES}
    base["session_id"] = f"syn-{label}-{seed:04d}-{uuid.uuid4().hex[:8]}"
    base["label"] = label
    base["label_source"] = "SYNTHETIC"
    base["campaign_id"] = f"syn-campaign-{seed:04d}"
    base["scenario_id"] = f"syn-{label}"
    base["dataset_version"] = "v1"
    base["created_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")

    if label == "benign":
        base["event_count"] = rng.randint(1, 4)
        base["duration_s"] = rng.randint(2, 30)
        base["http_request_count"] = base["event_count"]
        base["http_uri_diversity"] = base["event_count"]
    elif label == "reconnaissance":
        base["event_count"] = rng.randint(8, 25)
        base["duration_s"] = rng.randint(20, 120)
        base["http_request_count"] = base["event_count"]
        base["http_uri_diversity"] = rng.randint(6, 15)
        base["is_recon_only"] = 1.0
        base["request_rate_per_min"] = base["http_request_count"] / max(base["duration_s"] / 60.0, 1e-6)
    elif label == "brute_force":
        base["event_count"] = rng.randint(20, 50)
        base["auth_attempts"] = base["event_count"]
        base["auth_successes"] = rng.randint(0, 2)
        base["auth_failure_ratio"] = (base["auth_attempts"] - base["auth_successes"]) / max(base["auth_attempts"], 1)
        base["unique_usernames"] = rng.randint(5, 15)
        base["auth_failure_rate_per_min"] = (base["auth_attempts"] - base["auth_successes"]) / max(base["duration_s"] / 60.0, 1e-6)
    elif label == "default_credentials":
        base["event_count"] = rng.randint(2, 5)
        base["auth_attempts"] = base["event_count"]
        base["auth_successes"] = 1.0
        base["auth_failure_ratio"] = (base["auth_attempts"] - 1) / max(base["auth_attempts"], 1)
        base["contains_default_credentials"] = 1.0
    elif label == "command_injection":
        base["event_count"] = rng.randint(4, 12)
        base["http_request_count"] = base["event_count"]
        base["contains_command_injection"] = 1.0
        base["command_count"] = rng.randint(1, 4)
        base["command_diversity"] = base["command_count"]
    elif label == "path_traversal":
        base["event_count"] = rng.randint(3, 10)
        base["http_request_count"] = base["event_count"]
        base["contains_path_traversal"] = 1.0
        base["http_uri_diversity"] = base["event_count"]
    elif label == "anomaly":
        # Deliberately odd: high event rate + weird port pattern + low auth
        base["event_count"] = rng.randint(50, 200)
        base["duration_s"] = rng.randint(5, 30)
        base["ports_touched"] = rng.randint(8, 20)
        base["devices_touched"] = rng.randint(3, 5)
        base["request_rate_per_min"] = base["event_count"] / max(base["duration_s"] / 60.0, 1e-6)
        base["time_between_events_mean_s"] = 0.05
    return base


LABELS = ["benign", "reconnaissance", "brute_force", "default_credentials",
          "command_injection", "path_traversal", "anomaly"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bootstrap a synthetic dataset")
    parser.add_argument("--out", required=True)
    parser.add_argument("--per-label", type=int, default=30)
    parser.add_argument("--sessions-per-campaign", type=int, default=5,
                       help="Number of sessions per campaign (default: 5)")
    args = parser.parse_args(argv)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    rows: List[dict] = []
    seed = 0
    campaign_counter = 0

    for label in LABELS:
        # Calculate how many campaigns we need for this label
        sessions_needed = args.per_label
        campaigns_needed = max(1, sessions_needed // args.sessions_per_campaign)

        for camp in range(campaigns_needed):
            campaign_id = f"syn-campaign-{label}-{campaign_counter:04d}"
            campaign_counter += 1

            # Generate sessions_per_campaign sessions for this campaign
            # with realistic within-campaign correlation
            sessions_in_campaign = args.sessions_per_campaign if camp < campaigns_needed - 1 else (sessions_needed - camp * args.sessions_per_campaign)

            # Generate a base profile for this campaign (shared characteristics)
            campaign_rng = random.Random(campaign_counter * 1000 + seed)
            base_event_count = campaign_rng.randint(10, 30)
            base_duration = campaign_rng.randint(20, 60)

            for s in range(sessions_in_campaign):
                row = _make_session(label, seed)
                # Override campaign_id to group sessions
                row["campaign_id"] = campaign_id
                # Add within-campaign variation (realistic correlation)
                # Sessions in the same campaign share similar but not identical patterns
                variation = random.Random(seed * 17 + s)
                row["event_count"] = int(float(row["event_count"]) * (0.8 + variation.random() * 0.4))
                row["duration_s"] = int(float(row["duration_s"]) * (0.7 + variation.random() * 0.6))
                rows.append(row)
                seed += 1

    fieldnames = ["session_id", "label", "label_source", "campaign_id", "scenario_id",
                  "dataset_version", "created_at"] + FEATURE_NAMES
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

    print(f"OK: wrote {len(rows)} synthetic sessions to {out_path}")
    print("All rows are clearly labeled label_source=SYNTHETIC — never confuse with real captures.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
