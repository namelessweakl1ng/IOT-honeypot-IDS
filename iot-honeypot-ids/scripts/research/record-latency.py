#!/usr/bin/env python3
"""Record T0-T9 lab timestamps without inventing or cross-clock subtraction."""
from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STAGES = [
    ("T0", "attacker generated request"), ("T1", "honeypot received request"),
    ("T2", "honeypot telemetry record emitted"), ("T3", "Filebeat forwarded event"),
    ("T4", "Logstash accepted and normalized event"), ("T5", "Elasticsearch indexed event"),
    ("T6", "session reconstruction completed"), ("T7", "feature extraction completed"),
    ("T8", "detector decision completed"), ("T9", "API/dashboard response returned"),
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timestamps", required=True, type=Path, help="JSON object mapping T0..T9 to ISO-8601 timestamps; omit unavailable stages")
    parser.add_argument("--context", required=True, type=Path, help="JSON containing campaign_id, event_id, session_id, detection_id, host_id, and run context")
    parser.add_argument("--clock-sync-status", choices=("synchronized", "unsynchronized", "unknown"), default="unknown")
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()
    timestamps = json.loads(args.timestamps.read_text(encoding="utf-8"))
    context = json.loads(args.context.read_text(encoding="utf-8"))
    required_context = ("campaign_id", "event_id", "session_id", "detection_id", "run_id", "host_id")
    missing_context = [key for key in required_context if key not in context or context[key] in (None, "")]
    if missing_context:
        raise SystemExit("ERROR: context must identify these fields; use NOT MEASURED where no ID exists: " + ", ".join(missing_context))
    normalized = {}
    for stage, _meaning in STAGES:
        value = timestamps.get(stage)
        if value in (None, "", "NOT MEASURED"):
            normalized[stage] = {"timestamp_utc": None, "status": "NOT MEASURED"}
            continue
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise SystemExit(f"ERROR: {stage} must have an explicit timezone")
        normalized[stage] = {"timestamp_utc": parsed.astimezone(timezone.utc).isoformat(), "status": "MEASURED"}
    durations = {}
    for index in range(len(STAGES) - 1):
        left, right = STAGES[index][0], STAGES[index + 1][0]
        if args.clock_sync_status != "synchronized" or not normalized[left]["timestamp_utc"] or not normalized[right]["timestamp_utc"]:
            durations[f"{left}_{right}_ms"] = "NOT MEASURED"
        else:
            first = datetime.fromisoformat(normalized[left]["timestamp_utc"])
            second = datetime.fromisoformat(normalized[right]["timestamp_utc"])
            delta = (second - first).total_seconds() * 1000
            if delta < 0:
                durations[f"{left}_{right}_ms"] = "INVALID_CLOCK_ORDER"
            else:
                durations[f"{left}_{right}_ms"] = round(delta, 3)
    try:
        commit = subprocess.check_output(["git", "-C", str(ROOT.parent), "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        commit = "UNKNOWN"
    measured_count = sum(v["status"] == "MEASURED" for v in normalized.values())
    artifact = {"status": "MEASURED" if measured_count == len(STAGES) else "PARTIAL" if measured_count else "NOT RUN",
                "data_category": "CONTROLLED_LAB", "context": context, "clock_sync_status": args.clock_sync_status,
                "software_commit": commit, "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
                "stages": {stage: {"meaning": meaning, **normalized[stage]} for stage, meaning in STAGES},
                "adjacent_durations_ms": durations,
                "limitations": ["Cross-host durations are calculated only when clock_sync_status is synchronized.", "A missing timestamp is NOT MEASURED, never zero."]}
    out = args.output or ROOT / "research" / "measurements" / f"latency-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    print(f"Latency artifact: {out}")
    print(json.dumps({"status": artifact["status"], "measured_stages": measured_count, "clock_sync_status": args.clock_sync_status, "durations": durations}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
