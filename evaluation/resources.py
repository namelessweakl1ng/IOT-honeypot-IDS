"""Read-only local Docker resource sampler."""

import argparse
import csv
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

UNITS = {"B": 1, "KB": 1000, "MB": 1000**2, "GB": 1000**3, "TB": 1000**4, "KIB": 1024, "MIB": 1024**2, "GIB": 1024**3, "TIB": 1024**4}
FIELDS = [
    "timestamp",
    "host_label",
    "container_name",
    "cpu_percent",
    "memory_usage_bytes",
    "memory_limit_bytes",
    "memory_percent",
    "network_rx_bytes",
    "network_tx_bytes",
    "block_read_bytes",
    "block_write_bytes",
    "pids",
]


def quantity(value: str) -> int:
    match = re.fullmatch(r"\s*([0-9]+(?:\.[0-9]+)?)\s*([A-Za-z]+)\s*", value)
    if not match or match.group(2).upper() not in UNITS:
        raise ValueError(f"unsupported Docker quantity: {value!r}")
    return round(float(match.group(1)) * UNITS[match.group(2).upper()])


def pair(value: str) -> tuple[int, int]:
    left, right = value.split("/", 1)
    return quantity(left), quantity(right)


def parse_stat(item: dict, host_label: str, timestamp: str) -> dict:
    memory, memory_limit = pair(item["MemUsage"])
    network_rx, network_tx = pair(item["NetIO"])
    block_read, block_write = pair(item["BlockIO"])

    def percent(value):
        return float(value.strip().removesuffix("%")) if value and value != "--" else None

    return {
        "timestamp": timestamp,
        "host_label": host_label,
        "container_name": item.get("Name") or item.get("Container"),
        "cpu_percent": percent(item.get("CPUPerc")),
        "memory_usage_bytes": memory,
        "memory_limit_bytes": memory_limit,
        "memory_percent": percent(item.get("MemPerc")),
        "network_rx_bytes": network_rx,
        "network_tx_bytes": network_tx,
        "block_read_bytes": block_read,
        "block_write_bytes": block_write,
        "pids": int(item["PIDs"]) if item.get("PIDs") else None,
    }


def sample(host_label: str) -> list[dict]:
    command = ["docker", "stats", "--no-stream", "--format", "{{json .}}"]
    result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or f"docker stats exited {result.returncode}")
    timestamp = datetime.now(timezone.utc).isoformat()
    return [parse_stat(json.loads(line), host_label, timestamp) for line in result.stdout.splitlines() if line.strip()]


def main():
    parser = argparse.ArgumentParser(description="Sample local Docker containers without modifying them")
    parser.add_argument("--host-label", required=True)
    parser.add_argument("--interval", type=float, default=1)
    parser.add_argument("--duration", type=float, default=120)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.interval <= 0 or args.duration <= 0:
        parser.error("interval and duration must be positive")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + args.duration
    with args.output.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader()
        try:
            while time.monotonic() < deadline:
                try:
                    writer.writerows(sample(args.host_label))
                except (OSError, subprocess.SubprocessError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
                    print(f"WARNING: Docker stats sample skipped: {exc}", file=sys.stderr)
                stream.flush()
                time.sleep(min(args.interval, max(0, deadline - time.monotonic())))
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
