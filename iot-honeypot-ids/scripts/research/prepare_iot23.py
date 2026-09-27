#!/usr/bin/env python3
"""Prepare real IoT-23 flows and produce measured audit artifacts."""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "model-lab"))
from model_lab.datasets.import_iot23 import discover_zeek_files, import_iot23  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    files = discover_zeek_files(args.input)
    if not files:
        raise SystemExit(f"ERROR: no conn.log.labeled files found below {args.input}")
    version = "1.0.0"
    imported = import_iot23(args.input, args.output, version)
    data_path = args.output / "normalized" / "flows.jsonl"
    if not data_path.is_file() or data_path.stat().st_size == 0:
        raise SystemExit("ERROR: importer produced no canonical flow records")

    labels: Counter[str] = Counter()
    originals: Counter[str] = Counter()
    binary_labels: Counter[str] = Counter()
    scenarios: Counter[str] = Counter()
    missing: Counter[str] = Counter()
    feature_stats = {name: {"count": 0, "sum": 0.0, "min": None, "max": None} for name in ("duration", "bytes_in", "bytes_out", "packets_in", "packets_out")}
    earliest = latest = None
    flow_hash = hashlib.sha256()
    temp_db = tempfile.NamedTemporaryFile(prefix="trapsig-iot23-audit-", suffix=".sqlite", delete=False)
    temp_db.close()
    db = sqlite3.connect(temp_db.name)
    db.execute("CREATE TABLE flow_hashes (hash TEXT PRIMARY KEY)")
    duplicate_count = 0
    with data_path.open(encoding="utf-8") as stream:
        for line in stream:
            row = json.loads(line)
            flow_hash.update(line.encode("utf-8"))
            labels[str(row.get("project_label", "UNMAPPED"))] += 1
            originals[str(row.get("original_label", ""))] += 1
            binary_labels[str(row.get("binary_label", "UNKNOWN"))] += 1
            scenarios[str(row.get("source_scenario", ""))] += 1
            for field in ("timestamp", "source_ip", "destination_ip", "protocol", "duration", "bytes_in", "bytes_out", "packets_in", "packets_out"):
                if row.get(field) in (None, ""):
                    missing[field] += 1
            for name, stats in feature_stats.items():
                value = row.get(name)
                if value is not None:
                    number = float(value)
                    stats["count"] += 1
                    stats["sum"] += number
                    stats["min"] = number if stats["min"] is None else min(stats["min"], number)
                    stats["max"] = number if stats["max"] is None else max(stats["max"], number)
            ts = row.get("timestamp")
            if ts:
                earliest = ts if earliest is None else min(earliest, ts)
                latest = ts if latest is None else max(latest, ts)
            measurement_fields = ("timestamp", "source_ip", "destination_ip", "source_port", "destination_port", "protocol", "duration", "bytes_in", "bytes_out", "packets_in", "packets_out", "original_label", "original_detailed_label")
            identity = hashlib.sha256(json.dumps({k: row.get(k) for k in measurement_fields}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            try:
                db.execute("INSERT INTO flow_hashes VALUES (?)", (identity,))
            except sqlite3.IntegrityError:
                duplicate_count += 1
    db.close()
    Path(temp_db.name).unlink(missing_ok=True)
    if len(scenarios) != 23:
        raise SystemExit(f"ERROR: expected all 23 IoT-23 scenarios, found {len(scenarios)}; refusing to publish a partial benchmark manifest")
    for stats in feature_stats.values():
        count = stats.pop("count")
        total = stats.pop("sum")
        stats["mean"] = total / count if count else None
    manifest = {
        "dataset_name": "IoT-23", "dataset_version": version, "data_category": "PUBLIC_DATASET",
        "source": "https://www.stratosphereips.org/datasets-iot23",
        "citation": "Sebastian Garcia, Agustin Parmisano, & Maria Jose Erquiaga. (2020). IoT-23: A labeled dataset with malicious and benign IoT network traffic (Version 1.0.0) [Data set]. Zenodo. https://doi.org/10.5281/zenodo.4743746",
        "source_file_count": len(files), "source_checksum": imported.get("source_checksum"),
        "source_import_rejected_rows": imported.get("records_rejected", 0),
        "prepared_jsonl_sha256": flow_hash.hexdigest(), "record_count": sum(labels.values()),
        "scenario_count": len(scenarios), "scenario_distribution": dict(sorted(scenarios.items())),
        "class_distribution": dict(sorted(binary_labels.items())),
        "benign_count": binary_labels.get("benign", 0), "malicious_count": binary_labels.get("malicious", 0),
        "project_label_distribution": dict(sorted(labels.items())),
        "original_label_distribution": dict(sorted(originals.items())),
        "binary_label_distribution": dict(sorted(binary_labels.items())),
        "label_summary": {"original_label_distribution": dict(sorted(originals.items())), "project_label_distribution": dict(sorted(labels.items())), "binary_label_distribution": dict(sorted(binary_labels.items()))},
        "feature_summary": feature_stats,
        "missing_values": dict(sorted(missing.items())), "missing_values_summary": dict(sorted(missing.items())),
        "exact_duplicate_rows": duplicate_count, "duplicate_summary": {"exact_flow_rows": duplicate_count},
        "time_range_utc": {"earliest": earliest, "latest": latest},
        "feature_version": "iot23-flow-v1", "label_source": "EXTERNAL_DATASET",
        "dataset_card": "docs/research/datasets/IOT23_DATASET_CARD.md",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "raw_data_path": str(args.input.resolve()), "prepared_data_path": str(data_path.resolve()),
        "verification_status": "PREPARED_FROM_LOCAL_DATA",
        "limitations": ["IoT-23 is network-flow data, not Pi honeypot telemetry.", "Scenario-level split must be applied by the experiment runner.", "Labels are analyst-derived dataset labels, not TRAPSIG detector output."],
    }
    prepared_manifest = args.output / "manifest.json"
    prepared_manifest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    out_manifest = ROOT / "research" / "datasets" / "iot23" / "manifest.json"
    out_manifest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    lines = ["# IoT-23 preparation summary", "", f"- Flows: {manifest['record_count']}", f"- Scenarios: {manifest['scenario_count']}", f"- Exact duplicate rows: {duplicate_count}", f"- Earliest UTC: {earliest}", f"- Latest UTC: {latest}", "- Project label distribution:"]
    lines += [f"  - {label}: {count}" for label, count in sorted(labels.items())]
    lines += ["", "Values above were calculated from this local preparation run; they are not prefilled benchmark results."]
    text = "\n".join(lines) + "\n"
    (args.output / "summary.md").write_text(text, encoding="utf-8")
    (ROOT / "research" / "datasets" / "iot23" / "summary.md").write_text(text, encoding="utf-8")
    print(f"Prepared {manifest['record_count']} IoT-23 flows from {manifest['scenario_count']} scenarios.")
    print(f"Manifest: {out_manifest}")
    print(f"Summary: {ROOT / 'research' / 'datasets' / 'iot23' / 'summary.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
