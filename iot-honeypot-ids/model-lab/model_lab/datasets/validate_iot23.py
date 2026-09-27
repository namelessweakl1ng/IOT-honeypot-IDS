"""Validate prepared IoT-23 normalized flows and print a measured JSON audit.

Run from the nested project root:
    PYTHONPATH=model-lab python -m model_lab.datasets.validate_iot23 \
      research/datasets/iot23/prepared/normalized/flows.jsonl
"""
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

from .iot23_features import NUMERIC_FEATURES, feature_vector


REQUIRED = ("record_id", "source_scenario", "source_file", "source_row_id",
            "timestamp", "original_label", "project_label", "binary_label", "label_source", "data_category")


def validate(path: Path, expected_scenarios: int | None = 23) -> dict:
    if not path.is_file():
        raise ValueError(f"prepared IoT-23 JSONL not found: {path}")
    labels: Counter[str] = Counter()
    original: Counter[str] = Counter()
    scenarios: Counter[str] = Counter()
    missing: Counter[str] = Counter()
    invalid: list[dict] = []
    invalid_count = 0
    earliest = latest = None
    samples = 0
    temp = tempfile.NamedTemporaryFile(prefix="iot23-validate-", suffix=".sqlite", delete=False)
    temp.close()
    db = sqlite3.connect(temp.name)
    db.execute("CREATE TABLE ids (id TEXT PRIMARY KEY)")
    db.execute("CREATE TABLE flows (hash TEXT PRIMARY KEY)")
    duplicate_ids = duplicate_flows = 0
    feature_fields = ("timestamp", "source_ip", "destination_ip", "source_port", "destination_port", "protocol", *NUMERIC_FEATURES, "original_label", "original_detailed_label")
    try:
        with path.open(encoding="utf-8") as stream:
            for line_no, line in enumerate(stream, 1):
                try:
                    row = json.loads(line)
                    if not isinstance(row, dict):
                        raise ValueError("row is not a JSON object")
                    absent = [name for name in REQUIRED if name not in row or row[name] in (None, "")]
                    if absent:
                        raise ValueError("missing required values: " + ", ".join(absent))
                    if row["label_source"] != "EXTERNAL_DATASET":
                        raise ValueError("IoT-23 label_source must be EXTERNAL_DATASET")
                    if row.get("dataset_id") != "iot23":
                        raise ValueError("dataset_id must be iot23")
                    if row.get("dataset_version") not in ("1.0.0", "v1.0.0", "v1"):
                        raise ValueError("unexpected dataset_version")
                    if row["binary_label"] not in ("benign", "malicious", "unknown", "BENIGN", "MALICIOUS", "UNKNOWN"):
                        raise ValueError("invalid binary_label")
                    feature_vector(row)
                    stamp = datetime.fromisoformat(str(row["timestamp"]).replace("Z", "+00:00"))
                    if stamp.tzinfo is None:
                        raise ValueError("timestamp must include a timezone")
                    stamp = stamp.astimezone(timezone.utc).isoformat()
                    earliest = stamp if earliest is None else min(earliest, stamp)
                    latest = stamp if latest is None else max(latest, stamp)
                    samples += 1
                    scenario = str(row["source_scenario"])
                    scenarios[scenario] += 1
                    labels[str(row["project_label"])] += 1
                    original[str(row["original_label"])] += 1
                    for field in ("timestamp", "source_ip", "destination_ip", "source_port", "destination_port", "protocol", *NUMERIC_FEATURES):
                        if row.get(field) in (None, ""):
                            missing[field] += 1
                    try:
                        db.execute("INSERT INTO ids VALUES (?)", (str(row["record_id"]),))
                    except sqlite3.IntegrityError:
                        duplicate_ids += 1
                    identity = hashlib.sha256(json.dumps({key: row.get(key) for key in feature_fields}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                    try:
                        db.execute("INSERT INTO flows VALUES (?)", (identity,))
                    except sqlite3.IntegrityError:
                        duplicate_flows += 1
                except (json.JSONDecodeError, ValueError, TypeError, OverflowError) as exc:
                    invalid_count += 1
                    if len(invalid) < 100:
                        invalid.append({"line": line_no, "reason": str(exc)})
        db.commit()
    finally:
        db.close()
        Path(temp.name).unlink(missing_ok=True)
    result = {"dataset": "IoT-23", "dataset_version": "1.0.0", "data_category": "PUBLIC_DATASET",
              "path": str(path.resolve()), "samples": samples, "scenarios": dict(sorted(scenarios.items())),
              "scenario_count": len(scenarios), "mapped_label_counts": dict(sorted(labels.items())),
              "original_label_counts": dict(sorted(original.items())),
              "timestamp_range": {"earliest_utc": earliest, "latest_utc": latest},
              "missing_values": dict(sorted(missing.items())),
              "duplicates": {"record_ids": duplicate_ids, "exact_flow_measurements": duplicate_flows},
              "invalid_row_count": invalid_count, "invalid_rows": invalid,
              "expected_scenarios": expected_scenarios}
    if expected_scenarios is not None and len(scenarios) != expected_scenarios:
        result["validation_error"] = f"expected {expected_scenarios} scenarios, found {len(scenarios)}"
    if duplicate_ids:
        result["validation_error"] = f"{duplicate_ids} duplicate record_id value(s)"
    if samples == 0:
        result["validation_error"] = "no valid flow records"
    generated_manifest = path.parent.parent / "manifest.json"
    if generated_manifest.is_file():
        try:
            manifest = json.loads(generated_manifest.read_text(encoding="utf-8"))
            result["source_import_rejected_rows"] = int(manifest.get("source_import_rejected_rows", 0))
            result["dataset_version"] = str(manifest.get("dataset_version", result["dataset_version"]))
            if result["source_import_rejected_rows"]:
                result["validation_error"] = f"source importer rejected {result['source_import_rejected_rows']} row(s)"
        except (OSError, ValueError, TypeError):
            result["validation_error"] = "generated preparation manifest is malformed"
    if invalid_count:
        result["validation_error"] = f"{invalid_count} invalid row(s)"
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate prepared IoT-23 normalized flow JSONL")
    parser.add_argument("dataset", type=Path, help="path to prepared normalized/flows.jsonl")
    parser.add_argument("--expected-scenarios", type=int, default=23,
                        help="expected source scenario count (default: 23; use 0 to disable)")
    args = parser.parse_args(argv)
    expected = None if args.expected_scenarios == 0 else args.expected_scenarios
    try:
        result = validate(args.dataset, expected)
    except (OSError, ValueError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2), file=sys.stderr)
        return 2
    result["status"] = "FAIL" if "validation_error" in result else "PASS"
    print(json.dumps(result, indent=2))
    return 1 if result["status"] == "FAIL" else 0


if __name__ == "__main__":
    raise SystemExit(main())
