#!/usr/bin/env python3
"""Dataset audit — generates JSON + Markdown reports for a dataset.

Usage:
    python -m model_lab.dataset_audit --dataset model-lab/datasets/v1
    python -m scripts.research.audit_dataset --dataset model-lab/datasets/v1

Reports:
    - total sessions
    - total events
    - unique campaigns
    - class distribution
    - label provenance distribution
    - feature leakage audit
    - suspiciously constant features
    - temporal coverage
"""
import sys
import json
from pathlib import Path

# Add project root to path
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "shared"))
sys.path.insert(0, str(ROOT / "model-lab"))

from schemas.leakage_audit import audit_feature_set
from schemas.label_provenance import audit_dataset_labels, LabelSource


def audit_dataset(dataset_path: str) -> dict:
    """Audit a dataset directory."""
    p = Path(dataset_path)
    if not p.exists():
        return {"error": f"dataset not found: {dataset_path}"}

    # Load dataset rows (CSV or JSONL)
    rows = []
    csv_file = p / "sessions.csv"
    jsonl_file = p / "sessions.jsonl"
    if csv_file.exists():
        import pandas as pd
        df = pd.read_csv(csv_file)
        rows = df.to_dict("records")
    elif jsonl_file.exists():
        with open(jsonl_file) as f:
            for line in f:
                if line.strip():
                    rows.append(json.loads(line))
    else:
        return {"error": f"no sessions.csv or sessions.jsonl in {dataset_path}"}

    # Label provenance audit
    label_report = audit_dataset_labels(rows)

    # Feature leakage audit (if features are available)
    feature_names = []
    if rows:
        first = rows[0]
        feature_names = [k for k in first.keys() if k not in (
            "session_id", "label", "label_source", "scenario_id",
            "campaign_id", "dataset_origin", "start_time", "created_at"
        )]
    leakage_report = audit_feature_set(feature_names) if feature_names else {"error": "no features found"}

    # Class distribution
    from collections import Counter
    class_dist = Counter(r.get("label", "unknown") for r in rows)

    # Temporal coverage
    timestamps = [r.get("start_time") or r.get("created_at") for r in rows]
    timestamps = [t for t in timestamps if t]
    temporal = {
        "has_timestamps": len(timestamps) > 0,
        "earliest": min(timestamps) if timestamps else None,
        "latest": max(timestamps) if timestamps else None,
    }

    report = {
        "dataset_path": str(p),
        "total_sessions": len(rows),
        "class_distribution": dict(class_dist),
        "label_provenance": label_report,
        "feature_leakage_audit": leakage_report,
        "temporal_coverage": temporal,
        "is_safe_for_training": label_report.get("is_safe_for_training", False)
                                and leakage_report.get("is_safe_for_training", False),
    }
    return report


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Audit a TRAPSIG dataset")
    parser.add_argument("--dataset", required=True, help="path to dataset directory")
    parser.add_argument("--format", choices=["json", "markdown"], default="json")
    args = parser.parse_args()

    report = audit_dataset(args.dataset)

    if args.format == "json":
        print(json.dumps(report, indent=2, default=str))
    else:
        print(f"# Dataset Audit: {args.dataset}")
        print()
        print(f"- Total sessions: {report.get('total_sessions', 0)}")
        print(f"- Safe for training: {report.get('is_safe_for_training', False)}")
        print()
        print("## Class Distribution")
        for label, count in sorted(report.get("class_distribution", {}).items()):
            print(f"- {label}: {count}")
        print()
        print("## Label Provenance")
        for k, v in report.get("label_provenance", {}).items():
            print(f"- {k}: {v}")
        print()
        print("## Feature Leakage Audit")
        for k, v in report.get("feature_leakage_audit", {}).items():
            if k != "reports":
                print(f"- {k}: {v}")


if __name__ == "__main__":
    main()
