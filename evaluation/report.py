"""Download measured data and render a conservative Markdown report."""

import argparse
import csv
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode

from backend.app.services.evaluation import descriptive_statistics

from .http import request_json, request_text


def fmt(value):
    return "— (Not measured)" if value is None else f"{value:.4f}" if isinstance(value, float) else str(value)


def resource_summary(paths: list[Path]) -> dict:
    if not paths:
        return {"status": "NOT_MEASURED"}
    groups = defaultdict(lambda: {"cpu_percent": [], "memory_usage_bytes": [], "memory_percent": []})
    invalid = 0
    for path in paths:
        with path.open(newline="") as stream:
            for row in csv.DictReader(stream):
                key = (row.get("host_label"), row.get("container_name"))
                if not all(key):
                    invalid += 1
                    continue
                for field in groups[key]:
                    try:
                        groups[key][field].append(float(row[field]))
                    except (KeyError, TypeError, ValueError):
                        invalid += 1
    containers = []
    for (host, container), values in sorted(groups.items()):
        stats = {
            field: {key: value for key, value in descriptive_statistics(samples).items() if key in {"count", "mean", "max", "p95"}}
            for field, samples in values.items()
        }
        containers.append(
            {
                "host_label": host,
                "container_name": container,
                "sample_count": max((len(value) for value in values.values()), default=0),
                "cpu_percent": stats["cpu_percent"],
                "memory_usage_bytes": stats["memory_usage_bytes"],
                "memory_percent": stats["memory_percent"],
            }
        )
    return {"status": "MEASURED" if containers else "NOT_MEASURED", "invalid_samples": invalid, "containers": containers}


def host_summary(paths: list[Path]) -> dict:
    if not paths:
        return {"status": "NOT_MEASURED"}
    hosts = [json.loads(path.read_text()) for path in paths]
    return {"status": "MEASURED" if hosts else "NOT_MEASURED", "hosts": hosts}


def measurement_status(summary: dict) -> dict[str, str]:
    cohorts = summary.get("cohorts", [])
    ingestion = sum(c.get("latency", {}).get("ingestion_latency_event_samples", {}).get("sample_count", 0) for c in cohorts)
    rates = sum(c.get("latency", {}).get("observed_event_rate", {}).get("count", 0) for c in cohorts)
    scored = sum(c.get("overall", {}).get("scored_experiments", 0) for c in cohorts)
    return {
        "detection_evaluation": "MEASURED" if scored else "NOT_MEASURED",
        "ingestion_latency": "MEASURED" if ingestion else "NOT_MEASURED",
        "resource_utilization": summary["resource_measurements"]["status"],
        "host_clock_provenance": summary["host_metadata"]["status"],
        "ingestion_completeness": summary["ingestion_completeness"]["status"],
        "observed_event_rate": "MEASURED" if rates else "NOT_MEASURED",
    }


def render(summary: dict) -> str:
    lines = [
        "# TRAPSIG Evaluation Report",
        "",
        "> **CLOCK SYNCHRONIZATION NOT VERIFIED** unless supplied host records show synchronization.",
        "",
        "## Measurement status",
        "",
    ]
    for name, status in summary["measurement_status"].items():
        lines.append(f"- {name.replace('_', ' ').title()}: **{status}**")
    lines += [""]
    cohorts = summary.get("cohorts", [])
    if not cohorts:
        lines += ["## Results", "", "**NOT MEASURED — NO EVALUATION DATA.**", ""]
    for cohort in cohorts:
        overall = cohort["overall"]
        lines += [
            f"## Configuration `{cohort['evaluation_config_fingerprint']}`",
            "",
            f"Scored: {overall['scored_experiments']}; inconclusive: {overall['inconclusive_experiments']}",
            "",
            "| TP | FN | FP | TN |",
            "|---:|---:|---:|---:|",
            f"| {overall['TP']} | {overall['FN']} | {overall['FP']} | {overall['TN']} |",
            "",
        ]
        for name in ("precision", "recall", "f1", "specificity", "false_positive_rate", "accuracy"):
            lines.append(f"- {name.replace('_', ' ').title()}: {fmt(overall[name])}")
        ingestion = cohort["latency"]["ingestion_latency_event_samples"]
        lines += [
            "",
            "### Event-level ingestion latency",
            "",
            f"Samples: {ingestion['sample_count']}; missing/invalid: {ingestion['missing_or_invalid_count']}; "
            f"mean: {fmt(ingestion['mean'])}; median: {fmt(ingestion['median'])}; p95: {fmt(ingestion['p95'])}",
            "",
        ]
    lines += ["## Resource utilization", ""]
    if summary["resource_measurements"]["status"] == "NOT_MEASURED":
        lines += ["**NOT MEASURED**", ""]
    else:
        for row in summary["resource_measurements"]["containers"]:
            lines.append(
                f"- {row['host_label']} / {row['container_name']}: {row['sample_count']} samples; "
                f"CPU mean {fmt(row['cpu_percent']['mean'])}%, max {fmt(row['cpu_percent']['max'])}%; "
                f"memory mean {fmt(row['memory_usage_bytes']['mean'])} bytes"
            )
    lines += [
        "",
        "## Host/clock provenance",
        "",
        json.dumps(summary["host_metadata"], indent=2),
        "",
        "## Ingestion completeness",
        "",
        json.dumps(summary["ingestion_completeness"], indent=2),
        "",
        "## Limitations",
        "",
        "TRAPSIG is a controlled lab platform, not a production IDS. Results apply only to measured hardware, configuration, batch, and bounded scenarios.",
        "",
    ]
    return "\n".join(lines)


def generate(
    api_url: str,
    output: Path,
    evaluation_id: str | None = None,
    batch: str | None = None,
    config: str | None = None,
    resource_csvs: list[Path] | None = None,
    host_infos: list[Path] | None = None,
    completeness_json: Path | None = None,
) -> Path:
    evaluation_id = evaluation_id or "REPORT-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    directory = output / evaluation_id
    directory.mkdir(parents=True, exist_ok=False)
    query = urlencode({key: value for key, value in {"evaluation_batch_id": batch, "evaluation_config_fingerprint": config}.items() if value})
    suffix = f"?{query}" if query else ""
    summary = request_json(f"{api_url.rstrip('/')}/evaluation/summary{suffix}")
    summary["resource_measurements"] = resource_summary(resource_csvs or [])
    summary["host_metadata"] = host_summary(host_infos or [])
    summary["ingestion_completeness"] = json.loads(completeness_json.read_text()) if completeness_json else {"status": "NOT_MEASURED"}
    summary["measurement_status"] = measurement_status(summary)
    (directory / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    (directory / "experiments.csv").write_text(request_text(f"{api_url.rstrip('/')}/evaluation/export.csv{suffix}"))
    (directory / "report.md").write_text(render(summary))
    return directory


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--evaluation-id")
    parser.add_argument("--batch")
    parser.add_argument("--config")
    parser.add_argument("--resource-csv", action="append", type=Path, default=[])
    parser.add_argument("--host-info", action="append", type=Path, default=[])
    parser.add_argument("--completeness-json", type=Path)
    parser.add_argument("--output", type=Path, default=Path(__file__).parent / "results")
    args = parser.parse_args()
    print(generate(args.api_url, args.output, args.evaluation_id, args.batch, args.config, args.resource_csv, args.host_info, args.completeness_json))


if __name__ == "__main__":
    main()
