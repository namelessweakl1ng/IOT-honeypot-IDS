"""Download measured data and render a conservative Markdown report."""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from .http import request_json, request_text


def fmt(value):
    return "— (Not measured)" if value is None else f"{value:.4f}" if isinstance(value, float) else str(value)


def render(summary: dict) -> str:
    lines = [
        "# TRAPSIG Evaluation Report",
        "",
        "> **CLOCK SYNCHRONIZATION NOT VERIFIED** unless preflight records accompany this report.",
        "",
        "Ingestion latency, step telemetry coverage, and cross-host timing are only defensible when host clocks are synchronized.",
        "",
    ]
    cohorts = summary.get("cohorts", [])
    if not cohorts:
        return (
            "\n".join(lines + ["## Results", "", "**NOT MEASURED — NO EVALUATION DATA.**", "", "Run controlled experiments to generate measured results."])
            + "\n"
        )
    for cohort in cohorts:
        overall = cohort["overall"]
        lines += [
            f"## Cohort `{cohort['cohort_id']}`",
            "",
            f"Scored: {overall['scored_experiments']}; inconclusive: {overall['inconclusive_experiments']}",
            "",
            "### Confusion matrix",
            "",
            "| TP | FN | FP | TN |",
            "|---:|---:|---:|---:|",
            f"| {overall['TP']} | {overall['FN']} | {overall['FP']} | {overall['TN']} |",
            "",
            "### Overall metrics",
            "",
        ]
        for name in ("precision", "recall", "f1", "specificity", "false_positive_rate", "accuracy"):
            lines.append(f"- {name.replace('_', ' ').title()}: {fmt(overall[name])}")
        lines += ["", "### Per-rule metrics", "", "| Rule | TP | FN | FP | TN | Precision | Recall |", "|---|---:|---:|---:|---:|---:|---:|"]
        for row in cohort["per_detection_type"]:
            lines.append(
                f"| {row['detection_type']} | {row['tp']} | {row['fn']} | {row['fp']} | {row['tn']} | {fmt(row['precision'])} | {fmt(row['recall'])} |"
            )
        lines += ["", "### Per-scenario metrics", "", "| Scenario | Kind | Runs | Scored | Inconclusive |", "|---|---|---:|---:|---:|"]
        for row in cohort["per_scenario"]:
            lines.append(f"| {row['scenario_id']} | {row['kind']} | {row['run_count']} | {row['scored_count']} | {row['inconclusive_count']} |")
        lines += ["", "### Latency, ingestion, and telemetry coverage", ""]
        for name, stats in cohort["latency"].items():
            lines.append(f"- {name.replace('_', ' ').title()}: count {stats['count']}, mean {fmt(stats['mean'])}, p95 {fmt(stats['p95'])}")
        lines += [
            "",
            f"### Controls\n\nTN: {cohort['controls']['tn']}; FP: {cohort['controls']['fp']}",
            "",
            f"### Inconclusive runs\n\nCount: {len(cohort['inconclusive'])}",
            "",
        ]
    lines += [
        "## Limitations",
        "",
        "TRAPSIG is a controlled lab platform, not a production IDS. Results apply only to the measured "
        "hardware, configuration, and bounded scenarios. Small samples and controls must not be generalized "
        "to real benign IoT traffic.",
    ]
    return "\n".join(lines) + "\n"


def generate(api_url: str, output: Path, evaluation_id: str | None = None) -> Path:
    evaluation_id = evaluation_id or "REPORT-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    directory = output / evaluation_id
    directory.mkdir(parents=True, exist_ok=False)
    summary = request_json(f"{api_url.rstrip('/')}/evaluation/summary")
    (directory / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    (directory / "experiments.csv").write_text(request_text(f"{api_url.rstrip('/')}/evaluation/export.csv"))
    (directory / "report.md").write_text(render(summary))
    return directory


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--evaluation-id")
    parser.add_argument("--output", type=Path, default=Path(__file__).parent / "results")
    args = parser.parse_args()
    print(generate(args.api_url, args.output, args.evaluation_id))


if __name__ == "__main__":
    main()
