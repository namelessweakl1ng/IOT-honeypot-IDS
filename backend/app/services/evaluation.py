"""Pure, conservative aggregation for completed research experiments."""

import csv
import hashlib
import io
import json
import math
import statistics
from collections import defaultdict
from typing import Any, Iterable

from .detector import SUPPORTED_DETECTION_TYPES

EXPORT_COLUMNS = (
    "experiment_id",
    "evaluation_batch_id",
    "replicate",
    "scenario_id",
    "trial_kind",
    "expected_detection",
    "result",
    "result_reason",
    "ground_truth_valid",
    "telemetry_settled",
    "software_revision",
    "detector_ruleset_version",
    "scenario_manifest_sha256",
    "evaluation_config_fingerprint",
    "unexpected_detection_types",
    "matched_event_count",
    "linked_session_count",
    "linked_detection_count",
    "evidence_latency_seconds",
    "detection_latency_seconds",
    "processing_latency_seconds",
    "ingestion_latency_count",
    "ingestion_latency_min_seconds",
    "ingestion_latency_mean_seconds",
    "ingestion_latency_p50_seconds",
    "ingestion_latency_p95_seconds",
    "ingestion_latency_max_seconds",
    "runner_duration_seconds",
    "experiment_duration_seconds",
    "observed_event_rate_eps",
    "telemetry_step_count",
    "telemetry_steps_covered",
    "telemetry_step_coverage",
    "start_time",
    "end_time",
)


def safe_divide(numerator: float, denominator: float) -> float | None:
    return numerator / denominator if denominator else None


def percentile(values: Iterable[float], percent: float) -> float | None:
    ordered = sorted(values)
    if not ordered:
        return None
    position = (len(ordered) - 1) * percent
    lower, upper = math.floor(position), math.ceil(position)
    if lower == upper:
        return float(ordered[lower])
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def descriptive_statistics(values: Iterable[float | int | None]) -> dict[str, float | int | None]:
    valid = [float(value) for value in values if value is not None and math.isfinite(float(value))]
    if not valid:
        return {"count": 0, "min": None, "mean": None, "p50": None, "median": None, "p95": None, "max": None, "standard_deviation": None}
    median = percentile(valid, 0.5)
    return {
        "count": len(valid),
        "min": min(valid),
        "mean": statistics.fmean(valid),
        "p50": median,
        "median": median,
        "p95": percentile(valid, 0.95),
        "max": max(valid),
        "standard_deviation": statistics.stdev(valid) if len(valid) >= 2 else None,
    }


def ingestion_statistics(samples: Iterable[float | None]) -> dict[str, Any]:
    values = list(samples)
    result = descriptive_statistics(values)
    result["sample_count"] = result.pop("count")
    result["missing_or_invalid_count"] = sum(value is None for value in values)
    return result


def classification_metrics(tp: int, fn: int, fp: int, tn: int) -> dict[str, float | None]:
    precision, recall = safe_divide(tp, tp + fp), safe_divide(tp, tp + fn)
    return {
        "precision": precision,
        "recall": recall,
        "f1": None if precision is None or recall is None or precision + recall == 0 else 2 * precision * recall / (precision + recall),
        "specificity": safe_divide(tn, tn + fp),
        "false_positive_rate": safe_divide(fp, fp + tn),
        "accuracy": safe_divide(tp + tn, tp + fn + fp + tn),
    }


def evaluation_config_fingerprint(experiment: dict[str, Any]) -> str | None:
    config = experiment.get("config_snapshot") or {}
    required = (
        "session_timeout_seconds",
        "brute_force_threshold",
        "web_enumeration_threshold",
        "multi_service_threshold",
        "detector_ruleset_version",
        "trapsig_schema_version",
    )
    revision = experiment.get("software_revision")
    if not all(field in config for field in required) or not isinstance(revision, str) or not revision.strip() or revision.lower() == "unknown":
        return None
    values = {field: config[field] for field in required}
    values["software_revision"] = revision
    return hashlib.sha256(json.dumps(values, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


# Temporary source compatibility for callers from the initial PR revision.
cohort_id = evaluation_config_fingerprint


def _summary(records: list[dict[str, Any]], event_samples: dict[str, list[float | None]]) -> dict[str, Any]:
    counts = {name: sum(record.get("result") == name for record in records) for name in ("TP", "FN", "FP", "TN")}
    overall = {
        **counts,
        **classification_metrics(counts["TP"], counts["FN"], counts["FP"], counts["TN"]),
        "total_experiments": len(records),
        "scored_experiments": sum(counts.values()),
        "inconclusive_experiments": sum(r.get("result") == "INCONCLUSIVE" for r in records),
    }
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        grouped[record.get("scenario_id", "UNKNOWN")].append(record)
    fields = {
        "evidence_latency": "evidence_latency_seconds",
        "detection_latency": "detection_latency_seconds",
        "processing_latency": "processing_latency_seconds",
        "settle_duration": "settle_wait_seconds",
        "observed_event_rate": "observed_event_rate_eps",
        "telemetry_step_coverage": "telemetry_step_coverage",
    }
    scenarios = []
    for scenario_id, runs in sorted(grouped.items()):
        kind = runs[0].get("trial_kind", "attack")
        row = {
            "scenario_id": scenario_id,
            "trial_kind": kind,
            "expected_detection": runs[0].get("expected_detection"),
            "run_count": len(runs),
            "scored_count": sum(r.get("result") in {"TP", "FN", "FP", "TN"} for r in runs),
            "inconclusive_count": sum(r.get("result") == "INCONCLUSIVE" for r in runs),
        }
        if kind == "control":
            row.update(tn=sum(r.get("result") == "TN" for r in runs), fp=sum(r.get("result") == "FP" for r in runs))
            row["false_positive_rate"] = safe_divide(row["fp"], row["tn"] + row["fp"])
        else:
            row.update(tp=sum(r.get("result") == "TP" for r in runs), fn=sum(r.get("result") == "FN" for r in runs))
            row["detection_rate"] = safe_divide(row["tp"], row["tp"] + row["fn"])
        row["measurements"] = {name: descriptive_statistics(r.get(field) for r in runs) for name, field in fields.items()}
        row["measurements"]["ingestion_latency_event_samples"] = ingestion_statistics(
            sample for run in runs for sample in event_samples.get(run.get("experiment_id"), [])
        )
        scenarios.append(row)
    controls = [r for r in records if r.get("trial_kind") == "control" and r.get("result") in {"TN", "FP"}]
    rules = []
    for detection_type in sorted(SUPPORTED_DETECTION_TYPES):
        positives = [
            r
            for r in records
            if r.get("trial_kind", "attack") == "attack" and r.get("expected_detection") == detection_type and r.get("result") in {"TP", "FN"}
        ]
        tp = sum(detection_type in (r.get("observed_detection_types") or []) for r in positives)
        fp = sum(detection_type in (r.get("observed_detection_types") or []) for r in controls)
        rules.append(
            {
                "detection_type": detection_type,
                "methodology": "positive-vs-control",
                "tp": tp,
                "fn": len(positives) - tp,
                "fp": fp,
                "tn": len(controls) - fp,
                **classification_metrics(tp, len(positives) - tp, fp, len(controls) - fp),
            }
        )
    latency = {name: descriptive_statistics(r.get(field) for r in records) for name, field in fields.items()}
    latency["ingestion_latency_event_samples"] = ingestion_statistics(
        sample for record in records for sample in event_samples.get(record.get("experiment_id"), [])
    )
    return {
        "overall": overall,
        "per_scenario": scenarios,
        "per_detection_type": rules,
        "latency": latency,
        "controls": {"runs": len(controls), "tn": counts["TN"], "fp": counts["FP"]},
        "inconclusive": [r for r in records if r.get("result") == "INCONCLUSIVE"],
        "unexpected_detection_occurrences": sum(len(r.get("unexpected_detection_types") or []) for r in records),
    }


def aggregate(experiments: list[dict[str, Any]], event_samples: dict[str, list[float | None]] | None = None) -> dict[str, Any]:
    completed = [dict(item) for item in experiments if item.get("status") == "completed"]
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    excluded = []
    for item in completed:
        fingerprint = item.get("evaluation_config_fingerprint") or evaluation_config_fingerprint(item)
        if fingerprint is None:
            reason = (
                "MISSING_SOFTWARE_REVISION"
                if not str(item.get("software_revision") or "").strip() or str(item.get("software_revision")).lower() == "unknown"
                else "LEGACY_INCOMPLETE"
            )
            excluded.append({**item, "evaluation_exclusion_reason": reason})
        elif not item.get("trial_kind") or not isinstance(item.get("observed_detection_types"), list):
            excluded.append({**item, "evaluation_exclusion_reason": "LEGACY_INCOMPLETE"})
        else:
            item["evaluation_config_fingerprint"] = fingerprint
            groups[fingerprint].append(item)
    summaries = []
    for fingerprint, records in groups.items():
        summary = _summary(records, event_samples or {})
        summary.update(
            evaluation_config_fingerprint=fingerprint, cohort_id=fingerprint, latest_end_time=max((r.get("end_time", "") for r in records), default="")
        )
        summaries.append(summary)
    summaries.sort(key=lambda value: value["latest_end_time"], reverse=True)
    return {
        "cohorts": summaries,
        "most_recent_evaluation_config_fingerprint": summaries[0]["evaluation_config_fingerprint"] if summaries else None,
        "most_recent_cohort_id": summaries[0]["cohort_id"] if summaries else None,
        "cancelled_experiments": sum(item.get("status") == "cancelled" for item in experiments),
        "excluded_incomplete_count": len(excluded),
        "legacy_incomplete_count": len(excluded),
        "excluded_incomplete": excluded,
        "resource_measurements": {"status": "NOT_MEASURED"},
        "host_metadata": {"status": "NOT_MEASURED"},
        "ingestion_completeness": {"status": "NOT_MEASURED"},
    }


def export_rows(experiments: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for item in experiments:
        if item.get("status") != "completed":
            continue
        row = {column: item.get(column) for column in EXPORT_COLUMNS}
        row["evaluation_config_fingerprint"] = row["evaluation_config_fingerprint"] or evaluation_config_fingerprint(item)
        for field in ("unexpected_detection_types",):
            row[field] = "|".join(row[field] or [])
        rows.append(row)
    return rows


def export_csv(experiments: list[dict[str, Any]]) -> str:
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=EXPORT_COLUMNS, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    writer.writerows(export_rows(experiments))
    return output.getvalue()
