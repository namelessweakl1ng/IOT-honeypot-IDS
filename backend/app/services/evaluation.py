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

COHORT_FIELDS = (
    "detector_ruleset_version",
    "session_timeout_seconds",
    "brute_force_threshold",
    "web_enumeration_threshold",
    "multi_service_threshold",
    "trapsig_schema_version",
    "software_revision",
)

EXPORT_COLUMNS = (
    "experiment_id",
    "scenario_id",
    "scenario_kind",
    "expected_detection",
    "result",
    "result_reason",
    "ground_truth_valid",
    "telemetry_settled",
    "software_revision",
    "detector_ruleset_version",
    "scenario_manifest_sha256",
    "cohort_id",
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
    """Linear interpolation (R-7), deterministic and dependency-free."""
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
        return {"count": 0, "min": None, "mean": None, "p50": None, "p95": None, "max": None, "standard_deviation": None}
    return {
        "count": len(valid),
        "min": min(valid),
        "mean": statistics.fmean(valid),
        "p50": percentile(valid, 0.5),
        "p95": percentile(valid, 0.95),
        "max": max(valid),
        "standard_deviation": statistics.stdev(valid) if len(valid) >= 2 else None,
    }


def classification_metrics(tp: int, fn: int, fp: int, tn: int) -> dict[str, float | None]:
    precision = safe_divide(tp, tp + fp)
    recall = safe_divide(tp, tp + fn)
    return {
        "precision": precision,
        "recall": recall,
        "f1": None if precision is None or recall is None or precision + recall == 0 else 2 * precision * recall / (precision + recall),
        "specificity": safe_divide(tn, tn + fp),
        "false_positive_rate": safe_divide(fp, fp + tn),
        "accuracy": safe_divide(tp + tn, tp + fn + fp + tn),
    }


def cohort_id(experiment: dict[str, Any]) -> str | None:
    config = experiment.get("config_snapshot") or {}
    required_config = {
        "session_timeout_seconds",
        "brute_force_threshold",
        "web_enumeration_threshold",
        "multi_service_threshold",
        "detector_ruleset_version",
        "trapsig_schema_version",
    }
    if not required_config.issubset(config) or "software_revision" not in experiment:
        return None
    values = {
        "detector_ruleset_version": experiment.get("detector_ruleset_version") or config.get("detector_ruleset_version"),
        "session_timeout_seconds": config.get("session_timeout_seconds"),
        "brute_force_threshold": config.get("brute_force_threshold"),
        "web_enumeration_threshold": config.get("web_enumeration_threshold"),
        "multi_service_threshold": config.get("multi_service_threshold"),
        "trapsig_schema_version": config.get("trapsig_schema_version") or (experiment.get("trapsig") or {}).get("schema_version"),
        "software_revision": experiment.get("software_revision") or config.get("software_revision"),
    }
    payload = json.dumps(values, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def _counts(records: list[dict[str, Any]]) -> dict[str, int]:
    return {name: sum(record.get("result") == name for record in records) for name in ("TP", "FN", "FP", "TN")}


def _summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    counts = _counts(records)
    scored = sum(counts.values())
    overall = {
        **counts,
        **classification_metrics(counts["TP"], counts["FN"], counts["FP"], counts["TN"]),
        "total_experiments": len(records),
        "scored_experiments": scored,
        "inconclusive_experiments": sum(r.get("result") == "INCONCLUSIVE" for r in records),
    }
    scenarios = []
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        grouped[record.get("scenario_id", "UNKNOWN")].append(record)
    metric_fields = {
        "evidence_latency": "evidence_latency_seconds",
        "detection_latency": "detection_latency_seconds",
        "processing_latency": "processing_latency_seconds",
        "ingestion_latency": "ingestion_latency_mean_seconds",
        "settle_duration": "settle_wait_seconds",
        "observed_event_rate": "observed_event_rate_eps",
        "telemetry_step_coverage": "telemetry_step_coverage",
    }
    for scenario_id, runs in sorted(grouped.items()):
        kind = runs[0].get("scenario_kind", "attack")
        row = {
            "scenario_id": scenario_id,
            "kind": kind,
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
        row["measurements"] = {name: descriptive_statistics(r.get(field) for r in runs) for name, field in metric_fields.items()}
        scenarios.append(row)
    rules = []
    controls = [r for r in records if r.get("scenario_kind") == "control" and r.get("result") in {"TN", "FP"}]
    for detection_type in sorted(SUPPORTED_DETECTION_TYPES):
        positives = [
            r
            for r in records
            if r.get("scenario_kind", "attack") == "attack" and r.get("expected_detection") == detection_type and r.get("result") in {"TP", "FN"}
        ]
        tp = sum(detection_type in (r.get("observed_detection_types") or []) for r in positives)
        fn = len(positives) - tp
        fp = sum(detection_type in (r.get("observed_detection_types") or []) for r in controls)
        tn = len(controls) - fp
        rules.append(
            {
                "detection_type": detection_type,
                "methodology": "positive-vs-control",
                "tp": tp,
                "fn": fn,
                "fp": fp,
                "tn": tn,
                **classification_metrics(tp, fn, fp, tn),
            }
        )
    latency = {name: descriptive_statistics(r.get(field) for r in records) for name, field in metric_fields.items()}
    return {
        "overall": overall,
        "per_scenario": scenarios,
        "per_detection_type": rules,
        "latency": latency,
        "controls": {"runs": len(controls), "tn": counts["TN"], "fp": counts["FP"]},
        "inconclusive": [r for r in records if r.get("result") == "INCONCLUSIVE"],
        "unexpected_detection_occurrences": sum(len(r.get("unexpected_detection_types") or []) for r in records),
    }


def aggregate(experiments: list[dict[str, Any]]) -> dict[str, Any]:
    completed = [dict(item) for item in experiments if item.get("status") == "completed"]
    cancelled = sum(item.get("status") == "cancelled" for item in experiments)
    cohorts: dict[str, list[dict[str, Any]]] = defaultdict(list)
    legacy = []
    for item in completed:
        identity = item.get("cohort_id") or cohort_id(item)
        if identity is None or not item.get("scenario_kind") or not isinstance(item.get("observed_detection_types"), list):
            legacy.append({**item, "evaluation_exclusion_reason": "LEGACY_INCOMPLETE"})
        else:
            item["cohort_id"] = identity
            cohorts[identity].append(item)
    summaries = []
    for identity, records in cohorts.items():
        summary = _summary(records)
        summary.update(cohort_id=identity, latest_end_time=max((r.get("end_time", "") for r in records), default=""))
        summaries.append(summary)
    summaries.sort(key=lambda value: value["latest_end_time"], reverse=True)
    return {
        "cohorts": summaries,
        "most_recent_cohort_id": summaries[0]["cohort_id"] if summaries else None,
        "cancelled_experiments": cancelled,
        "legacy_incomplete_count": len(legacy),
        "legacy_incomplete": legacy,
        "overall": summaries[0]["overall"] if len(summaries) == 1 else None,
        "per_scenario": summaries[0]["per_scenario"] if len(summaries) == 1 else [],
        "per_detection_type": summaries[0]["per_detection_type"] if len(summaries) == 1 else [],
        "latency": summaries[0]["latency"] if len(summaries) == 1 else {},
        "controls": summaries[0]["controls"] if len(summaries) == 1 else {},
        "inconclusive": summaries[0]["inconclusive"] if len(summaries) == 1 else [],
    }


def export_rows(experiments: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {column: item.get(column) if column != "cohort_id" else item.get(column) or cohort_id(item) for column in EXPORT_COLUMNS}
        for item in experiments
        if item.get("status") == "completed"
    ]


def export_csv(experiments: list[dict[str, Any]]) -> str:
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=EXPORT_COLUMNS, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    writer.writerows(export_rows(experiments))
    return output.getvalue()
