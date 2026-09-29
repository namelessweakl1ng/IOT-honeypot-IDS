"""Experiment validation, direct correlation, and scientific result semantics."""

from datetime import datetime, timedelta
from ipaddress import ip_address, ip_network
from typing import Any

from .evaluation import descriptive_statistics, evaluation_config_fingerprint
from .scenarios import SERVICE_TO_HONEYPOT


def parse_time(value: str | datetime | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def validate_lab_host(value: str, lab_subnet: str, field: str) -> str:
    try:
        address = ip_address(value)
        network = ip_network(lab_subnet, strict=False)
    except ValueError as exc:
        raise ValueError(f"{field} must be a valid IP address") from exc
    if not network.is_private:
        raise ValueError("LAB_SUBNET must be private")
    if address.is_loopback or address not in network or address in {network.network_address, network.broadcast_address}:
        raise ValueError(f"{field} must be a usable host address inside LAB_SUBNET")
    return str(address)


def exact_filter(field: str, value: Any) -> dict[str, Any]:
    """Match fresh typed fields and historical dynamic text+keyword fields."""
    operator = "terms" if isinstance(value, (list, tuple, set)) else "term"
    return {
        "bool": {
            "should": [{operator: {field: value}}, {operator: {f"{field}.keyword": value}}],
            "minimum_should_match": 1,
        }
    }


def event_query(experiment: dict[str, Any]) -> dict[str, Any]:
    return {
        "bool": {
            "filter": [
                {"range": {"@timestamp": {"gte": experiment["start_time"], "lte": experiment["end_time"]}}},
                exact_filter("source.ip", experiment["attacker_ip"]),
                exact_filter("destination.ip", experiment["target_ip"]),
                exact_filter("service.name", experiment["target_honeypots"]),
            ],
            "must_not": [
                {"term": {"trapsig.internal": True}},
                {"term": {"source.ip": "127.0.0.1"}},
                {"term": {"source.ip": "::1"}},
            ],
        }
    }


def _nonnegative(later: datetime | None, earlier: datetime | None) -> float | None:
    if later is None or earlier is None:
        return None
    value = (later - earlier).total_seconds()
    return value if value >= 0 else None


def correlate(
    experiment: dict[str, Any], events: list[dict[str, Any]], sessions: list[dict[str, Any]], detections: list[dict[str, Any]], *, scientific: bool = False
) -> dict[str, Any]:
    """Link by event IDs and sessions; scientific mode enforces ground truth."""
    start, end = parse_time(experiment["start_time"]), parse_time(experiment["end_time"])
    targets = set(experiment.get("target_honeypots", []))
    matched = []
    for event in events:
        occurred = parse_time(event.get("@timestamp"))
        service = event.get("service", {}).get("name")
        if (
            occurred
            and start <= occurred <= end
            and event.get("source", {}).get("ip") == experiment["attacker_ip"]
            and event.get("destination", {}).get("ip") == experiment["target_ip"]
            and (not targets or service in targets)
            and not event.get("trapsig", {}).get("internal")
            and event.get("source", {}).get("ip") not in {"127.0.0.1", "::1"}
        ):
            matched.append(event)
    event_ids = {e.get("event", {}).get("id", e.get("_id")) for e in matched}
    event_ids.discard(None)
    linked = [s for s in sessions if event_ids.intersection(s.get("event_ids", []))]
    session_ids = {s["session_id"] for s in linked}
    detected = [d for d in detections if d.get("session_id") in session_ids]
    expected = experiment.get("expected_detection")
    matching = [d for d in detected if expected and d.get("type") == expected]
    primary_observed = bool(matching)
    is_control = experiment.get("trial_kind", experiment.get("scenario_kind", "attack")) == "control"
    observed = bool(detected) if is_control else primary_observed
    first_match = min(matching, key=lambda d: parse_time(d.get("detected_at") or d.get("timestamp"))) if matching else None
    evidence = parse_time(first_match.get("evidence_end_time") or first_match.get("timestamp")) if first_match else None
    detected_at = parse_time(first_match.get("detected_at")) if first_match else None
    occurred_times = [parse_time(e.get("@timestamp")) for e in matched]
    ingested_times = [parse_time(e.get("event", {}).get("ingested")) for e in matched]
    occurred_times = [v for v in occurred_times if v]
    ingested_times = [v for v in ingested_times if v]
    ingestion_latencies = []
    for event in matched:
        latency = _nonnegative(parse_time(event.get("event", {}).get("ingested")), parse_time(event.get("@timestamp")))
        if latency is not None:
            ingestion_latencies.append(latency)
    ingestion = descriptive_statistics(ingestion_latencies)
    observed_types = sorted({d.get("type") for d in detected if d.get("type")})
    runner_start, runner_end = parse_time(experiment.get("runner_start_time")), parse_time(experiment.get("runner_end_time"))
    runner_duration = _nonnegative(runner_end, runner_start)
    experiment_duration = _nonnegative(end, start)
    steps = experiment.get("runner_steps") or []
    telemetry_step_count = len(steps) if experiment.get("ground_truth_valid") and steps else 0
    covered = 0
    coverage_available = bool(telemetry_step_count)
    tolerance = float(experiment.get("evaluation_step_time_tolerance_seconds", 2))
    for step in steps if coverage_available else []:
        step_start, step_end = parse_time(step.get("started_at")), parse_time(step.get("ended_at"))
        if not step_start or not step_end or step_end < step_start:
            coverage_available = False
            break
        honeypot = SERVICE_TO_HONEYPOT.get(step.get("service"))
        if any(
            honeypot == event.get("service", {}).get("name")
            and step_start - timedelta(seconds=tolerance) <= parse_time(event.get("@timestamp")) <= step_end + timedelta(seconds=tolerance)
            for event in matched
            if parse_time(event.get("@timestamp"))
        ):
            covered += 1
    result = {
        **experiment,
        "event_ids": sorted(event_ids),
        "session_ids": sorted(session_ids),
        "detection_ids": sorted(d["detection_id"] for d in detected),
        "observed_detection_types": observed_types,
        "unexpected_detection_types": sorted(set(observed_types) - ({expected} if expected else set())),
        "observed_detection": observed,
        "first_event_at": min(occurred_times).isoformat() if occurred_times else None,
        "last_event_at": max(occurred_times).isoformat() if occurred_times else None,
        "first_event_ingested_at": min(ingested_times).isoformat() if ingested_times else None,
        "last_event_ingested_at": max(ingested_times).isoformat() if ingested_times else None,
        "evidence_latency_seconds": _nonnegative(evidence, start),
        "detection_latency_seconds": _nonnegative(detected_at, start),
        "processing_latency_seconds": _nonnegative(detected_at, evidence),
        "matched_event_count": len(matched),
        "linked_session_count": len(linked),
        "linked_detection_count": len(detected),
        "runner_step_count": len(steps),
        "runner_duration_seconds": runner_duration,
        "experiment_duration_seconds": experiment_duration,
        "observed_event_rate_eps": (
            len(matched) / (max(occurred_times) - min(occurred_times)).total_seconds()
            if len(matched) >= 2 and (max(occurred_times) - min(occurred_times)).total_seconds() > 0
            else None
        ),
        "ingestion_latency_count": ingestion["count"],
        "ingestion_latency_min_seconds": ingestion["min"],
        "ingestion_latency_mean_seconds": ingestion["mean"],
        "ingestion_latency_p50_seconds": ingestion["p50"],
        "ingestion_latency_p95_seconds": ingestion["p95"],
        "ingestion_latency_max_seconds": ingestion["max"],
        "telemetry_step_count": telemetry_step_count if coverage_available else None,
        "telemetry_steps_covered": covered if coverage_available else None,
        "telemetry_step_coverage": covered / telemetry_step_count if coverage_available else None,
    }
    result["evaluation_config_fingerprint"] = evaluation_config_fingerprint(result)
    if not scientific:
        result["result"] = "TP" if observed else "FN"
        return result
    reason = None
    if not experiment.get("ground_truth_valid"):
        reason = "RUNNER_FAILED" if experiment.get("runner_status") in {"failed", "partial"} else "NO_GROUND_TRUTH"
    elif not matched:
        reason = "NO_TELEMETRY"
    if reason:
        outcome = "INCONCLUSIVE"
    elif is_control:
        outcome = "FP" if detected else "TN"
    else:
        outcome = "TP" if observed else "FN"
    result["result"] = outcome
    result["result_reason"] = reason
    return result
