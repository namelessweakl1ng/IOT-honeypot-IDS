import json
from copy import deepcopy
from pathlib import Path

import pytest

from backend.app.services.evaluation import aggregate, classification_metrics, cohort_id, export_csv, percentile
from backend.app.services.experiments import correlate
from backend.app.services.scenarios import ScenarioCatalog, ScenarioCatalogError
from evaluation.resources import parse_stat

CONFIG = {
    "session_timeout_seconds": 300,
    "brute_force_threshold": 5,
    "web_enumeration_threshold": 4,
    "multi_service_threshold": 3,
    "detector_ruleset_version": "rules-1",
    "trapsig_schema_version": "1",
    "software_revision": "abc",
}


def experiment(kind="attack", expected="BRUTE_FORCE"):
    return {
        "experiment_id": "EXP-1",
        "scenario_id": "case",
        "trial_kind": kind,
        "expected_detection": expected,
        "status": "completed",
        "attacker_ip": "192.168.50.10",
        "target_ip": "192.168.50.20",
        "target_honeypots": ["cowrie"],
        "start_time": "2026-01-01T00:00:00+00:00",
        "end_time": "2026-01-01T00:00:10+00:00",
        "runner_start_time": "2026-01-01T00:00:01+00:00",
        "runner_end_time": "2026-01-01T00:00:03+00:00",
        "ground_truth_valid": True,
        "telemetry_settled": True,
        "runner_status": "completed",
        "runner_steps": [
            {"step": 1, "service": "ssh", "started_at": "2026-01-01T00:00:01+00:00", "ended_at": "2026-01-01T00:00:02+00:00", "status": "completed"}
        ],
        "detector_ruleset_version": "rules-1",
        "software_revision": "abc",
        "config_snapshot": deepcopy(CONFIG),
        "trapsig": {"schema_version": "1"},
    }


def event(ingested="2026-01-01T00:00:02+00:00"):
    return {
        "_id": "event-1",
        "@timestamp": "2026-01-01T00:00:01+00:00",
        "event": {"id": "event-1", "ingested": ingested},
        "source": {"ip": "192.168.50.10"},
        "destination": {"ip": "192.168.50.20"},
        "service": {"name": "cowrie"},
    }


def session():
    return {"session_id": "session-1", "event_ids": ["event-1"]}


def detection(kind="BRUTE_FORCE"):
    return {
        "detection_id": "det-1",
        "session_id": "session-1",
        "type": kind,
        "evidence_end_time": "2026-01-01T00:00:02+00:00",
        "detected_at": "2026-01-01T00:00:03+00:00",
    }


def test_control_validation_and_catalog_kinds(tmp_path):
    base = {
        "id": "one",
        "name": "one",
        "description": "one",
        "trial_kind": "control",
        "expected_detection": "BRUTE_FORCE",
        "target_services": ["ssh"],
        "steps": [{"service": "ssh"}],
    }
    (tmp_path / "one.yaml").write_text(json.dumps(base))
    with pytest.raises(ScenarioCatalogError, match="null expected_detection"):
        ScenarioCatalog(tmp_path).load()
    base.update(trial_kind="attack", expected_detection="NONE")
    (tmp_path / "one.yaml").write_text(json.dumps(base))
    with pytest.raises(ScenarioCatalogError, match="unknown expected"):
        ScenarioCatalog(tmp_path).load()
    catalog = ScenarioCatalog().load()
    assert catalog["ssh-bruteforce"].trial_kind == "attack"
    assert catalog["ssh-control"].trial_kind == "control"
    assert catalog["ssh-control"].expected_detection is None


def test_missing_trial_kind_defaults_to_attack(tmp_path):
    manifest = {
        "id": "one",
        "name": "one",
        "description": "one",
        "expected_detection": "BRUTE_FORCE",
        "target_services": ["ssh"],
        "steps": [{"service": "ssh"}],
    }
    (tmp_path / "one.yaml").write_text(json.dumps(manifest))
    assert ScenarioCatalog(tmp_path).load()["one"].trial_kind == "attack"


def test_control_and_attack_outcomes_and_counts():
    control = experiment("control", None)
    tn = correlate(control, [event()], [session()], [], scientific=True)
    assert tn["result"] == "TN" and tn["observed_detection"] is False
    fp = correlate(control, [event()], [session()], [detection("MQTT_PROBING")], scientific=True)
    assert fp["result"] == "FP" and fp["observed_detection"] is True and fp["observed_detection_types"] == ["MQTT_PROBING"]
    assert correlate(control, [], [], [], scientific=True)["result"] == "INCONCLUSIVE"
    attack = correlate(experiment(), [event()], [session()], [detection(), detection()], scientific=True)
    assert attack["result"] == "TP" and attack["observed_detection_types"] == ["BRUTE_FORCE"]
    assert attack["matched_event_count"] == 1 and attack["runner_duration_seconds"] == 2
    assert attack["observed_event_rate_eps"] is None and attack["telemetry_step_coverage"] == 1
    assert correlate(experiment(), [event()], [session()], [], scientific=True)["result"] == "FN"
    invalid = experiment()
    invalid["ground_truth_valid"] = False
    assert correlate(invalid, [event()], [session()], [detection()], scientific=True)["result"] == "INCONCLUSIVE"


def test_ingestion_statistics_and_negative_exclusion():
    measured = correlate(experiment(), [event()], [session()], [], scientific=True)
    assert measured["ingestion_latency_count"] == 1 and measured["ingestion_latency_mean_seconds"] == 1
    negative = correlate(experiment(), [event("2025-12-31T23:59:59+00:00")], [session()], [], scientific=True)
    assert negative["ingestion_latency_count"] == 0 and negative["ingestion_latency_mean_seconds"] is None
    assert percentile([1, 2, 3, 4], 0.5) == 2.5
    assert percentile([1, 2, 3, 4], 0.95) == pytest.approx(3.85)


def test_metrics_cohorts_per_rule_and_export():
    attack = correlate(experiment(), [event()], [session()], [detection(), detection("MULTI_SERVICE_ACTIVITY")], scientific=True)
    control = correlate(experiment("control", None), [event()], [session()], [detection("MQTT_PROBING")], scientific=True)
    summary = aggregate([attack, control, {"status": "cancelled"}])
    cohort = summary["cohorts"][0]
    assert {key: cohort["overall"][key] for key in ("TP", "FP", "FN", "TN")} == {"TP": 1, "FP": 1, "FN": 0, "TN": 0}
    brute = next(row for row in cohort["per_detection_type"] if row["detection_type"] == "BRUTE_FORCE")
    assert (brute["tp"], brute["fp"]) == (1, 0)
    assert cohort["unexpected_detection_occurrences"] == 2
    assert classification_metrics(1, 1, 1, 1)["f1"] == 0.5
    assert classification_metrics(0, 0, 0, 0)["precision"] is None
    changed = deepcopy(attack)
    changed.pop("evaluation_config_fingerprint")
    changed["software_revision"] = "def"
    changed["config_snapshot"]["software_revision"] = "def"
    assert cohort_id(attack) != cohort_id(changed)
    assert len(aggregate([attack, changed])["cohorts"]) == 2
    output = export_csv([attack])
    assert "experiment_id,evaluation_batch_id,replicate,scenario_id,trial_kind" in output and "password" not in output


def test_docker_json_parser_uses_binary_and_decimal_units():
    row = parse_stat(
        {"Name": "backend", "CPUPerc": "1.5%", "MemUsage": "1MiB / 2MiB", "MemPerc": "50%", "NetIO": "1kB / 2kB", "BlockIO": "3MB / 4MB", "PIDs": "7"},
        "analysis",
        "now",
    )
    assert row["memory_usage_bytes"] == 1048576 and row["network_tx_bytes"] == 2000 and row["pids"] == 7


def test_results_are_ignored():
    assert "evaluation/results/*" in Path(".gitignore").read_text()
