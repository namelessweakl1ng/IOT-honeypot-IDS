import argparse
import asyncio
import csv
import json
from copy import deepcopy
from datetime import datetime
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from backend.app.api import evaluation, experiments
from backend.app.main import app
from backend.app.services.evaluation import aggregate, evaluation_config_fingerprint, ingestion_statistics
from backend.app.services.experiments import correlate
from evaluation import run_matrix
from evaluation.completeness import fetch_present_event_ids, load_ids, mapped_event_id
from evaluation.host_info import capture
from evaluation.report import measurement_status, resource_summary
from evaluation.run_matrix import make_plan, resolve_batch_id
from tests.evaluation.test_framework import CONFIG, detection, event, experiment, session


def test_batch_and_replicate_are_validated_and_persisted(monkeypatch):
    save = AsyncMock(side_effect=lambda _index, _id, document: document)
    monkeypatch.setattr(experiments.store, "save", save)
    body = {
        "name": "replicate",
        "scenario_id": "ssh-bruteforce",
        "attacker_ip": "192.168.50.20",
        "target_ip": "192.168.50.10",
        "evaluation_batch_id": "FINAL-2026",
        "replicate": 2,
    }
    response = TestClient(app).post("/experiments", json=body)
    assert response.status_code == 201
    assert response.json()["evaluation_batch_id"] == "FINAL-2026" and response.json()["replicate"] == 2
    body["replicate"] = 0
    assert TestClient(app).post("/experiments", json=body).status_code == 422


def test_batch_and_fingerprint_filtering():
    a = {"evaluation_batch_id": "FINAL", "software_revision": "abc", "config_snapshot": deepcopy(CONFIG)}
    b = {"evaluation_batch_id": "DEBUG", "software_revision": "def", "config_snapshot": deepcopy(CONFIG)}
    fingerprint = evaluation_config_fingerprint(a)
    assert evaluation._filter([a, b], "FINAL", None) == [a]
    assert evaluation._filter([a, b], None, fingerprint) == [a]


def test_structured_shuffled_plan_preserves_replicates():
    args = argparse.Namespace(scenario=["ssh-control"], all_attacks=False, all_controls=False, all_evaluation=False, repetitions=3, shuffle=True, seed=7)
    plan = make_plan(args)
    assert {entry["replicate"] for entry in plan} == {1, 2, 3}
    assert all(entry["trial_kind"] == "control" for entry in plan)


def test_explicit_and_automatic_batch_ids_are_safe():
    assert resolve_batch_id("FINAL-2026") == "FINAL-2026"
    assert resolve_batch_id(None).startswith("EVAL-")
    for unsafe in ("../FINAL", "bad/batch", "..", ""):
        with pytest.raises(ValueError):
            resolve_batch_id(unsafe)


def test_execute_persists_explicit_batch_and_replicates(monkeypatch, tmp_path):
    created_payloads = []

    def fake_request(url, method="GET", data=None):
        if url.endswith("/experiments"):
            created_payloads.append(data)
            return {"experiment_id": f"EXP-{len(created_payloads)}"}
        return {"experiment_id": url.split("/")[-2], "status": "completed", "result": "TN"}

    monkeypatch.setattr(run_matrix, "RESULTS", tmp_path)
    monkeypatch.setattr(run_matrix, "request_json", fake_request)
    monkeypatch.setattr(run_matrix, "run", lambda *args, **kwargs: {})
    args = argparse.Namespace(
        api_url="http://backend", target_ip="192.168.50.10", attacker_ip="192.168.50.20", repetitions=2, seed=None, shuffle=False, batch_id="FINAL-2026"
    )
    plan = [{"scenario_id": "ssh-control", "trial_kind": "control", "replicate": 1}, {"scenario_id": "ssh-control", "trial_kind": "control", "replicate": 2}]
    result = run_matrix.execute(args, plan)
    assert result.parent.name == "FINAL-2026"
    assert [payload["replicate"] for payload in created_payloads] == [1, 2]
    assert {payload["evaluation_batch_id"] for payload in created_payloads} == {"FINAL-2026"}
    manifest = json.loads(result.read_text())
    assert manifest["evaluation_run_id"] == "FINAL-2026"


def test_unknown_revision_has_no_fingerprint_and_is_excluded():
    item = experiment()
    item["software_revision"] = "unknown"
    item.pop("evaluation_config_fingerprint", None)
    assert evaluation_config_fingerprint(item) is None
    summary = aggregate([item])
    assert summary["cohorts"] == []
    assert summary["excluded_incomplete"][0]["evaluation_exclusion_reason"] == "MISSING_SOFTWARE_REVISION"


def test_observed_rate_uses_event_window():
    second = event("2026-01-01T00:00:04+00:00")
    second["event"]["id"] = second["_id"] = "event-2"
    second["@timestamp"] = "2026-01-01T00:00:03+00:00"
    linked = session()
    linked["event_ids"].append("event-2")
    result = correlate(experiment(), [event(), second], [linked], [detection()], scientific=True)
    assert result["observed_event_rate_eps"] == 1.0
    second["@timestamp"] = event()["@timestamp"]
    assert correlate(experiment(), [event(), second], [linked], [], scientific=True)["observed_event_rate_eps"] is None


def test_event_level_ingestion_statistics_not_means_of_means():
    stats = ingestion_statistics([1.0, 2.0, 100.0, None])
    assert stats["sample_count"] == 3 and stats["missing_or_invalid_count"] == 1
    assert stats["mean"] == pytest.approx(103 / 3) and stats["median"] == 2.0 and stats["p95"] == pytest.approx(90.2)


def test_event_fetch_is_bounded(monkeypatch):
    search = AsyncMock(return_value=[])
    monkeypatch.setattr(evaluation.store, "search_all", search)
    asyncio.run(evaluation.fetch_events_by_ids([f"id-{i}" for i in range(501)], batch_size=250))
    assert search.await_count == 3


def test_event_presence_returns_present_ids_only(monkeypatch):
    monkeypatch.setattr(
        evaluation,
        "fetch_events_by_ids",
        AsyncMock(return_value={"known": {"event": {"id": "known"}}}),
    )
    response = TestClient(app).post("/evaluation/event-presence", json={"event_ids": ["known", "missing"]})
    assert response.status_code == 200
    assert response.json() == {"present_event_ids": ["known"]}
    oversized = TestClient(app).post("/evaluation/event-presence", json={"event_ids": [str(index) for index in range(251)]})
    assert oversized.status_code == 422


def test_resource_summary_and_missing_state(tmp_path):
    assert resource_summary([]) == {"status": "NOT_MEASURED"}
    path = tmp_path / "resources.csv"
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["host_label", "container_name", "cpu_percent", "memory_usage_bytes", "memory_percent"])
        writer.writeheader()
        writer.writerow({"host_label": "pi", "container_name": "cowrie", "cpu_percent": "10", "memory_usage_bytes": "100", "memory_percent": "5"})
        writer.writerow({"host_label": "pi", "container_name": "cowrie", "cpu_percent": "bad", "memory_usage_bytes": "300", "memory_percent": "15"})
    result = resource_summary([path])
    row = result["containers"][0]
    assert result["status"] == "MEASURED" and row["cpu_percent"]["mean"] == 10
    assert row["memory_usage_bytes"]["mean"] == 200 and result["invalid_samples"] == 1


def test_host_metadata_required_fields(monkeypatch):
    monkeypatch.setattr("evaluation.host_info.version", lambda command: None)
    data = capture("sensor")
    required = {
        "captured_at_utc",
        "role",
        "hostname",
        "platform",
        "kernel",
        "architecture",
        "python_version",
        "docker_version",
        "docker_compose_version",
        "utc_system_time",
        "timezone",
        "ntp_synchronization",
        "git_software_revision",
    }
    assert required <= data.keys() and data["docker_version"] is None


def test_completeness_mapping_and_unmappable_denominator(tmp_path):
    custom = {"event_id": "custom-1", "timestamp": "2026-01-01T00:00:00Z"}
    cowrie = {"eventid": "cowrie.login.failed", "session": "abc", "timestamp": "2026-01-01T00:00:01Z"}
    assert mapped_event_id(custom) == "custom-1"
    assert mapped_event_id(cowrie) == "cowrie.login.failed-abc-2026-01-01T00:00:01Z"
    path = tmp_path / "sensor.jsonl"
    path.write_text("\n".join([json.dumps(custom), json.dumps(cowrie), "not-json"]))
    loaded = load_ids([path])
    assert loaded["sensor_events_total"] == 3 and len(loaded["event_ids"]) == 2 and loaded["unmappable_events"] == 1


def test_completeness_batches_presence_requests(monkeypatch):
    calls = []

    def fake_request(url, method, data):
        calls.append((url, method, data))
        return {"present_event_ids": data["event_ids"][:1]}

    monkeypatch.setattr("evaluation.completeness.request_json", fake_request)
    present = fetch_present_event_ids("http://backend", [f"event-{index}" for index in range(501)])
    assert len(calls) == 3 and all(call[0].endswith("/evaluation/event-presence") for call in calls)
    assert all(call[1] == "POST" and len(call[2]["event_ids"]) <= 250 for call in calls)
    assert present == {"event-0", "event-250", "event-500"}


def test_out_of_window_events_are_filtered_not_unmappable(tmp_path):
    path = tmp_path / "sensor.jsonl"
    path.write_text(json.dumps({"event_id": "old", "timestamp": "2025-01-01T00:00:00Z"}) + "\n")
    loaded = load_ids([path], start=datetime.fromisoformat("2026-01-01T00:00:00+00:00"))
    assert loaded["sensor_events_total"] == 1
    assert loaded["sensor_events_in_window"] == 0
    assert loaded["filtered_out_events"] == 1
    assert loaded["unmappable_events"] == 0
    assert loaded["event_ids"] == []


def test_measurement_status_distinguishes_zero_from_measured():
    summary = {
        "cohorts": [],
        "resource_measurements": {"status": "NOT_MEASURED"},
        "host_metadata": {"status": "NOT_MEASURED"},
        "ingestion_completeness": {"status": "NOT_MEASURED"},
    }
    assert set(measurement_status(summary).values()) == {"NOT_MEASURED"}
