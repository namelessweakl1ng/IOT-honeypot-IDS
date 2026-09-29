import asyncio
import json
from copy import deepcopy
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from elasticsearch import NotFoundError
from fastapi import HTTPException

from attacks.runner import run as runner
from backend.app.api import experiments
from backend.app.elastic import ElasticStore
from backend.app.schemas import GroundTruthSubmission
from backend.app.services.scenario_contract import allowed_step_statuses
from backend.app.services.scenarios import ScenarioCatalog

HISTORICAL_EXPERIMENT_FIELDS = {
    "experiment_id",
    "scenario_id",
    "status",
    "target_honeypots",
    "expected_detection",
    "event_ids",
    "session_ids",
    "detection_ids",
    "result",
    "attacker_ip",
    "target_ip",
    "created_at",
    "start_time",
    "end_time",
    "observed_detection",
    "detection_latency_seconds",
    "trapsig",
}
HISTORICAL_DETECTION_FIELDS = {
    "detection_id",
    "session_id",
    "type",
    "severity",
    "rule_id",
    "evidence_event_ids",
    "source_ip",
    "timestamp",
    "reason",
    "trapsig",
}


def test_mapping_upgrades_are_strictly_additive():
    experiment = json.loads(Path("elk/elasticsearch/mapping-upgrades/trapsig-experiments.json").read_text())["properties"]
    detection = json.loads(Path("elk/elasticsearch/mapping-upgrades/trapsig-detections.json").read_text())["properties"]
    assert not HISTORICAL_EXPERIMENT_FIELDS.intersection(experiment)
    assert not HISTORICAL_DETECTION_FIELDS.intersection(detection)
    assert set(experiment) == {
        "scenario_manifest_sha256",
        "scenario_step_services",
        "scenario_step_allowed_statuses",
        "detector_ruleset_version",
        "software_revision",
        "run_id",
        "runner_status",
        "result_reason",
        "cancelled_at",
        "runner_start_time",
        "runner_end_time",
        "first_event_at",
        "last_event_at",
        "first_event_ingested_at",
        "last_event_ingested_at",
        "settle_wait_seconds",
        "evidence_latency_seconds",
        "processing_latency_seconds",
        "ground_truth_valid",
        "telemetry_settled",
        "config_snapshot",
        "runner_steps",
        "scenario_kind",
        "cohort_id",
        "observed_detection_types",
        "unexpected_detection_types",
        "matched_event_count",
        "linked_session_count",
        "linked_detection_count",
        "runner_step_count",
        "ingestion_latency_count",
        "telemetry_step_count",
        "telemetry_steps_covered",
        "ingestion_latency_min_seconds",
        "ingestion_latency_mean_seconds",
        "ingestion_latency_p50_seconds",
        "ingestion_latency_p95_seconds",
        "ingestion_latency_max_seconds",
        "runner_duration_seconds",
        "experiment_duration_seconds",
        "observed_event_rate_eps",
        "telemetry_step_coverage",
        "evaluation_step_time_tolerance_seconds",
    }
    assert set(detection) == {"evidence_end_time", "detected_at"}


class PitClient:
    def __init__(self, pages=None, search_error=None, missing=False):
        self.pages = list(pages or [])
        self.search_error = search_error
        self.missing = missing
        self.search_calls = []
        self.closed = []

    async def open_point_in_time(self, **kwargs):
        if self.missing:
            raise NotFoundError("missing", None, None)
        return {"id": "pit-1"}

    async def search(self, **kwargs):
        self.search_calls.append(kwargs)
        if self.search_error:
            raise self.search_error
        return {"hits": {"hits": self.pages.pop(0)}}

    async def close_point_in_time(self, **kwargs):
        self.closed.append(kwargs["id"])


def hit(identifier, sort):
    return {"_id": identifier, "_source": {"value": identifier}, "sort": sort}


def make_store(client):
    instance = object.__new__(ElasticStore)
    instance.client = client
    return instance


def test_search_all_uses_pit_mapping_independent_tiebreaker_and_returns_all_pages():
    client = PitClient([[hit("1", [1, 1]), hit("2", [2, 2])], [hit("3", [3, 3])]])
    result = asyncio.run(make_store(client).search_all("trapsig-events-*", sort=[{"@timestamp": "asc"}], page_size=2))
    assert [item["_id"] for item in result] == ["1", "2", "3"]
    assert all(call["sort"] == [{"@timestamp": "asc"}, {"_shard_doc": "asc"}] for call in client.search_calls)
    forbidden = {"event.id", "session_id", "detection_id", "experiment_id"}
    assert not forbidden.intersection({next(iter(item)) for item in client.search_calls[0]["sort"]})
    assert client.search_calls[1]["search_after"] == [2, 2]
    assert client.closed == ["pit-1"]


def test_search_all_closes_pit_on_search_error():
    client = PitClient(search_error=RuntimeError("search failed"))
    with pytest.raises(RuntimeError, match="search failed"):
        asyncio.run(make_store(client).search_all("trapsig-sessions", sort=[{"start_time": "asc"}]))
    assert client.closed == ["pit-1"]


def test_search_all_missing_index_is_empty():
    client = PitClient(missing=True)
    assert asyncio.run(make_store(client).search_all("missing", missing_index_is_empty=True)) == []


def submission(steps, overall_status="completed"):
    return GroundTruthSubmission.model_validate(
        {
            "run_id": "RUN-1",
            "experiment_id": "EXP-1",
            "scenario_id": "ssh-bruteforce",
            "scenario_manifest_sha256": "hash",
            "target": "192.168.50.10",
            "source": "runner",
            "expected_detection": "BRUTE_FORCE",
            "start_time": "2026-01-01T00:00:01Z",
            "end_time": "2026-01-01T00:00:20Z",
            "overall_status": overall_status,
            "steps": [
                {"step": number, "service": service, "started_at": "2026-01-01T00:00:02Z", "ended_at": "2026-01-01T00:00:03Z", "status": status}
                for number, service, status in steps
            ],
        }
    )


BASE_EXPERIMENT = {
    "experiment_id": "EXP-1",
    "status": "running",
    "scenario_id": "ssh-bruteforce",
    "scenario_manifest_sha256": "hash",
    "scenario_step_services": ["ssh"] * 6,
    "scenario_step_allowed_statuses": ["completed|rejected"] * 6,
    "target_ip": "192.168.50.10",
    "expected_detection": "BRUTE_FORCE",
    "start_time": "2026-01-01T00:00:00Z",
}


@pytest.mark.parametrize(
    "steps",
    [
        [],
        [(1, "ssh", "rejected")] * 5,
        [(i, "ssh", "rejected") for i in range(1, 8)],
        [(1, "ssh", "rejected"), (1, "ssh", "rejected"), *[(i, "ssh", "rejected") for i in range(3, 7)]],
        [(1, "telnet", "rejected"), *[(i, "ssh", "rejected") for i in range(2, 7)]],
        [(2, "ssh", "rejected"), (1, "ssh", "rejected"), *[(i, "ssh", "rejected") for i in range(3, 7)]],
    ],
)
def test_ground_truth_rejects_incomplete_or_wrong_step_contract(monkeypatch, steps):
    monkeypatch.setattr(experiments, "experiment", AsyncMock(return_value=deepcopy(BASE_EXPERIMENT)))
    with pytest.raises(HTTPException) as error:
        asyncio.run(experiments.ground_truth("EXP-1", submission(steps)))
    assert error.value.status_code == 422


def test_ground_truth_accepts_complete_rejected_auth_sequence(monkeypatch):
    monkeypatch.setattr(experiments, "experiment", AsyncMock(return_value=deepcopy(BASE_EXPERIMENT)))
    save = AsyncMock(side_effect=lambda _index, _id, document: document)
    monkeypatch.setattr(experiments.store, "save", save)
    steps = [(i, "ssh", "rejected") for i in range(1, 7)]
    result = asyncio.run(experiments.ground_truth("EXP-1", submission(steps)))
    assert result["ground_truth_valid"] is True


@pytest.mark.parametrize(
    "scenario_id,status,expected_valid",
    [
        ("ssh-interaction", "rejected", False),
        ("ssh-interaction", "completed", True),
        ("camera-default-creds", "rejected", True),
        ("router-default-creds", "rejected", True),
        ("mqtt-recon", "rejected", False),
        ("iot-probe", "rejected", False),
        ("mqtt-recon", "failed", False),
        ("iot-probe", "failed", False),
    ],
)
def test_ground_truth_status_must_prove_step_intent(monkeypatch, scenario_id, status, expected_valid):
    scenario = ScenarioCatalog().get(scenario_id)
    experiment = {
        **deepcopy(BASE_EXPERIMENT),
        "scenario_id": scenario.id,
        "scenario_manifest_sha256": scenario.manifest_sha256,
        "scenario_step_services": list(scenario.step_services),
        "scenario_step_allowed_statuses": ["|".join(values) for values in scenario.step_allowed_statuses],
        "expected_detection": scenario.expected_detection,
    }
    payload = submission([(number, service, status) for number, service in enumerate(scenario.step_services, 1)])
    payload.scenario_id = scenario.id
    payload.scenario_manifest_sha256 = scenario.manifest_sha256
    payload.expected_detection = scenario.expected_detection
    monkeypatch.setattr(experiments, "experiment", AsyncMock(return_value=experiment))
    monkeypatch.setattr(experiments.store, "save", AsyncMock(side_effect=lambda _index, _id, document: document))
    result = asyncio.run(experiments.ground_truth("EXP-1", payload))
    assert result["ground_truth_valid"] is expected_valid


def test_central_step_contract_distinguishes_authentication_from_command_intent():
    assert allowed_step_statuses({"service": "ssh"}) == {"completed", "rejected"}
    assert allowed_step_statuses({"service": "ssh", "command": "id"}) == {"completed"}
    assert allowed_step_statuses({"service": "camera"}) == {"completed", "rejected"}
    assert allowed_step_statuses({"service": "mqtt"}) == {"completed"}


@pytest.mark.parametrize(
    "scenario_id,expected_step_status,expected_overall",
    [("ssh-bruteforce", "rejected", "completed"), ("ssh-interaction", "failed", "failed")],
)
def test_runner_classifies_ssh_rejection_by_step_intent(monkeypatch, scenario_id, expected_step_status, expected_overall):
    monkeypatch.setenv("LAB_SUBNET", "192.168.50.0/24")

    def reject(_target, _step):
        raise runner.ExpectedRejection("authentication rejected")

    monkeypatch.setattr(runner, "execute", reject)
    result = runner.run(scenario_id, "192.168.50.10")
    assert {step["status"] for step in result["steps"]} == {expected_step_status}
    assert result["overall_status"] == expected_overall


def test_finish_resumes_after_settle_failure_and_preserves_end_time(monkeypatch):
    state = {**deepcopy(BASE_EXPERIMENT), "attacker_ip": "192.168.50.20", "target_honeypots": ["cowrie"]}

    async def get_experiment(_identifier):
        return {**state, "_id": "EXP-1"}

    async def save(_index, _identifier, document):
        state.clear()
        state.update(deepcopy(document))
        return document

    calls = 0

    async def flaky_settle(_doc):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("temporary Elasticsearch failure")
        return True, 0.1

    monkeypatch.setattr(experiments, "experiment", get_experiment)
    monkeypatch.setattr(experiments.store, "save", save)
    monkeypatch.setattr(experiments, "settle", flaky_settle)
    monkeypatch.setattr(experiments.store, "search_all", AsyncMock(return_value=[]))
    with pytest.raises(RuntimeError, match="temporary"):
        asyncio.run(experiments.finish("EXP-1"))
    original_end = state["end_time"]
    assert state["status"] == "correlating"
    result = asyncio.run(experiments.finish("EXP-1"))
    assert result["status"] == "completed"
    assert result["end_time"] == original_end


def test_correlating_can_be_cancelled_and_no_longer_blocks_start(monkeypatch):
    state = {**deepcopy(BASE_EXPERIMENT), "status": "correlating", "end_time": "2026-01-01T00:00:30Z"}
    scenario = ScenarioCatalog().get("ssh-bruteforce")
    next_experiment = {
        "experiment_id": "EXP-2",
        "status": "created",
        "scenario_id": scenario.id,
        "scenario_manifest_sha256": scenario.manifest_sha256,
    }

    async def get_experiment(identifier):
        return state if identifier == "EXP-1" else next_experiment

    monkeypatch.setattr(experiments, "experiment", get_experiment)
    monkeypatch.setattr(experiments.store, "save", AsyncMock(side_effect=lambda _index, _id, document: document))
    active_search = AsyncMock(return_value=[])
    monkeypatch.setattr(experiments.store, "search_all", active_search)
    cancelled = asyncio.run(experiments.cancel("EXP-1"))
    assert cancelled["status"] == "cancelled"
    started = asyncio.run(experiments.start("EXP-2"))
    assert started["status"] == "running"
    active_search.assert_awaited_once()


def test_experiments_page_keeps_independent_request_results():
    source = Path("frontend/src/app/experiments/page.tsx").read_text()
    assert "Promise.allSettled" in source
    assert 'experimentResult.status === "fulfilled"' in source
    assert 'scenarioResult.status === "fulfilled"' in source


def test_correlating_ui_exposes_retry_and_cancel_actions():
    source = Path("frontend/src/components/experiment-console.tsx").read_text()
    assert '["created", "running", "correlating"]' in source
    assert "Retry correlation" in source
    assert 'transition(item.experiment_id, "finish")' in source
    assert 'transition(item.experiment_id, "cancel")' in source
