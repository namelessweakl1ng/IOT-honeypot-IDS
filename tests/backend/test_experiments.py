from unittest.mock import AsyncMock

from fastapi.testclient import TestClient

from backend.app.api import experiments
from backend.app.main import app
from backend.app.services.experiments import correlate


def test_experiment_list_treats_missing_index_as_empty(monkeypatch):
    search = AsyncMock(return_value=[])
    monkeypatch.setattr(experiments.store, "search", search)
    response = TestClient(app).get("/experiments")
    assert response.status_code == 200
    assert response.json() == []
    search.assert_awaited_once_with("trapsig-experiments", size=200, sort_field="created_at", missing_index_is_empty=True)


def test_create_derives_scenario_contract_from_catalog(monkeypatch):
    save = AsyncMock(side_effect=lambda _index, _id, document: document)
    monkeypatch.setattr(experiments.store, "save", save)
    payload = {
        "name": "First run",
        "description": "Baseline",
        "scenario_id": "ssh-bruteforce",
        "attacker_ip": "192.168.50.20",
        "target_ip": "192.168.50.10",
    }
    response = TestClient(app).post("/experiments", json=payload)
    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "created"
    assert body["target_honeypots"] == ["cowrie"]
    assert body["expected_detection"] == "BRUTE_FORCE"
    assert body["scenario_manifest_sha256"]


def test_correlation_uses_window_source_and_target():
    experiment = {
        "start_time": "2026-01-01T00:00:00Z",
        "end_time": "2026-01-01T00:05:00Z",
        "attacker_ip": "192.168.50.20",
        "target_ip": "192.168.50.10",
        "expected_detection": "BRUTE_FORCE",
    }
    events = [
        {
            "@timestamp": "2026-01-01T00:01:00Z",
            "event": {"id": "yes"},
            "source": {"ip": "192.168.50.20"},
            "destination": {"ip": "192.168.50.10"},
        },
        {
            "@timestamp": "2026-01-01T00:01:00Z",
            "event": {"id": "no"},
            "source": {"ip": "192.168.50.30"},
            "destination": {"ip": "192.168.50.10"},
        },
    ]
    result = correlate(
        experiment,
        events,
        [{"session_id": "s1", "event_ids": ["yes"]}],
        [{"detection_id": "d1", "session_id": "s1", "type": "BRUTE_FORCE"}],
    )
    assert result["event_ids"] == ["yes"]
    assert result["result"] == "TP"
