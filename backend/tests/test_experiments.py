from unittest.mock import AsyncMock

import pytest
from elasticsearch import NotFoundError
from fastapi.testclient import TestClient

from app.api import experiments
from app.elastic import ElasticStore
from app.main import app


def test_get_experiments_returns_empty_when_index_is_missing(monkeypatch):
    search = AsyncMock(return_value=[])
    monkeypatch.setattr(experiments.store, "search", search)

    response = TestClient(app).get("/experiments")

    assert response.status_code == 200
    assert response.json() == []
    search.assert_awaited_once_with(
        "trapsig-experiments",
        size=200,
        sort_field="created_at",
        missing_index_is_empty=True,
    )


@pytest.mark.asyncio
async def test_search_treats_only_missing_index_as_empty():
    store = object.__new__(ElasticStore)
    store.client = AsyncMock()
    store.client.search.side_effect = NotFoundError("missing", None, None)

    assert await store.search("missing", missing_index_is_empty=True) == []

    store.client.search.side_effect = RuntimeError("connection failure")
    with pytest.raises(RuntimeError, match="connection failure"):
        await store.search("broken", missing_index_is_empty=True)


def test_create_experiment_still_indexes_first_document(monkeypatch):
    save = AsyncMock(side_effect=lambda _index, _id, document: document)
    monkeypatch.setattr(experiments.store, "save", save)
    payload = {
        "name": "First run",
        "description": "Baseline",
        "scenario_id": "ssh-bruteforce",
        "target_honeypots": ["cowrie"],
        "attacker_ip": "192.0.2.10",
        "target_ip": "192.0.2.20",
        "expected_detection": "Repeated login failures",
    }

    response = TestClient(app).post("/experiments", json=payload)

    assert response.status_code == 201
    assert response.json()["status"] == "created"
    assert response.json()["experiment_id"].startswith("EXP-")
    save.assert_awaited_once()
