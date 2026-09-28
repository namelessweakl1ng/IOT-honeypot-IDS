from unittest.mock import AsyncMock

import pytest
from elasticsearch import NotFoundError
from fastapi.testclient import TestClient

from app.api import analytics
from app.elastic import ElasticStore
from app.main import app


def result(total=0, aggregations=None, hits=None):
    return {"hits": {"total": {"value": total}, "hits": hits or []}, "aggregations": aggregations or {}}


def test_overview_returns_normal_aggregation_response(monkeypatch):
    events = result(4, {
        "events_over_time": {"buckets": [{"key": 1, "key_as_string": "2026-01-01T00:00:00Z", "doc_count": 4}]},
        "unique_sources": {"value": 2}, "honeypots": {"buckets": [{"key": "cowrie-01", "doc_count": 4}]},
        "protocols": {"buckets": []}, "categories": {"buckets": []}, "actions": {"buckets": []}, "outcomes": {"buckets": []},
        "auth_outcomes": {"values": {"buckets": [{"key": "failure", "doc_count": 3}]}},
        "top_sources": {"buckets": [{"key": "192.0.2.4", "doc_count": 4, "honeypots": {"buckets": [{"key": "cowrie-01", "doc_count": 4}]}}]},
    })
    sessions = result(1, {"failed_auth": {"value": 3}, "multi_service": {"doc_count": 0}})
    detections = result(1, {"severity": {"buckets": [{"key": "high", "doc_count": 1}]}, "types": {"buckets": [{"key": "BRUTE_FORCE", "doc_count": 1}]}})
    aggregate = AsyncMock(side_effect=[events, sessions, detections])
    monkeypatch.setattr(analytics.store, "aggregate", aggregate)

    response = TestClient(app).get("/analytics/overview?minutes=60")

    assert response.status_code == 200
    body = response.json()
    assert body["totals"] == {"events": 4, "sessions": 1, "detections": 1, "unique_sources": 2, "failed_auth_attempts": 3, "multi_service_sessions": 0}
    assert body["source_honeypot_matrix"][0]["honeypots"] == {"cowrie-01": 4}
    assert body["detection_types"] == [{"name": "BRUTE_FORCE", "count": 1}]


@pytest.mark.parametrize("missing_position", [0, 1, 2])
def test_overview_handles_missing_event_session_or_detection_index(monkeypatch, missing_position):
    responses = [
        result(2, {"unique_sources": {"value": 1}}),
        result(3, {"failed_auth": {"value": 0}, "multi_service": {"doc_count": 0}}),
        result(4),
    ]
    responses[missing_position] = result()
    monkeypatch.setattr(analytics.store, "aggregate", AsyncMock(side_effect=responses))

    response = TestClient(app).get("/analytics/overview?minutes=15")

    assert response.status_code == 200
    totals = response.json()["totals"]
    assert [totals["events"], totals["sessions"], totals["detections"]][missing_position] == 0


def test_overview_no_events_returns_intentional_empty_collections(monkeypatch):
    monkeypatch.setattr(analytics.store, "aggregate", AsyncMock(side_effect=[result(), result(), result()]))
    body = TestClient(app).get("/analytics/overview").json()
    assert body["events_over_time"] == []
    assert body["top_sources"] == []
    assert body["recent_events"] == []


def test_overview_rejects_invalid_time_range():
    response = TestClient(app).get("/analytics/overview?minutes=42")
    assert response.status_code == 422
    assert "minutes must be one of" in response.json()["detail"]


def test_overview_propagates_elasticsearch_errors(monkeypatch):
    monkeypatch.setattr(analytics.store, "aggregate", AsyncMock(side_effect=RuntimeError("cluster unavailable")))
    with pytest.raises(RuntimeError, match="cluster unavailable"):
        TestClient(app, raise_server_exceptions=True).get("/analytics/overview")


@pytest.mark.asyncio
async def test_aggregate_missing_index_is_empty_but_other_errors_propagate():
    store = object.__new__(ElasticStore)
    store.client = AsyncMock()
    store.client.search.side_effect = NotFoundError("missing", None, None)
    empty = await store.aggregate("missing", {"match_all": {}}, {}, missing_index_is_empty=True)
    assert empty["hits"]["total"]["value"] == 0

    store.client.search.side_effect = RuntimeError("transport failed")
    with pytest.raises(RuntimeError, match="transport failed"):
        await store.aggregate("broken", {"match_all": {}}, {}, missing_index_is_empty=True)
