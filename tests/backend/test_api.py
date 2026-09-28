from fastapi.testclient import TestClient

from backend.app.elastic import store
from backend.app.main import app
from backend.app.services.pi_manager import pi_manager

client = TestClient(app)


async def fake_health():
    return {"status": "green"}


async def fake_get(index, document_id):
    return None


def test_health(monkeypatch):
    monkeypatch.setattr(store, "health", fake_health)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["elasticsearch"] == "green"


def test_collection_endpoints_use_stored_schema_sort_fields(monkeypatch):
    calls = []

    async def schema_search(index, query=None, size=100, sort_field="@timestamp"):
        calls.append((index, sort_field))
        documents = {
            "trapsig-sessions": [{"session_id": "SES-1", "start_time": "2026-01-01T00:00:00Z"}],
            "trapsig-detections": [{"detection_id": "DET-1", "timestamp": "2026-01-01T00:00:01Z"}],
            "trapsig-experiments": [{"experiment_id": "EXP-1", "created_at": "2026-01-01T00:00:02Z"}],
        }
        return documents.get(index, [])

    monkeypatch.setattr(store, "search", schema_search)
    assert client.get("/sessions").json()[0]["session_id"] == "SES-1"
    assert client.get("/detections").json()[0]["detection_id"] == "DET-1"
    assert client.get("/experiments").json()[0]["experiment_id"] == "EXP-1"
    assert calls == [
        ("trapsig-sessions", "start_time"),
        ("trapsig-detections", "timestamp"),
        ("trapsig-experiments", "created_at"),
    ]


def test_missing_event(monkeypatch):
    monkeypatch.setattr(store, "get", fake_get)
    assert client.get("/events/missing").status_code == 404


def test_experiment_validation():
    assert client.post("/experiments", json={}).status_code == 422


def test_honeypot_validation(monkeypatch):
    async def configured(identifier, action):
        if identifier == "invalid":
            raise ValueError("unknown honeypot")
        return {"honeypot_id": identifier, "action": action}

    monkeypatch.setattr(pi_manager, "action", configured)
    assert client.post("/honeypots/camera/restart").status_code == 200
    assert client.post("/honeypots/invalid/start").status_code == 404
