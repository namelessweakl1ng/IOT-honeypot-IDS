"""Pass 5.6: Final runtime mode boundary audit tests.

Tests:
1. GET /mode does NOT depend on ES — returns 200 + mode even when ES ping fails/raises
2. DEMO rollback failure scenarios (401, 500, malformed body, network error)
3. Session materialization mode gate verification
4. Security: no secrets in mode/health responses
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "dashboard" / "api"))

from app import runtime_mode, es_client  # type: ignore  # noqa: E402


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("TRAPSIG_TEST_BYPASS_IP_ALLOWLIST", "1")
    monkeypatch.setenv("API_SECRET_KEY", "test-key-123")
    runtime_mode._current_mode = runtime_mode.RuntimeMode.EMPTY
    import importlib
    from app import main as _main
    importlib.reload(_main)
    from fastapi.testclient import TestClient
    return TestClient(_main.app)


@pytest.fixture(autouse=True)
def reset_mode():
    runtime_mode._current_mode = runtime_mode.RuntimeMode.EMPTY
    yield
    runtime_mode._current_mode = runtime_mode.RuntimeMode.EMPTY


# ---- Issue 1: GET /mode must NOT depend on Elasticsearch ----

class TestModeEndpointESIndependence:
    """GET /mode returns ONLY the runtime mode. It must NOT call es_client.ping().
    Mode and ES health are independent facts."""

    def test_mode_live_es_ping_returns_false(self, client, monkeypatch):
        """LIVE + ES ping returns False → /mode still returns 200 + LIVE."""
        runtime_mode._current_mode = runtime_mode.RuntimeMode.LIVE
        monkeypatch.setattr(es_client, "ping", lambda: False)
        r = client.get("/mode")
        assert r.status_code == 200
        assert r.json()["mode"] == "LIVE"

    def test_mode_live_es_ping_raises_exception(self, client, monkeypatch):
        """LIVE + ES ping raises exception → /mode still returns 200 + LIVE."""
        runtime_mode._current_mode = runtime_mode.RuntimeMode.LIVE
        def boom():
            raise ConnectionError("ES connection lost")
        monkeypatch.setattr(es_client, "ping", boom)
        r = client.get("/mode")
        assert r.status_code == 200
        assert r.json()["mode"] == "LIVE"

    def test_mode_empty_es_ping_returns_true(self, client, monkeypatch):
        """EMPTY + ES ping returns True → /mode returns EMPTY (ES doesn't change mode)."""
        runtime_mode._current_mode = runtime_mode.RuntimeMode.EMPTY
        monkeypatch.setattr(es_client, "ping", lambda: True)
        r = client.get("/mode")
        assert r.status_code == 200
        assert r.json()["mode"] == "EMPTY"

    def test_mode_demo_es_ping_raises(self, client, monkeypatch):
        """DEMO + ES ping raises → /mode returns DEMO."""
        runtime_mode._current_mode = runtime_mode.RuntimeMode.DEMO
        def boom():
            raise RuntimeError("ES exploded")
        monkeypatch.setattr(es_client, "ping", boom)
        r = client.get("/mode")
        assert r.status_code == 200
        assert r.json()["mode"] == "DEMO"

    def test_mode_response_has_no_es_field(self, client):
        """The /mode response must NOT contain an es_reachable field.
        ES health belongs in /health, not /mode."""
        r = client.get("/mode")
        data = r.json()
        assert "es_reachable" not in data
        assert "mode" in data


# ---- Issue 2: DEMO rollback failure scenarios (backend tests) ----

class TestDemoRollbackBackendGate:
    """The backend /mode/reset endpoint must properly reject/accept transitions.
    These verify the backend side; the frontend rollback verification is tested
    via Bun tests."""

    def test_reset_from_demo_succeeds(self, client):
        runtime_mode._current_mode = runtime_mode.RuntimeMode.DEMO
        r = client.post("/mode/reset", headers={"X-API-Key": "test-key-123"})
        assert r.status_code == 200
        assert r.json()["mode"] == "EMPTY"

    def test_reset_requires_api_key(self, client):
        runtime_mode._current_mode = runtime_mode.RuntimeMode.DEMO
        r = client.post("/mode/reset")
        assert r.status_code == 401

    def test_reset_from_empty_is_idempotent(self, client):
        runtime_mode._current_mode = runtime_mode.RuntimeMode.EMPTY
        r = client.post("/mode/reset", headers={"X-API-Key": "test-key-123"})
        assert r.status_code == 200
        assert r.json()["mode"] == "EMPTY"


# ---- Session materialization mode gate ----

class TestMaterializationModeGate:
    """Both automatic scheduler and manual endpoint must enforce mode==LIVE."""

    def test_manual_materialize_empty_rejected(self, client):
        """POST /sessions/materialize in EMPTY → 403."""
        runtime_mode._current_mode = runtime_mode.RuntimeMode.EMPTY
        r = client.post("/sessions/materialize", headers={"X-API-Key": "test-key-123"})
        assert r.status_code == 403
        assert "LIVE mode" in r.json()["detail"]

    def test_manual_materialize_demo_rejected(self, client):
        """POST /sessions/materialize in DEMO → 403."""
        runtime_mode._current_mode = runtime_mode.RuntimeMode.DEMO
        r = client.post("/sessions/materialize", headers={"X-API-Key": "test-key-123"})
        assert r.status_code == 403
        assert "LIVE mode" in r.json()["detail"]

    def test_manual_materialize_no_api_key_rejected(self, client):
        """POST /sessions/materialize without API key → 401 (even in LIVE)."""
        runtime_mode._current_mode = runtime_mode.RuntimeMode.LIVE
        r = client.post("/sessions/materialize")
        assert r.status_code == 401

    def test_manual_materialize_live_allowed(self, client, monkeypatch):
        """POST /sessions/materialize in LIVE + ES down → 200 with degraded (mode gate passes)."""
        runtime_mode._current_mode = runtime_mode.RuntimeMode.LIVE
        monkeypatch.setattr(es_client, "ping", lambda: False)
        r = client.post("/sessions/materialize", headers={"X-API-Key": "test-key-123"})
        assert r.status_code == 200
        assert r.json()["status"] == "degraded"


# ---- Scheduler mode gate ----

class TestSchedulerModeGate:
    """The automatic scheduler must check mode FIRST, then ES."""

    def test_scheduler_empty_es_up_no_materialize(self, monkeypatch):
        from app import session_scheduler
        runtime_mode._current_mode = runtime_mode.RuntimeMode.EMPTY
        monkeypatch.setattr(es_client, "ping", lambda: True)
        assert session_scheduler._should_materialize() is False

    def test_scheduler_demo_es_up_no_materialize(self, monkeypatch):
        from app import session_scheduler
        runtime_mode._current_mode = runtime_mode.RuntimeMode.DEMO
        monkeypatch.setattr(es_client, "ping", lambda: True)
        assert session_scheduler._should_materialize() is False

    def test_scheduler_live_es_up_materialize(self, monkeypatch):
        from app import session_scheduler
        runtime_mode._current_mode = runtime_mode.RuntimeMode.LIVE
        monkeypatch.setattr(es_client, "ping", lambda: True)
        assert session_scheduler._should_materialize() is True

    def test_scheduler_live_es_down_no_materialize(self, monkeypatch):
        from app import session_scheduler
        runtime_mode._current_mode = runtime_mode.RuntimeMode.LIVE
        monkeypatch.setattr(es_client, "ping", lambda: False)
        assert session_scheduler._should_materialize() is False

    def test_scheduler_live_es_ping_raises_no_materialize(self, monkeypatch):
        from app import session_scheduler
        runtime_mode._current_mode = runtime_mode.RuntimeMode.LIVE
        def boom():
            raise ConnectionError("ES down")
        monkeypatch.setattr(es_client, "ping", boom)
        assert session_scheduler._should_materialize() is False


# ---- Mode transition rules ----

class TestModeTransitions:
    """Forbidden transitions must be rejected."""

    def test_demo_to_live_forbidden(self, client):
        runtime_mode._current_mode = runtime_mode.RuntimeMode.DEMO
        r = client.post("/mode/live", headers={"X-API-Key": "test-key-123"})
        assert r.status_code == 409

    def test_live_to_demo_forbidden(self, client):
        runtime_mode._current_mode = runtime_mode.RuntimeMode.LIVE
        r = client.post("/mode/demo", headers={"X-API-Key": "test-key-123"})
        assert r.status_code == 409

    def test_empty_to_demo_allowed(self, client):
        r = client.post("/mode/demo", headers={"X-API-Key": "test-key-123"})
        assert r.status_code == 200
        assert r.json()["mode"] == "DEMO"

    def test_empty_to_live_allowed(self, client):
        r = client.post("/mode/live", headers={"X-API-Key": "test-key-123"})
        assert r.status_code == 200
        assert r.json()["mode"] == "LIVE"

    def test_live_to_empty_allowed(self, client):
        runtime_mode._current_mode = runtime_mode.RuntimeMode.LIVE
        r = client.post("/mode/reset", headers={"X-API-Key": "test-key-123"})
        assert r.status_code == 200
        assert r.json()["mode"] == "EMPTY"


# ---- Security: no secrets in mode/health responses ----

class TestNoSecretsInResponses:
    """No credentials may appear in any mode/health response."""

    def test_mode_response_no_secrets(self, client):
        r = client.get("/mode")
        body = r.text.lower()
        for secret in ["password", "api_secret", "elastic_password",
                       "api_secret_key", "test-key", "trapsig_backend",
                       "pi_ssh", "pi_ip", "known_hosts"]:
            assert secret not in body, f"secret '{secret}' in /mode response"

    def test_health_response_no_secrets(self, client, monkeypatch):
        monkeypatch.setattr(es_client, "ping", lambda: False)
        r = client.get("/health")
        body = r.text.lower()
        for secret in ["password", "api_secret", "elastic_password",
                       "api_secret_key", "test-key", "trapsig_backend"]:
            assert secret not in body, f"secret '{secret}' in /health response"

    def test_scheduler_status_no_secrets(self, client):
        r = client.get("/sessions/scheduler/status")
        body = r.text.lower()
        for secret in ["password", "api_secret", "elastic_password",
                       "api_secret_key", "test-key", "trapsig_backend"]:
            assert secret not in body, f"secret '{secret}' in scheduler status"
