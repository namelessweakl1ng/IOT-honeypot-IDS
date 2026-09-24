"""Pass 5.2: Runtime mode semantics regression tests.

Tests the backend-owned mode gating for session materialization.
The critical invariant: ES reachable ≠ LIVE mode. Mode is the GATE,
ES availability is a DEPENDENCY. Both required for materialization.

Covers scenarios A-L from the spec:
A. mode=EMPTY + ES reachable → materializer NOT called
B. mode=DEMO + ES reachable → materializer NOT called
C. mode=LIVE + ES reachable → materializer called
D. mode=LIVE + ES unavailable → materializer not called / safe skip
E. EMPTY → ES becomes reachable → remains EMPTY
F. DEMO → ES becomes reachable → remains DEMO
G. LIVE → ES becomes unreachable → remains LIVE but skips materialization
H. LIVE → DEMO → subsequent scheduler cycles stop materializing
I. DEMO → LIVE → subsequent cycles may materialize (via reset→live)
J. Pi CONNECTED while mode=DEMO → does not activate live materialization
K. ES reachable while mode=EMPTY → does not activate live materialization
L. Application startup in EMPTY → scheduler starts but performs no live materialization
"""
import asyncio
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "dashboard" / "api"))

from app import runtime_mode, session_scheduler, session_materializer, es_client  # type: ignore  # noqa: E402


@pytest.fixture(autouse=True)
def reset_mode():
    """Reset to EMPTY before each test."""
    runtime_mode._current_mode = runtime_mode.RuntimeMode.EMPTY
    yield
    runtime_mode._current_mode = runtime_mode.RuntimeMode.EMPTY


# ---- Helper: verify scheduler cycle behavior with mocked materializer ----

async def _verify_cycle_skips_materializer(monkeypatch):
    """Verify the scheduler does NOT call materializer in the current mode+ES state.
    Returns True if materializer was NOT called (correct for EMPTY/DEMO/ES-down)."""
    mock_mat = MagicMock(return_value={"status": "ok", "sessions_materialized": 0})
    monkeypatch.setattr(session_materializer, "materialize_sessions", mock_mat)

    # Check the gate: if _should_materialize() returns False, the loop
    # would NOT call _run_materialization_cycle() at all.
    if not session_scheduler._should_materialize():
        # Gate says skip — materializer must NOT be called
        assert not mock_mat.called, "materializer was called despite _should_materialize()=False"
        return True

    # Gate says proceed — simulate the cycle
    # Use a proper async wrapper for to_thread
    async def mock_to_thread(fn, **kw):
        return fn(**kw)
    monkeypatch.setattr(asyncio, "to_thread", mock_to_thread)
    await session_scheduler._run_materialization_cycle()
    return not mock_mat.called  # True = materializer was NOT called


async def _verify_cycle_calls_materializer(monkeypatch):
    """Verify the scheduler DOES call materializer in LIVE+ES-reachable state.
    Returns True if materializer WAS called (correct for LIVE+ES-up)."""
    mock_mat = MagicMock(return_value={"status": "ok", "sessions_materialized": 1})
    monkeypatch.setattr(session_materializer, "materialize_sessions", mock_mat)

    if not session_scheduler._should_materialize():
        return False  # gate says skip — materializer NOT called

    async def mock_to_thread(fn, **kw):
        return fn(**kw)
    monkeypatch.setattr(asyncio, "to_thread", mock_to_thread)
    await session_scheduler._run_materialization_cycle()
    return mock_mat.called


# ---- A: mode=EMPTY + ES reachable → materializer NOT called ----

class TestModeEmptyEsReachable:
    def test_A_empty_mode_es_reachable_no_materialization(self, monkeypatch):
        """mode=EMPTY, ES reachable → scheduler must NOT call materializer."""
        monkeypatch.setattr(es_client, "ping", lambda: True)
        runtime_mode._current_mode = runtime_mode.RuntimeMode.EMPTY

        result = asyncio.run(_verify_cycle_skips_materializer(monkeypatch))
        assert result is True, "materializer was called in EMPTY mode!"


# ---- B: mode=DEMO + ES reachable → materializer NOT called ----

class TestModeDemoEsReachable:
    def test_B_demo_mode_es_reachable_no_materialization(self, monkeypatch):
        """mode=DEMO, ES reachable → scheduler must NOT call materializer."""
        monkeypatch.setattr(es_client, "ping", lambda: True)
        runtime_mode._current_mode = runtime_mode.RuntimeMode.DEMO

        result = asyncio.run(_verify_cycle_skips_materializer(monkeypatch))
        assert result is True, "materializer was called in DEMO mode!"


# ---- C: mode=LIVE + ES reachable → materializer called ----

class TestModeLiveEsReachable:
    def test_C_live_mode_es_reachable_materializer_called(self, monkeypatch):
        """mode=LIVE, ES reachable → scheduler MUST call materializer."""
        monkeypatch.setattr(es_client, "ping", lambda: True)
        runtime_mode._current_mode = runtime_mode.RuntimeMode.LIVE

        result = asyncio.run(_verify_cycle_calls_materializer(monkeypatch))
        assert result is True, "materializer was NOT called in LIVE mode!"


# ---- D: mode=LIVE + ES unavailable → materializer not called ----

class TestModeLiveEsUnavailable:
    def test_D_live_mode_es_down_no_materialization(self, monkeypatch):
        """mode=LIVE, ES unreachable → scheduler skips (no materialization)."""
        monkeypatch.setattr(es_client, "ping", lambda: False)
        runtime_mode._current_mode = runtime_mode.RuntimeMode.LIVE

        result = asyncio.run(_verify_cycle_skips_materializer(monkeypatch))
        assert result is True, "materializer was called when ES is down!"


# ---- E: EMPTY → ES becomes reachable → remains EMPTY ----

class TestEmptyStaysEmptyWhenEsStarts:
    def test_E_empty_stays_empty_when_es_becomes_reachable(self, monkeypatch):
        """ES becoming reachable must NOT change the mode from EMPTY to LIVE."""
        # Start with EMPTY + ES unreachable
        runtime_mode._current_mode = runtime_mode.RuntimeMode.EMPTY
        monkeypatch.setattr(es_client, "ping", lambda: False)
        assert runtime_mode.get_mode() == runtime_mode.RuntimeMode.EMPTY

        # ES becomes reachable
        monkeypatch.setattr(es_client, "ping", lambda: True)
        # Mode must still be EMPTY
        assert runtime_mode.get_mode() == runtime_mode.RuntimeMode.EMPTY
        # Scheduler must still NOT materialize
        assert session_scheduler._should_materialize() is False


# ---- F: DEMO → ES becomes reachable → remains DEMO ----

class TestDemoStaysDemoWhenEsStarts:
    def test_F_demo_stays_demo_when_es_becomes_reachable(self, monkeypatch):
        """ES becoming reachable must NOT change the mode from DEMO to LIVE."""
        runtime_mode._current_mode = runtime_mode.RuntimeMode.DEMO
        monkeypatch.setattr(es_client, "ping", lambda: False)

        # ES becomes reachable
        monkeypatch.setattr(es_client, "ping", lambda: True)
        assert runtime_mode.get_mode() == runtime_mode.RuntimeMode.DEMO
        assert session_scheduler._should_materialize() is False


# ---- G: LIVE → ES becomes unreachable → remains LIVE but skips ----

class TestLiveStaysLiveWhenEsGoesDown:
    def test_G_live_stays_live_when_es_unreachable(self, monkeypatch):
        """ES going down must NOT change the mode from LIVE."""
        runtime_mode._current_mode = runtime_mode.RuntimeMode.LIVE
        monkeypatch.setattr(es_client, "ping", lambda: True)

        # ES goes down
        monkeypatch.setattr(es_client, "ping", lambda: False)
        assert runtime_mode.get_mode() == runtime_mode.RuntimeMode.LIVE
        # But scheduler skips because ES is down
        assert session_scheduler._should_materialize() is False

        # When ES comes back, scheduler resumes
        monkeypatch.setattr(es_client, "ping", lambda: True)
        assert session_scheduler._should_materialize() is True


# ---- H: LIVE → DEMO → subsequent scheduler cycles stop ----

class TestLiveToDemoStopsScheduler:
    def test_H_live_to_demo_stops_materialization(self, monkeypatch):
        """Transitioning LIVE → DEMO must stop materialization.
        Note: direct LIVE→DEMO is FORBIDDEN — must go through EMPTY."""
        runtime_mode._current_mode = runtime_mode.RuntimeMode.LIVE
        monkeypatch.setattr(es_client, "ping", lambda: True)
        assert session_scheduler._should_materialize() is True

        # LIVE → DEMO is forbidden — must reset to EMPTY first
        success, msg = runtime_mode.set_mode(runtime_mode.RuntimeMode.DEMO)
        assert not success, "LIVE→DEMO should be forbidden"

        # Correct path: LIVE → EMPTY → DEMO
        runtime_mode.reset_to_empty()
        runtime_mode.enter_demo()
        assert runtime_mode.get_mode() == runtime_mode.RuntimeMode.DEMO
        assert session_scheduler._should_materialize() is False


# ---- I: DEMO → LIVE → subsequent cycles may materialize ----

class TestDemoToLiveEnablesScheduler:
    def test_I_demo_to_live_via_empty_enables_materialization(self, monkeypatch):
        """Transitioning DEMO → LIVE (via EMPTY) enables materialization."""
        runtime_mode._current_mode = runtime_mode.RuntimeMode.DEMO
        monkeypatch.setattr(es_client, "ping", lambda: True)
        assert session_scheduler._should_materialize() is False

        # DEMO → LIVE is forbidden — must go through EMPTY
        success, msg = runtime_mode.set_mode(runtime_mode.RuntimeMode.LIVE)
        assert not success, "DEMO→LIVE should be forbidden"

        # Correct path: DEMO → EMPTY → LIVE
        runtime_mode.reset_to_empty()
        runtime_mode.enter_live()
        assert runtime_mode.get_mode() == runtime_mode.RuntimeMode.LIVE
        assert session_scheduler._should_materialize() is True


# ---- J: Pi CONNECTED while mode=DEMO → no live materialization ----

class TestPiConnectedDoesNotActivateLive:
    def test_J_pi_connected_demo_mode_no_materialization(self, monkeypatch):
        """Pi being connected does NOT activate live materialization.
        Only mode=LIVE + ES reachable enables materialization."""
        runtime_mode._current_mode = runtime_mode.RuntimeMode.DEMO
        monkeypatch.setattr(es_client, "ping", lambda: True)
        # Even if ES is reachable and Pi is "connected", mode is DEMO
        assert session_scheduler._should_materialize() is False

        # Mode must explicitly transition to LIVE
        runtime_mode.reset_to_empty()
        runtime_mode.enter_live()
        assert session_scheduler._should_materialize() is True


# ---- K: ES reachable while mode=EMPTY → no live materialization ----

class TestEsReachableEmptyModeNoMaterialization:
    def test_K_es_reachable_empty_mode_no_materialization(self, monkeypatch):
        """ES reachable does NOT mean LIVE. EMPTY + ES reachable → no materialization."""
        runtime_mode._current_mode = runtime_mode.RuntimeMode.EMPTY
        monkeypatch.setattr(es_client, "ping", lambda: True)
        assert session_scheduler._should_materialize() is False


# ---- L: Application startup in EMPTY → scheduler starts but no live materialization ----

class TestStartupInEmpty:
    def test_L_startup_empty_scheduler_runs_but_no_materialization(self, monkeypatch):
        """On startup, mode is EMPTY. Scheduler starts but must NOT materialize."""
        # On startup, mode is EMPTY (the default)
        assert runtime_mode.get_mode() == runtime_mode.RuntimeMode.EMPTY

        # Even if ES is reachable at startup
        monkeypatch.setattr(es_client, "ping", lambda: True)
        assert session_scheduler._should_materialize() is False

        # The scheduler task itself starts (verified in test_pass51_scheduler.py)
        # but it skips materialization because mode != LIVE


# ---- Mode transition API tests ----

class TestModeTransitionAPI:
    """Test the mode transition endpoints via FastAPI TestClient."""

    @pytest.fixture
    def client(self, monkeypatch):
        monkeypatch.setenv("TRAPSIG_TEST_BYPASS_IP_ALLOWLIST", "1")
        monkeypatch.setenv("API_SECRET_KEY", "test-key-123")
        runtime_mode._current_mode = runtime_mode.RuntimeMode.EMPTY
        import importlib
        from app import main as _main
        importlib.reload(_main)
        from fastapi.testclient import TestClient
        return TestClient(_main.app)

    def test_get_mode_returns_empty(self, client):
        r = client.get("/mode")
        assert r.status_code == 200
        assert r.json()["mode"] == "EMPTY"

    def test_post_mode_live_requires_api_key(self, client):
        r = client.post("/mode/live")
        assert r.status_code == 401

    def test_post_mode_live_from_empty_succeeds(self, client):
        r = client.post("/mode/live", headers={"X-API-Key": "test-key-123"})
        assert r.status_code == 200
        assert r.json()["mode"] == "LIVE"

    def test_post_mode_live_from_demo_forbidden(self, client):
        runtime_mode._current_mode = runtime_mode.RuntimeMode.DEMO
        r = client.post("/mode/live", headers={"X-API-Key": "test-key-123"})
        assert r.status_code == 409
        assert "Cannot enter LIVE while DEMO" in r.json()["detail"]

    def test_post_mode_reset_from_live_succeeds(self, client):
        runtime_mode._current_mode = runtime_mode.RuntimeMode.LIVE
        r = client.post("/mode/reset", headers={"X-API-Key": "test-key-123"})
        assert r.status_code == 200
        assert r.json()["mode"] == "EMPTY"

    def test_post_mode_demo_from_live_forbidden(self, client):
        runtime_mode._current_mode = runtime_mode.RuntimeMode.LIVE
        r = client.post("/mode/demo", headers={"X-API-Key": "test-key-123"})
        assert r.status_code == 409
        assert "Cannot enter DEMO while LIVE" in r.json()["detail"]

    def test_scheduler_status_includes_mode(self, client):
        r = client.get("/sessions/scheduler/status")
        assert r.status_code == 200
        data = r.json()
        assert "application_mode" in data
        assert data["application_mode"] in ("EMPTY", "DEMO", "LIVE")

    def test_health_includes_mode(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        assert "mode" in r.json()

    def test_mode_endpoints_no_secrets(self, client):
        """Mode endpoints must not expose credentials."""
        r = client.get("/mode")
        body = r.text
        for secret in ["password", "api_secret", "elastic_password", "API_SECRET_KEY", "test-key"]:
            assert secret not in body.lower(), f"secret '{secret}' in mode response"
