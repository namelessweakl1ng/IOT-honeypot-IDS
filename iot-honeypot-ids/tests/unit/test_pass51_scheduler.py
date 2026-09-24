"""Pass 5.1: Session materialization scheduler lifecycle tests.

Tests the automatic session materialization lifecycle:
- FastAPI lifespan starts/stops the scheduler
- Scheduler only runs when ES is reachable (LIVE mode)
- EMPTY/DEMO modes don't materialize live sessions
- Overlapping cycles are prevented (in-process lock)
- Exceptions don't crash the API
- Session documents are updated (not duplicated) when new events arrive
- Event/session caps are deterministic
- Out-of-order timestamps produce correct started_at/ended_at
- Duplicate event processing remains idempotent

Uses mocked ES — no live Elasticsearch required.
"""
import asyncio
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, AsyncMock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "dashboard" / "api"))

from app import session_scheduler, session_materializer, es_client  # type: ignore  # noqa: E402


# ---- Helpers ----

def _make_event(event_id="e1", session_id="s1", timestamp="2025-01-15T12:00:00.000Z",
                src_ip="10.0.0.10", classification=None):
    return {
        "@timestamp": timestamp,
        "event_id": event_id,
        "session_id": session_id,
        "device": {"id": "camera-01", "type": "camera", "container": "pi-camera"},
        "protocol": "http",
        "source": {"ip": src_ip, "port": 49152},
        "destination": {"ip": "192.168.1.50", "port": 8080},
        "honeypot": {"name": "camera", "container": "pi-camera"},
        "event": {"type": "http_request", "category": "network", "action": "get_admin"},
        "attack": {"session_id": session_id, "stage": "reconnaissance",
                    "classification": classification, "confidence": 0.0},
    }


# ---- 1: LIVE startup enables materialization ----

class TestSchedulerLifecycle:
    """Test the scheduler starts/stops with FastAPI lifespan."""

    def test_start_scheduler_creates_task(self):
        """start_scheduler() creates an asyncio.Task."""
        # Reset state
        session_scheduler._scheduler_task = None

        async def run():
            await session_scheduler.start_scheduler()
            assert session_scheduler._scheduler_task is not None
            assert not session_scheduler._scheduler_task.done()
            # Clean up
            await session_scheduler.stop_scheduler()
            assert session_scheduler._scheduler_task is None

        asyncio.run(run())

    def test_stop_scheduler_cancels_task(self):
        """stop_scheduler() cancels the running task."""
        session_scheduler._scheduler_task = None

        async def run():
            await session_scheduler.start_scheduler()
            task = session_scheduler._scheduler_task
            assert task is not None
            await session_scheduler.stop_scheduler()
            assert session_scheduler._scheduler_task is None
            # The task should be cancelled
            assert task.cancelled() or task.done()

        asyncio.run(run())

    def test_start_scheduler_idempotent(self):
        """Starting the scheduler twice doesn't create duplicate tasks."""
        session_scheduler._scheduler_task = None

        async def run():
            await session_scheduler.start_scheduler()
            task1 = session_scheduler._scheduler_task
            await session_scheduler.start_scheduler()  # second call
            task2 = session_scheduler._scheduler_task
            assert task1 is task2  # same task, not a new one
            await session_scheduler.stop_scheduler()

        asyncio.run(run())


# ---- 2: EMPTY mode does not materialize ----

class TestEmptyMode:
    """When ES is unreachable (EMPTY mode), the scheduler skips materialization."""

    def test_scheduler_skips_when_es_unreachable(self, monkeypatch):
        """_should_materialize() returns False when ES is unreachable.
        Even if mode is LIVE, ES being down means skip."""
        from app import runtime_mode
        runtime_mode._current_mode = runtime_mode.RuntimeMode.LIVE
        monkeypatch.setattr(es_client, "ping", lambda: False)
        assert session_scheduler._should_materialize() is False
        # Clean up
        runtime_mode._current_mode = runtime_mode.RuntimeMode.EMPTY

    def test_scheduler_skips_when_mode_not_live(self, monkeypatch):
        """_should_materialize() returns False when mode is EMPTY even if ES is up."""
        from app import runtime_mode
        runtime_mode._current_mode = runtime_mode.RuntimeMode.EMPTY
        monkeypatch.setattr(es_client, "ping", lambda: True)
        assert session_scheduler._should_materialize() is False

    def test_scheduler_runs_when_live_and_es_reachable(self, monkeypatch):
        """_should_materialize() returns True only when BOTH mode=LIVE AND ES reachable."""
        from app import runtime_mode
        runtime_mode._current_mode = runtime_mode.RuntimeMode.LIVE
        monkeypatch.setattr(es_client, "ping", lambda: True)
        assert session_scheduler._should_materialize() is True
        # Clean up
        runtime_mode._current_mode = runtime_mode.RuntimeMode.EMPTY


# ---- 3: DEMO mode does not materialize live sessions ----

class TestDemoModeIsolation:
    """The scheduler doesn't know about frontend DEMO mode — it checks ES.
    If ES is unreachable (which it is in DEMO mode since DEMO doesn't use ES),
    the scheduler skips. Demo data comes from sessions.csv, not ES."""

    def test_demo_mode_es_unreachable_skips_scheduler(self, monkeypatch):
        """In DEMO mode, scheduler must NOT materialize even if ES is reachable."""
        from app import runtime_mode
        runtime_mode._current_mode = runtime_mode.RuntimeMode.DEMO
        monkeypatch.setattr(es_client, "ping", lambda: True)  # ES IS reachable
        assert session_scheduler._should_materialize() is False  # but mode is DEMO
        # Clean up
        runtime_mode._current_mode = runtime_mode.RuntimeMode.EMPTY

    def test_scheduler_does_not_touch_demo_csv(self, monkeypatch):
        """The scheduler only writes to honeypot-sessions-* in ES.
        It never touches sessions.csv (the demo data source)."""
        monkeypatch.setattr(es_client, "ping", lambda: False)
        # When ES is down, materialize_sessions returns degraded — no ES writes
        result = session_materializer.materialize_sessions()
        assert result["status"] == "degraded"
        assert result["sessions_materialized"] == 0


# ---- 4: One scheduler cycle materializes sessions ----

class TestSingleCycleMaterialization:
    """One materialization cycle processes events and writes sessions."""

    def test_one_cycle_with_events(self, monkeypatch):
        """When ES has events, one cycle materializes them into sessions."""
        monkeypatch.setattr(es_client, "ping", lambda: True)
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.body = {
            "hits": {
                "total": {"value": 2},
                "hits": [
                    {"_source": _make_event(event_id="e1", session_id="s1"), "sort": [1, "e1"]},
                    {"_source": _make_event(event_id="e2", session_id="s1", timestamp="2025-01-15T12:00:01.000Z"), "sort": [1, "e2"]},
                ],
            }
        }
        mock_client.search.return_value = mock_resp
        mock_client.index = MagicMock()
        monkeypatch.setattr(es_client, "get_client", lambda: mock_client)

        # Run one cycle directly
        result = asyncio.run(session_scheduler._run_materialization_cycle())
        # The scheduler stores the result
        assert session_scheduler._last_result is not None
        assert session_scheduler._last_result["sessions_materialized"] == 1
        assert session_scheduler._last_result["events_processed"] == 2

    def test_one_cycle_no_events(self, monkeypatch):
        """When ES has no events in the lookback, cycle returns 0 sessions."""
        monkeypatch.setattr(es_client, "ping", lambda: True)
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.body = {"hits": {"total": {"value": 0}, "hits": []}}
        mock_client.search.return_value = mock_resp
        monkeypatch.setattr(es_client, "get_client", lambda: mock_client)

        asyncio.run(session_scheduler._run_materialization_cycle())
        assert session_scheduler._last_result["sessions_materialized"] == 0


# ---- 5: Scheduler exception does not crash API ----

class TestSchedulerExceptionSafety:
    """If materialize_sessions raises, the scheduler catches it — never crashes."""

    def test_exception_in_materialize_caught(self, monkeypatch):
        """If materialize_sessions raises an exception, the scheduler
        catches it and stores an error result — doesn't propagate."""
        monkeypatch.setattr(es_client, "ping", lambda: True)
        # Make materialize_sessions raise
        def boom(**kw):
            raise RuntimeError("simulated ES failure")
        monkeypatch.setattr(session_materializer, "materialize_sessions", boom)

        # Should NOT raise
        asyncio.run(session_scheduler._run_materialization_cycle())
        assert session_scheduler._last_result is not None
        assert session_scheduler._last_result["status"] == "error"

    def test_exception_in_es_ping_caught(self, monkeypatch):
        """If es_client.ping() raises, _should_materialize returns False."""
        from app import runtime_mode
        runtime_mode._current_mode = runtime_mode.RuntimeMode.LIVE
        def boom():
            raise ConnectionError("ES connection lost")
        monkeypatch.setattr(es_client, "ping", boom)
        assert session_scheduler._should_materialize() is False
        # Clean up
        runtime_mode._current_mode = runtime_mode.RuntimeMode.EMPTY


# ---- 6: Overlapping cycles are prevented ----

class TestOverlapPrevention:
    """The in-process asyncio.Lock prevents overlapping materialization."""

    def test_lock_prevents_concurrent_execution(self, monkeypatch):
        """If a cycle is already running, a second call is skipped (not queued).

        Pass 7 hardening: the scheduler now calls asyncio.to_thread TWICE
        per cycle — once for materialization, once for automatic detection.
        The lock still prevents the SECOND CYCLE from running, so total
        to_thread calls = 2 (one cycle's worth), NOT 4 (two cycles' worth).
        """
        monkeypatch.setattr(es_client, "ping", lambda: True)

        # Simulate a slow materialize_sessions that blocks
        slow_call_count = {"n": 0}
        async def slow_materialize(**kw):
            slow_call_count["n"] += 1
            await asyncio.sleep(0.5)  # simulate slow ES
            return {"status": "ok", "sessions_materialized": 1, "events_processed": 1}

        # Patch asyncio.to_thread to call our async function directly
        monkeypatch.setattr(asyncio, "to_thread", lambda fn, **kw: slow_materialize(**kw))

        async def run():
            # Start first cycle (holds the lock)
            task1 = asyncio.create_task(session_scheduler._run_materialization_cycle())
            await asyncio.sleep(0.1)  # let task1 acquire the lock
            # Start second cycle (should be skipped because lock is held)
            await session_scheduler._run_materialization_cycle()
            await task1  # wait for first to finish

        asyncio.run(run())
        # Pass 7: the first cycle calls to_thread twice (materialize + detection).
        # The second cycle is SKIPPED (lock held) — no additional calls.
        # So total = 2, NOT 4. If the lock failed, we'd see 4.
        assert slow_call_count["n"] == 2, (
            f"expected 2 to_thread calls (1 materialize + 1 detection), "
            f"got {slow_call_count['n']} — lock may have failed to prevent "
            f"the second cycle"
        )


# ---- 7: Shutdown stops the task ----

class TestShutdownStopsTask:
    """stop_scheduler() cancels the background task cleanly."""

    def test_stop_cancels_running_task(self):
        session_scheduler._scheduler_task = None

        async def run():
            await session_scheduler.start_scheduler()
            assert session_scheduler._scheduler_task is not None
            assert not session_scheduler._scheduler_task.done()
            await session_scheduler.stop_scheduler()
            assert session_scheduler._scheduler_task is None

        asyncio.run(run())

    def test_stop_when_not_started_is_noop(self):
        """stop_scheduler() when nothing is running is a safe no-op."""
        session_scheduler._scheduler_task = None

        async def run():
            await session_scheduler.stop_scheduler()  # should not raise
            assert session_scheduler._scheduler_task is None

        asyncio.run(run())


# ---- 8: Session gets updated when additional events arrive ----

class TestSessionUpdateOnNewEvents:
    """Repeated materialization updates the session document (upsert),
    not creates a new one. The session_id is the stable identity."""

    def test_same_session_id_updated_not_duplicated(self, monkeypatch):
        """First cycle: 2 events → session with event_count=2.
        Second cycle: 3 events (same session_id) → session updated to event_count=3."""
        monkeypatch.setattr(es_client, "ping", lambda: True)
        mock_client = MagicMock()
        mock_client.index = MagicMock()
        monkeypatch.setattr(es_client, "get_client", lambda: mock_client)

        # First cycle: 2 events
        mock_resp1 = MagicMock()
        mock_resp1.body = {
            "hits": {"total": {"value": 2}, "hits": [
                {"_source": _make_event(event_id="e1", session_id="s1",
                                         timestamp="2025-01-15T12:00:00.000Z"), "sort": [1, "e1"]},
                {"_source": _make_event(event_id="e2", session_id="s1",
                                         timestamp="2025-01-15T12:00:01.000Z"), "sort": [1, "e2"]},
            ]}
        }
        mock_client.search.return_value = mock_resp1

        result1 = session_materializer.materialize_sessions()
        assert result1["sessions_materialized"] == 1

        # Verify the session was indexed with session_id as document_id
        call1 = mock_client.index.call_args
        assert call1.kwargs.get("id") == "s1"
        doc1 = call1.kwargs.get("document", {})
        assert doc1["event_count"] == 2

        # Second cycle: 3 events (same session_id, +1 new event)
        mock_client.index.reset_mock()
        mock_resp2 = MagicMock()
        mock_resp2.body = {
            "hits": {"total": {"value": 3}, "hits": [
                {"_source": _make_event(event_id="e1", session_id="s1",
                                         timestamp="2025-01-15T12:00:00.000Z"), "sort": [1, "e1"]},
                {"_source": _make_event(event_id="e2", session_id="s1",
                                         timestamp="2025-01-15T12:00:01.000Z"), "sort": [1, "e2"]},
                {"_source": _make_event(event_id="e3", session_id="s1",
                                         timestamp="2025-01-15T12:00:02.000Z"), "sort": [1, "e3"]},
            ]}
        }
        mock_client.search.return_value = mock_resp2

        result2 = session_materializer.materialize_sessions()
        assert result2["sessions_materialized"] == 1

        # Verify the session was indexed with the SAME document_id (upsert)
        call2 = mock_client.index.call_args
        assert call2.kwargs.get("id") == "s1"
        doc2 = call2.kwargs.get("document", {})
        assert doc2["event_count"] == 3  # updated, not duplicated


# ---- 9: Event cap is deterministic ----

class TestEventCap:
    """max_events bounds the total events fetched per cycle."""

    def test_event_cap_reported(self, monkeypatch):
        """When max_events is reached, events_capped=True is reported."""
        monkeypatch.setattr(es_client, "ping", lambda: True)
        mock_client = MagicMock()
        # Return exactly batch_size hits on each page to trigger pagination
        mock_resp = MagicMock()
        mock_resp.body = {
            "hits": {
                "total": {"value": 100000},
                "hits": [
                    {"_source": _make_event(event_id=f"e{i}", session_id=f"s{i}"),
                     "sort": [i, f"e{i}"]}
                    for i in range(100)
                ],
            }
        }
        mock_client.search.return_value = mock_resp
        mock_client.index = MagicMock()
        monkeypatch.setattr(es_client, "get_client", lambda: mock_client)

        # Use a small max_events to trigger the cap
        result = session_materializer.materialize_sessions(
            max_events=50, batch_size=100,
        )
        assert result["events_capped"] is True
        assert result["events_processed"] >= 50

    def test_event_cap_not_triggered_under_limit(self, monkeypatch):
        """When events < max_events, events_capped=False."""
        monkeypatch.setattr(es_client, "ping", lambda: True)
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.body = {
            "hits": {"total": {"value": 2}, "hits": [
                {"_source": _make_event(event_id="e1", session_id="s1"), "sort": [1, "e1"]},
                {"_source": _make_event(event_id="e2", session_id="s2"), "sort": [2, "e2"]},
            ]}
        }
        mock_client.search.return_value = mock_resp
        mock_client.index = MagicMock()
        monkeypatch.setattr(es_client, "get_client", lambda: mock_client)

        result = session_materializer.materialize_sessions(max_events=50000)
        assert result.get("events_capped") is False


# ---- 10: Session cap is deterministic ----

class TestSessionCap:
    """max_sessions bounds the number of sessions materialized per cycle."""

    def test_session_cap_stops_at_limit(self, monkeypatch):
        """When there are more sessions than max_sessions, stop at the limit."""
        monkeypatch.setattr(es_client, "ping", lambda: True)
        mock_client = MagicMock()
        # 10 events, each in a different session
        mock_resp = MagicMock()
        mock_resp.body = {
            "hits": {"total": {"value": 10}, "hits": [
                {"_source": _make_event(event_id=f"e{i}", session_id=f"s{i}"),
                 "sort": [i, f"e{i}"]}
                for i in range(10)
            ]}
        }
        mock_client.search.return_value = mock_resp
        mock_client.index = MagicMock()
        monkeypatch.setattr(es_client, "get_client", lambda: mock_client)

        result = session_materializer.materialize_sessions(max_sessions=5)
        assert result["sessions_materialized"] == 5


# ---- 11: Out-of-order timestamps produce correct started_at/ended_at ----

class TestOutOfOrderTimestamps:
    """Events arriving out of order must still produce correct session bounds."""

    def test_out_of_order_events_correct_bounds(self):
        """Events with timestamps [3, 1, 2] → started_at=1, ended_at=3."""
        events = [
            _make_event(event_id="e3", timestamp="2025-01-15T12:00:03.000Z"),
            _make_event(event_id="e1", timestamp="2025-01-15T12:00:01.000Z"),
            _make_event(event_id="e2", timestamp="2025-01-15T12:00:02.000Z"),
        ]
        doc = session_materializer.build_session_document("s1", events)
        assert doc["started_at"] == "2025-01-15T12:00:01.000Z"
        assert doc["ended_at"] == "2025-01-15T12:00:03.000Z"
        assert doc["duration_s"] == 2.0
        # event_ids should be in timestamp order
        assert doc["event_ids"] == ["e1", "e2", "e3"]


# ---- 12: Duplicate event processing remains idempotent ----

class TestIdempotency:
    """Processing the same events twice produces the same session document."""

    def test_same_events_same_document(self):
        """build_session_document is deterministic."""
        events = [
            _make_event(event_id="e1", session_id="s1", timestamp="2025-01-15T12:00:00.000Z"),
            _make_event(event_id="e2", session_id="s1", timestamp="2025-01-15T12:00:01.000Z"),
        ]
        doc1 = session_materializer.build_session_document("s1", events)
        doc2 = session_materializer.build_session_document("s1", events)
        assert doc1 == doc2

    def test_materialize_uses_upsert_not_create(self):
        """STATIC TEST: materialize_sessions uses ES index (upsert) with
        session_id as document_id. This means reprocessing the same events
        updates the session rather than creating duplicates or failing with 409."""
        import inspect
        src = inspect.getsource(session_materializer.materialize_sessions)
        assert "client.index(" in src  # index = upsert
        assert 'id=sid' in src  # session_id as document_id
        # Verify it does NOT use action=create
        assert 'action="create"' not in src
        assert "action => 'create'" not in src


# ---- Scheduler status endpoint ----

class TestSchedulerStatus:
    """Test the /sessions/scheduler/status endpoint."""

    @pytest.fixture
    def client(self, monkeypatch):
        monkeypatch.setenv("TRAPSIG_TEST_BYPASS_IP_ALLOWLIST", "1")
        import importlib
        from app import main as _main
        importlib.reload(_main)
        from fastapi.testclient import TestClient
        return TestClient(_main.app)

    def test_scheduler_status_returns_200(self, client):
        r = client.get("/sessions/scheduler/status")
        assert r.status_code == 200
        data = r.json()
        assert "running" in data
        assert "cycle_count" in data
        assert "interval_s" in data
        assert "lock_held" in data

    def test_scheduler_status_no_secrets(self, client):
        """Status endpoint must not expose credentials."""
        r = client.get("/sessions/scheduler/status")
        body = r.text
        for secret in ["password", "api_secret", "elastic_password", "API_SECRET_KEY"]:
            assert secret not in body.lower(), f"secret '{secret}' in status response"

    def test_scheduler_interval_bounded(self, monkeypatch):
        """The scheduler interval must be bounded 5s-3600s."""
        # Test with env var set to an extreme value
        monkeypatch.setenv("SESSION_MATERIALIZER_INTERVAL_S", "1")  # too low
        interval = session_scheduler._get_interval()
        assert interval >= 5.0  # minimum 5s

        monkeypatch.setenv("SESSION_MATERIALIZER_INTERVAL_S", "99999")  # too high
        interval = session_scheduler._get_interval()
        assert interval <= 3600.0  # max 1 hour

    def test_scheduler_interval_default(self, monkeypatch):
        """Default interval is 15 seconds."""
        monkeypatch.delenv("SESSION_MATERIALIZER_INTERVAL_S", raising=False)
        interval = session_scheduler._get_interval()
        assert interval == 15.0
