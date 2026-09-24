"""Session materialization scheduler — lightweight background loop.

Architecture:
- FastAPI lifespan context manager starts/stops an asyncio.Task
- The task runs materialize_sessions() at a bounded cadence
- An in-process asyncio.Lock prevents overlapping executions
- Exceptions are caught — never crash FastAPI
- Only materializes when ES is reachable (LIVE mode)
- Does NOT run in EMPTY/DEMO mode (those don't have live ES telemetry)

The scheduler is the AUTOMATIC runtime trigger for session materialization.
The browser does NOT trigger materialization — it only reads pre-materialized
sessions via GET /sessions.

Cadence: every 15 seconds by default (configurable via
SESSION_MATERIALIZER_INTERVAL_S env var). This is a reasonable balance for
a local lab — fast enough to surface sessions within seconds of an attack,
slow enough to avoid hammering ES.

Bounds per cycle:
- lookback_minutes: 60 (only process events from the last hour)
- max_events: 50000 (safety cap on total events fetched)
- max_sessions: 500 (safety cap on sessions materialized per cycle)
"""
from __future__ import annotations

import asyncio
import logging
import os
from typing import Optional

from . import es_client, runtime_mode, session_materializer

log = logging.getLogger("session_scheduler")

# ---- Config ----
DEFAULT_INTERVAL_S = 15
DEFAULT_LOOKBACK_MINUTES = 60
DEFAULT_MAX_EVENTS = 50000
DEFAULT_MAX_SESSIONS = 500

# ---- State (module-level for test visibility) ----
_scheduler_task: Optional[asyncio.Task] = None
_materialize_lock: asyncio.Lock = asyncio.Lock()
_last_result: Optional[dict] = None
_cycle_count: int = 0


def _get_interval() -> float:
    """Read the materialization interval from env, with bounds."""
    try:
        val = float(os.environ.get("SESSION_MATERIALIZER_INTERVAL_S", str(DEFAULT_INTERVAL_S)))
        # Bound to 5s minimum (don't hammer ES) and 3600s max (1 hour)
        return max(5.0, min(val, 3600.0))
    except (ValueError, TypeError):
        return DEFAULT_INTERVAL_S


def _should_materialize() -> bool:
    """Determine if the scheduler should run materialization this cycle.

    Two conditions, BOTH required:
    1. Backend mode == LIVE (mode is the GATE — ES reachable does NOT mean LIVE)
    2. ES is reachable (ES is a DEPENDENCY, not a mode indicator)

    If mode is EMPTY or DEMO, the scheduler skips regardless of ES availability.
    This prevents:
    - ES reachable + EMPTY → fabricating sessions from old events
    - ES reachable + DEMO → contaminating live data with demo semantics
    - Pi connected + DEMO → accidentally activating live materialization
    """
    # Gate 1: mode must be LIVE
    if not runtime_mode.is_live():
        return False
    # Gate 2: ES must be reachable (dependency check, not mode indicator)
    try:
        return es_client.ping()
    except Exception:  # noqa: BLE001
        return False


async def _run_materialization_cycle():
    """Run one materialization cycle. Catches all exceptions.

    Uses an in-process asyncio.Lock to prevent overlapping executions.
    If the previous cycle is still running, this call is skipped (not queued).
    """
    global _last_result, _cycle_count

    if _materialize_lock.locked():
        log.debug("skipping cycle — previous materialization still running")
        return

    async with _materialize_lock:
        _cycle_count += 1
        try:
            # Run the synchronous materialize_sessions in a thread pool
            # to avoid blocking the event loop.
            result = await asyncio.to_thread(
                session_materializer.materialize_sessions,
                lookback_minutes=DEFAULT_LOOKBACK_MINUTES,
                max_sessions=DEFAULT_MAX_SESSIONS,
                max_events=DEFAULT_MAX_EVENTS,
            )
            _last_result = result

            # Log at appropriate level — don't flood logs when there's no telemetry
            if result.get("sessions_materialized", 0) > 0:
                log.info(
                    "materialization cycle %d: %d sessions written, %d events processed",
                    _cycle_count,
                    result["sessions_materialized"],
                    result["events_processed"],
                )
            elif result.get("status") == "degraded":
                # ES unavailable — log at debug to avoid flooding
                log.debug("materialization cycle %d: ES unavailable", _cycle_count)
            elif _cycle_count % 4 == 0:
                # No telemetry — log every 4th cycle (~1 min at 15s interval)
                log.debug("materialization cycle %d: no sessions (0 events)", _cycle_count)

            if result.get("events_capped"):
                log.warning(
                    "cycle %d: event cap reached (%d events) — some sessions may be incomplete",
                    _cycle_count, result.get("events_processed", 0),
                )

            # ---- Automatic detection pipeline ----
            if (result.get("sessions_materialized", 0) > 0
                    and result.get("status") in ("ok", "partial")):
                try:
                    detection_result = await asyncio.to_thread(_run_automatic_detection)
                    result["automatic_detection"] = detection_result
                except Exception as det_exc:
                    log.error("materialization cycle %d: automatic detection failed: %s", _cycle_count, det_exc, exc_info=True)
                    result["automatic_detection"] = {"status": "error", "error": f"{det_exc.__class__.__name__}: {det_exc}"}

        except Exception as exc:  # noqa: BLE001 — catch ALL, never crash FastAPI
            log.error(
                "materialization cycle %d failed: %s", _cycle_count, exc, exc_info=True
            )
            _last_result = {
                "status": "error",
                "error": f"{exc.__class__.__name__}: {exc}",
                "sessions_materialized": 0,
                "events_processed": 0,
            }


def _run_automatic_detection() -> dict:
    """Run the automatic detection pipeline after session materialization.

    CONFIG-AWARE SKIP: skip sessions that already have a detection with the
    SAME detector_config_fingerprint. If config changed (model activated,
    threshold changed), re-evaluate.
    """
    from . import campaign_correlator, hybrid_detector, es_client
    try:
        from . import anomaly_detector, feature_extractor, model_registry
        from .hybrid_detector import _compute_config_fingerprint, DETECTOR_VERSION, RULE_CONFIDENCE_THRESHOLD, SUPERVISED_PROBABILITY_THRESHOLD
        active_model = model_registry.get_active_model()
        anom_svc = anomaly_detector.get_service()
        current_fingerprint = _compute_config_fingerprint(
            supervised_model_id=active_model.get("model_id") if active_model else None,
            supervised_model_version=active_model.get("version") if active_model else None,
            feature_schema_version=feature_extractor.FEATURE_SCHEMA_VERSION,
            anomaly_threshold=anom_svc.threshold if anom_svc.is_ready() else None,
            rule_confidence_threshold=RULE_CONFIDENCE_THRESHOLD,
            supervised_probability_threshold=SUPERVISED_PROBABILITY_THRESHOLD,
        )
    except Exception:
        current_fingerprint = None

    summary = {"campaigns": None, "detections_attempted": 0, "detections_persisted": 0,
               "detections_no_signal": 0, "detection_errors": 0, "status": "ok"}

    try:
        camp_result = campaign_correlator.correlate_campaigns(lookback_minutes=DEFAULT_LOOKBACK_MINUTES, max_campaigns=100)
        summary["campaigns"] = {"status": camp_result.get("status"),
                                "campaigns_materialized": camp_result.get("campaigns_materialized", 0),
                                "sessions_campaign_linked": camp_result.get("sessions_campaign_linked", 0)}
    except Exception as exc:
        log.error("automatic detection: campaign correlation failed: %s", exc)
        summary["campaigns"] = {"status": "error", "error": str(exc)}
        summary["status"] = "partial"

    try:
        client = es_client.get_client()
        resp = client.search(index="honeypot-sessions-*", body={
            "query": {"range": {"started_at": {"gte": f"now-{DEFAULT_LOOKBACK_MINUTES}m/m"}}},
            "size": DEFAULT_MAX_SESSIONS, "_source": ["session_id"]})
        raw = resp.body if hasattr(resp, "body") else resp
        recent_session_ids = [h.get("_source", {}).get("session_id")
                               for h in (raw.get("hits") or {}).get("hits", [])
                               if isinstance(h, dict) and h.get("_source", {}).get("session_id")]
    except Exception as exc:
        log.error("automatic detection: failed to fetch recent sessions: %s", exc)
        summary["status"] = "error"
        return summary

    sessions_with_matching_fingerprint = set()
    try:
        det_resp = client.search(index="honeypot-detections-*", body={
            "query": {"terms": {"session_id": recent_session_ids}},
            "size": min(len(recent_session_ids), 10000),
            "_source": ["session_id", "detector_config_fingerprint"]})
        det_raw = det_resp.body if hasattr(det_resp, "body") else det_resp
        for h in (det_raw.get("hits") or {}).get("hits", []):
            src = h.get("_source", {})
            sid = src.get("session_id")
            existing_fp = src.get("detector_config_fingerprint")
            if sid and current_fingerprint and existing_fp == current_fingerprint:
                sessions_with_matching_fingerprint.add(sid)
    except Exception:
        pass

    for sid in recent_session_ids:
        if sid in sessions_with_matching_fingerprint:
            summary["detections_no_signal"] += 1
            continue
        summary["detections_attempted"] += 1
        try:
            det = hybrid_detector.evaluate_session(sid)
            if det is None:
                summary["detections_no_signal"] += 1
            elif det.get("persisted"):
                summary["detections_persisted"] += 1
            else:
                summary["detection_errors"] += 1
        except Exception as exc:
            log.warning("automatic detection: hybrid failed for %s: %s", sid, exc)
            summary["detection_errors"] += 1

    if summary["detection_errors"] > 0 and summary["detections_persisted"] == 0:
        summary["status"] = "error"
    elif summary["detection_errors"] > 0:
        summary["status"] = "partial"
    return summary


async def _scheduler_loop():
    """The background loop. Runs until cancelled.

    Each iteration:
    1. Check if ES is reachable (LIVE mode)
    2. If reachable, run one materialization cycle
    3. Sleep for the configured interval
    4. Repeat
    """
    interval = _get_interval()
    log.info("session materialization scheduler started (interval=%.0fs)", interval)

    while True:
        try:
            if _should_materialize():
                await _run_materialization_cycle()
            else:
                # Mode is not LIVE or ES not reachable — skip silently
                log.debug("scheduler: mode=%s, ES reachable check skipped",
                          runtime_mode.get_mode().value)
        except asyncio.CancelledError:
            log.info("session materialization scheduler cancelled")
            break
        except Exception as exc:  # noqa: BLE001 — never crash FastAPI
            log.error("scheduler loop error: %s", exc, exc_info=True)

        await asyncio.sleep(interval)


async def start_scheduler():
    """Start the background materialization task.

    Called from FastAPI lifespan startup. If a scheduler is already
    running, this is a no-op (prevents duplicate tasks on reload).
    """
    global _scheduler_task
    if _scheduler_task is not None and not _scheduler_task.done():
        log.warning("scheduler already running — not starting a second one")
        return
    _scheduler_task = asyncio.create_task(_scheduler_loop())
    log.info("session materialization scheduler task created")


async def stop_scheduler():
    """Stop the background materialization task.

    Called from FastAPI lifespan shutdown. Cancels the task and waits
    for it to finish cleanly.
    """
    global _scheduler_task
    if _scheduler_task is None:
        return
    _scheduler_task.cancel()
    try:
        await _scheduler_task
    except asyncio.CancelledError:
        pass
    _scheduler_task = None
    log.info("session materialization scheduler stopped")


def get_scheduler_status() -> dict:
    """Return the current scheduler status for observability.

    This is read-only — no credentials, no secrets, no internal paths.
    Includes the backend-owned application mode so the frontend can
    display the authoritative mode.
    """
    return {
        "running": _scheduler_task is not None and not _scheduler_task.done(),
        "cycle_count": _cycle_count,
        "last_result": _last_result,
        "interval_s": _get_interval(),
        "lock_held": _materialize_lock.locked(),
        "application_mode": runtime_mode.get_mode().value,
    }
