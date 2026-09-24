"""FastAPI entry point — exposes the TRAPSIG dashboard API."""
from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from . import es_client, model_registry, pi_client, runtime_mode, session_materializer, session_scheduler
from . import campaign_correlator, feature_extractor, rule_detector, anomaly_detector, hybrid_detector
from .config import settings

# ---- Logging ------------------------------------------------------
logging.basicConfig(
    level=settings.log_level,
    format="%(asctime)s %(levelname)s %(name)s | %(message)s",
)
log = logging.getLogger("api")

# ---- Lifespan: start/stop session materialization scheduler --------
@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan context manager.

    Startup: start the session materialization scheduler (background task).
    Shutdown: stop the scheduler cleanly.

    The scheduler runs at a bounded cadence (default 15s) and only
    materializes sessions when ES is reachable (LIVE mode). It never
    crashes FastAPI — all exceptions are caught.
    """
    # Only start the scheduler if ES is expected to be available.
    # We don't check ping() here because ES might start after FastAPI.
    # The scheduler itself checks ping() each cycle and skips if ES
    # is unreachable.
    await session_scheduler.start_scheduler()
    log.info("FastAPI lifespan: session scheduler started")

    yield  # FastAPI serves requests here

    # Shutdown: stop the scheduler cleanly
    await session_scheduler.stop_scheduler()
    log.info("FastAPI lifespan: session scheduler stopped")


# ---- App ----------------------------------------------------------
app = FastAPI(
    title="TRAPSIG — Dashboard API",
    description="Sessions, detections, models, experiments, honeypot control, and replay endpoints.",
    version="0.2.0",
    lifespan=lifespan,
)

# CORS: restrict to localhost + lab subnet, NOT wildcard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# ---- IP allow-list middleware -------------------------------------
@app.middleware("http")
async def ip_allowlist(request: Request, call_next):
    # Health/readiness endpoints are always open for Docker healthchecks
    if request.url.path in {"/health", "/"}:
        return await call_next(request)
    # In test environments where starlette TestClient can't set a real client
    # IP (starlette <0.42 doesn't support client= kwarg), allow bypassing the
    # IP allow-list via TRAPSIG_TEST_BYPASS_IP_ALLOWLIST=1. This is ONLY for
    # tests — the auth boundary (require_api_key) still applies. Production
    # deployments never set this env var.
    if os.environ.get("TRAPSIG_TEST_BYPASS_IP_ALLOWLIST", "0") == "1":
        return await call_next(request)
    client_ip = request.client.host if request.client else "0.0.0.0"
    import ipaddress
    try:
        ip = ipaddress.ip_address(client_ip)
    except ValueError:
        # Non-IP client (e.g. test client, malformed host header) — reject.
        # We never weaken the allow-list just because we couldn't parse the IP.
        log.warning("rejected request from non-IP client: %s", client_ip)
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"detail": "client ip not parseable"},
        )
    if not any(ip in net for net in settings.allowed_networks):
        log.warning("rejected request from non-lab IP: %s", client_ip)
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"detail": "client ip not in lab subnet"},
        )
    return await call_next(request)


# ---- API key auth for mutating endpoints --------------------------
def require_api_key(request: Request):
    """Simple API key check for POST endpoints.

    Reads API_SECRET_KEY from os.environ directly (not from the cached
    Settings) so tests can inject env changes. The browser never sees
    this value — only the X-API-Key header is checked.
    """
    import os as _os
    expected = _os.environ.get("API_SECRET_KEY", "") or settings.api_secret_key
    if not expected:
        # No key configured at all — fail closed.
        raise HTTPException(503, "API_SECRET_KEY not configured on server")
    key = request.headers.get("X-API-Key", "")
    if not key or key != expected:
        raise HTTPException(401, "missing or invalid API key")


# ---- Models (request bodies) --------------------------------------
class TrainingRequest(BaseModel):
    algorithm: str = "random_forest"
    dataset_version: str = "v1"
    feature_version: str = settings.default_feature_version
    seed: int = settings.default_random_seed
    notes: str = ""


class ReplayRequest(BaseModel):
    scenario_id: str
    target: str
    campaign_id: str | None = None


class HoneypotConfigRequest(BaseModel):
    enabled: list[str] = []


# ---- Routes -------------------------------------------------------
@app.get("/")
def root():
    return {"name": "trapsig", "version": app.version}


@app.get("/health")
def health():
    es_ok = es_client.ping()
    models_dir = Path(settings.model_path)
    models_ok = models_dir.exists()
    return {
        "status": "ok" if (es_ok and models_ok) else "degraded",
        "elasticsearch": "ok" if es_ok else "down",
        "models_dir": "ok" if models_ok else "missing",
        "version": app.version,
        "mode": runtime_mode.get_mode().value,
    }


# ---- Runtime mode (backend-owned) ----
# The backend owns the authoritative application mode. The frontend may
# request transitions, but the backend validates and owns the state.
# Mode transitions are protected by require_api_key (mutating endpoints).

@app.get("/mode")
def get_mode():
    """Return the current backend-owned runtime mode.

    Read-only — no API key required. The frontend uses this to display
    the authoritative mode (not its own local state).

    This endpoint returns ONLY the runtime mode. It does NOT call
    es_client.ping() — ES health is a separate concern, available via
    GET /health. Mode and ES availability are independent facts:
        LIVE + ES down = mode is still LIVE (but scheduler skips)
        EMPTY + ES up = mode is still EMPTY (no auto-activation)
    """
    return {
        "mode": runtime_mode.get_mode().value,
    }


@app.post("/mode/live")
def enter_live_mode(_: None = Depends(require_api_key)):
    """Transition to LIVE mode. Only valid from EMPTY.

    Requires API key (mutating endpoint). The browser never sees the key.
    This is the backend-owned mode transition — the frontend's
    enterLiveMode() calls this endpoint server-side.
    """
    success, message = runtime_mode.enter_live()
    if not success:
        raise HTTPException(409, message)
    return {"mode": runtime_mode.get_mode().value, "message": message}


@app.post("/mode/demo")
def enter_demo_mode(_: None = Depends(require_api_key)):
    """Transition to DEMO mode. Only valid from EMPTY.

    Requires API key (mutating endpoint).
    """
    success, message = runtime_mode.enter_demo()
    if not success:
        raise HTTPException(409, message)
    return {"mode": runtime_mode.get_mode().value, "message": message}


@app.post("/mode/reset")
def reset_mode(_: None = Depends(require_api_key)):
    """Reset to EMPTY mode. Valid from DEMO or LIVE.

    Requires API key (mutating endpoint).
    """
    success, message = runtime_mode.reset_to_empty()
    if not success:
        raise HTTPException(409, message)
    return {"mode": runtime_mode.get_mode().value, "message": message}


# ---- Stats (for the dashboard overview) ----
@app.get("/stats")
def stats():
    """Aggregate counts from Elasticsearch."""
    if not es_client.ping():
        return {"status": "degraded", "error": "Elasticsearch unavailable"}
    try:
        # search_events now returns {events: [...], total: N} (not raw ES response)
        events_resp = es_client.search_events(size=0)
        sessions = es_client.search_sessions(size=0)
        detections = es_client.search_detections(size=0)
        total_events = events_resp.get("total", 0) if isinstance(events_resp, dict) else 0
        total_sessions = len(sessions) if isinstance(sessions, list) else 0
        total_detections = len(detections) if isinstance(detections, list) else 0
        return {
            "status": "ok",
            "total_events": total_events,
            "total_sessions": total_sessions,
            "total_detections": total_detections,
        }
    except Exception as e:
        # Log full exception server-side, but return a generic error to the
        # client — never echo raw exception strings (may include ES URLs,
        # auth details, or internal filesystem paths).
        log.error("stats query failed: %s", e, exc_info=True)
        return {"status": "error", "error": "internal query failure — see server logs"}


# ---- Events / Sessions / Detections ----
@app.get("/events")
def events(
    size: int = 100,
    source_ip: str | None = None,
    device: str | None = None,
):
    query: dict = {"match_all": {}}
    if source_ip or device:
        must = []
        if source_ip:
            must.append({"term": {"source.ip": source_ip}})
        if device:
            must.append({"term": {"device.id": device}})
        query = {"bool": {"must": must}}
    return es_client.search_events(size=min(size, 500), query=query)


@app.get("/sessions")
def sessions(size: int = 50, source_ip: str | None = None):
    return {"sessions": es_client.search_sessions(size=min(size, 200), source_ip=source_ip)}


@app.get("/sessions/{session_id}")
def session_detail(session_id: str):
    out = es_client.get_session(session_id)
    if out is None:
        raise HTTPException(404, "session not found")
    return out


@app.post("/sessions/materialize")
def sessions_materialize(
    lookback_minutes: int = 60,
    max_sessions: int = 500,
    _: None = Depends(require_api_key),
):
    """Materialize session documents from recent events in Elasticsearch.

    This is the session-generation path: events → sessions.

    The endpoint queries recent events from honeypot-events-* (bounded by
    lookback_minutes, NOT a full scan), groups by session_id using the
    existing reconstruct_sessions(), builds session documents with summary
    fields + event ID lineage, and upserts to honeypot-sessions-*.

    Idempotent: session_id is used as the ES document_id with index (upsert)
    action. Reprocessing the same events updates the session document rather
    than creating duplicates.

    Requires API key (mutating endpoint).

    Mode gate: manual materialization is ONLY allowed when the backend
    runtime mode is LIVE. This prevents bypassing the scheduler's mode
    gate via the manual endpoint. EMPTY and DEMO modes reject
    materialization with 403.

    Args:
        lookback_minutes: Only process events from the last N minutes (default 60)
        max_sessions: Safety cap on sessions to materialize (default 500)
    """
    # Mode gate — same contract as the automatic scheduler
    if not runtime_mode.is_live():
        raise HTTPException(
            403,
            f"Materialization requires LIVE mode (current: {runtime_mode.get_mode().value})",
        )
    # Bound the lookback to prevent accidental full scans
    lookback_minutes = max(1, min(lookback_minutes, 1440))  # 1 min to 24 hours
    max_sessions = max(1, min(max_sessions, 2000))
    return session_materializer.materialize_sessions(
        lookback_minutes=lookback_minutes,
        max_sessions=max_sessions,
    )


@app.get("/sessions/scheduler/status")
def sessions_scheduler_status():
    """Return the session materialization scheduler status.

    Read-only observability endpoint. No credentials, no secrets.
    Shows: running state, cycle count, last result, interval, lock state.
    """
    return session_scheduler.get_scheduler_status()


@app.get("/detections")
def detections(size: int = 50, session_id: str | None = None):
    return {"detections": es_client.search_detections(size=min(size, 200), session_id=session_id)}


@app.get("/detections/{detection_id}")
def detection_detail(detection_id: str):
    try:
        resp = es_client.get_client().search(index="honeypot-detections-*",
            body={"query": {"term": {"detection_id": detection_id}}, "size": 1})
        raw = resp.body if hasattr(resp, "body") else resp
        hits = (raw.get("hits") or {}).get("hits") or []
        if not hits:
            raise HTTPException(404, "detection not found")
        detection = hits[0].get("_source", {})
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, "detection fetch failed")

    lineage = {"detection": detection}
    session_id = detection.get("session_id")
    if session_id:
        session = es_client.get_session(session_id)
        lineage["session"] = session
        if session:
            lineage["events"] = session.get("events") or []
            try:
                features = feature_extractor.extract_for_session(session_id)
                lineage["features"] = features
            except Exception:
                lineage["features"] = None
    campaign_id = detection.get("campaign_id")
    if campaign_id:
        try:
            lineage["campaign"] = campaign_correlator.get_campaign(campaign_id)
        except Exception:
            lineage["campaign"] = None
    else:
        lineage["campaign"] = None
    lineage["model"] = {"model_id": detection.get("model_id"), "engine": detection.get("engine"),
                        "note": "Built-in detector" if detection.get("engine") in ("rule_engine", "anomaly_detector", "hybrid") else "ML model"}
    return lineage


@app.get("/detections/{detection_id}/lineage")
def detection_lineage(detection_id: str):
    full = detection_detail(detection_id)
    return {"detection_id": full["detection"].get("detection_id"),
            "session_id": full["detection"].get("session_id"),
            "campaign_id": full["detection"].get("campaign_id"),
            "model_id": full["detection"].get("model_id"),
            "engine": full["detection"].get("engine"),
            "label": full["detection"].get("label"),
            "session_event_count": len(full.get("events") or []),
            "feature_schema_version": (full.get("features") or {}).get("feature_schema_version"),
            "lineage_chain": ["detection", "session" if full.get("session") else None,
                              f"events ({len(full.get('events') or [])})" if full.get("events") else None,
                              "features" if full.get("features") else None,
                              "campaign" if full.get("campaign") else None,
                              "model" if full.get("model") else None]}


# ---- Campaigns ----
@app.get("/campaigns")
def campaigns(size: int = 50, source_ip: str | None = None):
    return {"campaigns": campaign_correlator.search_campaigns(size=min(size, 200), source_ip=source_ip)}


@app.get("/campaigns/{campaign_id}")
def campaign_detail(campaign_id: str):
    out = campaign_correlator.get_campaign(campaign_id)
    if out is None:
        raise HTTPException(404, "campaign not found")
    return out


@app.post("/campaigns/correlate")
def campaigns_correlate(lookback_minutes: int = 240, max_campaigns: int = 200, _: None = Depends(require_api_key)):
    if not runtime_mode.is_live():
        raise HTTPException(403, f"Campaign correlation requires LIVE mode (current: {runtime_mode.get_mode().value})")
    lookback_minutes = max(1, min(lookback_minutes, 1440))
    max_campaigns = max(1, min(max_campaigns, 1000))
    return campaign_correlator.correlate_campaigns(lookback_minutes=lookback_minutes, max_campaigns=max_campaigns)


# ---- Features ----
@app.get("/features/schema")
def features_schema():
    return feature_extractor.get_schema()


@app.get("/features/{session_id}")
def features_for_session(session_id: str):
    out = feature_extractor.extract_for_session(session_id)
    if out is None:
        raise HTTPException(404, "session not found or no events")
    return out


# ---- Detection engines ----
@app.post("/detect/rule/{session_id}")
def detect_rule(session_id: str, _: None = Depends(require_api_key)):
    if not runtime_mode.is_live():
        raise HTTPException(403, f"Detection requires LIVE mode (current: {runtime_mode.get_mode().value})")
    det = rule_detector.detect_for_session(session_id)
    if det is None:
        return {"status": "ok", "message": "no rule fired", "session_id": session_id}
    if not det.get("persisted", False):
        raise HTTPException(503, f"rule fired but detection could not be persisted: {det.get('persistence_error', 'unknown')}")
    return det


@app.post("/detect/anomaly/{session_id}")
def detect_anomaly(session_id: str, _: None = Depends(require_api_key)):
    if not runtime_mode.is_live():
        raise HTTPException(403, f"Detection requires LIVE mode (current: {runtime_mode.get_mode().value})")
    det = anomaly_detector.detect_for_session(session_id)
    if det is None:
        return {"status": "ok", "message": "session not anomalous or detector not trained", "session_id": session_id}
    if not det.get("persisted", False):
        raise HTTPException(503, f"anomaly detected but could not be persisted: {det.get('persistence_error', 'unknown')}")
    return det


@app.post("/detect/hybrid/{session_id}")
def detect_hybrid(session_id: str, _: None = Depends(require_api_key)):
    if not runtime_mode.is_live():
        raise HTTPException(403, f"Detection requires LIVE mode (current: {runtime_mode.get_mode().value})")
    det = hybrid_detector.evaluate_session(session_id)
    if det is None:
        return {"status": "ok", "message": "no signal fired", "session_id": session_id}
    if not det.get("persisted", False):
        raise HTTPException(503, f"hybrid signal fired but detection could not be persisted: {det.get('persistence_error', 'unknown')}")
    return det


# ---- Anomaly detector training ----
class AnomalyTrainRequest(BaseModel):
    lookback_minutes: int = 1440
    contamination: float = 0.05
    target_fpr: float = 0.05
    seed: int = 42


@app.post("/anomaly/train")
def anomaly_train(req: AnomalyTrainRequest, _: None = Depends(require_api_key)):
    if not runtime_mode.is_live():
        raise HTTPException(403, f"Training requires LIVE mode (current: {runtime_mode.get_mode().value})")
    import sys as _sys
    from pathlib import Path as _Path
    _ml_root = _Path(settings.model_path).parent
    if str(_ml_root) not in _sys.path:
        _sys.path.insert(0, str(_ml_root))
    try:
        client = es_client.get_client()
        resp = client.search(index="honeypot-sessions-*", body={
            "query": {"range": {"started_at": {"gte": f"now-{req.lookback_minutes}m/m"}}}, "size": 5000})
        raw = resp.body if hasattr(resp, "body") else resp
        sessions = [h.get("_source", {}) for h in (raw.get("hits") or {}).get("hits", []) if isinstance(h, dict)]
    except Exception as exc:
        raise HTTPException(500, f"failed to fetch sessions: {exc}")
    if len(sessions) < 10:
        raise HTTPException(400, f"need at least 10 sessions to train (got {len(sessions)})")
    feature_vectors = []
    for s in sessions:
        sid = s.get("session_id")
        if not sid: continue
        feats = feature_extractor.extract_for_session(sid)
        if feats and feats.get("feature_vector"):
            feature_vectors.append(feats["feature_vector"])
    if len(feature_vectors) < 10:
        raise HTTPException(400, f"need at least 10 valid feature vectors (got {len(feature_vectors)})")
    svc = anomaly_detector.get_service()
    try:
        svc.train(feature_vectors, contamination=req.contamination, seed=req.seed)
        svc.select_threshold_for_fpr(feature_vectors, target_fpr=req.target_fpr)
        svc.save()
    except Exception as exc:
        raise HTTPException(500, f"training failed: {exc}")
    return {"status": "trained", "sessions_processed": len(sessions),
            "feature_vectors_trained": len(feature_vectors),
            "feature_schema_version": svc.feature_schema_version,
            "threshold": svc.threshold, "threshold_selection_method": svc.threshold_selection_method,
            "trained_at": svc.trained_at, "model_version": anomaly_detector.DETECTOR_VERSION,
            "training_mode": "operational", "threshold_calibration": "same_data",
            "research_note": "OPERATIONAL training — threshold calibrated on the same sessions used for training. For leakage-resistant research evaluation, use model-lab/model_lab/research.py which performs proper train/val/test split with threshold selection on validation data only."}


@app.get("/anomaly/status")
def anomaly_status():
    svc = anomaly_detector.get_service()
    return {"is_ready": svc.is_ready(), "model_version": anomaly_detector.DETECTOR_VERSION,
            "feature_schema_version": svc.feature_schema_version, "threshold": svc.threshold,
            "threshold_selection_method": svc.threshold_selection_method, "target_fpr": svc.target_fpr,
            "trained_at": svc.trained_at, "training_session_count": svc.training_session_count,
            "training_mode": "operational", "threshold_calibration": "same_data"}


# ---- Models ----
@app.get("/models")
def models():
    return {"models": model_registry.list_models()}


# CRITICAL: /models/active MUST be declared BEFORE /models/{model_id}.
@app.get("/models/active")
def models_active(role: str = "default"):
    return {"model": model_registry.get_active_model(role=role)}


@app.get("/models/{model_id}")
def model_detail(model_id: str):
    m = model_registry.get_model(model_id)
    if m is None:
        raise HTTPException(404, "model not found")
    return m


@app.post("/models/{model_id}/status")
def model_status(model_id: str, status: str, _: None = Depends(require_api_key)):
    try:
        out = model_registry.update_status(model_id, status)
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    if out is None:
        raise HTTPException(404, "model not found")
    return out


# ---- Experiments ----
@app.get("/experiments")
def experiments():
    """Experiments live under model-lab/experiments/ as JSON files."""
    exp_dir = Path(settings.model_path).parent / "experiments"
    out = []
    if exp_dir.exists():
        for p in sorted(exp_dir.glob("*.json")):
            import json
            try:
                out.append(json.loads(p.read_text()))
            except Exception:
                continue
    return {"experiments": out}


@app.get("/metrics")
def metrics(model_id: str | None = None):
    if model_id:
        m = model_registry.get_model(model_id)
        return m["metrics"] if m else {}
    all_models = model_registry.list_models()
    return {m["model_id"]: m.get("metrics", {}) for m in all_models}


# ---- Training (protected) ----
@app.post("/training")
def training(req: TrainingRequest, _: None = Depends(require_api_key)):
    """Trigger a training run via the model-lab CLI (synchronously)."""
    import subprocess
    import sys

    ml_root = Path(settings.model_path).parent
    if not ml_root.exists():
        raise HTTPException(500, f"model-lab root missing: {ml_root}")

    cmd = [
        sys.executable, "-m", "model_lab.train",
        "--algorithm", req.algorithm,
        "--dataset-version", req.dataset_version,
        "--feature-version", req.feature_version,
        "--seed", str(req.seed),
    ]
    log.info("launching training: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd, cwd=str(ml_root), capture_output=True, text=True, timeout=600
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(504, "training timed out (10 min)")
    except FileNotFoundError:
        raise HTTPException(500, "model_lab.train module not found")
    return {
        "returncode": result.returncode,
        "stdout_tail": result.stdout[-2000:],
        "stderr_tail": result.stderr[-2000:],
    }


# ---- Replay (protected) ----
@app.post("/replay")
def replay(req: ReplayRequest, _: None = Depends(require_api_key)):
    """Trigger a replay scenario via the attacker runner."""
    import subprocess
    from pathlib import Path as P

    # Defensive: validate the target BEFORE doing anything else. Never accept
    # arbitrary targets — must be a valid IP inside the lab subnet.
    import ipaddress
    try:
        ip = ipaddress.ip_address(req.target)
    except ValueError:
        raise HTTPException(400, "target is not a valid IP")
    if not any(ip in net for net in settings.allowed_networks):
        raise HTTPException(400, f"target {req.target} not in lab subnet")

    # Check explicit honeypot target allowlist if configured
    honeypot_targets = os.environ.get("HONEYPOT_TARGETS", "")
    if honeypot_targets:
        allowed_targets = [t.strip() for t in honeypot_targets.split(",")]
        if req.target not in allowed_targets:
            raise HTTPException(400, f"target {req.target} not in HONEYPOT_TARGETS allowlist")

    attacker_root = P(settings.model_path).parent.parent / "attacker"
    if not attacker_root.exists():
        raise HTTPException(500, f"attacker root missing: {attacker_root}")

    runner = attacker_root / "run-scenario.sh"
    cmd = [str(runner), "--target", req.target, "--scenario", req.scenario_id]
    if req.campaign_id:
        cmd += ["--campaign-id", req.campaign_id]
    log.info("launching replay: %s", " ".join(cmd))
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        raise HTTPException(504, "replay timed out (5 min)")
    return {
        "returncode": result.returncode,
        "stdout_tail": result.stdout[-2000:],
        "stderr_tail": result.stderr[-2000:],
    }


# ---- Honeypot management (protected) -----------------------------
# All operations go through pi_client — no direct subprocess / ssh
# construction here. The pi_client module enforces:
#   * no hardcoded PI_IP / PI_SSH_USER defaults (returns NOT_CONFIGURED)
#   * no StrictHostKeyChecking=no (uses accept-new opt-in only)
#   * deterministic pi_status: CONNECTED / OFFLINE / AUTH_FAILED /
#     HOST_KEY_UNKNOWN / HOST_KEY_CHANGED / TIMEOUT / SSH_NOT_INSTALLED /
#     NOT_CONFIGURED / ERROR
#
# Secrets never leak: the response only includes the pi_status enum,
# container state, and a short human message. No IP, no user, no key path.


@app.get("/honeypots")
def honeypots():
    """Return honeypot fleet status.

    Probes the Pi via SSH using pi_client (no hardcoded defaults). When the
    Pi is not configured or unreachable, returns pi_status='NOT_CONFIGURED'
    or pi_status='OFFLINE' / 'AUTH_FAILED' / 'TIMEOUT' / etc. — never fake
    'running'.
    """
    return pi_client.get_honeypot_fleet()


@app.post("/honeypots/{honeypot_id}/start")
def honeypot_start(honeypot_id: str, _: None = Depends(require_api_key)):
    """Start a honeypot container on the Pi. Verifies resulting state.

    HTTP status mapping:
        200 — action succeeded and resulting state verified
        404 — unknown honeypot id
        503 — Pi not configured or unreachable (pi_status in body)
        500 — action ran but state verification failed
    """
    return _honeypot_action(honeypot_id, "start")


@app.post("/honeypots/{honeypot_id}/stop")
def honeypot_stop(honeypot_id: str, _: None = Depends(require_api_key)):
    """Stop a honeypot container on the Pi. Verifies resulting state."""
    return _honeypot_action(honeypot_id, "stop")


@app.post("/honeypots/{honeypot_id}/restart")
def honeypot_restart(honeypot_id: str, _: None = Depends(require_api_key)):
    """Restart a honeypot container on the Pi. Verifies resulting state."""
    return _honeypot_action(honeypot_id, "restart")


def _honeypot_action(honeypot_id: str, action: str):
    """Execute a Docker container action on the Pi via pi_client.

    Maps pi_client's structured result to HTTP status codes so the caller
    can distinguish "not configured" from "action failed" from "verified".
    """
    result = pi_client.container_action(honeypot_id, action)
    pi_status = result.get("pi_status", "")
    msg = result.get("message", "")
    success = bool(result.get("success"))

    # Unknown honeypot → 404
    if "unknown honeypot" in msg:
        raise HTTPException(404, msg)
    # Invalid action → 400
    if "invalid action" in msg:
        raise HTTPException(400, msg)
    # Pi not configured / unreachable → 503
    if pi_status in {
        pi_client.PiStatus.NOT_CONFIGURED.value,
        pi_client.PiStatus.OFFLINE.value,
        pi_client.PiStatus.AUTH_FAILED.value,
        pi_client.PiStatus.HOST_KEY_UNKNOWN.value,
        pi_client.PiStatus.HOST_KEY_CHANGED.value,
        pi_client.PiStatus.TIMEOUT.value,
        pi_client.PiStatus.SSH_NOT_INSTALLED.value,
    }:
        raise HTTPException(503, f"Pi unavailable: {pi_status}")
    # SSH succeeded but action failed or state not verified → 500
    if not success:
        raise HTTPException(500, msg)
    # All good
    return result
