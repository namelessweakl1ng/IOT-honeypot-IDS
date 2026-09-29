import asyncio
from datetime import datetime, timezone
from time import monotonic
from uuid import uuid4

from fastapi import APIRouter, HTTPException

from ..config import get_settings
from ..elastic import store
from ..schemas import ExperimentCreate, GroundTruthSubmission
from ..services.detector import DETECTOR_RULESET_VERSION
from ..services.experiments import correlate, event_query, exact_filter, parse_time, validate_lab_host
from ..services.scenarios import ScenarioCatalog, ScenarioCatalogError
from ..services.telemetry import SCHEMA_VERSION
from .common import one

router = APIRouter(prefix="/experiments", tags=["experiments"])
INDEX = "trapsig-experiments"


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


@router.get("")
async def experiments():
    try:
        return await store.search(INDEX, size=200, sort_field="created_at", missing_index_is_empty=True)
    except TypeError as exc:
        # Compatibility with simple injected stores that predate the optional flag.
        if "missing_index_is_empty" not in str(exc):
            raise
        return await store.search(INDEX, size=200, sort_field="created_at")


@router.post("", status_code=201)
async def create(payload: ExperimentCreate):
    settings = get_settings()
    try:
        scenario = ScenarioCatalog().get(payload.scenario_id)
        attacker = validate_lab_host(payload.attacker_ip, settings.lab_subnet, "attacker_ip")
        target = validate_lab_host(payload.target_ip, settings.lab_subnet, "target_ip")
    except (ScenarioCatalogError, ValueError) as exc:
        raise HTTPException(422, str(exc)) from exc
    identifier = "EXP-" + uuid4().hex[:12].upper()
    doc = {
        **payload.model_dump(),
        "attacker_ip": attacker,
        "target_ip": target,
        "target_honeypots": list(scenario.target_honeypots),
        "expected_detection": scenario.expected_detection,
        "scenario_manifest_sha256": scenario.manifest_sha256,
        "scenario_step_services": list(scenario.step_services),
        "trapsig": {"schema_version": SCHEMA_VERSION},
        "experiment_id": identifier,
        "status": "created",
        "created_at": now(),
        "ground_truth_valid": False,
    }
    return await store.save(INDEX, identifier, doc)


@router.get("/{identifier}")
async def experiment(identifier: str):
    return await one(INDEX, identifier)


@router.post("/{identifier}/start")
async def start(identifier: str):
    doc = await experiment(identifier)
    if doc["status"] == "running":
        return doc
    if doc["status"] != "created":
        raise HTTPException(409, "only a created experiment can be started")
    try:
        scenario = ScenarioCatalog().get(doc["scenario_id"])
    except ScenarioCatalogError as exc:
        raise HTTPException(409, f"scenario is unavailable; create a new experiment: {exc}") from exc
    if scenario.manifest_sha256 != doc["scenario_manifest_sha256"]:
        raise HTTPException(409, "scenario manifest changed; create a new experiment")
    active = await store.search_all(INDEX, exact_filter("status", ["running", "correlating"]), sort=[{"created_at": "asc"}], missing_index_is_empty=True)
    if any(item.get("experiment_id") != identifier for item in active):
        raise HTTPException(409, "another experiment is running or correlating")
    settings = get_settings()
    doc.update(
        status="running",
        start_time=now(),
        detector_ruleset_version=DETECTOR_RULESET_VERSION,
        software_revision=settings.trapsig_revision,
        config_snapshot={
            "session_timeout_seconds": settings.session_timeout_seconds,
            "brute_force_threshold": settings.brute_force_threshold,
            "web_enumeration_threshold": settings.web_enumeration_threshold,
            "multi_service_threshold": settings.multi_service_threshold,
            "detector_ruleset_version": DETECTOR_RULESET_VERSION,
            "trapsig_schema_version": SCHEMA_VERSION,
        },
    )
    doc.pop("_id", None)
    return await store.save(INDEX, identifier, doc)


@router.post("/{identifier}/cancel")
async def cancel(identifier: str):
    doc = await experiment(identifier)
    if doc["status"] == "cancelled":
        return doc
    if doc["status"] not in {"created", "running", "correlating"}:
        raise HTTPException(409, "only a created, running, or correlating experiment can be cancelled")
    doc.update(status="cancelled", cancelled_at=now())
    doc.pop("_id", None)
    return await store.save(INDEX, identifier, doc)


@router.post("/{identifier}/ground-truth")
async def ground_truth(identifier: str, payload: GroundTruthSubmission):
    doc = await experiment(identifier)
    if doc["status"] not in {"running", "correlating"}:
        raise HTTPException(409, "ground truth is accepted only while running or correlating")
    data = payload.model_dump(mode="json")
    if payload.experiment_id and payload.experiment_id != identifier:
        raise HTTPException(409, "ground-truth experiment_id mismatch")
    if payload.scenario_id != doc["scenario_id"] or payload.scenario_manifest_sha256 != doc["scenario_manifest_sha256"]:
        raise HTTPException(409, "ground-truth scenario or manifest mismatch")
    if payload.target != doc["target_ip"] or payload.expected_detection != doc["expected_detection"]:
        raise HTTPException(409, "ground-truth target or expected detection mismatch")
    if payload.end_time < payload.start_time or payload.start_time < parse_time(doc["start_time"]):
        raise HTTPException(422, "ground-truth times are outside the experiment window")
    if doc.get("end_time") and payload.end_time > parse_time(doc["end_time"]):
        raise HTTPException(422, "ground-truth ends after the experiment")
    existing = doc.get("ground_truth")
    if existing:
        if existing == data:
            return doc
        raise HTTPException(409, "a conflicting ground-truth run already exists")
    expected_steps = list(enumerate(doc.get("scenario_step_services", ()), start=1))
    actual_steps = [(step.step, step.service) for step in payload.steps]
    if not expected_steps or actual_steps != expected_steps:
        raise HTTPException(422, "ground-truth steps do not match the scenario manifest")
    valid = payload.overall_status == "completed" and all(step.status != "failed" for step in payload.steps)
    doc.update(
        ground_truth=data,
        run_id=payload.run_id,
        runner_status=payload.overall_status,
        runner_start_time=data["start_time"],
        runner_end_time=data["end_time"],
        runner_steps=data["steps"],
        ground_truth_valid=valid,
    )
    doc.pop("_id", None)
    return await store.save(INDEX, identifier, doc)


async def settle(doc: dict) -> tuple[bool, float]:
    settings = get_settings()
    started, unchanged_since, previous = monotonic(), monotonic(), None
    while True:
        count = await store.count("trapsig-events-*", event_query(doc), missing_index_is_empty=True)
        if count != previous:
            previous, unchanged_since = count, monotonic()
        elapsed = monotonic() - started
        # Do not declare an empty stream settled after only the quiet period:
        # Filebeat may not have delivered its first matching event yet.
        if count > 0 and monotonic() - unchanged_since >= settings.experiment_settle_quiet_seconds:
            return True, elapsed
        if elapsed >= settings.experiment_settle_timeout_seconds:
            # A consistently empty bounded window is settled but has no
            # telemetry. A changing stream at the deadline is a settle timeout.
            return (count == 0), elapsed
        await asyncio.sleep(settings.experiment_settle_poll_seconds)


@router.post("/{identifier}/finish")
async def finish(identifier: str):
    doc = await experiment(identifier)
    if doc["status"] == "completed":
        return doc
    if doc["status"] not in {"running", "correlating"}:
        raise HTTPException(409, "only a running or correlating experiment can be finished")
    if doc["status"] == "running":
        # Persist the evidence window before any settling I/O. A retry from
        # correlating deliberately reuses this immutable end time.
        doc.update(status="correlating", end_time=now())
        doc.pop("_id", None)
        await store.save(INDEX, identifier, doc)
    elif not doc.get("end_time"):
        raise HTTPException(409, "correlating experiment has no recorded end_time")
    doc.pop("_id", None)
    settled, wait = await settle(doc)
    doc.update(telemetry_settled=settled, settle_wait_seconds=wait)
    if not settled:
        doc.update(status="completed", result="INCONCLUSIVE", result_reason="SETTLE_TIMEOUT", observed_detection=None)
        return await store.save(INDEX, identifier, doc)
    try:
        from ..services import processor as processor_module

        if processor_module.processor:
            await processor_module.processor.process_once()
        events = await store.search_all("trapsig-events-*", event_query(doc), sort=[{"@timestamp": "asc"}], missing_index_is_empty=True)
        sessions = await store.search_all(
            "trapsig-sessions",
            {
                "bool": {
                    "filter": [
                        exact_filter("source_ip", doc["attacker_ip"]),
                        {"range": {"start_time": {"lte": doc["end_time"]}}},
                        {"range": {"end_time": {"gte": doc["start_time"]}}},
                    ]
                }
            },
            sort=[{"start_time": "asc"}],
            missing_index_is_empty=True,
        )
        session_ids = [s["session_id"] for s in sessions]
        detections = (
            []
            if not session_ids
            else await store.search_all("trapsig-detections", exact_filter("session_id", session_ids), sort=[{"timestamp": "asc"}], missing_index_is_empty=True)
        )
        doc = correlate(doc, events, sessions, detections, scientific=True)
    except Exception:
        doc.update(result="INCONCLUSIVE", result_reason="PROCESSING_ERROR", observed_detection=None)
    doc["status"] = "completed"
    return await store.save(INDEX, identifier, doc)
