"""Read-only research evaluation and export endpoints."""

import json
from typing import Any

from fastapi import APIRouter, Query
from fastapi.responses import PlainTextResponse

from ..elastic import store
from ..services.evaluation import aggregate, evaluation_config_fingerprint, export_csv, export_rows
from ..services.experiments import exact_filter, parse_time

router = APIRouter(prefix="/evaluation", tags=["evaluation"])
EVENT_ID_BATCH_SIZE = 250


def _filter(records: list[dict[str, Any]], batch: str | None, fingerprint: str | None) -> list[dict[str, Any]]:
    if batch is not None:
        records = [record for record in records if record.get("evaluation_batch_id") == batch]
    if fingerprint is not None:
        records = [record for record in records if (record.get("evaluation_config_fingerprint") or evaluation_config_fingerprint(record)) == fingerprint]
    return records


async def _records(batch: str | None = None, fingerprint: str | None = None):
    records = await store.search_all("trapsig-experiments", {"match_all": {}}, sort=[{"created_at": "asc"}], missing_index_is_empty=True)
    return _filter(records, batch, fingerprint)


async def fetch_events_by_ids(event_ids: list[str], batch_size: int = EVENT_ID_BATCH_SIZE) -> dict[str, dict[str, Any]]:
    """Fetch linked raw events in bounded PIT queries without mutating them."""
    events: dict[str, dict[str, Any]] = {}
    for offset in range(0, len(event_ids), batch_size):
        ids = event_ids[offset : offset + batch_size]
        found = await store.search_all(
            "trapsig-events-*", exact_filter("event.id", ids), sort=[{"@timestamp": "asc"}], page_size=batch_size, missing_index_is_empty=True
        )
        for event in found:
            identifier = event.get("event", {}).get("id")
            if identifier:
                events[identifier] = event
    return events


async def _event_samples(records: list[dict[str, Any]]) -> dict[str, list[float | None]]:
    identifiers = list(dict.fromkeys(identifier for record in records for identifier in record.get("event_ids", [])))
    events = await fetch_events_by_ids(identifiers)
    samples = {}
    for record in records:
        values = []
        for identifier in record.get("event_ids", []):
            event = events.get(identifier)
            occurred = parse_time(event.get("@timestamp")) if event else None
            ingested = parse_time(event.get("event", {}).get("ingested")) if event else None
            delta = (ingested - occurred).total_seconds() if occurred and ingested else None
            values.append(delta if delta is not None and delta >= 0 else None)
        samples[record.get("experiment_id")] = values
    return samples


@router.get("/summary")
async def summary(evaluation_batch_id: str | None = None, evaluation_config_fingerprint: str | None = None):
    records = await _records(evaluation_batch_id, evaluation_config_fingerprint)
    return aggregate(records, await _event_samples(records))


@router.get("/export.csv", response_class=PlainTextResponse)
async def csv_export(evaluation_batch_id: str | None = None, evaluation_config_fingerprint: str | None = None):
    records = await _records(evaluation_batch_id, evaluation_config_fingerprint)
    return PlainTextResponse(export_csv(records), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=experiments.csv"})


@router.get("/export.json", response_class=PlainTextResponse)
async def json_export(evaluation_batch_id: str | None = Query(default=None), evaluation_config_fingerprint: str | None = Query(default=None)):
    records = await _records(evaluation_batch_id, evaluation_config_fingerprint)
    return PlainTextResponse(
        json.dumps(export_rows(records), indent=2), media_type="application/json", headers={"Content-Disposition": "attachment; filename=experiments.json"}
    )
