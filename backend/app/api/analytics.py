import asyncio
from typing import Any

from fastapi import APIRouter, Query

from ..elastic import store

router = APIRouter(prefix="/analytics", tags=["analytics"])
ALLOWED_MINUTES = {15, 60, 360, 1440, 10080}


def _query(minutes: int, timestamp_field: str, exclude_healthchecks: bool = False) -> dict[str, Any]:
    filters: list[dict[str, Any]] = [{"range": {timestamp_field: {"gte": f"now-{minutes}m"}}}]
    query: dict[str, Any] = {"filter": filters}
    if exclude_healthchecks:
        # Sensor container health probes originate on loopback. Raw events remain untouched;
        # only analytics excludes this deterministic monitoring source.
        query["must_not"] = [{"terms": {"source.ip": ["127.0.0.1", "::1"]}}]
    return {"bool": query}


def _buckets(result: dict[str, Any], name: str) -> list[dict[str, Any]]:
    buckets = result.get("aggregations", {}).get(name, {}).get("buckets", [])
    return [{"name": str(item["key"]), "count": int(item["doc_count"])} for item in buckets]


def _hits(result: dict[str, Any]) -> list[dict[str, Any]]:
    return [{**hit.get("_source", {}), "_id": hit.get("_id")} for hit in result.get("hits", {}).get("hits", [])]


def _total(result: dict[str, Any]) -> int:
    total = result.get("hits", {}).get("total", 0)
    return int(total.get("value", 0) if isinstance(total, dict) else total)


@router.get("/overview")
async def overview(minutes: int = Query(60)) -> dict[str, Any]:
    if minutes not in ALLOWED_MINUTES:
        from fastapi import HTTPException
        raise HTTPException(422, "minutes must be one of 15, 60, 360, 1440, 10080")

    interval = "1m" if minutes <= 60 else "10m" if minutes <= 360 else "1h" if minutes <= 1440 else "12h"
    events_task = store.aggregate(
        "trapsig-events-*", _query(minutes, "@timestamp", True), {
            "events_over_time": {"date_histogram": {"field": "@timestamp", "fixed_interval": interval, "min_doc_count": 1}},
            "unique_sources": {"cardinality": {"field": "source.ip"}},
            "honeypots": {"terms": {"field": "honeypot.id", "size": 10}},
            "protocols": {"terms": {"field": "network.protocol", "size": 10}},
            "categories": {"terms": {"field": "event.category", "size": 10}},
            "actions": {"terms": {"field": "event.action", "size": 10}},
            "outcomes": {"terms": {"field": "event.outcome", "size": 10}},
            "auth_outcomes": {"filter": {"term": {"event.category": "authentication"}}, "aggs": {"values": {"terms": {"field": "event.outcome", "size": 5}}}},
            "top_sources": {"terms": {"field": "source.ip", "size": 8}, "aggs": {"honeypots": {"terms": {"field": "honeypot.id", "size": 10}}}},
        }, size=8, sort=[{"@timestamp": "desc"}], missing_index_is_empty=True,
    )
    sessions_task = store.aggregate(
        "trapsig-sessions", _query(minutes, "start_time"), {
            "failed_auth": {"sum": {"field": "failed_authentication_attempts"}},
            "multi_service": {"filter": {"script": {"script": "doc.containsKey('honeypots_touched.keyword') && doc['honeypots_touched.keyword'].size() > 1"}}},
        }, size=10, sort=[{"start_time": "desc"}], missing_index_is_empty=True,
    )
    detections_task = store.aggregate(
        "trapsig-detections", _query(minutes, "timestamp"), {
            "severity": {"terms": {"field": "severity.keyword", "size": 8}},
            "types": {"terms": {"field": "type.keyword", "size": 16}},
        }, size=8, sort=[{"timestamp": "desc"}], missing_index_is_empty=True,
    )
    events, sessions, detections = await asyncio.gather(events_task, sessions_task, detections_task)
    event_aggs = events.get("aggregations", {})
    source_buckets = event_aggs.get("top_sources", {}).get("buckets", [])
    session_hits = _hits(sessions)
    session_sources = {item.get("session_id"): item.get("source_ip") for item in session_hits}
    detection_hits = _hits(detections)
    for detection in detection_hits:
        detection["source_ip"] = session_sources.get(detection.get("session_id"))
    return {
        "range_minutes": minutes,
        "totals": {
            "events": _total(events), "sessions": _total(sessions), "detections": _total(detections),
            "unique_sources": int(event_aggs.get("unique_sources", {}).get("value", 0)),
            "failed_auth_attempts": int(sessions.get("aggregations", {}).get("failed_auth", {}).get("value", 0)),
            "multi_service_sessions": int(sessions.get("aggregations", {}).get("multi_service", {}).get("doc_count", 0)),
        },
        "events_over_time": [{"time": str(item.get("key_as_string", item["key"])), "count": int(item["doc_count"])} for item in event_aggs.get("events_over_time", {}).get("buckets", [])],
        "honeypots": _buckets(events, "honeypots"), "protocols": _buckets(events, "protocols"),
        "categories": _buckets(events, "categories"), "actions": _buckets(events, "actions"), "outcomes": _buckets(events, "outcomes"),
        "top_sources": [{"name": str(item["key"]), "count": int(item["doc_count"])} for item in source_buckets],
        "auth_outcomes": [{"name": str(item["key"]), "count": int(item["doc_count"])} for item in event_aggs.get("auth_outcomes", {}).get("values", {}).get("buckets", [])],
        "detection_severity": _buckets(detections, "severity"), "detection_types": _buckets(detections, "types"),
        "source_honeypot_matrix": [{"source": str(item["key"]), "honeypots": {str(cell["key"]): int(cell["doc_count"]) for cell in item.get("honeypots", {}).get("buckets", [])}} for item in source_buckets],
        "sessions": session_hits, "recent_detections": detection_hits, "recent_events": _hits(events),
    }
