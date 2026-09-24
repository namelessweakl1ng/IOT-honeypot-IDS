"""Elasticsearch client + thin query helpers."""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ApiError, TransportError

from .config import settings

log = logging.getLogger("es_client")

_client: Optional[Elasticsearch] = None


def get_client() -> Elasticsearch:
    """Lazy singleton ES client."""
    global _client
    if _client is None:
        _client = Elasticsearch(
            settings.elasticsearch_url,
            basic_auth=(settings.elastic_user, settings.elastic_password),
            request_timeout=10,
            retry_on_timeout=True,
            max_retries=3,
        )
    return _client


def ping() -> bool:
    try:
        return bool(get_client().ping())
    except (ApiError, TransportError, Exception) as exc:  # noqa: BLE001
        log.error("ES ping failed: %s", exc)
        return False


def search_events(
    *,
    index: str = "honeypot-events-*",
    size: int = 100,
    query: Optional[Dict[str, Any]] = None,
    sort: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Search helper for honeypot events.

    Returns a normalized response with only _source fields — no ES metadata
    (_index, _id, _score, _version) leaks to the API consumer.
    Handles malformed ES responses gracefully (never raises).
    """
    body: Dict[str, Any] = {"query": query or {"match_all": {}}}
    if sort:
        body["sort"] = sort
    else:
        body["sort"] = [{"@timestamp": {"order": "desc"}}]
    try:
        resp = get_client().search(index=index, body=body, size=size)
        raw = resp.body if hasattr(resp, "body") else resp
        # Defensive: handle malformed ES responses (missing hits, non-dict, etc.)
        if not isinstance(raw, dict):
            log.error("ES returned non-dict response: %s", type(raw))
            return {"events": [], "total": 0, "error": "malformed ES response (non-dict)"}
        hits_obj = raw.get("hits", {})
        if not isinstance(hits_obj, dict):
            log.error("ES hits field is not a dict: %s", type(hits_obj))
            return {"events": [], "total": 0, "error": "malformed ES response (hits not dict)"}
        raw_hits = hits_obj.get("hits", [])
        if not isinstance(raw_hits, list):
            log.error("ES hits.hits is not a list: %s", type(raw_hits))
            return {"events": [], "total": 0, "error": "malformed ES response (hits.hits not list)"}
        # Extract only _source from each hit — never leak ES internals
        events: List[Dict[str, Any]] = []
        for h in raw_hits:
            if isinstance(h, dict) and "_source" in h:
                events.append(h["_source"])
            else:
                log.warning("ES hit missing _source: %s", h)
        total = hits_obj.get("total", {})
        if isinstance(total, dict):
            total_value = total.get("value", 0)
        else:
            total_value = int(total) if total else 0
        return {
            "events": events,
            "total": total_value,
        }
    except (ApiError, TransportError) as exc:
        log.error("ES search failed: %s", exc)
        # str(exc) may be just the status code; include exc type for diagnostics
        error_msg = str(exc) or exc.__class__.__name__
        if not error_msg or error_msg == "None":
            error_msg = f"{exc.__class__.__name__}: {getattr(exc, 'status_code', 'unknown')}"
        return {"events": [], "total": 0, "error": error_msg}
    except Exception as exc:  # noqa: BLE001 — catch ALL to prevent API crash
        log.error("unexpected ES search error: %s", exc, exc_info=True)
        return {"events": [], "total": 0, "error": f"{exc.__class__.__name__}: {exc}"}


def search_sessions(*, size: int = 50, source_ip: Optional[str] = None) -> List[Dict[str, Any]]:
    q: Dict[str, Any] = {"match_all": {}}
    if source_ip:
        q = {"term": {"source.ip": source_ip}}
    try:
        resp = get_client().search(
            index="honeypot-sessions-*",
            body={"query": q, "sort": [{"started_at": {"order": "desc"}}]},
            size=size,
        )
        body = resp.body if hasattr(resp, "body") else resp
        return [h["_source"] for h in body["hits"]["hits"]]
    except (ApiError, TransportError) as exc:
        log.error("ES sessions search failed: %s", exc)
        return []


def get_session(session_id: str) -> Optional[Dict[str, Any]]:
    """Get a session document + its event timeline."""
    try:
        # Look up the session
        resp = get_client().search(
            index="honeypot-sessions-*",
            body={"query": {"term": {"session_id": session_id}}, "size": 1},
        )
        body = resp.body if hasattr(resp, "body") else resp
        hits = body["hits"]["hits"]
        if not hits:
            return None
        session = hits[0]["_source"]

        # Fetch the event timeline for that session
        ev_resp = get_client().search(
            index="honeypot-events-*",
            body={
                "query": {"term": {"session_id": session_id}},
                "sort": [{"@timestamp": {"order": "asc"}}],
                "size": 500,
            },
        )
        ev_body = ev_resp.body if hasattr(ev_resp, "body") else ev_resp
        session["events"] = [h["_source"] for h in ev_body["hits"]["hits"]]
        return session
    except (ApiError, TransportError) as exc:
        log.error("ES session fetch failed: %s", exc)
        return None


def search_detections(*, size: int = 50, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
    q: Dict[str, Any] = {"match_all": {}}
    if session_id:
        q = {"term": {"session_id": session_id}}
    try:
        resp = get_client().search(
            index="honeypot-detections-*",
            body={"query": q, "sort": [{"@timestamp": {"order": "desc"}}]},
            size=size,
        )
        body = resp.body if hasattr(resp, "body") else resp
        return [h["_source"] for h in body["hits"]["hits"]]
    except (ApiError, TransportError) as exc:
        log.error("ES detections search failed: %s", exc)
        return []
