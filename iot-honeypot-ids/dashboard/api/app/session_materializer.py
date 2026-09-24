"""Session materialization — derives session documents from raw events.

Architecture:
    honeypot-events-*  (raw telemetry, source of truth)
        ↓
    reconstruct_sessions()  (existing: groups events by session_id)
        ↓
    build_session_document()  (new: aggregates event summary into session doc)
        ↓
    honeypot-sessions-*  (derived analytical representation)

The session document is MATERIALIZED on demand via the /sessions/materialize
endpoint. This avoids scanning the entire events index on every /sessions
request. The materialization is idempotent: session_id is used as the ES
document_id with upsert (index action, not create), so reprocessing the same
events produces the same session document without duplicates.

Session identity = session_id (emitted by honeypots). NOT source IP.
Multiple sessions from the same source IP remain distinct when their
session_ids differ.

Event → session lineage: the session document contains event_ids (list of
event_id values from the source events). The /sessions/{id} endpoint
fetches the session document AND the event timeline from honeypot-events-*.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from . import es_client

log = logging.getLogger("session_materializer")


def _to_epoch(iso_ts: str) -> Optional[float]:
    """Parse ISO-8601 timestamp to epoch seconds. Returns None on failure."""
    if not iso_ts or not isinstance(iso_ts, str):
        return None
    s = iso_ts
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except (ValueError, TypeError):
        return None


def build_session_document(session_id: str, events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build a session document from a list of events sharing the same session_id.

    This function does NOT write to ES — it only constructs the document.
    The caller (materialize_sessions) handles ES indexing.

    The document includes:
    - session_id (primary identity)
    - started_at / ended_at (derived from earliest/latest event timestamps)
    - event_count, event_ids (lineage)
    - source/destination (from first event)
    - honeypot, protocol, device (from first event)
    - attack classification/stage (aggregated from events)
    - auth_attempts, auth_successes, unique_usernames (aggregated)
    - bytes_in, bytes_out (summed from http/network fields)

    Fields that cannot be derived from the events are omitted (not fabricated).
    """
    if not events:
        return {}

    # Sort events by timestamp for deterministic derivation
    events_with_ts = [(e, _to_epoch(e.get("@timestamp", ""))) for e in events]
    events_with_ts = [(e, t) for e, t in events_with_ts if t is not None]
    if not events_with_ts:
        # No valid timestamps — can't build a meaningful session
        log.warning("session %s has no events with valid timestamps", session_id)
        return {}
    events_with_ts.sort(key=lambda x: x[1])
    sorted_events = [e for e, _ in events_with_ts]
    times = [t for _, t in events_with_ts]

    first_event = sorted_events[0]
    last_event = sorted_events[-1]
    started_at = first_event.get("@timestamp", "")
    ended_at = last_event.get("@timestamp", "")
    duration_s = times[-1] - times[0] if times else 0.0

    # Source / destination (from first event — they should be consistent within a session)
    source = first_event.get("source", {})
    destination = first_event.get("destination", {})
    device = first_event.get("device", {})
    honeypot = first_event.get("honeypot", {})
    protocol = first_event.get("protocol", "")

    # Event IDs for lineage
    event_ids = [e.get("event_id") for e in sorted_events if e.get("event_id")]
    event_count = len(sorted_events)

    # Aggregate authentication data
    auth_attempts = 0
    auth_successes = 0
    usernames: set = set()
    for e in sorted_events:
        auth = e.get("authentication") or {}
        if auth.get("attempted"):
            auth_attempts += 1
            if auth.get("success"):
                auth_successes += 1
            u = auth.get("username")
            if u:
                usernames.add(u)

    # Aggregate HTTP data
    bytes_in = 0
    bytes_out = 0
    uri_count = 0
    unique_uris: set = set()
    for e in sorted_events:
        http = e.get("http") or {}
        bytes_in += int(http.get("bytes_in", 0) or 0)
        bytes_out += int(http.get("bytes_out", 0) or 0)
        if http.get("uri"):
            uri_count += 1
            unique_uris.add(http["uri"])
        network = e.get("network") or {}
        bytes_in += int(network.get("bytes_in", 0) or 0)
        bytes_out += int(network.get("bytes_out", 0) or 0)

    # Aggregate attack classification/stage
    classifications: set = set()
    stages: set = set()
    max_confidence = 0.0
    for e in sorted_events:
        attack = e.get("attack") or {}
        if attack.get("classification"):
            classifications.add(attack["classification"])
        if attack.get("stage"):
            stages.add(attack["stage"])
        conf = attack.get("confidence", 0.0) or 0.0
        if conf > max_confidence:
            max_confidence = conf

    # Build the session document — only include fields we can derive
    doc: Dict[str, Any] = {
        "@timestamp": started_at,  # session creation time = first event time
        "session_id": session_id,
        "started_at": started_at,
        "ended_at": ended_at,
        "duration_s": round(duration_s, 3),
        "event_count": event_count,
        "event_ids": event_ids,  # lineage: session → events
        "protocol": protocol,
    }

    # Include source if available
    if source.get("ip"):
        doc["source"] = {"ip": source["ip"]}
        if source.get("port"):
            doc["source"]["port"] = int(source["port"])

    # Include destination if available
    if destination.get("ip"):
        doc["destination"] = {"ip": destination["ip"]}
        if destination.get("port"):
            doc["destination"]["port"] = int(destination["port"])

    # Include device if available
    if device.get("id"):
        doc["device"] = {"id": device["id"]}
        if device.get("type"):
            doc["device"]["type"] = device["type"]

    # Include honeypot if available
    if honeypot.get("name"):
        doc["honeypot"] = honeypot

    # Include aggregated auth data
    if auth_attempts > 0:
        doc["auth_attempts"] = auth_attempts
        doc["auth_successes"] = auth_successes
        doc["unique_usernames"] = len(usernames)

    # Include HTTP aggregates
    if bytes_in > 0 or bytes_out > 0:
        doc["bytes_in"] = bytes_in
        doc["bytes_out"] = bytes_out
    if uri_count > 0:
        doc["uri_count"] = uri_count
        doc["unique_uris"] = len(unique_uris)

    # Include attack classification (pick the highest-confidence one)
    if classifications:
        # If multiple classifications, pick the one with highest confidence
        # For simplicity, join them — the session has multiple attack types
        doc["classification"] = list(classifications)[0] if len(classifications) == 1 else "mixed"
    if stages:
        doc["attack_stage"] = list(stages)[0] if len(stages) == 1 else "mixed"
    if max_confidence > 0:
        doc["confidence"] = max_confidence

    return doc


def materialize_sessions(
    *,
    lookback_minutes: int = 60,
    max_sessions: int = 500,
    max_events: int = 50000,
    batch_size: int = 5000,
) -> Dict[str, Any]:
    """Materialize session documents from recent events in ES.

    This is the materialization entry point. It:
    1. Queries recent events from honeypot-events-* (bounded by lookback)
    2. Groups by session_id using reconstruct_sessions()
    3. Builds session documents via build_session_document()
    4. Upserts to honeypot-sessions-* (idempotent — session_id as doc_id)

    Args:
        lookback_minutes: Only process events from the last N minutes (default 60)
        max_sessions: Safety cap on number of sessions to materialize (default 500)
        max_events: Safety cap on total events to fetch (default 50000).
            Replaces the previous `max_sessions * 50` heuristic which could
            silently truncate sessions with >50 events.
        batch_size: ES page size for search_after pagination (default 5000)

    Returns:
        Summary dict with counts + any errors.
        If max_events was reached, `events_capped` is True.
    """
    if not es_client.ping():
        return {
            "status": "degraded",
            "error": "Elasticsearch unavailable",
            "sessions_materialized": 0,
            "events_processed": 0,
        }

    # 1. Fetch recent events (bounded — NOT a full scan)
    # Sort by session_id + @timestamp + event_id for deterministic ordering.
    # The event_id tiebreaker ensures search_after pagination doesn't skip
    # or duplicate events when multiple events share the same session_id + timestamp.
    query = {
        "query": {
            "range": {"@timestamp": {"gte": f"now-{lookback_minutes}m/m"}}
        },
        "sort": [
            {"session_id": "asc"},
            {"@timestamp": "asc"},
            {"event_id": "asc"},  # stable tiebreaker
        ],
    }

    all_events: List[Dict[str, Any]] = []
    events_capped = False
    try:
        client = es_client.get_client()
        # Use search_after pagination to avoid scroll timeout issues
        page = client.search(index="honeypot-events-*", body=query, size=batch_size)
        raw = page.body if hasattr(page, "body") else page
        hits = raw.get("hits", {}).get("hits", [])
        all_events.extend(h.get("_source", {}) for h in hits if isinstance(h, dict))

        # Paginate via search_after — bounded by max_events (NOT max_sessions * 50)
        while len(hits) >= batch_size and len(all_events) < max_events:
            last_sort = hits[-1].get("sort")
            if not last_sort:
                break
            query_with_after = dict(query)
            query_with_after["search_after"] = last_sort
            page = client.search(index="honeypot-events-*", body=query_with_after, size=batch_size)
            raw = page.body if hasattr(page, "body") else page
            hits = raw.get("hits", {}).get("hits", [])
            if not hits:
                break
            all_events.extend(h.get("_source", {}) for h in hits if isinstance(h, dict))

        # Check if we hit the event cap
        if len(all_events) >= max_events:
            events_capped = True
            log.warning(
                "event cap reached: fetched %d events (max_events=%d) — "
                "some sessions may be incomplete in this cycle",
                len(all_events), max_events,
            )

    except Exception as exc:  # noqa: BLE001
        log.error("failed to fetch events for session materialization: %s", exc, exc_info=True)
        return {
            "status": "error",
            "error": f"{exc.__class__.__name__}: {exc}",
            "sessions_materialized": 0,
            "events_processed": 0,
        }

    if not all_events:
        return {
            "status": "ok",
            "sessions_materialized": 0,
            "events_processed": 0,
            "note": "no events found in the lookback window",
        }

    # 2. Group by session_id (reuse existing reconstruct_sessions)
    # Import here to avoid circular import at module level
    import sys as _sys
    from pathlib import Path as _Path
    _ml_path = _Path(__file__).resolve().parents[2] / "dashboard" / "ml"
    if str(_ml_path) not in _sys.path:
        _sys.path.insert(0, str(_ml_path))
    from features import reconstruct_sessions  # type: ignore

    grouped = reconstruct_sessions(all_events)
    dropped = grouped.pop("_dropped_count", 0)  # type: ignore

    # 3. Build session documents
    sessions_to_write: List[Dict[str, Any]] = []
    for session_id, events in grouped.items():
        if len(sessions_to_write) >= max_sessions:
            log.info("max_sessions cap reached (%d), stopping", max_sessions)
            break
        doc = build_session_document(session_id, events)
        if doc:
            sessions_to_write.append(doc)

    # 4. Upsert to ES (idempotent — session_id as document_id)
    written = 0
    errors = 0
    index_name = "honeypot-sessions-" + datetime.now(timezone.utc).strftime("%Y.%m.%d")
    try:
        client = es_client.get_client()
        for doc in sessions_to_write:
            sid = doc["session_id"]
            # Use index (upsert) action — not create — so reprocessing
            # the same events updates the session document rather than
            # creating duplicates or failing with 409.
            client.index(
                index=index_name,
                id=sid,
                document=doc,
            )
            written += 1
    except Exception as exc:  # noqa: BLE001
        log.error("failed to index session %s: %s", doc.get("session_id"), exc)
        errors += 1

    return {
        "status": "ok" if errors == 0 else "partial",
        "sessions_materialized": written,
        "events_processed": len(all_events),
        "events_dropped_no_session_id": dropped,
        "errors": errors,
        "lookback_minutes": lookback_minutes,
        "events_capped": events_capped,
    }
