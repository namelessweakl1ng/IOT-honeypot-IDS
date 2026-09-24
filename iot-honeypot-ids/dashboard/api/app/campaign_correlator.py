"""Campaign correlation — derives higher-level attack groupings from sessions.

STABLE CAMPAIGN IDENTITY: campaign_id is derived from (source_ip, first_session_id)
only — timestamps don't affect the ID. The temporal gap determines membership.
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from . import es_client

log = logging.getLogger("campaign_correlator")

CAMPAIGN_GAP_MINUTES = 60
MAX_CAMPAIGNS_PER_CYCLE = 200
MAX_SESSIONS_PER_CYCLE = 5000
CAMPAIGN_INDEX_PREFIX = "honeypot-campaigns"


def _to_epoch(ts: Any) -> Optional[float]:
    if not ts or not isinstance(ts, str): return None
    s = ts
    if s.endswith("Z"): s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except (ValueError, TypeError): return None


def _campaign_id(source_ip: str, first_session_epoch: float, first_session_id: str) -> str:
    h = hashlib.sha1()
    h.update(source_ip.encode("utf-8"))
    h.update(b"|")
    h.update(first_session_id.encode("utf-8"))
    return "camp-" + h.hexdigest()[:16]


def _group_sessions_by_source(sessions):
    by_source = {}
    for s in sessions:
        src = (s.get("source") or {}).get("ip")
        if src: by_source.setdefault(src, []).append(s)
    return by_source


def _split_into_campaigns(sessions, gap_minutes=CAMPAIGN_GAP_MINUTES):
    if not sessions: return []
    with_ts = [(s, _to_epoch(s.get("started_at") or s.get("@timestamp"))) for s in sessions]
    with_ts.sort(key=lambda x: (x[1] if x[1] is not None else float("inf"), x[0].get("session_id", "")))
    gap_s = gap_minutes * 60.0
    groups, current, last_t = [], [], None
    for s, t in with_ts:
        if last_t is not None and t is not None and (t - last_t) > gap_s:
            if current: groups.append(current)
            current = []
        current.append(s)
        if t is not None: last_t = t
    if current: groups.append(current)
    return groups


def build_campaign_document(source_ip, sessions):
    if not sessions: return {}
    with_ts = [(s, _to_epoch(s.get("started_at") or s.get("@timestamp"))) for s in sessions]
    with_ts.sort(key=lambda x: (x[1] if x[1] is not None else float("inf"), x[0].get("session_id", "")))
    sorted_sessions = [s for s, _ in with_ts]
    times = [t for _, t in with_ts if t is not None]
    times.sort()

    first_session = sorted_sessions[0]
    first_session_id = first_session.get("session_id", "")
    first_epoch = times[0] if times else 0.0
    campaign_id = _campaign_id(source_ip, first_epoch, first_session_id)
    session_ids = [s.get("session_id") for s in sorted_sessions if s.get("session_id")]

    started_at = first_session.get("started_at") or first_session.get("@timestamp", "")
    ended_at = sorted_sessions[-1].get("ended_at") or sorted_sessions[-1].get("@timestamp", "")
    if times:
        if not started_at: started_at = datetime.fromtimestamp(times[0], tz=timezone.utc).isoformat()
        if not ended_at: ended_at = datetime.fromtimestamp(times[-1], tz=timezone.utc).isoformat()

    now_epoch = datetime.now(timezone.utc).timestamp()
    last_epoch = times[-1] if times else 0.0
    campaign_status = "active" if (now_epoch - last_epoch) < (CAMPAIGN_GAP_MINUTES * 60) else "closed"

    classifications, honeypots, protocols = set(), set(), set()
    total_events = 0
    for s in sorted_sessions:
        cls = s.get("classification")
        if cls: classifications.add(cls)
        hp = (s.get("honeypot") or {}).get("name")
        if hp: honeypots.add(hp)
        proto = s.get("protocol")
        if proto: protocols.add(proto)
        try: total_events += int(s.get("event_count", 0) or 0)
        except: pass

    doc = {
        "campaign_id": campaign_id,
        "session_ids": session_ids,
        "session_count": len(sessions),
        "started_at": started_at,
        "ended_at": ended_at,
        "first_seen": started_at,
        "last_seen": ended_at,
        "last_session_id": sorted_sessions[-1].get("session_id", "") if sorted_sessions else "",
        "last_session_at": ended_at,
        "duration_s": round(times[-1] - times[0], 3) if len(times) >= 2 else 0.0,
        "event_count": total_events,
        "source": {"ip": source_ip},
        "correlation_window_minutes": CAMPAIGN_GAP_MINUTES,
        "correlation_criteria": "source.ip + temporal_proximity (CAMPAIGN_GAP_MINUTES)",
        "campaign_status": campaign_status,
    }
    if honeypots: doc["honeypots"] = sorted(honeypots)
    if protocols: doc["protocols"] = sorted(protocols)
    if classifications: doc["classifications"] = sorted(classifications)
    return doc


def _merge_campaign_into_persisted(persisted, new_sessions, source_ip):
    new_doc = build_campaign_document(source_ip, new_sessions)
    if not new_doc: return persisted
    persisted_session_ids = list(persisted.get("session_ids") or [])
    new_session_ids = list(new_doc.get("session_ids") or [])
    existing_set = set(persisted_session_ids)
    seen = set()
    unique_new = [sid for sid in new_session_ids if sid not in existing_set and not (sid in seen or seen.add(sid))]
    merged_session_ids = persisted_session_ids + unique_new

    persisted_started = persisted.get("started_at", "")
    persisted_first_seen = persisted.get("first_seen", persisted_started)
    persisted_event_count = int(persisted.get("event_count", 0) or 0)

    existing_for_events = set(persisted_session_ids)
    seen_batch = set()
    additional = 0
    for sess in new_sessions:
        sid = sess.get("session_id")
        if not sid or sid in existing_for_events or sid in seen_batch: continue
        seen_batch.add(sid)
        try: additional += int(sess.get("event_count", 0) or 0)
        except: pass
    merged_event_count = persisted_event_count + additional

    new_last = new_doc.get("last_session_at", "")
    persisted_last = persisted.get("last_session_at", persisted.get("ended_at", ""))
    new_epoch = _to_epoch(new_last)
    persisted_epoch = _to_epoch(persisted_last)
    if new_epoch and (not persisted_epoch or new_epoch > persisted_epoch):
        final_ended = new_doc.get("ended_at", "")
        final_last_seen = new_doc.get("last_seen", "")
        final_last_id = new_doc.get("last_session_id", "")
        final_last_at = new_last
    else:
        final_ended = persisted.get("ended_at", "")
        final_last_seen = persisted.get("last_seen", "")
        final_last_id = persisted.get("last_session_id", "")
        final_last_at = persisted_last

    now_epoch = datetime.now(timezone.utc).timestamp()
    final_epoch = _to_epoch(final_last_at) or 0.0
    status = "active" if (now_epoch - final_epoch) < (CAMPAIGN_GAP_MINUTES * 60) else "closed"

    merged = {
        "campaign_id": persisted.get("campaign_id"),
        "session_ids": merged_session_ids,
        "session_count": len(merged_session_ids),
        "started_at": persisted_started,
        "first_seen": persisted_first_seen,
        "ended_at": final_ended,
        "last_seen": final_last_seen,
        "last_session_id": final_last_id,
        "last_session_at": final_last_at,
        "duration_s": round((_to_epoch(final_last_at) or 0) - (_to_epoch(persisted_started) or 0), 3),
        "event_count": merged_event_count,
        "source": {"ip": source_ip},
        "correlation_window_minutes": CAMPAIGN_GAP_MINUTES,
        "correlation_criteria": "source.ip + temporal_proximity (CAMPAIGN_GAP_MINUTES)",
        "campaign_status": status,
    }
    h = set(persisted.get("honeypots") or []); h.update(new_doc.get("honeypots") or [])
    p = set(persisted.get("protocols") or []); p.update(new_doc.get("protocols") or [])
    c = set(persisted.get("classifications") or []); c.update(new_doc.get("classifications") or [])
    if h: merged["honeypots"] = sorted(h)
    if p: merged["protocols"] = sorted(p)
    if c: merged["classifications"] = sorted(c)
    return merged


def find_active_campaigns_for_source(source_ip):
    try:
        client = es_client.get_client()
        resp = client.search(index=f"{CAMPAIGN_INDEX_PREFIX}-*", body={
            "query": {"bool": {"filter": [{"term": {"source.ip": source_ip}}, {"term": {"campaign_status": "active"}}]}},
            "sort": [{"last_session_at": {"order": "desc"}}], "size": 10,
        })
        raw = resp.body if hasattr(resp, "body") else resp
        return [h.get("_source", {}) for h in (raw.get("hits") or {}).get("hits", []) if isinstance(h, dict)]
    except Exception as exc:
        log.warning("failed to find active campaigns for %s: %s", source_ip, exc)
        return []


def _close_campaign(client, campaign_id, index_name):
    try:
        client.update(index=index_name, id=campaign_id, body={"doc": {"campaign_status": "closed"}})
        return True
    except Exception as exc:
        log.warning("failed to close campaign %s: %s", campaign_id, exc)
        return False


def correlate_campaigns(*, lookback_minutes=240, max_campaigns=MAX_CAMPAIGNS_PER_CYCLE, max_sessions=MAX_SESSIONS_PER_CYCLE):
    if not es_client.ping():
        return {"status": "degraded", "error": "Elasticsearch unavailable", "campaigns_materialized": 0,
                "sessions_processed": 0, "sessions_campaign_linked": 0, "campaign_index_errors": 0, "session_update_errors": 0,
                "campaigns_closed": 0, "campaigns_attached": 0, "campaigns_created": 0}

    try:
        client = es_client.get_client()
        resp = client.search(index="honeypot-sessions-*", body={
            "query": {"range": {"started_at": {"gte": f"now-{lookback_minutes}m/m"}}},
            "sort": [{"started_at": "asc"}, {"session_id": "asc"}], "size": max_sessions,
        })
        raw = resp.body if hasattr(resp, "body") else resp
        sessions = [h.get("_source", {}) for h in (raw.get("hits") or {}).get("hits", []) if isinstance(h, dict)]
    except Exception as exc:
        return {"status": "error", "error": f"{exc.__class__.__name__}: {exc}", "campaigns_materialized": 0,
                "sessions_processed": 0, "sessions_campaign_linked": 0, "campaign_index_errors": 0, "session_update_errors": 0,
                "campaigns_closed": 0, "campaigns_attached": 0, "campaigns_created": 0}

    if not sessions:
        return {"status": "ok", "campaigns_materialized": 0, "sessions_processed": 0, "sessions_campaign_linked": 0,
                "campaign_index_errors": 0, "session_update_errors": 0, "campaigns_closed": 0, "campaigns_attached": 0, "campaigns_created": 0}

    by_source = _group_sessions_by_source(sessions)
    campaign_docs, session_campaign_updates = [], []
    campaigns_closed = campaigns_attached = campaigns_created = 0
    gap_s = CAMPAIGN_GAP_MINUTES * 60.0

    for source_ip, src_sessions in by_source.items():
        if len(campaign_docs) >= max_campaigns: break
        with_ts = [(s, _to_epoch(s.get("started_at") or s.get("@timestamp"))) for s in src_sessions]
        with_ts.sort(key=lambda x: (x[1] if x[1] is not None else float("inf"), x[0].get("session_id", "")))

        active_campaigns = find_active_campaigns_for_source(source_ip)
        active_campaign = active_campaigns[0] if active_campaigns else None
        active_last_epoch = _to_epoch((active_campaign or {}).get("last_session_at")) if active_campaign else None
        existing_campaign_id = (active_campaign or {}).get("campaign_id")
        current_group = []
        last_t = active_last_epoch

        for s, t in with_ts:
            if last_t is not None and t is not None and (t - last_t) > gap_s:
                if existing_campaign_id and current_group:
                    doc = _merge_campaign_into_persisted(active_campaign, current_group, source_ip) if active_campaign else build_campaign_document(source_ip, current_group)
                    if doc:
                        if existing_campaign_id: doc["campaign_id"] = existing_campaign_id
                        campaign_docs.append(doc)
                        for sess in current_group:
                            sid = sess.get("session_id")
                            if sid: session_campaign_updates.append((sid, doc["campaign_id"]))
                if existing_campaign_id:
                    index_name = CAMPAIGN_INDEX_PREFIX + "-" + datetime.now(timezone.utc).strftime("%Y.%m.%d")
                    if _close_campaign(client, existing_campaign_id, index_name): campaigns_closed += 1
                current_group = [s]
                existing_campaign_id = None
                active_campaign = None
                campaigns_created += 1
            else:
                if not current_group: current_group = [s]
                else: current_group.append(s)
                if existing_campaign_id: campaigns_attached += 1
            if t is not None: last_t = t

        if current_group:
            if active_campaign and existing_campaign_id:
                doc = _merge_campaign_into_persisted(active_campaign, current_group, source_ip)
            else:
                doc = build_campaign_document(source_ip, current_group)
            if doc:
                if existing_campaign_id: doc["campaign_id"] = existing_campaign_id
                campaign_docs.append(doc)
                for sess in current_group:
                    sid = sess.get("session_id")
                    if sid: session_campaign_updates.append((sid, doc["campaign_id"]))

    if not campaign_docs:
        return {"status": "ok", "campaigns_materialized": 0, "sessions_processed": len(sessions),
                "sessions_campaign_linked": 0, "campaign_index_errors": 0, "session_update_errors": 0,
                "campaigns_closed": campaigns_closed, "campaigns_attached": campaigns_attached, "campaigns_created": campaigns_created}

    written, campaign_errors = 0, 0
    index_name = CAMPAIGN_INDEX_PREFIX + "-" + datetime.now(timezone.utc).strftime("%Y.%m.%d")
    for doc in campaign_docs:
        try:
            client.index(index=index_name, id=doc["campaign_id"], document=doc)
            written += 1
        except Exception as exc:
            log.error("failed to index campaign %s: %s", doc.get("campaign_id"), exc)
            campaign_errors += 1

    session_update_errors = 0
    session_updates_succeeded = 0
    for sid, cid in session_campaign_updates:
        try:
            search_resp = client.search(index="honeypot-sessions-*", body={"query": {"term": {"session_id": sid}}, "size": 1})
            sr = search_resp.body if hasattr(search_resp, "body") else search_resp
            shits = (sr.get("hits") or {}).get("hits") or []
            if not shits: continue
            hit = shits[0]
            client.update(index=hit["_index"], id=hit["_id"], body={"doc": {"campaign_id": cid}})
            session_updates_succeeded += 1
        except Exception as exc:
            log.warning("failed to update session %s with campaign_id: %s", sid, exc)
            session_update_errors += 1

    total_errors = campaign_errors + session_update_errors
    total_writes = written + session_updates_succeeded
    status = "ok" if total_errors == 0 else ("partial" if total_writes > 0 else "error")

    return {"status": status, "campaigns_materialized": written, "sessions_processed": len(sessions),
            "sessions_campaign_linked": session_updates_succeeded, "campaign_index_errors": campaign_errors,
            "session_update_errors": session_update_errors, "campaigns_closed": campaigns_closed,
            "campaigns_attached": campaigns_attached, "campaigns_created": campaigns_created, "lookback_minutes": lookback_minutes}


def search_campaigns(*, size=50, source_ip=None):
    q = {"match_all": {}} if not source_ip else {"term": {"source.ip": source_ip}}
    try:
        resp = es_client.get_client().search(index=f"{CAMPAIGN_INDEX_PREFIX}-*", body={"query": q, "sort": [{"started_at": {"order": "desc"}}]}, size=min(size, 200))
        raw = resp.body if hasattr(resp, "body") else resp
        return [h.get("_source", {}) for h in (raw.get("hits") or {}).get("hits", []) if isinstance(h, dict)]
    except Exception as exc:
        log.error("campaign search failed: %s", exc)
        return []


def get_campaign(campaign_id):
    try:
        client = es_client.get_client()
        resp = client.search(index=f"{CAMPAIGN_INDEX_PREFIX}-*", body={"query": {"term": {"campaign_id": campaign_id}}, "size": 1})
        raw = resp.body if hasattr(resp, "body") else resp
        hits = (raw.get("hits") or {}).get("hits") or []
        if not hits: return None
        campaign = hits[0].get("_source", {})
        session_ids = campaign.get("session_ids") or []
        if session_ids:
            sess_resp = client.search(index="honeypot-sessions-*", body={"query": {"terms": {"session_id": session_ids}}, "sort": [{"started_at": "asc"}], "size": min(len(session_ids), 500)})
            sr = sess_resp.body if hasattr(sess_resp, "body") else sess_resp
            campaign["sessions"] = [h.get("_source", {}) for h in (sr.get("hits") or {}).get("hits", []) if isinstance(h, dict)]
        else:
            campaign["sessions"] = []
        return campaign
    except Exception as exc:
        log.error("campaign fetch failed: %s", exc)
        return None
