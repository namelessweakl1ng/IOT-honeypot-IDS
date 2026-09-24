"""Logstash-equivalent normalization — pure Python reference implementation.

This module mirrors the field-level transformation performed by
dashboard/logstash/pipelines/beats.conf. It exists so the normalization
contract can be unit-tested deterministically without running Logstash.

CONTRACT:
- Input: a raw event dict as emitted by a honeypot (cowrie / camera / iot-service)
  wrapped in a simulated Filebeat envelope.
- Output: a normalized event dict with ECS-style fields, plus the
  routing decision (target_index, document_id, action).

The Python implementation is the SOURCE OF TRUTH for the test suite.
The Logstash .conf file is the production implementation. If they
diverge, a test should fail.

Limitations: this is a pure-Python reference. It does NOT replicate
Filebeat's ndjson parser quirks, Logstash ruby block side effects, or
ES dynamic mapping. It only normalizes field names + values.
"""
from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple


# Required top-level fields for an event to be considered well-formed.
# Matches shared/schemas/event_schema.py REQUIRED_FIELDS.
REQUIRED_FIELDS = (
    "@timestamp",
    "event_id",
    "session_id",
    "source.ip",
    "device.id",
    "event.type",
    "honeypot.name",
)


def _get_nested(d: Dict[str, Any], path: str) -> Any:
    """Get a nested value by dot-path. Returns None if any segment is missing."""
    cur: Any = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _has_nested(d: Dict[str, Any], path: str) -> bool:
    """Check if a nested dot-path exists in the dict."""
    return _get_nested(d, path) is not None


def _cowrie_classify(eventid: Optional[str]) -> Dict[str, str]:
    """Cowrie classification based on eventid pattern (mirrors beats.conf)."""
    out: Dict[str, str] = {}
    if not eventid:
        return out
    if re.match(r"^cowrie\.session\.", eventid):
        out["event.type"] = "session"
    if re.match(r"^cowrie\.login", eventid):
        out["event.category"] = "authentication"
    if re.match(r"^cowrie\.command", eventid):
        out["event.category"] = "execution"
        out["attack.stage"] = "execution"
    return out


def _uri_classify(uri: Optional[str]) -> Dict[str, str]:
    """URI-based attack classification (mirrors beats.conf enrichment)."""
    out: Dict[str, str] = {}
    if not uri:
        return out
    if re.search(r"(\.\.|%2e%2e|%00|etc/passwd)", uri):
        out["attack.classification"] = "path_traversal"
    if re.search(r"(exec|cmd|shell)", uri):
        out["attack.classification"] = "command_injection"
    if re.search(r"(login|admin|config|firmware)", uri):
        out["attack.stage"] = "reconnaissance"
    return out


def normalize(raw_event: Dict[str, Any], honeypot_hint: Optional[str] = None) -> Dict[str, Any]:
    """Normalize a raw honeypot event to ECS-style fields.

    Args:
        raw_event: the dict the honeypot wrote (cowrie nested object, camera/iot flat).
        honeypot_hint: optional override for the honeypot identity (e.g. from
            Filebeat's `fields.honeypot`). When omitted, the honeypot.name
            from the event itself is used.

    Returns:
        The normalized event dict, including `ingested_at`, `timestamp_source`,
        and routing metadata in `_routing` (target_index, document_id, action).
        The `_routing` key is internal — Logstash uses @metadata which never
        reaches ES.
    """
    event = dict(raw_event)  # shallow copy — we'll mutate
    cowrie_block = event.pop("cowrie", None) if isinstance(event.get("cowrie"), dict) else None

    # ---- Cowrie field renames ----
    if cowrie_block:
        # classify BEFORE renames (mirrors beats.conf ordering)
        cls = _cowrie_classify(cowrie_block.get("eventid"))
        for k, v in cls.items():
            # nested: event.type -> [event][type]
            top, sub = k.split(".", 1)
            event.setdefault(top, {})
            if isinstance(event[top], dict):
                event[top][sub] = v
            else:
                # Defensive: if event.type was already a flat string, replace it
                event[top] = {sub: v}

        # field renames
        renames = [
            (["cowrie", "eventid"],    ["event", "action"]),
            (["cowrie", "session"],    ["session_id"]),
            (["cowrie", "src_ip"],     ["source", "ip"]),
            (["cowrie", "src_port"],   ["source", "port"]),
            (["cowrie", "dst_ip"],     ["destination", "ip"]),
            (["cowrie", "dst_port"],   ["destination", "port"]),
            (["cowrie", "username"],   ["authentication", "username"]),
            (["cowrie", "message"],    ["event", "note"]),
            (["cowrie", "sensor"],     ["device", "id"]),
        ]
        for src_path, dst_path in renames:
            src_val = cowrie_block.get(src_path[-1])
            if src_val is None:
                continue
            cur = event
            for p in dst_path[:-1]:
                cur = cur.setdefault(p, {}) if not isinstance(cur, dict) or p not in cur else cur[p]
                if not isinstance(cur, dict):
                    cur = {}
                    break
            else:
                cur[dst_path[-1]] = src_val

        # explicit honeypot identity (nested)
        event.setdefault("device", {})["type"] = "ssh"
        event.setdefault("honeypot", {})["name"] = "cowrie"
        event.setdefault("honeypot", {})["container"] = "pi-cowrie"
        event["protocol"] = "ssh"

        # CRITICAL: Cowrie events don't emit event.type. Set a default so
        # the event passes required-field validation. The Cowrie eventid
        # (now [event][action]) is the action verb — event.type is a coarse
        # classification. We default to "cowrie_event" if no classify rule
        # matched; the beats.conf does NOT do this, but it should — without
        # it, EVERY cowrie event fails required-field validation and routes
        # to honeypot-errors-* instead of honeypot-events-cowrie-*.
        if not _get_nested(event, "event.type"):
            event.setdefault("event", {})["type"] = "cowrie_event"

    # ---- honeypot identity hint from Filebeat fields ----
    if honeypot_hint and not _get_nested(event, "honeypot.name"):
        event.setdefault("honeypot", {})["name"] = honeypot_hint

    # ---- ingested_at + timestamp_source ----
    event["ingested_at"] = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    if "@timestamp" in event:
        event["timestamp_source"] = "source_provided"
    else:
        event["@timestamp"] = event["ingested_at"]
        event["timestamp_source"] = "ingest_fallback"

    # ---- URI enrichment ----
    uri = _get_nested(event, "http.uri")
    uri_cls = _uri_classify(uri)
    for k, v in uri_cls.items():
        top, sub = k.split(".", 1)
        event.setdefault(top, {})
        if isinstance(event[top], dict):
            event[top][sub] = v

    # ---- auth success → default_credentials ----
    auth = event.get("authentication") or {}
    if auth.get("attempted") and auth.get("success"):
        event.setdefault("attack", {})["classification"] = "default_credentials"

    # ---- event_id fallback (Logstash fingerprint) ----
    # CRITICAL: event_id MUST be generated BEFORE required-field validation.
    # The previous Logstash ordering validated `event_id` first, then
    # generated it via fingerprint below — so a legitimately event_id-less
    # event was permanently tagged malformed before the fingerprint could
    # fill it in. A valid event (with @timestamp + session_id + event.action
    # but no event_id) MUST become a normal event after deterministic ID
    # generation.
    #
    # Deterministic inputs: @timestamp + session_id + event.action.
    # Same inputs → same event_id → ES action=create rejects duplicates.
    if "event_id" not in event:
        ts = str(event.get("@timestamp", ""))
        sid = str(event.get("session_id", ""))
        action = str(_get_nested(event, "event.action") or "")
        event["event_id"] = "evt-" + hashlib.sha1(
            f"{ts}|{sid}|{action}".encode("utf-8")
        ).hexdigest()

    # ---- Validation / malformed routing ----
    # NOTE: by this point event_id has been generated if possible.
    # If event_id is STILL missing, it's because @timestamp / session_id /
    # event.action were ALSO missing — so the event is genuinely malformed
    # for multiple reasons. The error message reflects the actual missing
    # fields, not just "event_id".
    missing = [f for f in REQUIRED_FIELDS if not _has_nested(event, f)]
    is_malformed = bool(missing)
    if is_malformed:
        tags = event.get("tags") or []
        if not isinstance(tags, list):
            tags = [tags]
        if "malformed" not in tags:
            tags.append("malformed")
        event["tags"] = tags
        event["_error"] = f"missing required field(s): {', '.join(missing)}"

    # ---- Index routing ----
    hp_name = _get_nested(event, "honeypot.name") or "unknown"
    if is_malformed:
        # errors index pattern: honeypot-errors-YYYY.MM
        ts = datetime.now(timezone.utc).strftime("%Y.%m")
        target_index = f"honeypot-errors-{ts}"
        document_id = "err-" + hashlib.sha1(
            (str(event.get("@timestamp", "")) + str(event.get("session_id", "")) + str(uuid.uuid4())).encode("utf-8")
        ).hexdigest()
        # populate errors template fields
        event.setdefault("error_id", document_id)
        event.setdefault("stage", "logstash_normalization")
        event.setdefault("reason", event.get("_error", "malformed"))
        event.setdefault("tag", "malformed")
        action = "create"
    else:
        target_index = f"honeypot-events-{hp_name}"
        # daily suffix is added by ES on write — Logstash uses %{+YYYY.MM.dd}
        # but our normalize() returns just the prefix; the caller adds the date.
        document_id = event["event_id"]
        action = "create"

    # Strip the internal _error field before output (mirrors beats.conf remove_field)
    event.pop("_error", None)
    event["_routing"] = {
        "target_index": target_index,
        "document_id": document_id,
        "action": action,
        "is_malformed": is_malformed,
    }
    return event


# --------------------------------------------------------------------
# Fixture loaders — return (raw_event, expected_normalized_fields) pairs
# so tests can assert field survival across the pipeline.
# --------------------------------------------------------------------

def camera_fixture() -> Dict[str, Any]:
    """A realistic camera honeypot event as written to camera.jsonl."""
    return {
        "@timestamp": "2025-01-01T12:00:00.000Z",
        "event_id": "evt-camera-1",
        "session_id": "sess-camera-1",
        "device": {
            "id": "camera-01",
            "type": "camera",
            "hostname": "iot-bridge-01",
            "container": "pi-camera",
        },
        "protocol": "http",
        "source": {"ip": "192.168.1.20", "port": 54321},
        "destination": {"ip": "0.0.0.0", "port": 8080},
        "http": {
            "method": "GET",
            "uri": "/admin",
            "status": 200,
            "user_agent": "curl/8.0",
            "bytes_in": 0,
            "bytes_out": 0,
        },
        "honeypot": {"name": "camera", "container": "pi-camera"},
        "event": {"type": "http_request", "category": "discovery", "action": "get_admin"},
        "attack": {"session_id": "sess-camera-1", "stage": "reconnaissance", "classification": None, "confidence": 0.0},
    }


def iot_fixture() -> Dict[str, Any]:
    """A realistic IoT-service honeypot event as written to iot.jsonl."""
    return {
        "@timestamp": "2025-01-01T12:00:01.000Z",
        "event_id": "evt-iot-1",
        "session_id": "sess-iot-1",
        "device": {
            "id": "iot-01",
            "type": "iot_service",
            "hostname": "iot-bridge-01",
            "container": "pi-iot-service",
        },
        "protocol": "tcp_iot",
        "source": {"ip": "192.168.1.20", "port": 54322},
        "destination": {"ip": "0.0.0.0", "port": 9000},
        "event": {"type": "command", "category": "network", "action": "command"},
        "honeypot": {"name": "iot-service", "container": "pi-iot-service"},
        "attack": {"session_id": "sess-iot-1", "stage": "execution", "classification": None, "confidence": 0.0},
    }


def cowrie_fixture() -> Dict[str, Any]:
    """A realistic Cowrie event as Filebeat wraps it (nested under `cowrie`)."""
    return {
        "@timestamp": "2025-01-01T12:00:02.000Z",
        "cowrie": {
            "eventid": "cowrie.login.success",
            "session": "sess-cowrie-1",
            "src_ip": "192.168.1.20",
            "src_port": 54323,
            "dst_ip": "192.168.1.50",
            "dst_port": 2222,
            "username": "admin",
            "message": "login attempt",
            "sensor": "cowrie-01",
        },
    }


def malformed_missing_session_id() -> Dict[str, Any]:
    """Camera event with session_id stripped — must route to errors index."""
    ev = camera_fixture()
    ev.pop("session_id")
    return ev


def malformed_missing_source_ip() -> Dict[str, Any]:
    """Camera event with source.ip stripped — must route to errors index."""
    ev = camera_fixture()
    ev["source"] = {"port": 54321}  # ip removed
    return ev


def missing_timestamp() -> Dict[str, Any]:
    """Camera event with @timestamp stripped — should use ingest_fallback."""
    ev = camera_fixture()
    ev.pop("@timestamp")
    return ev
