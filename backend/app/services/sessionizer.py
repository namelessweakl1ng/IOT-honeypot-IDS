from datetime import datetime
from hashlib import sha256
from typing import Any

def _dt(value: str) -> datetime: return datetime.fromisoformat(value.replace("Z", "+00:00"))

def reconstruct_sessions(events: list[dict[str, Any]], timeout_seconds: int = 300) -> list[dict[str, Any]]:
    ordered = sorted(events, key=lambda e: (_dt(e["@timestamp"]), e["event"]["id"]))
    groups: list[list[dict[str, Any]]] = []
    active: dict[str, list[dict[str, Any]]] = {}
    for event in ordered:
        source = event["source"]["ip"]
        group = active.get(source)
        if group and (_dt(event["@timestamp"]) - _dt(group[-1]["@timestamp"])).total_seconds() > timeout_seconds:
            groups.append(group); group = None
        if group is None: group = []; active[source] = group
        group.append(event)
    groups.extend(active.values())
    return [_materialize(group) for group in sorted(groups, key=lambda g: (_dt(g[0]["@timestamp"]), g[0]["source"]["ip"]))]

def _materialize(events: list[dict[str, Any]]) -> dict[str, Any]:
    first, last = events[0], events[-1]
    ids = [e["event"]["id"] for e in events]
    auth = [e for e in events if e["event"].get("category") == "authentication"]
    # Source and window start stay stable as later events extend an active session,
    # allowing the processor to upsert rather than duplicate derived documents.
    sid = "SES-" + sha256(f'{first["source"]["ip"]}|{first["@timestamp"]}'.encode()).hexdigest()[:16]
    return {"session_id": sid, "source_ip": first["source"]["ip"], "start_time": first["@timestamp"], "end_time": last["@timestamp"],
      "duration": (_dt(last["@timestamp"])-_dt(first["@timestamp"])).total_seconds(),
      "honeypots_touched": sorted({e["honeypot"]["id"] for e in events}), "services_touched": sorted({e["service"]["name"] for e in events}),
      "protocols": sorted({e["network"]["protocol"] for e in events}), "event_count": len(events), "event_ids": ids,
      "authentication_attempts": len(auth), "failed_authentication_attempts": sum(e["event"].get("outcome")=="failure" for e in auth),
      "credentials": [e.get("authentication", {}) for e in auth if e.get("authentication")],
      "commands": [e["process"]["command_line"] for e in events if e.get("process", {}).get("command_line")],
      "urls": [e["url"]["path"] for e in events if e.get("url", {}).get("path")], "events": events}
