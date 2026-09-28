from datetime import datetime, timezone
from typing import Any

def correlate(experiment: dict[str, Any], events: list[dict[str, Any]], sessions: list[dict[str, Any]], detections: list[dict[str, Any]]) -> dict[str, Any]:
    start=datetime.fromisoformat(experiment["start_time"].replace("Z","+00:00")); end=datetime.fromisoformat(experiment["end_time"].replace("Z","+00:00"))
    matched=[e for e in events if start <= datetime.fromisoformat(e["@timestamp"].replace("Z","+00:00")) <= end and e["source"]["ip"]==experiment["attacker_ip"] and e["destination"]["ip"]==experiment["target_ip"]]
    event_ids={e["event"]["id"] for e in matched}; linked=[s for s in sessions if event_ids.intersection(s["event_ids"])]
    session_ids={s["session_id"] for s in linked}; detected=[d for d in detections if d["session_id"] in session_ids]
    expected=experiment["expected_detection"].upper(); observed=any(d["type"]==expected for d in detected)
    latency=None
    matching=[d for d in detected if d["type"]==expected and d.get("timestamp")]
    if matching:
        first=min(datetime.fromisoformat(d["timestamp"].replace("Z","+00:00")) for d in matching)
        latency=max(0.0,(first-start).total_seconds())
    return {**experiment,"event_ids":sorted(event_ids),"session_ids":sorted(session_ids),"detection_ids":sorted(d["detection_id"] for d in detected),"observed_detection":observed,"detection_latency_seconds":latency,"result":"TP" if observed else "FN"}
