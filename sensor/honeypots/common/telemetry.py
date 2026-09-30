"""Creation and JSONL persistence of normalized honeypot events."""

import json
import os
import uuid
from datetime import datetime, timezone


def base_event(service: str, protocol: str, port: int, client: tuple[str, int], details: dict, data_received: bool = True) -> dict:
    auth = bool(details.get("username"))
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_id": str(uuid.uuid4()),
        "category": "authentication" if auth else "web" if protocol == "http" else "network",
        "type": "info",
        "action": "login_attempt" if auth else details.get("operation", "request" if data_received else "connect"),
        "outcome": "failure" if auth else "unknown",
        "source_ip": client[0],
        "source_port": client[1],
        "destination_port": port,
        "protocol": protocol,
        "service": service,
        "honeypot_id": service + "-01",
        "honeypot_type": service.replace("-", "_"),
        "summary": f"{service} {details.get('operation') or details.get('method') or 'interaction'}",
    }


def write_jsonl(path: str, event: dict) -> None:
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(event, separators=(",", ":")) + "\n")
