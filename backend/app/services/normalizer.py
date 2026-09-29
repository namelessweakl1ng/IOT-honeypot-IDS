from hashlib import sha256
from datetime import datetime, timezone
from typing import Any, Callable
from .telemetry import SCHEMA_VERSION, is_loopback


def normalize(raw: dict[str, Any], honeypot_type: str, honeypot_id: str, sensor_id: str, now: Callable[[], datetime] | None = None) -> dict[str, Any]:
    """Reference equivalent of Logstash mappings for contract and smoke tests."""
    cowrie = honeypot_type == "ssh_telnet"
    timestamp = raw.get("timestamp") or raw.get("@timestamp")
    source_ip = raw.get("src_ip") if cowrie else raw.get("source_ip")
    if not timestamp or not source_ip:
        raise ValueError("timestamp and source IP are required")
    identifier = f'{raw.get("eventid")}-{raw.get("session", "")}-{timestamp}' if cowrie and raw.get("eventid") else raw.get("event_id")
    identifier = identifier or sha256(f"{timestamp}|{source_ip}|{raw}".encode()).hexdigest()
    cowrie_id = raw.get("eventid", "")
    login = cowrie_id in {"cowrie.login.failed", "cowrie.login.success"}
    category = "authentication" if login else "process" if cowrie_id == "cowrie.command.input" else raw.get("category", "session" if cowrie else "network")
    outcome = "failure" if cowrie_id == "cowrie.login.failed" else "success" if cowrie_id == "cowrie.login.success" else raw.get("outcome", "unknown")
    event: dict[str, Any] = {
        "@timestamp": timestamp,
        "event": {"id": identifier, "ingested": (now or (lambda: datetime.now(timezone.utc)))().astimezone(timezone.utc).isoformat().replace("+00:00", "Z"), "category": category, "type": raw.get("type", "info"), "action": "login_attempt" if login else "command" if cowrie_id == "cowrie.command.input" else raw.get("action", "observe"), "outcome": outcome},
        "source": {"ip": source_ip, "port": raw.get("src_port") or raw.get("source_port")},
        "destination": {"ip": raw.get("destination_ip", "sensor"), "port": raw.get("dst_port") or raw.get("destination_port")},
        "network": {"transport": "tcp", "protocol": (raw.get("protocol") or ("telnet" if raw.get("dst_port") == 2223 else "ssh")) if cowrie else raw.get("protocol")},
        "service": {"name": "cowrie" if cowrie else raw.get("service")},
        "honeypot": {"id": honeypot_id, "type": honeypot_type},
        "observer": {"name": "trapsig-pi", "type": "honeypot_sensor"},
        "trapsig": {"sensor_id": sensor_id, "schema_version": SCHEMA_VERSION, "internal": is_loopback(source_ip)},
        "message": raw.get("summary") or raw.get("message", identifier),
    }
    if event["trapsig"]["internal"]:
        event["trapsig"]["internal_reason"] = "loopback_source"
    for container in ("source", "destination"):
        if event[container]["port"] is not None:
            event[container]["port"] = int(event[container]["port"])
    authentication = raw.get("authentication") or ({"username": raw.get("username"), "password": raw.get("password")} if login else None)
    if authentication:
        event["authentication"] = authentication
    if raw.get("url"):
        event["url"] = {"path": raw["url"].get("path")}
    if raw.get("http"):
        event["http"] = raw["http"]
    if raw.get("mqtt"):
        event["mqtt"] = dict(raw["mqtt"])
        if event["mqtt"].get("packet_type") is not None:
            event["mqtt"]["packet_type"] = int(event["mqtt"]["packet_type"])
    if cowrie_id == "cowrie.command.input":
        event["process"] = {"command_line": raw.get("input", "")}
    return event
