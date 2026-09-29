from datetime import datetime, timezone
from hashlib import sha256
from typing import Any

from ..config import get_settings

WEAK = {("admin", "admin"), ("admin", "password"), ("root", "root"), ("admin", "1234")}
DETECTOR_RULESET_VERSION = "2"
SUPPORTED_DETECTION_TYPES = frozenset(
    {
        "RECONNAISSANCE",
        "BRUTE_FORCE",
        "DEFAULT_CREDENTIALS",
        "WEB_ENUMERATION",
        "COMMAND_INTERACTION",
        "MQTT_PROBING",
        "MULTI_SERVICE_ACTIVITY",
        "MULTI_STAGE_ATTACK",
    }
)


def detect(session: dict[str, Any]) -> list[dict[str, Any]]:
    cfg = get_settings()
    found = []
    events = session.get("events", [])
    ids = session["event_ids"]

    def add(kind: str, severity: str, reason: str, evidence: list[str], rule: str):
        key = f"{session['session_id']}:{rule}"
        found.append(
            {
                "detection_id": "DET-" + sha256(key.encode()).hexdigest()[:16],
                "session_id": session["session_id"],
                "source_ip": session.get("source_ip"),
                "type": kind,
                "severity": severity,
                "timestamp": session["end_time"],
                "evidence_end_time": session["end_time"],
                "detected_at": datetime.now(timezone.utc).isoformat(),
                "reason": reason,
                "evidence_event_ids": evidence,
                "rule_id": rule,
            }
        )

    failed = [e for e in events if e["event"].get("category") == "authentication" and e["event"].get("outcome") == "failure"]
    if len(failed) >= cfg.brute_force_threshold:
        add(
            "BRUTE_FORCE",
            "high",
            f"{len(failed)} authentication failures occurred in one session (threshold {cfg.brute_force_threshold}).",
            [e["event"]["id"] for e in failed],
            "auth-failures-v1",
        )
    weak = [e for e in events if (e.get("authentication", {}).get("username"), e.get("authentication", {}).get("password")) in WEAK]
    if weak:
        add(
            "DEFAULT_CREDENTIALS",
            "high",
            f"{len(weak)} known default credential pair(s) attempted.",
            [e["event"]["id"] for e in weak],
            "default-credentials-v1",
        )
    urls = list(dict.fromkeys(session.get("urls", [])))
    if len(urls) >= cfg.web_enumeration_threshold:
        add("WEB_ENUMERATION", "medium", f"{len(urls)} distinct web paths requested (threshold {cfg.web_enumeration_threshold}).", ids, "web-paths-v1")
    if session.get("commands"):
        add("COMMAND_INTERACTION", "high", f"{len(session['commands'])} command interaction(s) recorded.", ids, "command-v1")
    mqtt = [e for e in events if e.get("network", {}).get("protocol") == "mqtt"]
    mqtt_operations = {e.get("mqtt", {}).get("operation") for e in mqtt}
    if len(mqtt) >= 2 or mqtt_operations.intersection({"subscribe", "publish", "unsubscribe", "ping"}):
        add("MQTT_PROBING", "medium", f"{len(mqtt)} MQTT operation(s) observed.", [e["event"]["id"] for e in mqtt], "mqtt-v2")
    services = session.get("services_touched", [])
    if len(services) >= cfg.multi_service_threshold:
        add("MULTI_SERVICE_ACTIVITY", "high", f"Source touched {len(services)} services: {', '.join(services)}.", ids, "multi-service-v1")
    if failed and (urls or session.get("commands")) and len(services) >= 2:
        add("MULTI_STAGE_ATTACK", "critical", "Authentication activity was followed by interaction across multiple services.", ids, "multi-stage-v1")
    iot_probes = [e for e in events if e.get("service", {}).get("name") == "iot-service" and e.get("network", {}).get("protocol") == "tcp"]
    if len(iot_probes) >= 3:
        add("RECONNAISSANCE", "low", f"{len(iot_probes)} IoT probe interactions occurred.", [e["event"]["id"] for e in iot_probes], "recon-v2")
    return found
