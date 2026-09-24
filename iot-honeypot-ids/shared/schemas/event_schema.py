"""
Common event schema definition.

Mirrors the field set enforced by the Elasticsearch index templates
(see dashboard/elasticsearch/index-templates/honeypot-events.json) and the
fields produced by the Pi-side honeypots.

The schema is intentionally ECS-shaped (Elastic Common Schema) so events
flow naturally into Kibana without renaming.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

# Required top-level fields. Missing any of these marks the event as malformed
# and the Logstash pipeline routes it to the honeypot-errors-* dead-letter index.
REQUIRED_FIELDS: List[str] = [
    "@timestamp",
    "event_id",
    "session_id",
    "source.ip",
    "device.id",
    "event.type",
    "honeypot.name",
]


def validate(event: Dict[str, Any]) -> List[str]:
    """Return a list of missing-required-field errors. Empty list = valid."""
    errs: List[str] = []
    for f in REQUIRED_FIELDS:
        # Field paths use dot notation for nested fields.
        cur: Any = event
        ok = True
        for part in f.split("."):
            if not isinstance(cur, dict) or part not in cur:
                ok = False
                break
            cur = cur[part]
        if not ok:
            errs.append(f"missing required field: {f}")
    return errs


# Canonical list of event types the platform knows how to ingest.
KNOWN_EVENT_TYPES: List[str] = [
    "http_request",
    "authentication_attempt",
    "authentication_success",
    "authentication_failure",
    "command_execution",
    "session_start",
    "session_end",
    "connect",
    "disconnect",
    "stat_query",
    "list_query",
    "ping",
    "unknown_input",
]

# Canonical attack classifications used by the rule engine + ML labels.
KNOWN_CLASSIFICATIONS: List[str] = [
    "brute_force",
    "default_credentials",
    "reconnaissance",
    "credential_attack",
    "command_abuse",
    "command_injection",
    "path_traversal",
    "web_enumeration",
    "file_retrieval",
    "anomaly",
    "benign",
    "unknown",
]

# MITRE ATT&CK mapping — used by the rule engine.
# Only well-justified mappings are listed here.
MITRE_MAPPING: Dict[str, Dict[str, str]] = {
    "brute_force":         {"tactic": "Credential Access", "technique": "T1110 Brute Force"},
    "default_credentials": {"tactic": "Credential Access", "technique": "T1078 Valid Accounts"},
    "reconnaissance":      {"tactic": "Discovery",         "technique": "T1046 Network Service Scanning"},
    "command_abuse":       {"tactic": "Execution",         "technique": "T1059 Command and Scripting Interpreter"},
    "command_injection":   {"tactic": "Execution",         "technique": "T1059 Command and Scripting Interpreter"},
    "path_traversal":      {"tactic": "Collection",         "technique": "T1005 Data from Local System"},
    "web_enumeration":     {"tactic": "Discovery",         "technique": "T1046 Network Service Scanning"},
    "file_retrieval":      {"tactic": "Collection",         "technique": "T1005 Data from Local System"},
}


def mitre_for(classification: str) -> Optional[Dict[str, str]]:
    """Return MITRE tactic/technique for a classification, or None if not mapped."""
    return MITRE_MAPPING.get(classification)
