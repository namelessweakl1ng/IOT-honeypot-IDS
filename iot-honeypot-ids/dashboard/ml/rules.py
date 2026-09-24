"""
Rule engine — deterministic detection of obvious patterns.

These rules emit detections that the ML engine can use as ground-truth labels
during training (semi-supervised bootstrap), and as a fast first-line
detection at runtime.

Rules are intentionally conservative: if a rule fires, we are confident.
If no rule fires, the ML engine takes over.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional


def classify_session(events: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Return a detection dict if any rule fires on this session."""
    if not events:
        return None

    classifications = {(e.get("attack") or {}).get("classification") for e in events}
    classifications.discard(None)
    classifications.discard("")

    auth_attempts = sum(
        1 for e in events
        if (e.get("authentication") or {}).get("attempted")
    )
    auth_failures = sum(
        1 for e in events
        if (e.get("authentication") or {}).get("attempted")
        and not (e.get("authentication") or {}).get("success")
    )
    unique_users = {
        (e.get("authentication") or {}).get("username")
        for e in events
        if (e.get("authentication") or {}).get("attempted")
    }
    unique_users.discard(None)

    # Rule: many failed auths across many usernames -> brute_force
    if auth_attempts >= 5 and auth_failures >= 4 and len(unique_users) >= 3:
        return {
            "rule_id": "rule_brute_force_v1",
            "label": "brute_force",
            "confidence": 0.9,
            "explanation": (
                f"{auth_attempts} auth attempts, {auth_failures} failures, "
                f"{len(unique_users)} unique usernames"
            ),
        }

    # Rule: default_credentials used
    if "default_credentials" in classifications:
        return {
            "rule_id": "rule_default_credentials_v1",
            "label": "default_credentials",
            "confidence": 0.95,
            "explanation": "successful authentication with default credentials",
        }

    # Rule: command_injection signature in URIs
    if "command_injection" in classifications:
        return {
            "rule_id": "rule_command_injection_v1",
            "label": "command_injection",
            "confidence": 0.85,
            "explanation": "URI contains command-execution signature",
        }

    # Rule: path_traversal
    if "path_traversal" in classifications:
        return {
            "rule_id": "rule_path_traversal_v1",
            "label": "path_traversal",
            "confidence": 0.85,
            "explanation": "URI contains path-traversal signature",
        }

    # Rule: recon-only session (GET-only across many endpoints, no auth)
    http_methods = [
        (e.get("http") or {}).get("method") for e in events
        if e.get("http")
    ]
    unique_uris = {
        (e.get("http") or {}).get("uri") for e in events
        if (e.get("http") or {}).get("uri")
    }
    if (
        http_methods
        and all(m == "GET" for m in http_methods)
        and len(unique_uris) >= 4
        and auth_attempts == 0
    ):
        return {
            "rule_id": "rule_recon_v1",
            "label": "reconnaissance",
            "confidence": 0.7,
            "explanation": f"{len(unique_uris)} unique GET URIs, no auth",
        }

    return None
