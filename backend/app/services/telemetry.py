"""Shared telemetry-integrity rules."""

from ipaddress import ip_address
from typing import Any

SCHEMA_VERSION = "1"


def is_loopback(value: object) -> bool:
    """Recognize loopback only; private laboratory attackers remain analyzable."""
    try:
        return ip_address(str(value)).is_loopback
    except ValueError:
        return False


def is_internal_event(event: dict[str, Any]) -> bool:
    return event.get("trapsig", {}).get("internal") is True or is_loopback(event.get("source", {}).get("ip"))
