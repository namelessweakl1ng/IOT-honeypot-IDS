"""Non-secret execution-success rules shared by catalog and controlled runner."""

from typing import Any


def allowed_step_statuses(step: dict[str, Any]) -> frozenset[str]:
    """Return statuses proving the intended action for one manifest step."""
    service = step.get("service")
    if service == "ssh":
        return frozenset({"completed"}) if step.get("command") else frozenset({"completed", "rejected"})
    if service in {"camera", "http", "router"}:
        return frozenset({"completed", "rejected"})
    if service in {"telnet", "iot", "mqtt"}:
        return frozenset({"completed"})
    raise ValueError(f"unknown scenario service: {service!r}")
