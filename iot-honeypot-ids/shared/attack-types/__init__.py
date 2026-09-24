"""Taxonomy constants — re-exported by shared.schemas."""
from __future__ import annotations

# Re-export the canonical list from schemas/event_schema.py
from schemas.event_schema import (
    KNOWN_CLASSIFICATIONS,
    KNOWN_EVENT_TYPES,
    MITRE_MAPPING,
    mitre_for,
)

__all__ = [
    "KNOWN_CLASSIFICATIONS",
    "KNOWN_EVENT_TYPES",
    "MITRE_MAPPING",
    "mitre_for",
]
