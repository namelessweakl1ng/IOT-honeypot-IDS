"""Backend-owned runtime mode — EMPTY / DEMO / LIVE.

The backend owns the authoritative application mode. The frontend may
REQUEST a transition, but the backend validates and owns the resulting
state. This prevents a browser from bypassing mode semantics.

Mode transitions:
    EMPTY → DEMO   (explicit loadDemoData)
    DEMO → EMPTY   (explicit clearDemoData)
    EMPTY → LIVE   (explicit enterLiveMode, requires API key on backend)
    LIVE → EMPTY   (explicit resetMode, requires API key on backend)
    DEMO → LIVE    (FORBIDDEN — must clear to EMPTY first)
    LIVE → DEMO    (FORBIDDEN — must reset to EMPTY first)

The scheduler checks:
    1. mode == LIVE (mode is the GATE)
    2. es_client.ping() (ES is a DEPENDENCY, not a mode indicator)

Both are required. ES reachable does NOT mean LIVE.
Pi connected does NOT mean LIVE.
"""
from __future__ import annotations

import logging
from enum import Enum
from typing import Optional

log = logging.getLogger("runtime_mode")


class RuntimeMode(str, Enum):
    EMPTY = "EMPTY"
    DEMO = "DEMO"
    LIVE = "LIVE"


# ---- Backend-owned state (module-level singleton) ----
_current_mode: RuntimeMode = RuntimeMode.EMPTY


def get_mode() -> RuntimeMode:
    """Return the current backend-owned runtime mode."""
    return _current_mode


def set_mode(mode: RuntimeMode) -> tuple[bool, str]:
    """Transition to a new mode.

    Returns (success, message).

    Transition rules:
        EMPTY → DEMO:  allowed
        DEMO → EMPTY:  allowed
        EMPTY → LIVE:  allowed
        LIVE → EMPTY:  allowed
        DEMO → LIVE:   FORBIDDEN (must clear to EMPTY first)
        LIVE → DEMO:   FORBIDDEN (must reset to EMPTY first)
        same → same:   no-op success
    """
    global _current_mode
    old = _current_mode

    if old == mode:
        return True, f"Already in {mode.value} mode"

    # Forbidden transitions
    if old == RuntimeMode.DEMO and mode == RuntimeMode.LIVE:
        return False, "Cannot enter LIVE while DEMO is active — clear demo data first"
    if old == RuntimeMode.LIVE and mode == RuntimeMode.DEMO:
        return False, "Cannot enter DEMO while LIVE — reset to EMPTY first"

    # Allowed transitions
    _current_mode = mode
    log.info("mode transition: %s → %s", old.value, mode.value)
    return True, f"Mode transitioned: {old.value} → {mode.value}"


def enter_live() -> tuple[bool, str]:
    """Transition to LIVE mode. Only valid from EMPTY."""
    return set_mode(RuntimeMode.LIVE)


def enter_demo() -> tuple[bool, str]:
    """Transition to DEMO mode. Only valid from EMPTY."""
    return set_mode(RuntimeMode.DEMO)


def reset_to_empty() -> tuple[bool, str]:
    """Reset to EMPTY mode. Valid from DEMO or LIVE."""
    return set_mode(RuntimeMode.EMPTY)


def is_live() -> bool:
    """Check if the backend is in LIVE mode."""
    return _current_mode == RuntimeMode.LIVE


def is_demo() -> bool:
    """Check if the backend is in DEMO mode."""
    return _current_mode == RuntimeMode.DEMO


def is_empty() -> bool:
    """Check if the backend is in EMPTY mode."""
    return _current_mode == RuntimeMode.EMPTY
