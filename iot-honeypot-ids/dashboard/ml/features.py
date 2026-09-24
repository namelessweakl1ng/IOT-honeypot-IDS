"""
Session reconstruction + behavioral feature extraction.

Input  : a list of raw honeypot events (as produced by the Pi).
Output : a single feature dict per session, suitable for ML pipelines.

Feature engineering decisions are documented inline so the platform never
becomes a black box. See docs/ml/features.md for the rationale.
"""
from __future__ import annotations

import math
import statistics
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _to_epoch(ts: Any) -> Optional[float]:
    """Robust ISO-8601 -> epoch seconds."""
    if not ts:
        return None
    if isinstance(ts, (int, float)):
        return float(ts)
    s = str(ts)
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s).timestamp()
    except Exception:
        return None


def _mean(values: Iterable[float]) -> float:
    vals = list(values)
    return statistics.fmean(vals) if vals else 0.0


def _stdev(values: Iterable[float]) -> float:
    vals = list(values)
    return statistics.pstdev(vals) if len(vals) > 1 else 0.0


# --------------------------------------------------------------------------- #
# Session reconstruction
# --------------------------------------------------------------------------- #


def reconstruct_sessions(events: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Group events by session_id. Returns {session_id: [events]}.

    Events missing a session_id are dropped and logged via a side-channel
    field `_dropped`. The caller can choose how to surface that.
    """
    sessions: Dict[str, List[Dict[str, Any]]] = {}
    dropped = 0
    for e in events:
        sid = e.get("session_id") or (e.get("attack") or {}).get("session_id")
        if not sid:
            dropped += 1
            continue
        sessions.setdefault(sid, []).append(e)
    if dropped:
        # Tag the result so the caller can warn — never silently lose data.
        sessions["_dropped_count"] = dropped  # type: ignore[assignment]
    return sessions


# --------------------------------------------------------------------------- #
# Feature extraction
# --------------------------------------------------------------------------- #


# Order matters — this list is the canonical feature vector for v1.
#
# ⚠ LEAKAGE AUDIT (Phase 63 of the architectural review):
# Three features in v1 (`contains_path_traversal`, `contains_command_injection`,
# `contains_default_credentials`) are derived from the `attack.classification`
# field of events — which is the SAME field used as the ML training label.
# This creates label leakage: the model can learn a near-direct shortcut
# (e.g. `if contains_path_traversal == 1: predict path_traversal`) which
# explains the suspiciously perfect in-sample metrics.
#
# These features are kept in v1 for backwards compatibility and because they
# are useful for the RULE ENGINE (which runs deterministically and does not
# "learn" from them). But for classifier training, prefer FEATURE_NAMES_V2
# below which excludes the leaky features.
FEATURE_NAMES: List[str] = [
    "event_count",
    "duration_s",
    "bytes_in_total",
    "bytes_out_total",
    "auth_attempts",
    "auth_successes",
    "auth_failure_ratio",
    "unique_usernames",
    "command_count",
    "command_diversity",
    "http_request_count",
    "http_uri_diversity",
    "http_status_4xx_ratio",
    "http_status_5xx_ratio",
    "unique_protocols",
    "devices_touched",
    "ports_touched",
    "time_between_events_mean_s",
    "time_between_events_stdev_s",
    "request_rate_per_min",
    "auth_failure_rate_per_min",
    "contains_path_traversal",        # ⚠ LEAKY — derived from classification label
    "contains_command_injection",     # ⚠ LEAKY — derived from classification label
    "contains_default_credentials",   # ⚠ LEAKY — derived from classification label
    "is_recon_only",
]

# Features flagged as label-leaky. Used by the training pipeline to exclude
# them from the classifier input (while keeping them in the dataset for the
# rule engine and for explainability).
LEAKY_FEATURES: List[str] = [
    "contains_path_traversal",
    "contains_command_injection",
    "contains_default_credentials",
]

# v2 feature vector — same behavioral observables as v1 but with leaky
# features removed. Use this for honest classifier training/evaluation.
FEATURE_NAMES_V2: List[str] = [f for f in FEATURE_NAMES if f not in LEAKY_FEATURES]


def features_to_vector_v2(features: Dict[str, float]) -> List[float]:
    """Project the feature dict onto the v2 (leak-free) vector ordering."""
    return [float(features.get(n, 0.0)) for n in FEATURE_NAMES_V2]


def extract_features(session_events: List[Dict[str, Any]]) -> Dict[str, float]:
    """Extract the v1 feature vector from one session's events."""
    if not session_events:
        return {n: 0.0 for n in FEATURE_NAMES}

    # Sort by timestamp for stable derivations
    events_with_ts = [(e, _to_epoch(e.get("@timestamp"))) for e in session_events]
    events_with_ts = [(e, t) for e, t in events_with_ts if t is not None]
    events_with_ts.sort(key=lambda x: x[1])
    if not events_with_ts:
        return {n: 0.0 for n in FEATURE_NAMES}

    times = [t for _, t in events_with_ts]
    duration = max(times[-1] - times[0], 0.0)
    duration_min = max(duration / 60.0, 1e-6)

    # Authentication
    auth_attempts = 0
    auth_successes = 0
    usernames: set[str] = set()
    for e, _ in events_with_ts:
        a = e.get("authentication") or {}
        if a.get("attempted"):
            auth_attempts += 1
            if a.get("success"):
                auth_successes += 1
            u = a.get("username")
            if u:
                usernames.add(u)
    auth_failures = max(auth_attempts - auth_successes, 0)
    auth_failure_ratio = (auth_failures / auth_attempts) if auth_attempts else 0.0

    # Commands / IoT-protocol commands
    commands: List[str] = []
    for e, _ in events_with_ts:
        ev = e.get("event") or {}
        if ev.get("type") in {"command_execution", "command_abuse"}:
            # use http.uri or iot.raw as the command identifier
            cmd = (e.get("http") or {}).get("uri") or (e.get("iot") or {}).get("raw") or ""
            commands.append(cmd)
    unique_commands = len(set(commands))

    # HTTP features
    http_methods: List[str] = []
    http_uris: set[str] = set()
    http_status_4xx = 0
    http_status_5xx = 0
    http_count = 0
    for e, _ in events_with_ts:
        h = e.get("http") or {}
        if not h:
            continue
        http_count += 1
        if h.get("method"):
            http_methods.append(h["method"])
        if h.get("uri"):
            http_uris.add(h["uri"])
        st = h.get("status") or 0
        if 400 <= st < 500:
            http_status_4xx += 1
        elif 500 <= st < 600:
            http_status_5xx += 1

    # Network bytes
    bytes_in = sum((e.get("http") or {}).get("bytes_in", 0) or 0 for e, _ in events_with_ts)
    bytes_out = sum((e.get("http") or {}).get("bytes_out", 0) or 0 for e, _ in events_with_ts)
    bytes_in += sum((e.get("network") or {}).get("bytes_in", 0) or 0 for e, _ in events_with_ts)
    bytes_out += sum((e.get("network") or {}).get("bytes_out", 0) or 0 for e, _ in events_with_ts)

    # Protocols / devices / ports
    protocols: set[str] = set()
    devices: set[str] = set()
    ports: set[int] = set()
    for e, _ in events_with_ts:
        if e.get("protocol"):
            protocols.add(e["protocol"])
        d = e.get("device") or {}
        if d.get("id"):
            devices.add(d["id"])
        src = e.get("source") or {}
        if src.get("port"):
            ports.add(int(src["port"]))

    # Time between events
    deltas = [times[i + 1] - times[i] for i in range(len(times) - 1)]
    tbe_mean = _mean(deltas)
    tbe_stdev = _stdev(deltas)

    # Classification signals — derived from the rule engine tags
    classifications = {(e.get("attack") or {}).get("classification") for e, _ in events_with_ts}
    classifications.discard(None)
    classifications.discard("")
    contains_path_traversal = "path_traversal" in classifications
    contains_command_injection = "command_injection" in classifications
    contains_default_credentials = "default_credentials" in classifications

    # is_recon_only: session with no auth attempts, no command exec, no HTTP body
    has_exec = any((e.get("event") or {}).get("type") in {"command_execution"} for e, _ in events_with_ts)
    has_auth = auth_attempts > 0
    is_recon_only = (not has_exec) and (not has_auth)

    return {
        "event_count": float(len(events_with_ts)),
        "duration_s": float(duration),
        "bytes_in_total": float(bytes_in),
        "bytes_out_total": float(bytes_out),
        "auth_attempts": float(auth_attempts),
        "auth_successes": float(auth_successes),
        "auth_failure_ratio": float(auth_failure_ratio),
        "unique_usernames": float(len(usernames)),
        "command_count": float(len(commands)),
        "command_diversity": float(unique_commands),
        "http_request_count": float(http_count),
        "http_uri_diversity": float(len(http_uris)),
        "http_status_4xx_ratio": float(http_status_4xx / http_count if http_count else 0.0),
        "http_status_5xx_ratio": float(http_status_5xx / http_count if http_count else 0.0),
        "unique_protocols": float(len(protocols)),
        "devices_touched": float(len(devices)),
        "ports_touched": float(len(ports)),
        "time_between_events_mean_s": float(tbe_mean),
        "time_between_events_stdev_s": float(tbe_stdev),
        "request_rate_per_min": float(http_count / duration_min),
        "auth_failure_rate_per_min": float(auth_failures / duration_min),
        "contains_path_traversal": 1.0 if contains_path_traversal else 0.0,
        "contains_command_injection": 1.0 if contains_command_injection else 0.0,
        "contains_default_credentials": 1.0 if contains_default_credentials else 0.0,
        "is_recon_only": 1.0 if is_recon_only else 0.0,
    }


def features_to_vector(features: Dict[str, float]) -> List[float]:
    """Project the feature dict onto the canonical v1 vector ordering."""
    return [float(features.get(n, 0.0)) for n in FEATURE_NAMES]
