"""IoT-23 network-flow feature compatibility contract.

Only Zeek flow measurements are accepted as model inputs. Identifiers, paths,
labels, scenario names, endpoints, and timestamps are provenance, not features.
"""
from __future__ import annotations

import math
from typing import Any, Mapping

FEATURE_VERSION = "iot23-flow-v1"

# The manifest documents why honeypot/session features do not map to a flow.
FEATURE_MAP = {
    "duration_s": {"source": "duration", "transform": "numeric seconds", "status": "COMPATIBLE_PROXY", "note": "Flow duration is not reconstructed session duration."},
    "bytes_in": {"source": "bytes_in", "transform": "numeric; Zeek orig_bytes", "status": "COMPATIBLE_PROXY", "note": "Originator direction, not honeypot ingress semantics."},
    "bytes_out": {"source": "bytes_out", "transform": "numeric; Zeek resp_bytes", "status": "COMPATIBLE_PROXY", "note": "Responder direction, not honeypot egress semantics."},
    "packets_in": {"source": "packets_in", "transform": "numeric; Zeek orig_pkts", "status": "COMPATIBLE_PROXY", "note": "Flow packet count."},
    "packets_out": {"source": "packets_out", "transform": "numeric; Zeek resp_pkts", "status": "COMPATIBLE_PROXY", "note": "Flow packet count."},
    "source_port": {"source": "source_port", "transform": "integer", "status": "NETWORK_ONLY", "note": "May encode scenario/capture artifacts; exclude from default cross-scenario feature set."},
    "destination_port": {"source": "destination_port", "transform": "integer", "status": "NETWORK_ONLY", "note": "May encode scenario/capture artifacts; exclude from default cross-scenario feature set."},
    "protocol": {"source": "protocol", "transform": "categorical", "status": "NETWORK_ONLY", "note": "One-hot encoding must be fit on training scenarios only."},
    "event_count": {"source": None, "transform": None, "status": "UNAVAILABLE", "note": "IoT-23 rows are flows, not honeypot events."},
    "auth_attempts": {"source": None, "transform": None, "status": "UNAVAILABLE", "note": "Authentication event/session detail is not present in conn.log.labeled."},
    "command_count": {"source": None, "transform": None, "status": "UNAVAILABLE", "note": "Command telemetry is not present in conn.log.labeled."},
    "http_uri_diversity": {"source": None, "transform": None, "status": "UNAVAILABLE", "note": "No HTTP URI feature is guaranteed in the labeled connection log."},
    "contains_path_traversal": {"source": None, "transform": None, "status": "PROHIBITED", "note": "Label-derived and unavailable; leakage-safe mode forbids it."},
    "contains_command_injection": {"source": None, "transform": None, "status": "PROHIBITED", "note": "Label-derived and unavailable; leakage-safe mode forbids it."},
    "contains_default_credentials": {"source": None, "transform": None, "status": "PROHIBITED", "note": "Label-derived and unavailable; leakage-safe mode forbids it."},
}

# Deliberately conservative common subset: count/volume/time behavior only.
NUMERIC_FEATURES = ("duration", "bytes_in", "bytes_out", "packets_in", "packets_out")
FORBIDDEN_FEATURES = frozenset({
    "record_id", "dataset_id", "dataset_version", "source_file", "source_row_id",
    "source_scenario", "zeek_uid", "timestamp", "source_ip", "destination_ip",
    "source_port", "destination_port", "protocol", "native_label", "native_label_detail",
    "original_label", "original_detailed_label", "project_label", "canonical_label",
    "canonical_attack_family", "binary_label", "label_source", "label_mapping_reason",
    "label_mapping_confidence", "label_mapping_version", "feature_version",
    "contains_path_traversal", "contains_command_injection", "contains_default_credentials",
})


def feature_vector(flow: Mapping[str, Any]) -> dict[str, float | None]:
    """Return measured numeric values; preserve absent measurements as null."""
    result: dict[str, float | None] = {}
    for name in NUMERIC_FEATURES:
        value = flow.get(name)
        if value is None or value == "-":
            result[name] = None
            continue
        try:
            number = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"IoT-23 flow has invalid {name}: {value!r}") from exc
        if not math.isfinite(number) or number < 0:
            raise ValueError(f"IoT-23 flow has negative {name}: {number}")
        result[name] = number
    return result


def audit_feature_names(names: list[str] | tuple[str, ...]) -> None:
    """Fail closed if provenance, labels, or unsupported session fields are features."""
    illegal = sorted(set(names) & FORBIDDEN_FEATURES)
    if illegal:
        raise ValueError("IoT-23 leakage audit rejected feature(s): " + ", ".join(illegal))
    allowed = set(NUMERIC_FEATURES)
    unsupported = sorted(set(names) - allowed)
    if unsupported:
        raise ValueError("IoT-23 feature(s) have no approved mapping: " + ", ".join(unsupported))


def scenario_split(scenarios: list[str], seed: int = 42,
                   train_ratio: float = 0.6, validation_ratio: float = 0.2) -> dict[str, list[str]]:
    """Deterministically hold out whole scenarios; validation/test remain distinct."""
    import random
    unique = sorted(set(scenarios))
    if len(unique) < 3:
        raise ValueError("scenario-level train/validation/test split requires at least 3 scenarios")
    if not (0 < train_ratio < 1 and 0 < validation_ratio < 1 and train_ratio + validation_ratio < 1):
        raise ValueError("train_ratio and validation_ratio must be positive and sum to less than 1")
    random.Random(seed).shuffle(unique)
    n_train = max(1, int(len(unique) * train_ratio))
    n_validation = max(1, int(len(unique) * validation_ratio))
    if n_train + n_validation >= len(unique):
        n_train = len(unique) - 2
        n_validation = 1
    result = {
        "train": sorted(unique[:n_train]),
        "validation": sorted(unique[n_train:n_train + n_validation]),
        "test": sorted(unique[n_train + n_validation:]),
    }
    sets = [set(result[k]) for k in ("train", "validation", "test")]
    if any(sets[i] & sets[j] for i in range(3) for j in range(i + 1, 3)):
        raise AssertionError("internal error: scenario split overlap")
    return result
