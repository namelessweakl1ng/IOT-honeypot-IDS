"""Cross-dataset compatibility check.

Scientifically honest comparison between datasets requires that they share
a semantically equivalent feature space. IoT-23 and N-BaIoT do NOT:

- IoT-23: per-flow Zeek logs (ts, uid, IPs, ports, proto, duration, bytes, packets)
- N-BaIoT: per-device time-window statistical features (115 pre-computed stats)

These are FUNDAMENTALLY DIFFERENT representations. Merging them by column
position would be scientifically invalid.

This module enforces NOT_COMPARABLE when datasets are incompatible, with a
machine-readable reason.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class CompatibilityResult:
    """Result of a cross-dataset compatibility check."""
    dataset_a: str
    dataset_b: str
    comparable: bool
    reason: str
    shared_features: List[str] = field(default_factory=list)
    incompatible_aspects: List[str] = field(default_factory=list)
    comparable_subset: Optional[str] = None  # e.g. "binary_label_only" if only binary is comparable

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dataset_a": self.dataset_a,
            "dataset_b": self.dataset_b,
            "comparable": self.comparable,
            "reason": self.reason,
            "shared_features": self.shared_features,
            "incompatible_aspects": self.incompatible_aspects,
            "comparable_subset": self.comparable_subset,
        }


# Dataset representation profiles
DATASET_PROFILES: Dict[str, Dict[str, Any]] = {
    "iot23": {
        "name": "IoT-23",
        "representation": "per_flow_zeek_logs",
        "native_features": [
            "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
            "proto", "service", "duration", "orig_bytes", "resp_bytes",
            "conn_state", "local_orig", "local_resp", "missed_bytes",
            "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes",
            "tunnel_parents",
        ],
        "labels": "analyst_derived_per_flow",
        "label_source": "external_analyst_derived",
        "grouping_unit": "scenario_capture",
        "temporal_info": True,
        "feature_count": 21,
    },
    "nbaiot": {
        "name": "N-BaIoT",
        "representation": "per_device_statistical_window",
        "native_features": ["115 statistical features (packet count, jitter, byte stats, etc.)"],
        "labels": "device_condition",
        "label_source": "device_condition",
        "grouping_unit": "device_condition",
        "temporal_info": False,  # no explicit timestamps in feature rows
        "feature_count": 115,
    },
    "trapsig_synthetic": {
        "name": "TRAPSIG Synthetic v1",
        "representation": "per_session_behavioral_features",
        "native_features": [
            "event_count", "duration_s", "bytes_in_total", "bytes_out_total",
            "auth_attempts", "auth_successes", "auth_failure_ratio", "unique_usernames",
            "command_count", "command_diversity", "http_request_count", "http_uri_diversity",
            "http_status_4xx_ratio", "http_status_5xx_ratio", "unique_protocols",
            "devices_touched", "ports_touched", "time_between_events_mean_s",
            "time_between_events_stdev_s", "request_rate_per_min",
            "auth_failure_rate_per_min", "contains_path_traversal",
            "contains_command_injection", "contains_default_credentials", "is_recon_only",
        ],
        "labels": "scenario_defined",
        "label_source": "scenario",
        "grouping_unit": "campaign",
        "temporal_info": True,
        "feature_count": 25,
    },
}


def check_compatibility(dataset_a: str, dataset_b: str) -> CompatibilityResult:
    """Check whether two datasets can be scientifically compared.

    Returns a CompatibilityResult. If `comparable` is False, the reason
    explains why. A `comparable_subset` may be set if a limited comparison
    is defensible (e.g. binary malicious/benign only).
    """
    a = DATASET_PROFILES.get(dataset_a)
    b = DATASET_PROFILES.get(dataset_b)
    if a is None or b is None:
        return CompatibilityResult(
            dataset_a=dataset_a,
            dataset_b=dataset_b,
            comparable=False,
            reason=f"Unknown dataset: {dataset_a if a is None else dataset_b}",
        )

    # Same dataset → always comparable
    if dataset_a == dataset_b:
        shared = list(a["native_features"])
        return CompatibilityResult(
            dataset_a=dataset_a,
            dataset_b=dataset_b,
            comparable=True,
            reason="Same dataset — full feature space is shared.",
            shared_features=shared,
        )

    # Different representations → NOT_COMPARABLE at feature level
    if a["representation"] != b["representation"]:
        incompatible = [
            f"Different representations: {a['representation']} vs {b['representation']}",
            f"Different feature counts: {a['feature_count']} vs {b['feature_count']}",
            f"Different label sources: {a['label_source']} vs {b['label_source']}",
            f"Different grouping units: {a['grouping_unit']} vs {b['grouping_unit']}",
        ]
        # Binary label (malicious vs benign) IS comparable — both datasets have it
        return CompatibilityResult(
            dataset_a=dataset_a,
            dataset_b=dataset_b,
            comparable=False,
            reason=(
                f"NOT_COMPARABLE: {a['name']} ({a['representation']}) and "
                f"{b['name']} ({b['representation']}) have fundamentally different "
                f"feature spaces. Merging by column position would be scientifically "
                f"invalid. Only binary malicious/benign comparison is defensible."
            ),
            incompatible_aspects=incompatible,
            comparable_subset="binary_label_only",
        )

    # Same representation but different features → check shared features
    shared = set(a["native_features"]) & set(b["native_features"])
    if len(shared) == 0:
        return CompatibilityResult(
            dataset_a=dataset_a,
            dataset_b=dataset_b,
            comparable=False,
            reason=f"Same representation ({a['representation']}) but no shared features.",
        )

    return CompatibilityResult(
        dataset_a=dataset_a,
        dataset_b=dataset_b,
        comparable=True,
        reason=f"Same representation, {len(shared)} shared features.",
        shared_features=sorted(shared),
    )


def get_profile(dataset_id: str) -> Optional[Dict[str, Any]]:
    """Get the dataset profile for a dataset ID."""
    return DATASET_PROFILES.get(dataset_id)
