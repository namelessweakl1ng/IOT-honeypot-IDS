"""
N-BaIoT label mapping.

N-BaIoT dataset uses binary labels: benign vs malicious, with the
malicious class representing infected IoT devices (primarily Mirai
and BASHLITE/Gafgyt botnet infections).

N-BaIoT does NOT provide per-flow labels — it provides per-device
labels (the entire device is either benign or infected). This means
the label applies to ALL traffic from that device during the
infection period.

The native labels in N-BaIoT are:
- benign (device not infected)
- mirai (device infected with Mirai)
- gafgyt (device infected with BASHLITE/Gafgyt)

Since N-BaIoT provides statistical features (not raw flows), the
canonical schema for N-BaIoT differs from IoT-23 — we preserve the
statistical features as the canonical representation rather than
attempting to reconstruct flows.
"""
from __future__ import annotations

from typing import Dict, Tuple


# N-BaIoT label → canonical attack family mapping
LABEL_MAPPING: Dict[str, Dict[str, str]] = {
    "benign": {
        "canonical_family": "benign",
        "binary": "benign",
        "confidence": "1.0",
        "reason": "Device not infected — normal IoT traffic",
    },
    "mirai": {
        "canonical_family": "botnet_mirai",
        "binary": "malicious",
        "confidence": "1.0",
        "reason": "Device infected with Mirai botnet",
    },
    "gafgyt": {
        "canonical_family": "botnet_gafgyt",
        "binary": "malicious",
        "confidence": "1.0",
        "reason": "Device infected with BASHLITE/Gafgyt botnet",
    },
    # N-BaIoT sometimes uses these variants
    "BASHLITE": {
        "canonical_family": "botnet_gafgyt",
        "binary": "malicious",
        "confidence": "1.0",
        "reason": "BASHLITE is the original name for Gafgyt",
    },
    "Mirai": {
        "canonical_family": "botnet_mirai",
        "binary": "malicious",
        "confidence": "1.0",
        "reason": "Mirai botnet infection",
    },
}


def map_label(native_label: str) -> Tuple[str, str, str, float, str]:
    """Map a native N-BaIoT label to canonical family + binary label.

    Returns:
        (canonical_family, binary_label, canonical_label, confidence, reason)
    """
    # N-BaIoT labels are case-insensitive
    mapping = LABEL_MAPPING.get(native_label.strip())
    if mapping is None:
        # Try lowercase
        mapping = LABEL_MAPPING.get(native_label.strip().lower())
    if mapping is None:
        return ("unknown", "unknown", "unknown", 0.0, "unmapped")
    return (
        mapping["canonical_family"],
        mapping["binary"],
        mapping["canonical_family"],
        float(mapping["confidence"]),
        mapping["reason"],
    )


def get_all_native_labels() -> list[str]:
    return list(LABEL_MAPPING.keys())


def get_all_canonical_families() -> list[str]:
    return list(set(m["canonical_family"] for m in LABEL_MAPPING.values()))


def get_mapping_version() -> str:
    return "v1"


def get_mapping_dict() -> Dict[str, Dict[str, str]]:
    return LABEL_MAPPING
