"""
IoT-23 label mapping — COMPLETE taxonomy.

Based on the official IoT-23 dataset documentation from the Stratosphere
Research Laboratory. Every native label that appears in real IoT-23
conn.log.labeled files is mapped here.

Three levels:
1. native_label (as it appears in the Zeek log)
2. canonical_attack_family (TRAPSIG taxonomy)
3. binary_label (malicious/benign)

Labels that cannot be defensibly mapped → unknown/unknown.

The IoT-23 labels are analyst-derived (manual analysis + labeling rules),
NOT raw ground truth. We record this as label_source = external_analyst_derived.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, Tuple
import yaml


LABEL_MAPPING: Dict[str, Dict[str, str]] = {
    # ---- Benign ----
    "Benign": {
        "canonical_family": "benign",
        "binary": "benign",
        "confidence": "1.0",
        "reason": "Benign traffic — no attack behavior",
    },
    # ---- Horizontal Port Scan ----
    "PartOfAHorizontalPortScan": {
        "canonical_family": "discovery",
        "binary": "malicious",
        "confidence": "0.9",
        "reason": "Horizontal port scanning activity",
    },
    "PartOfAHorizontalPortScan-Attack": {
        "canonical_family": "discovery",
        "binary": "malicious",
        "confidence": "1.0",
        "reason": "Horizontal port scan — attack variant",
    },
    # ---- Command and Control (generic) ----
    "C&C": {
        "canonical_family": "command_and_control",
        "binary": "malicious",
        "confidence": "1.0",
        "reason": "Command and control communication",
    },
    "C&C-Attack": {
        "canonical_family": "command_and_control",
        "binary": "malicious",
        "confidence": "1.0",
        "reason": "C&C attack activity",
    },
    # ---- C&C — Mirai ----
    "C&C-Mirai": {
        "canonical_family": "command_and_control",
        "binary": "malicious",
        "confidence": "1.0",
        "reason": "Mirai C&C communication",
    },
    # ---- C&C — Torii ----
    "C&C-Torii": {
        "canonical_family": "command_and_control",
        "binary": "malicious",
        "confidence": "1.0",
        "reason": "Torii C&C communication",
    },
    # ---- C&C — HeartBeat ----
    "C&C-HeartBeat": {
        "canonical_family": "command_and_control",
        "binary": "malicious",
        "confidence": "1.0",
        "reason": "C&C heartbeat keepalive",
    },
    "C&C-HeartBeat-Attack": {
        "canonical_family": "command_and_control",
        "binary": "malicious",
        "confidence": "1.0",
        "reason": "C&C heartbeat — attack variant",
    },
    "C&C-HeartBeat-FileDownload": {
        "canonical_family": "command_and_control",
        "binary": "malicious",
        "confidence": "1.0",
        "reason": "C&C heartbeat with file download",
    },
    # ---- C&C — TCP / FileDownload ----
    "C&C-TCP": {
        "canonical_family": "command_and_control",
        "binary": "malicious",
        "confidence": "1.0",
        "reason": "C&C over TCP",
    },
    "C&C-FileDownload": {
        "canonical_family": "command_and_control",
        "binary": "malicious",
        "confidence": "1.0",
        "reason": "C&C file download",
    },
    # ---- C&C — Mirai variants (legacy naming) ----
    "C&C-Mirai-Ack": {
        "canonical_family": "command_and_control",
        "binary": "malicious",
        "confidence": "1.0",
        "reason": "Mirai C&C ACK flood variant",
    },
    "C&C-Mirai-Syn": {
        "canonical_family": "command_and_control",
        "binary": "malicious",
        "confidence": "1.0",
        "reason": "Mirai C&C SYN flood variant",
    },
    "C&C-Mirai-UDP": {
        "canonical_family": "command_and_control",
        "binary": "malicious",
        "confidence": "1.0",
        "reason": "Mirai C&C UDP flood variant",
    },
    "C&C-Mirai-UDPPlain": {
        "canonical_family": "command_and_control",
        "binary": "malicious",
        "confidence": "1.0",
        "reason": "Mirai C&C plain UDP flood variant",
    },
    # ---- DDoS ----
    "DDoS": {
        "canonical_family": "dos",
        "binary": "malicious",
        "confidence": "1.0",
        "reason": "Distributed denial of service",
    },
    # ---- File Download ----
    "FileDownload": {
        "canonical_family": "collection",
        "binary": "malicious",
        "confidence": "0.8",
        "reason": "File download activity — may be malicious",
    },
    # ---- Okiru (Hajime botnet) ----
    "Okiru": {
        "canonical_family": "botnet_okiru",
        "binary": "malicious",
        "confidence": "1.0",
        "reason": "Okiru/Hajime botnet infection",
    },
    "Okiru-Attack": {
        "canonical_family": "botnet_okiru",
        "binary": "malicious",
        "confidence": "1.0",
        "reason": "Okiru/Hajime attack activity",
    },
    # ---- Mirai (botnet, not C&C) ----
    "Mirai": {
        "canonical_family": "botnet_mirai",
        "binary": "malicious",
        "confidence": "1.0",
        "reason": "Mirai botnet malware activity",
    },
    "Mirai-CC": {
        "canonical_family": "command_and_control",
        "binary": "malicious",
        "confidence": "1.0",
        "reason": "Mirai command and control channel",
    },
    "Mirai-Scan": {
        "canonical_family": "discovery",
        "binary": "malicious",
        "confidence": "1.0",
        "reason": "Mirai network scanning activity",
    },
    "Mirai-Ack": {
        "canonical_family": "dos",
        "binary": "malicious",
        "confidence": "1.0",
        "reason": "Mirai ACK flood DoS attack",
    },
    "Mirai-Syn": {
        "canonical_family": "dos",
        "binary": "malicious",
        "confidence": "1.0",
        "reason": "Mirai SYN flood DoS attack",
    },
    "Mirai-UDP": {
        "canonical_family": "dos",
        "binary": "malicious",
        "confidence": "1.0",
        "reason": "Mirai UDP flood DoS attack",
    },
    "Mirai-UDPPlain": {
        "canonical_family": "dos",
        "binary": "malicious",
        "confidence": "1.0",
        "reason": "Mirai plain UDP flood DoS attack",
    },
    # ---- Torii ----
    "Torii": {
        "canonical_family": "botnet_torii",
        "binary": "malicious",
        "confidence": "1.0",
        "reason": "Torii botnet malware",
    },
    # ---- UnknownBotnet — real IoT-23 label seen in fixture data.
    # Mapped conservatively to botnet_unknown (not a specific family).
    "UnknownBotnet": {
        "canonical_family": "botnet_unknown",
        "binary": "malicious",
        "confidence": "0.7",
        "reason": "IoT-23 'UnknownBotnet' label — botnet activity of unidentified family",
    },
    # ---- Generic Attack ----
    "Attack": {
        "canonical_family": "attack_unspecified",
        "binary": "malicious",
        "confidence": "0.5",
        "reason": "Generic attack label without family detail",
    },
    # ---- Malicious (generic) ----
    "Malicious": {
        "canonical_family": "malicious_unspecified",
        "binary": "malicious",
        "confidence": "0.5",
        "reason": "Generic malicious label without family detail",
    },
    # ---- HeartBeat (standalone) ----
    "HeartBeat": {
        "canonical_family": "command_and_control",
        "binary": "malicious",
        "confidence": "0.8",
        "reason": "Heartbeat activity — likely C&C keepalive",
    },
    # ---- Zebro ----
    "Zebro": {
        "canonical_family": "botnet_zebro",
        "binary": "malicious",
        "confidence": "0.8",
        "reason": "Zebro botnet activity",
    },
    # ---- Antares ----
    "Antares-1": {
        "canonical_family": "attack_unspecified",
        "binary": "malicious",
        "confidence": "0.5",
        "reason": "Antares-1 scenario — unspecified attack family",
    },
    # ---- LuminusHTTPProxy ----
    "LuminusHTTPProxy": {
        "canonical_family": "proxy_abuse",
        "binary": "malicious",
        "confidence": "0.8",
        "reason": "Luminus HTTP proxy abuse",
    },
}


def map_label(native_label: str) -> Tuple[str, str, str, float, str]:
    """Map a native IoT-23 label to canonical family + binary label.

    Returns:
        (canonical_family, binary_label, canonical_label, confidence, reason)

    If the label cannot be mapped:
        canonical_family = "unknown"
        binary_label = "unknown"
        confidence = 0.0
        reason = "unmapped"
    """
    label = native_label.strip()
    # Try exact match
    mapping = LABEL_MAPPING.get(label)
    if mapping is None:
        # Try without trailing whitespace/newlines
        mapping = LABEL_MAPPING.get(label.rstrip())
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
    return "v3"  # v3 = adds UnknownBotnet mapping (found in real IoT-23 fixture)


def get_mapping_dict() -> Dict[str, Dict[str, str]]:
    return LABEL_MAPPING


def get_label_source() -> str:
    """IoT-23 labels are analyst-derived, not raw ground truth."""
    return "external_analyst_derived"


def get_project_mapping(native_label: str) -> Tuple[str, str]:
    """Apply the versioned, repository-tracked mapping contract."""
    mapping_path = Path(__file__).resolve().parents[2] / "research" / "datasets" / "iot23" / "mappings.yaml"
    if not mapping_path.is_file():
        raise FileNotFoundError(f"IoT-23 mapping contract missing: {mapping_path}")
    config = yaml.safe_load(mapping_path.read_text(encoding="utf-8")) or {}
    entry = (config.get("labels") or {}).get(native_label)
    if entry is None:
        fallback = config.get("unlisted") or {}
        return str(fallback.get("project_label", "UNMAPPED")), str(fallback.get("binary_label", "UNKNOWN"))
    return str(entry["project_label"]), str(entry["binary_label"])
