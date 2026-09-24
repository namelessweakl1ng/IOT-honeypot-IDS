"""
Canonical TRAPSIG schema for external dataset normalization.

This schema is independent of any specific dataset (IoT-23, N-BaIoT, etc.).
The ML pipeline consumes this canonical representation, not raw dataset columns.

Each record represents one network flow / session with:
- provenance (dataset_id, source_file, source_row_id)
- network metadata (timestamp, IPs, ports, protocol)
- flow statistics (duration, bytes, packets)
- labels (native + canonical + binary)
- feature availability flags
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Optional


@dataclass
class CanonicalFlow:
    """One normalized network flow/session in the TRAPSIG canonical schema."""
    # Identity + provenance
    record_id: str
    dataset_id: str
    dataset_version: str
    source_file: str = ""
    source_row_id: int = 0
    source_scenario: str = ""

    # Network metadata
    timestamp: str = ""
    source_ip: str = ""
    destination_ip: str = ""
    source_port: int = 0
    destination_port: int = 0
    protocol: str = ""

    # Flow statistics
    duration: float = 0.0
    bytes_in: int = 0
    bytes_out: int = 0
    packets_in: int = 0
    packets_out: int = 0

    # Labels (3 levels)
    native_label: str = ""
    native_label_detail: str = ""
    canonical_label: str = ""
    canonical_attack_family: str = ""
    binary_label: str = ""  # malicious, benign, unknown

    # Provenance metadata
    label_source: str = "external"  # external, scenario, rule, analyst, synthetic
    label_mapping_confidence: float = 1.0
    label_mapping_reason: str = ""

    # Feature version
    feature_version: str = "v2"

    # Additional dataset-specific fields (flexible)
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # Flatten extra fields to top level for CSV/Parquet
        for k, v in self.extra.items():
            if k not in d:
                d[k] = v
        del d["extra"]
        return d


@dataclass
class DatasetManifest:
    """Formal dataset manifest recording provenance and metadata."""
    dataset_id: str
    dataset_name: str
    dataset_version: str
    source: str
    source_url: str
    license: str
    source_format: str  # e.g. "zeek_conn_labeled"
    download_timestamp: str = ""
    source_checksum: str = ""
    importer_version: str = "1.0"
    normalization_version: str = "1.0"
    feature_version: str = "v2"
    record_count: int = 0
    scenario_count: int = 0
    label_count: int = 0
    created_at: str = ""
    label_mapping_version: str = "v1"
    label_mapping_file: str = "label_mapping.json"
    audit_file: str = "audit.json"
    normalized_file: str = "normalized/flows.parquet"
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        import json
        return json.dumps(self.to_dict(), indent=2, default=str)


@dataclass
class ProvenanceRecord:
    """Provenance for a single source file."""
    source_file: str
    source_scenario: str
    file_checksum: str = ""
    rows_seen: int = 0
    rows_imported: int = 0
    rows_rejected: int = 0
    rejection_reasons: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RawManifest:
    """Manifest of raw source files (not committed to Git)."""
    dataset_id: str
    dataset_version: str
    raw_directory: str = ""
    files: list = field(default_factory=list)  # list of ProvenanceRecord.to_dict()
    total_rows_seen: int = 0
    total_rows_imported: int = 0
    total_rows_rejected: int = 0
    created_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        import json
        return json.dumps(self.to_dict(), indent=2, default=str)
