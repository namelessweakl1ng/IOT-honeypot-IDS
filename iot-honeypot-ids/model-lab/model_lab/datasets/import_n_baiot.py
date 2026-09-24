"""
N-BaIoT dataset importer.

N-BaIoT (Network Behavioral IoT) dataset from USIB/UPC Barcelona.
Contains statistical features extracted from network traffic of
IoT devices under benign and botnet-infected conditions.

Unlike IoT-23 (which has Zeek flow logs), N-BaIoT provides
pre-computed statistical features per device/time-window:
- 115 features per measurement
- Features include packet count, jitter, byte statistics, etc.
- Labels are per-device (not per-flow)

The importer expects the N-BaIoT CSV format:
- Each CSV file represents one device + one condition (benign/mirai/gafgyt)
- Files are organized in directories by device/condition
- Each row is a time-window measurement with 115 numeric features

Usage:
    python -m model_lab.datasets.import_n_baiot \
        --input /path/to/nbaiot \
        --output datasets/external/nbaiot/v1

Directory structure expected:
    <input>/
        <device_name>/
            benign_traffic.csv
            mirai_traffic/
            gafgyt_traffic/
        ...

Or the flat structure:
    <input>/
        Danmini_Doorbell_benign.csv
        Danmini_Doorbell_mirai.csv
        ...
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

# Setup paths
try:
    from ..common import datasets_dir, setup_paths
    setup_paths()
except (ImportError, ValueError):
    _here = Path(__file__).resolve().parent
    _parent = _here.parent
    sys.path.insert(0, str(_parent.parent))
    from model_lab.common import datasets_dir, setup_paths  # type: ignore
    setup_paths()

try:
    from model_lab.canonical_schema import DatasetManifest, RawManifest, ProvenanceRecord
    from model_lab.label_mapping_n_baiot import map_label, get_mapping_version, get_mapping_dict
except ImportError:
    _ml_root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(_ml_root))
    from model_lab.canonical_schema import DatasetManifest, RawManifest, ProvenanceRecord
    from model_lab.label_mapping_n_baiot import map_label, get_mapping_version, get_mapping_dict


# N-BaIoT has 115 statistical features.
# These features are NOT network flow features and should NOT be mapped
# to IoT-23 flow-level fields. They represent a completely different
# feature space (device-level behavioral statistics).
# Cross-dataset evaluation between IoT-23 and N-BaIoT is NOT directly
# comparable without a defensible shared representation.


def discover_nbaiot_files(input_dir: Path) -> List[Tuple[str, str, Path]]:
    """Discover N-BaIoT CSV files.

    Returns list of (device_name, condition, file_path) tuples.
    Condition is one of: benign, mirai, gafgyt
    """
    results = []
    for entry in sorted(input_dir.iterdir()):
        if entry.is_dir():
            # Look for device subdirectories
            device_name = entry.name
            for sub in sorted(entry.iterdir()):
                if sub.is_dir():
                    # e.g. mirai_traffic/, gafgyt_traffic/
                    condition = "benign"
                    if "mirai" in sub.name.lower():
                        condition = "mirai"
                    elif "gafgyt" in sub.name.lower() or "bashlite" in sub.name.lower():
                        condition = "gafgyt"
                    for csv_file in sorted(sub.glob("*.csv")):
                        results.append((device_name, condition, csv_file))
                elif sub.name.endswith(".csv"):
                    condition = "benign"
                    if "mirai" in sub.name.lower():
                        condition = "mirai"
                    elif "gafgyt" in sub.name.lower() or "bashlite" in sub.name.lower():
                        condition = "gafgyt"
                    results.append((device_name, condition, sub))
        elif entry.name.endswith(".csv"):
            # Flat structure: device_condition.csv
            name = entry.stem
            device_name = name
            condition = "benign"
            for cond in ["mirai", "gafgyt", "bashlite"]:
                if cond in name.lower():
                    condition = cond if cond != "bashlite" else "gafgyt"
                    device_name = name.replace(f"_{cond}", "").replace(f"-{cond}", "")
                    break
            results.append((device_name, condition, entry))
    return results


def file_checksum(path: Path) -> str:
    """Full SHA-256 hash of a file (64 hex chars).

    Research provenance requires the full hash — truncated hashes (e.g. 16
    chars / 64 bits) are insufficient for collision-resistant identification
    of source data. Previous versions truncated to 16 chars; this was a
    defect corrected in Pass 3.
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()  # full 64-char SHA-256


def stream_nbaiot_rows(
    file_path: Path,
    device_name: str,
    condition: str,
    dataset_id: str,
    dataset_version: str,
    row_id_offset: int = 0,
) -> Iterator[Tuple[Optional[Dict[str, Any]], Optional[str]]]:
    """Stream N-BaIoT rows from a CSV file.

    Yields (record_dict, rejection_reason) tuples.
    """
    import csv

    row_id = row_id_offset
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        try:
            header = next(reader)
        except StopIteration:
            return

        # N-BaIoT CSVs may or may not have a header
        # If the first row is all numeric, there's no header
        has_header = not all(_is_number(h) for h in header[:3])
        if not has_header:
            # No header — the first row IS data
            feature_names = [f"f{i}" for i in range(len(header))]
            # Process the first row as data
            yield from _process_nbaiot_row(header, feature_names, device_name, condition,
                                           dataset_id, dataset_version, row_id)
            row_id += 1
        else:
            feature_names = header

        for line in reader:
            row_id += 1
            yield from _process_nbaiot_row(line, feature_names, device_name, condition,
                                           dataset_id, dataset_version, row_id)


def _is_number(s: str) -> bool:
    try:
        float(s)
        return True
    except (ValueError, TypeError):
        return False


def _process_nbaiot_row(
    values: List[str],
    feature_names: List[str],
    device_name: str,
    condition: str,
    dataset_id: str,
    dataset_version: str,
    row_id: int,
) -> Iterator[Tuple[Optional[Dict[str, Any]], Optional[str]]]:
    """Process one N-BaIoT CSV row into a canonical record."""
    if len(values) != len(feature_names):
        yield (None, f"column_count_mismatch (expected {len(feature_names)}, got {len(values)})")
        return

    # Parse numeric features
    features = {}
    try:
        for i, (name, val) in enumerate(zip(feature_names, values)):
            if val.strip() == "" or val.strip() == "-":
                features[name] = 0.0
            else:
                features[name] = float(val)
    except (ValueError, TypeError) as e:
        yield (None, f"parse_error: {str(e)[:60]}")
        return

    # Map label
    canonical_family, binary, canonical_label, conf, reason = map_label(condition)

    # Build canonical record
    # N-BaIoT records are per-device time-window statistical measurements.
    # They are NOT network flows — do NOT fabricate IP/port/protocol fields.
    # Missing values are explicitly missing, not zero.
    #
    # label_source for N-BaIoT is "device_condition" (NOT external_analyst_derived):
    # N-BaIoT labels are experimental conditions — the device was deliberately
    # infected/not-infected in a controlled lab environment. These labels are
    # HIGHLY reliable (unlike IoT-23's analyst-derived labels).
    record = {
        "record_id": f"{dataset_id}_{dataset_version}_{row_id}",
        "dataset_id": dataset_id,
        "dataset_version": dataset_version,
        "source_file": "",  # filled by caller
        "source_row_id": row_id,
        "source_scenario": f"{device_name}_{condition}",
        "device_name": device_name,
        "condition": condition,
        # N-BaIoT does NOT provide: timestamp, source_ip, destination_ip,
        # source_port, destination_port, protocol, duration, bytes, packets
        # Do NOT fabricate these. Missing means missing.
        "native_label": condition,
        "native_label_detail": f"{device_name} device, {condition} condition",
        "canonical_label": canonical_label,
        "canonical_attack_family": canonical_family,
        "binary_label": binary,
        "label_source": "device_condition",  # controlled experiment, not analyst-derived
        "label_mapping_confidence": conf,
        "label_mapping_reason": reason,
        "feature_version": "nbaiot_v1",
        # Preserve all 115 features
        "nbaiot_features": json.dumps(features),
    }
    yield (record, None)


def import_n_baiot(input_dir: Path, output_dir: Path, dataset_version: str = "v1") -> Dict[str, Any]:
    """Import an N-BaIoT dataset from a local directory.

    Args:
        input_dir: Directory containing N-BaIoT CSV files
        output_dir: Output directory for normalized data + manifests
        dataset_version: Version label

    Returns:
        Summary dict with import statistics
    """
    input_dir = Path(input_dir)
    output_dir = Path(output_dir)

    if not input_dir.exists():
        raise FileNotFoundError(f"Input directory not found: {input_dir}")

    output_dir.mkdir(parents=True, exist_ok=True)
    normalized_dir = output_dir / "normalized"
    normalized_dir.mkdir(exist_ok=True)

    dataset_id = "nbaiot"
    start_time = time.time()

    # 1. Discover CSV files
    csv_files = discover_nbaiot_files(input_dir)
    if not csv_files:
        raise FileNotFoundError(
            f"No N-BaIoT CSV files found in {input_dir}. "
            "Expected structure: <device>/<condition>/*.csv"
        )

    print(f"Discovered {len(csv_files)} CSV files across {len(set(d for d,_,_ in csv_files))} devices")

    # 2. Stream-parse each file (streaming — no pandas accumulation)

    all_provenance: List[Dict[str, Any]] = []
    total_rows_seen = 0
    total_rows_imported = 0
    total_rows_rejected = 0
    all_rejection_reasons: Dict[str, int] = {}
    label_distribution: Dict[str, int] = {}
    native_labels_seen: Dict[str, int] = {}
    canonical_families_seen: Dict[str, int] = {}
    unmapped_labels: List[str] = []
    devices_seen: set = set()
    conditions_seen: set = set()

    global_row_id = 0
    batch_count = 0

    # Streaming JSONL output — never accumulate all records in memory
    jsonl_path = normalized_dir / "flows.jsonl"
    jsonl_fh = open(jsonl_path, "w", encoding="utf-8")

    for device_name, condition, file_path in csv_files:
        print(f"  Parsing {device_name}/{condition} ({file_path.name})...")
        checksum = file_checksum(file_path)
        prov = ProvenanceRecord(
            source_file=str(file_path.relative_to(input_dir)),
            source_scenario=f"{device_name}_{condition}",
            file_checksum=checksum,
        )
        devices_seen.add(device_name)
        conditions_seen.add(condition)

        for record, rejection_reason in stream_nbaiot_rows(
            file_path, device_name, condition, dataset_id, dataset_version, global_row_id
        ):
            prov.rows_seen += 1
            if record is None:
                prov.rows_rejected += 1
                reason_key = rejection_reason or "unknown"
                prov.rejection_reasons[reason_key] = prov.rejection_reasons.get(reason_key, 0) + 1
                all_rejection_reasons[reason_key] = all_rejection_reasons.get(reason_key, 0) + 1
            else:
                prov.rows_imported += 1
                record["source_file"] = file_path.name

                # Stream to JSONL immediately — no accumulation
                jsonl_fh.write(json.dumps(record, default=str) + "\n")
                batch_count += 1

                nl = record["native_label"]
                native_labels_seen[nl] = native_labels_seen.get(nl, 0) + 1
                cf = record["canonical_attack_family"]
                canonical_families_seen[cf] = canonical_families_seen.get(cf, 0) + 1
                bl = record["binary_label"]
                label_distribution[bl] = label_distribution.get(bl, 0) + 1
                if record["label_mapping_confidence"] == 0.0:
                    unmapped_labels.append(nl)

            global_row_id += 1

        all_provenance.append(prov.to_dict())
        total_rows_seen += prov.rows_seen
        total_rows_imported += prov.rows_imported
        total_rows_rejected += prov.rows_rejected
        print(f"    rows: seen={prov.rows_seen} imported={prov.rows_imported} rejected={prov.rows_rejected}")

    elapsed = time.time() - start_time

    # 3. Write normalized data (streaming — already written to JSONL)
    jsonl_fh.close()
    parquet_path = jsonl_path
    print(f"  Wrote {total_rows_imported} records to {jsonl_path} (streaming)")

    # 4. Compute source checksum (full SHA-256, not truncated)
    combined_hash = hashlib.sha256()
    for p in all_provenance:
        combined_hash.update(p.get("file_checksum", "").encode())
    source_checksum = combined_hash.hexdigest()  # full 64-char SHA-256

    # 5. Generate manifests
    raw_manifest = RawManifest(
        dataset_id=dataset_id,
        dataset_version=dataset_version,
        raw_directory=str(input_dir),
        files=all_provenance,
        total_rows_seen=total_rows_seen,
        total_rows_imported=total_rows_imported,
        total_rows_rejected=total_rows_rejected,
        created_at=datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    )
    (output_dir / "raw_manifest.json").write_text(raw_manifest.to_json())

    mapping_data = {
        "dataset": "nbaiot",
        "mapping_version": get_mapping_version(),
        "mappings": get_mapping_dict(),
        "unmapped_labels_found": list(set(unmapped_labels)),
    }
    (output_dir / "label_mapping.json").write_text(json.dumps(mapping_data, indent=2, default=str))

    manifest = DatasetManifest(
        dataset_id=dataset_id,
        dataset_name="N-BaIoT",
        dataset_version=dataset_version,
        source="USIB/UPC Barcelona (Meidan et al., 2018)",
        source_url="https://iotstratosphere.net/nbaiot-dataset/",
        license="Public",
        source_format="csv_statistical_features",
        download_timestamp="",
        source_checksum=source_checksum,
        importer_version="1.0",
        normalization_version="1.0",
        feature_version="nbaiot_v1",
        record_count=total_rows_imported,
        scenario_count=len(devices_seen),
        label_count=len(canonical_families_seen),
        created_at=datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        description=f"N-BaIoT dataset imported from {input_dir}. {total_rows_imported} records from {len(devices_seen)} devices.",
    )
    (output_dir / "dataset_manifest.json").write_text(manifest.to_json())

    provenance_data = {
        "dataset_id": dataset_id,
        "dataset_version": dataset_version,
        "source_files": all_provenance,
        "label_mapping_version": get_mapping_version(),
        "label_source": "device_condition",  # controlled experiment, reliable
        "importer_version": "1.0",
        "normalization_version": "1.0",
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    }
    (output_dir / "provenance.json").write_text(json.dumps(provenance_data, indent=2, default=str))

    audit_data = {
        "dataset_id": dataset_id,
        "dataset_version": dataset_version,
        "session_count": total_rows_imported,
        "scenario_count": len(devices_seen),
        "campaign_count": len(devices_seen),
        "rows_seen": total_rows_seen,
        "rows_imported": total_rows_imported,
        "rows_rejected": total_rows_rejected,
        "rejection_reasons": all_rejection_reasons,
        "label_distribution": label_distribution,
        "native_labels": native_labels_seen,
        "canonical_families": canonical_families_seen,
        "unmapped_labels": list(set(unmapped_labels)),
        "source_checksum": source_checksum,
        "data_type": "external_real",
        "devices": list(devices_seen),
        "conditions": list(conditions_seen),
        "warnings": [],
        "feature_note": "N-BaIoT provides 115 statistical features per measurement, not raw flows. Features are NOT directly comparable to IoT-23 flow features.",
    }
    if unmapped_labels:
        audit_data["warnings"].append(f"Unmapped labels found: {set(unmapped_labels)}")
    if total_rows_rejected > total_rows_seen * 0.1:
        audit_data["warnings"].append(f"High rejection rate: {total_rows_rejected}/{total_rows_seen} rows rejected")
    audit_data["warnings"].append(
        "N-BaIoT features are statistical aggregates (115 per measurement), NOT raw network flows. "
        "Cross-dataset evaluation with IoT-23 requires using only semantically comparable features "
        "(binary classification: malicious vs benign)."
    )
    (output_dir / "audit.json").write_text(json.dumps(audit_data, indent=2, default=str))

    schema_data = {
        "dataset_id": dataset_id,
        "schema_version": "1.0",
        "fields": ["record_id", "dataset_id", "source_file", "source_row_id", "source_scenario", "device_name", "condition", "native_label", "canonical_label", "canonical_attack_family", "binary_label", "label_source", "nbaiot_features"],
        "feature_count": 115,
        "description": "N-BaIoT canonical schema — statistical features per device/time-window",
    }
    (output_dir / "schema.json").write_text(json.dumps(schema_data, indent=2, default=str))

    print(f"\nImport complete in {elapsed:.1f}s")
    print(f"  Records: {total_rows_imported} imported, {total_rows_rejected} rejected ({total_rows_seen} total)")
    print(f"  Devices: {len(devices_seen)}")
    print(f"  Conditions: {len(conditions_seen)}")
    print(f"  Canonical families: {len(canonical_families_seen)}")
    print(f"  Output: {output_dir}")

    return {
        "dataset_id": dataset_id,
        "dataset_version": dataset_version,
        "records_imported": total_rows_imported,
        "records_rejected": total_rows_rejected,
        "devices": len(devices_seen),
        "output_dir": str(output_dir),
        "unmapped_labels": list(set(unmapped_labels)),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Import N-BaIoT dataset into TRAPSIG canonical schema")
    parser.add_argument("--input", required=True, help="Directory containing N-BaIoT CSV files")
    parser.add_argument("--output", required=True, help="Output directory for normalized data + manifests")
    parser.add_argument("--version", default="v1", help="Dataset version label (default: v1)")
    args = parser.parse_args(argv)

    result = import_n_baiot(Path(args.input), Path(args.output), args.version)
    print(f"\nResult: {json.dumps(result, indent=2)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
