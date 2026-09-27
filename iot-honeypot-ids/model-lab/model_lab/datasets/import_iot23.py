"""
IoT-23 dataset importer.

Imports labeled Zeek connection logs (conn.log.labeled) from the IoT-23
dataset into the TRAPSIG canonical schema.

Key fixes in this iteration:
1. Reads #fields from the file itself (no hardcoded column count)
2. Handles mixed tab/space separators in the label column
3. Preserves Zeek uid for provenance
4. TRUE streaming: writes chunks to Parquet/JSONL, never accumulates all_flows
5. Complete label taxonomy (v2) with all real IoT-23 labels

Usage:
    python -m model_lab.datasets.import_iot23 \
        --input /path/to/iot23 \
        --output datasets/external/iot23/v1
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
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
    from model_lab.label_mapping_iot23 import map_label, get_mapping_version, get_mapping_dict, get_label_source, get_project_mapping
except ImportError:
    _ml_root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(_ml_root))
    from model_lab.canonical_schema import DatasetManifest, RawManifest, ProvenanceRecord
    from model_lab.label_mapping_iot23 import map_label, get_mapping_version, get_mapping_dict, get_label_source, get_project_mapping


# Default Zeek conn.log fields — used as fallback if #fields not in file
DEFAULT_ZEEK_FIELDS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "proto", "service", "duration", "orig_bytes", "resp_bytes",
    "conn_state", "local_orig", "local_resp", "missed_bytes",
    "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes",
    "tunnel_parents",
    "label", "detailed_label",
]


def parse_zeek_ts(ts_str: str) -> str:
    """Convert Zeek timestamp (epoch seconds) to ISO-8601."""
    try:
        epoch = float(ts_str)
        dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
        return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    except (ValueError, TypeError):
        return ""


def parse_zeek_line(line: str, fields: List[str]) -> Optional[Dict[str, str]]:
    """Parse one Zeek TSV line into a dict.

    Handles mixed tab/space in the last column (label field).
    Returns None for comment/empty lines.
    """
    if line.startswith("#") or not line.strip():
        return None

    # Split by tab first
    parts = line.rstrip("\n").split("\t")

    # If the last field contains spaces AND we have label fields,
    # the IoT-23 format sometimes uses tab for all columns except the last two
    # (label and detailed_label) which may be space-separated
    if len(parts) < len(fields) and "label" in fields:
        # Try splitting the last part by spaces to get label + detailed_label
        if len(parts) >= len(fields) - 2:
            # The last 1-2 fields might be space-separated
            remaining = " ".join(parts[len(fields)-2:])
            label_parts = remaining.split()
            if len(label_parts) >= 1:
                parts = parts[:len(fields)-2] + label_parts[:2]
                # Pad if we got fewer
                while len(parts) < len(fields):
                    parts.append("-")

    if len(parts) != len(fields):
        return None

    return dict(zip(fields, parts))


def discover_zeek_files(input_dir: Path) -> List[Tuple[str, Path]]:
    """Discover conn.log.labeled files in the input directory."""
    results = []
    for entry in sorted(input_dir.iterdir()):
        if entry.is_dir():
            bro_dir = entry / "bro"
            if bro_dir.is_dir():
                conn_file = bro_dir / "conn.log.labeled"
                if conn_file.exists():
                    results.append((entry.name, conn_file))
                    continue
            conn_file = entry / "conn.log.labeled"
            if conn_file.exists():
                results.append((entry.name, conn_file))
        elif entry.name == "conn.log.labeled":
            results.append((input_dir.name, entry))
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


def stream_flows(
    file_path: Path,
    scenario_name: str,
    dataset_id: str,
    dataset_version: str,
    fields_override: Optional[List[str]] = None,
) -> Iterator[Tuple[Optional[Dict[str, Any]], Optional[str]]]:
    """Stream flows from a Zeek conn.log.labeled file.

    Reads #fields from the file itself. Falls back to DEFAULT_ZEEK_FIELDS.
    """
    fields = fields_override or DEFAULT_ZEEK_FIELDS
    row_id = 0

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            row_id += 1

            # Read #fields header
            if line.startswith("#fields"):
                parts = line.strip().split("\t")[1:]
                if parts:
                    fields = parts
                continue

            # Skip other comments and empty lines
            if line.startswith("#") or not line.strip():
                continue

            parsed = parse_zeek_line(line, fields)
            if parsed is None:
                yield (None, f"column_count_mismatch")
                continue

            raw_label = parsed.get("label")
            if raw_label is None or raw_label.strip() in ("", "-"):
                yield (None, "missing_label")
                continue

            try:
                ts = parse_zeek_ts(parsed.get("ts", ""))
                src_ip = parsed.get("id.orig_h", "")
                dst_ip = parsed.get("id.resp_h", "")
                src_ip = None if src_ip == "-" else src_ip
                dst_ip = None if dst_ip == "-" else dst_ip
                src_port = int(float(parsed["id.orig_p"])) if parsed.get("id.orig_p", "-") != "-" else None
                dst_port = int(float(parsed["id.resp_p"])) if parsed.get("id.resp_p", "-") != "-" else None
                proto = parsed.get("proto", "")
                proto = None if proto == "-" else proto

                # Handle Zeek missing values ("-")
                duration_str = parsed.get("duration", "-")
                duration = float(duration_str) if duration_str != "-" else None
                orig_bytes_str = parsed.get("orig_bytes", "-")
                orig_bytes = int(float(orig_bytes_str)) if orig_bytes_str != "-" else None
                resp_bytes_str = parsed.get("resp_bytes", "-")
                resp_bytes = int(float(resp_bytes_str)) if resp_bytes_str != "-" else None
                orig_pkts_str = parsed.get("orig_pkts", "-")
                orig_pkts = int(float(orig_pkts_str)) if orig_pkts_str != "-" else None
                resp_pkts_str = parsed.get("resp_pkts", "-")
                resp_pkts = int(float(resp_pkts_str)) if resp_pkts_str != "-" else None
                for field_name, value in (("duration", duration), ("orig_bytes", orig_bytes), ("resp_bytes", resp_bytes), ("orig_pkts", orig_pkts), ("resp_pkts", resp_pkts)):
                    if value is not None and (not math.isfinite(value) or value < 0):
                        raise ValueError(f"invalid {field_name}")

                # Labels
                native_label = raw_label.strip()
                native_detail = parsed.get("detailed_label", parsed.get("detailed-label", "-")).strip()
                if native_detail == "-":
                    native_detail = ""

                # Use detailed_label for mapping if available
                label_to_map = native_detail if native_detail else native_label
                canonical_family, binary, canonical_label, conf, reason = map_label(label_to_map)
                project_label, project_binary = get_project_mapping(label_to_map)

                # Preserve Zeek uid for provenance
                zeek_uid = parsed.get("uid", "")

                flow = {
                    "record_id": f"{dataset_id}_{dataset_version}_{row_id}",
                    "dataset_id": dataset_id,
                    "dataset_version": dataset_version,
                    "source_file": file_path.name,
                    "source_row_id": row_id,
                    "source_scenario": scenario_name,
                    "zeek_uid": zeek_uid,  # preserved for provenance, NOT used as ML feature
                    "timestamp": ts,
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "source_port": src_port,
                    "destination_port": dst_port,
                    "protocol": proto,
                    "duration": duration,
                    "bytes_in": orig_bytes,
                    "bytes_out": resp_bytes,
                    "packets_in": orig_pkts,
                    "packets_out": resp_pkts,
                    "native_label": label_to_map if label_to_map else native_label,
                    # Keep dataset truth and project taxonomy as independent fields.
                    "original_label": native_label,
                    "project_label": project_label,
                    "original_detailed_label": native_detail,
                    "native_label_detail": native_detail,
                    "canonical_label": project_label,
                    "canonical_attack_family": canonical_family,
                    "binary_label": project_binary.lower(),
                    "label_source": get_label_source(),
                    "label_provenance_detail": "ANALYST_DERIVED_EXTERNAL_ANNOTATION",
                    "data_category": "PUBLIC_DATASET",
                    "label_mapping_confidence": conf,
                    "label_mapping_reason": reason,
                    "label_mapping_version": get_mapping_version(),
                    "feature_version": "iot23-flow-v1",
                }
                yield (flow, None)

            except (ValueError, TypeError, OverflowError) as e:
                yield (None, f"parse_error: {str(e)[:80]}")


def import_iot23(input_dir: Path, output_dir: Path, dataset_version: str = "v1",
                  batch_size: int = 50000) -> Dict[str, Any]:
    """Import an IoT-23 dataset with TRUE streaming (chunked writing).

    Args:
        input_dir: Directory containing IoT-23 scenario folders
        output_dir: Output directory for normalized data + manifests
        dataset_version: Version label
        batch_size: Number of records per write batch (default 50000)

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

    dataset_id = "iot23"
    start_time = time.time()

    zeek_files = discover_zeek_files(input_dir)
    if not zeek_files:
        raise FileNotFoundError(
            f"No conn.log.labeled files found in {input_dir}. "
            "Expected structure: <scenario>/bro/conn.log.labeled"
        )

    print(f"Discovered {len(zeek_files)} scenario files")

    all_provenance: List[Dict[str, Any]] = []
    total_rows_seen = 0
    total_rows_imported = 0
    total_rows_rejected = 0
    all_rejection_reasons: Dict[str, int] = {}
    label_distribution: Dict[str, int] = {}
    native_labels_seen: Dict[str, int] = {}
    canonical_families_seen: Dict[str, int] = {}
    unmapped_labels: List[str] = []
    scenarios_seen: set = set()

    # Streaming output — write in batches, never accumulate all_flows
    jsonl_path = normalized_dir / "flows.jsonl"
    parquet_available = False
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
        parquet_available = True
        parquet_path = normalized_dir / "flows.parquet"
        parquet_writer = None
        batch: List[Dict[str, Any]] = []
    except ImportError:
        pass

    # Always write JSONL as a streaming fallback
    jsonl_fh = open(jsonl_path, "w", encoding="utf-8")

    def write_batch(records: List[Dict[str, Any]]):
        nonlocal parquet_writer
        for rec in records:
            jsonl_fh.write(json.dumps(rec, default=str) + "\n")
        if parquet_available and records:
            table = pa.Table.from_pylist(records)
            if parquet_writer is None:
                parquet_writer = pq.ParquetWriter(parquet_path, table.schema)
            parquet_writer.write_table(table)

    current_batch: List[Dict[str, Any]] = []

    for scenario_name, file_path in zeek_files:
        print(f"  Parsing {scenario_name} ({file_path.name})...")
        checksum = file_checksum(file_path)
        prov = ProvenanceRecord(
            source_file=str(file_path.relative_to(input_dir)),
            source_scenario=scenario_name,
            file_checksum=checksum,
        )
        scenarios_seen.add(scenario_name)

        for flow, rejection_reason in stream_flows(file_path, scenario_name, dataset_id, dataset_version):
            prov.rows_seen += 1
            if flow is None:
                prov.rows_rejected += 1
                reason_key = rejection_reason or "unknown"
                prov.rejection_reasons[reason_key] = prov.rejection_reasons.get(reason_key, 0) + 1
                all_rejection_reasons[reason_key] = all_rejection_reasons.get(reason_key, 0) + 1
            else:
                prov.rows_imported += 1
                current_batch.append(flow)

                nl = flow["native_label"]
                native_labels_seen[nl] = native_labels_seen.get(nl, 0) + 1
                cf = flow["canonical_attack_family"]
                canonical_families_seen[cf] = canonical_families_seen.get(cf, 0) + 1
                bl = flow["binary_label"]
                label_distribution[bl] = label_distribution.get(bl, 0) + 1
                if flow["label_mapping_confidence"] == 0.0 or flow["project_label"] == "UNMAPPED":
                    unmapped_labels.append(nl)

                # Write batch when full
                if len(current_batch) >= batch_size:
                    write_batch(current_batch)
                    current_batch = []

        # Write remaining records for this file
        if current_batch:
            write_batch(current_batch)
            current_batch = []

        all_provenance.append(prov.to_dict())
        total_rows_seen += prov.rows_seen
        total_rows_imported += prov.rows_imported
        total_rows_rejected += prov.rows_rejected
        print(f"    rows: seen={prov.rows_seen} imported={prov.rows_imported} rejected={prov.rows_rejected}")

    # Write any final remaining records
    if current_batch:
        write_batch(current_batch)

    jsonl_fh.close()
    if parquet_available:
        try:
            if parquet_writer:
                parquet_writer.close()
        except NameError:
            pass

    elapsed = time.time() - start_time

    # Generate manifests
    # Full SHA-256 combination: hash the concatenation of per-file hashes.
    # This gives a reproducible dataset-level checksum that changes if ANY
    # source file changes. Full 64-char hash (not truncated).
    combined_hash = hashlib.sha256()
    for p in all_provenance:
        combined_hash.update(p.get("file_checksum", "").encode())
    source_checksum = combined_hash.hexdigest()  # full 64-char SHA-256

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
        "dataset": "iot23",
        "mapping_version": get_mapping_version(),
        "label_source": get_label_source(),
        "mappings": get_mapping_dict(),
        "unmapped_labels_found": list(set(unmapped_labels)),
    }
    (output_dir / "label_mapping.json").write_text(json.dumps(mapping_data, indent=2, default=str))

    manifest = DatasetManifest(
        dataset_id=dataset_id,
        dataset_name="IoT-23",
        dataset_version=dataset_version,
        source="Stratosphere Research Laboratory",
        source_url="https://www.stratosphereips.org/datasets-iot23",
        license="See official dataset landing page and Zenodo record; not asserted by this adapter",
        source_format="zeek_conn_labeled",
        download_timestamp="",
        source_checksum=source_checksum,
        importer_version="2.0",
        normalization_version="2.0",
        feature_version="iot23-flow-v1",
        label_mapping_version="trapsig-iot23-v1",
        normalized_file="normalized/flows.jsonl",
        record_count=total_rows_imported,
        scenario_count=len(scenarios_seen),
        label_count=len(canonical_families_seen),
        created_at=datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        description=f"IoT-23 dataset imported from {input_dir}. {total_rows_imported} flows from {len(scenarios_seen)} scenarios. Streaming import (batch_size={batch_size}).",
    )
    (output_dir / "dataset_manifest.json").write_text(manifest.to_json())

    provenance_data = {
        "dataset_id": dataset_id,
        "dataset_version": dataset_version,
        "source_files": all_provenance,
        "label_mapping_version": get_mapping_version(),
        "label_source": get_label_source(),
        "importer_version": "2.0",
        "normalization_version": "2.0",
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    }
    (output_dir / "provenance.json").write_text(json.dumps(provenance_data, indent=2, default=str))

    audit_data = {
        "dataset_id": dataset_id,
        "dataset_version": dataset_version,
        "record_count": total_rows_imported,
        "scenario_count": len(scenarios_seen),
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
        "label_source": get_label_source(),
        "label_mapping_version": get_mapping_version(),
        "importer_version": "2.0",
        "batch_size": batch_size,
        "warnings": [],
    }
    if unmapped_labels:
        audit_data["warnings"].append(f"Unmapped labels found: {set(unmapped_labels)}")
    if total_rows_rejected > total_rows_seen * 0.1:
        audit_data["warnings"].append(f"High rejection rate: {total_rows_rejected}/{total_rows_seen} rows rejected")
    audit_data["warnings"].append(
        "IoT-23 labels are analyst-derived (manual analysis + labeling rules), NOT raw ground truth. "
        "label_source=EXTERNAL_DATASET; label provenance detail=ANALYST_DERIVED_EXTERNAL_ANNOTATION."
    )
    (output_dir / "audit.json").write_text(json.dumps(audit_data, indent=2, default=str))

    schema_data = {
        "dataset_id": dataset_id,
        "schema_version": "2.0",
        "description": "TRAPSIG canonical flow schema for IoT-23 (Zeek conn.log.labeled)",
        "reads_fields_from_file": True,
        "preserves_zeek_uid": True,
        "streaming": True,
        "batch_size": batch_size,
    }
    (output_dir / "schema.json").write_text(json.dumps(schema_data, indent=2, default=str))

    print(f"\nImport complete in {elapsed:.1f}s")
    print(f"  Records: {total_rows_imported} imported, {total_rows_rejected} rejected ({total_rows_seen} total)")
    print(f"  Scenarios: {len(scenarios_seen)}")
    print(f"  Native labels: {len(native_labels_seen)}")
    print(f"  Canonical families: {len(canonical_families_seen)}")
    print(f"  Unmapped labels: {len(set(unmapped_labels))}")
    print(f"  Output: {output_dir}")

    return {
        "dataset_id": dataset_id,
        "dataset_version": dataset_version,
        "records_imported": total_rows_imported,
        "records_rejected": total_rows_rejected,
        "scenarios": len(scenarios_seen),
        "source_checksum": source_checksum,
        "rows_seen": total_rows_seen,
        "label_distribution": label_distribution,
        "canonical_families": canonical_families_seen,
        "output_dir": str(output_dir),
        "unmapped_labels": list(set(unmapped_labels)),
        "streaming": True,
        "batch_size": batch_size,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Import IoT-23 dataset into TRAPSIG canonical schema")
    parser.add_argument("--input", required=True, help="Directory containing IoT-23 scenario folders")
    parser.add_argument("--output", required=True, help="Output directory for normalized data + manifests")
    parser.add_argument("--version", default="v1", help="Dataset version label")
    parser.add_argument("--batch-size", type=int, default=50000, help="Records per write batch")
    args = parser.parse_args(argv)

    result = import_iot23(Path(args.input), Path(args.output), args.version, args.batch_size)
    print(f"\nResult: {json.dumps(result, indent=2)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
