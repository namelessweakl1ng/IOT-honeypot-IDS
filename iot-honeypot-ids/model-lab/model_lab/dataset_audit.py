"""
Dataset audit — profiling, leakage detection, and quality assessment.

Produces machine-readable and human-readable audit reports for any
dataset version. The audit identifies:

- session count, campaign count, sessions per campaign
- class distribution
- label provenance breakdown
- duplicate sessions / event IDs
- feature leakage (label-derived features)
- train/test overlap (campaign-level)
- timestamp coverage
- synthetic vs real data
- unique campaign ratio (the key metric: if every session has a unique
  campaign, campaign-level generalization is NOT testable)

Usage:
    from model_lab.dataset_audit import audit_dataset
    report = audit_dataset("v1")
    print(report.summary())
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import pandas as pd


# Known leaky features — imported from the single source of truth in features.py
# to prevent dual-maintenance drift.
import sys as _sys
from pathlib import Path as _Path
_ml_path = _Path(__file__).resolve().parents[2] / "dashboard" / "ml"
if str(_ml_path) not in _sys.path:
    _sys.path.insert(0, str(_ml_path))
try:
    from features import LEAKY_FEATURES  # type: ignore
except ImportError:
    # Fallback if features module is unavailable
    LEAKY_FEATURES = [
        "contains_path_traversal",
        "contains_command_injection",
        "contains_default_credentials",
    ]

# Feature classification: each feature is tagged with a category
FEATURE_CATEGORIES = {
    # Behavioral — observable at detection time, safe for ML
    "event_count": "behavioral",
    "duration_s": "behavioral",
    "bytes_in_total": "behavioral",
    "bytes_out_total": "behavioral",
    "auth_attempts": "behavioral",
    "auth_successes": "behavioral",
    "auth_failure_ratio": "behavioral",
    "unique_usernames": "behavioral",
    "command_count": "behavioral",
    "command_diversity": "behavioral",
    "http_request_count": "behavioral",
    "http_uri_diversity": "behavioral",
    "http_status_4xx_ratio": "behavioral",
    "http_status_5xx_ratio": "behavioral",
    "unique_protocols": "behavioral",
    "devices_touched": "behavioral",
    "ports_touched": "behavioral",
    "time_between_events_mean_s": "behavioral",
    "time_between_events_stdev_s": "behavioral",
    "request_rate_per_min": "behavioral",
    "auth_failure_rate_per_min": "behavioral",
    "is_recon_only": "behavioral",  # derived from behavior, not from classification
    # Label-derived — LEAKY, must be excluded from classifier training
    "contains_path_traversal": "label_derived",
    "contains_command_injection": "label_derived",
    "contains_default_credentials": "label_derived",
}


@dataclass
class DatasetAuditReport:
    """Machine-readable audit report."""
    dataset_version: str
    session_count: int
    campaign_count: int
    sessions_per_campaign: Dict[str, int]  # campaign_id → session count
    unique_campaign_ratio: float  # 1.0 = every session is its own campaign (BAD)
    class_distribution: Dict[str, int]
    label_sources: Dict[str, int]  # scenario: N, synthetic: N, etc.
    duplicate_session_ids: List[str]
    duplicate_count: int
    leaky_features: List[str]
    leaky_feature_exposure: Dict[str, float]  # feature → fraction of rows where it's non-zero
    timestamp_coverage: Dict[str, str]  # earliest, latest
    environments: Dict[str, int]  # lab: N, synthetic: N
    feature_categories: Dict[str, List[str]]  # category → features
    warnings: List[str] = field(default_factory=list)
    hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)

    def summary(self) -> str:
        """Human-readable summary."""
        lines = [
            f"DATASET AUDIT: v{self.dataset_version}",
            f"{'='*60}",
            f"Sessions:          {self.session_count}",
            f"Campaigns:         {self.campaign_count}",
            f"Unique camp ratio: {self.unique_campaign_ratio:.2f}",
            f"  ({'WARNING: every session is its own campaign' if self.unique_campaign_ratio >= 0.95 else 'OK: multiple sessions per campaign exist'})",
            f"",
            f"Class distribution:",
        ]
        for label, count in sorted(self.class_distribution.items()):
            lines.append(f"  {label:30s} {count:4d}")
        lines.append(f"")
        lines.append(f"Label sources:")
        for source, count in sorted(self.label_sources.items()):
            lines.append(f"  {source:30s} {count:4d}")
        lines.append(f"")
        lines.append(f"Environments:")
        for env, count in sorted(self.environments.items()):
            lines.append(f"  {env:30s} {count:4d}")
        lines.append(f"")
        if self.duplicate_count > 0:
            lines.append(f"DUPLICATES: {self.duplicate_count} duplicate session IDs found")
        else:
            lines.append(f"Duplicates: 0 (no duplicate session IDs)")
        lines.append(f"")
        lines.append(f"Leaky features: {len(self.leaky_features)}")
        for lf in self.leaky_features:
            exposure = self.leaky_feature_exposure.get(lf, 0)
            lines.append(f"  {lf:40s} exposure={exposure:.2%}")
        lines.append(f"")
        if self.warnings:
            lines.append(f"WARNINGS:")
            for w in self.warnings:
                lines.append(f"  ⚠ {w}")
        lines.append(f"")
        lines.append(f"Hash: {self.hash}")
        return "\n".join(lines)


def audit_dataset(
    csv_path: Path | str,
    dataset_version: str = "v1",
    feature_names: Optional[List[str]] = None,
) -> DatasetAuditReport:
    """Audit a dataset CSV file and produce a report.

    Args:
        csv_path: Path to sessions.csv
        dataset_version: Version label (v1, v2, etc.)
        feature_names: List of feature column names. If None, auto-detect.
    """
    csv_path = Path(csv_path)
    if not csv_path.exists():
        raise FileNotFoundError(f"Dataset not found: {csv_path}")

    df = pd.read_csv(csv_path)
    n = len(df)

    # Auto-detect feature columns if not provided
    if feature_names is None:
        meta_cols = {"session_id", "campaign_id", "scenario_id", "label", "label_source",
                     "run_id", "source_ip", "target_honeypot", "protocol", "start_time",
                     "end_time", "dataset_version", "feature_version", "environment",
                     "duration_s", "event_count", "created_at"}
        feature_names = [c for c in df.columns if c not in meta_cols]

    # Campaign analysis
    campaign_ids = df.get("campaign_id", pd.Series()).tolist()
    campaign_counts = Counter(campaign_ids)
    campaign_count = len(campaign_counts)
    unique_campaign_ratio = 1.0 if n == 0 else campaign_count / n

    sessions_per_campaign = {cid: cnt for cid, cnt in campaign_counts.most_common(20)}

    # Class distribution
    class_dist = Counter(df.get("label", pd.Series()).tolist())

    # Label sources
    label_sources = Counter(df.get("label_source", pd.Series()).fillna("unknown").tolist())

    # Environments
    environments = Counter(df.get("environment", pd.Series()).fillna("unknown").tolist())

    # Duplicates
    session_ids = df.get("session_id", pd.Series()).tolist()
    seen = set()
    duplicates = []
    for sid in session_ids:
        if sid in seen:
            duplicates.append(str(sid))
        seen.add(sid)

    # Leaky features
    leaky_present = [f for f in LEAKY_FEATURES if f in df.columns]
    leaky_exposure = {}
    for lf in leaky_present:
        non_zero = (df[lf] != 0).sum()
        leaky_exposure[lf] = float(non_zero / n) if n > 0 else 0.0

    # Feature categories
    feature_cats: Dict[str, List[str]] = {}
    for fn in feature_names:
        cat = FEATURE_CATEGORIES.get(fn, "unknown")
        feature_cats.setdefault(cat, []).append(fn)

    # Timestamp coverage
    ts_col = "start_time" if "start_time" in df.columns else "created_at" if "created_at" in df.columns else None
    timestamp_coverage = {}
    if ts_col and ts_col in df.columns:
        ts_series = pd.to_datetime(df[ts_col], errors="coerce").dropna()
        if len(ts_series) > 0:
            timestamp_coverage = {
                "earliest": ts_series.min().isoformat(),
                "latest": ts_series.max().isoformat(),
            }

    # Compute hash — full SHA-256 (64 hex chars) for research provenance.
    # Previous versions truncated to 16 chars; this was a defect corrected
    # in Pass 3. Full hash ensures collision-resistant dataset identification.
    hash_str = hashlib.sha256(
        pd.util.hash_pandas_object(df, index=True).values.tobytes()
    ).hexdigest() if n > 0 else ""

    # Warnings
    warnings = []
    if unique_campaign_ratio >= 0.95:
        warnings.append(
            "Dataset has ~1 session per campaign. Campaign-level generalization is NOT valid. "
            "Run scenarios with repetitions > 1 to produce multiple sessions per campaign."
        )
    if n < 100:
        warnings.append(f"Dataset is small ({n} sessions). Results may not be statistically meaningful.")
    if leaky_present:
        warnings.append(
            f"Dataset contains {len(leaky_present)} leaky features: {', '.join(leaky_present)}. "
            "These must be excluded from classifier training (use feature_version=v2)."
        )
    if "synthetic" in str(label_sources).lower() or "SYNTHETIC" in str(label_sources).upper():
        warnings.append(
            "Dataset contains synthetic/bootstrap data. Do not use as final research evidence. "
            "Generate real experimental data via the campaign runner."
        )
    if duplicates:
        warnings.append(f"{len(duplicates)} duplicate session IDs found. Deduplicate before training.")
    min_class = min(class_dist.values()) if class_dist else 0
    max_class = max(class_dist.values()) if class_dist else 0
    if max_class > 0 and min_class / max_class < 0.3:
        warnings.append(
            f"Class imbalance detected: min={min_class}, max={max_class}. "
            "Consider class_weight='balanced' or resampling."
        )

    return DatasetAuditReport(
        dataset_version=dataset_version,
        session_count=n,
        campaign_count=campaign_count,
        sessions_per_campaign=sessions_per_campaign,
        unique_campaign_ratio=unique_campaign_ratio,
        class_distribution=dict(class_dist),
        label_sources=dict(label_sources),
        duplicate_session_ids=duplicates[:20],
        duplicate_count=len(duplicates),
        leaky_features=leaky_present,
        leaky_feature_exposure=leaky_exposure,
        timestamp_coverage=timestamp_coverage,
        environments=dict(environments),
        feature_categories=feature_cats,
        warnings=warnings,
        hash=hash_str,
    )
