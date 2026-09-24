"""
Campaign / session / experiment data model.

This module defines the provenance-tracking data structures that connect
attack scenarios → campaigns → sessions → datasets → models → detections.

The key insight: one campaign can produce multiple sessions. The previous
dataset treated every row as an independent campaign (campaign_id was
unique per row), which made campaign-level generalization impossible to
evaluate.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


# --------------------------------------------------------------------------- #
# Campaign — a logically related attack operation
# --------------------------------------------------------------------------- #

@dataclass
class Campaign:
    """A campaign groups one or more sessions from a related attack operation."""
    campaign_id: str
    scenario_id: str
    scenario_version: str = "1.0"
    attacker_id: str = "pc2-attacker"
    target_id: str = "pi-honeypot"
    honeypot: str = ""
    start_time: str = ""
    end_time: str = ""
    status: str = "planned"  # planned, running, completed, failed
    label: str = ""  # ground-truth label from scenario
    label_source: str = "scenario"
    environment: str = "lab"
    repetitions: int = 1
    session_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @staticmethod
    def create(scenario_id: str, label: str, honeypot: str = "", repetitions: int = 1) -> "Campaign":
        """Create a new campaign with auto-generated ID."""
        ts = int(time.time())
        short_uuid = uuid.uuid4().hex[:8]
        campaign_id = f"camp-{scenario_id}-{ts}-{short_uuid}"
        return Campaign(
            campaign_id=campaign_id,
            scenario_id=scenario_id,
            honeypot=honeypot,
            label=label,
            start_time=_now_iso(),
            repetitions=repetitions,
        )


# --------------------------------------------------------------------------- #
# Session — one concrete interaction sequence with a honeypot
# --------------------------------------------------------------------------- #

@dataclass
class SessionRecord:
    """A session record with full provenance."""
    session_id: str
    campaign_id: str
    scenario_id: str
    label: str
    label_source: str  # scenario, rule, analyst, synthetic, unlabeled
    run_id: str  # unique per execution within a campaign
    source_ip: str = ""
    target_honeypot: str = ""
    protocol: str = ""
    start_time: str = ""
    end_time: str = ""
    duration_s: float = 0.0
    event_count: int = 0
    features: Dict[str, float] = field(default_factory=dict)
    feature_version: str = "v2"
    dataset_version: str = ""
    environment: str = "lab"  # lab, synthetic, demo

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_csv_row(self) -> Dict[str, Any]:
        """Flatten to a CSV-compatible row (features as top-level columns)."""
        row: Dict[str, Any] = {
            "session_id": self.session_id,
            "campaign_id": self.campaign_id,
            "scenario_id": self.scenario_id,
            "label": self.label,
            "label_source": self.label_source,
            "run_id": self.run_id,
            "source_ip": self.source_ip,
            "target_honeypot": self.target_honeypot,
            "protocol": self.protocol,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_s": self.duration_s,
            "event_count": self.event_count,
            "dataset_version": self.dataset_version,
            "feature_version": self.feature_version,
            "environment": self.environment,
        }
        # Flatten features as top-level columns
        for k, v in self.features.items():
            row[k] = v
        return row

    @staticmethod
    def from_csv_row(row: Dict[str, Any], feature_names: List[str]) -> "SessionRecord":
        """Reconstruct from a CSV row."""
        features = {fn: float(row.get(fn, 0) or 0) for fn in feature_names}
        return SessionRecord(
            session_id=row.get("session_id", ""),
            campaign_id=row.get("campaign_id", ""),
            scenario_id=row.get("scenario_id", ""),
            label=row.get("label", ""),
            label_source=row.get("label_source", ""),
            run_id=row.get("run_id", ""),
            source_ip=row.get("source_ip", ""),
            target_honeypot=row.get("target_honeypot", ""),
            protocol=row.get("protocol", ""),
            start_time=row.get("start_time", ""),
            end_time=row.get("end_time", ""),
            duration_s=float(row.get("duration_s", 0) or 0),
            event_count=int(float(row.get("event_count", 0) or 0)),
            features=features,
            feature_version=row.get("feature_version", "v2"),
            dataset_version=row.get("dataset_version", ""),
            environment=row.get("environment", "synthetic"),
        )


# --------------------------------------------------------------------------- #
# Experiment configuration
# --------------------------------------------------------------------------- #

@dataclass
class ExperimentConfig:
    """Reproducible experiment configuration."""
    experiment_id: str
    training_scenarios: List[str]  # scenario IDs for training
    held_out_scenarios: List[str]  # scenario IDs held out (unknown family)
    repetitions: int = 10
    feature_version: str = "v2"
    split_strategy: str = "campaign"  # campaign, temporal, unknown_family, session
    test_ratio: float = 0.2
    seed: int = 42
    models: List[str] = field(default_factory=lambda: ["supervised", "anomaly", "hybrid"])
    algorithm: str = "random_forest"
    hyperparameters: Dict[str, Any] = field(default_factory=lambda: {
        "n_estimators": 100, "max_depth": 8, "class_weight": "balanced"
    })
    created_at: str = ""
    git_commit: str = ""
    configuration_hash: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = _now_iso()
        if not self.experiment_id:
            self.experiment_id = f"exp-{int(time.time())}-{uuid.uuid4().hex[:6]}"
        # Compute a configuration hash for reproducibility verification
        config_str = json.dumps({
            "training_scenarios": sorted(self.training_scenarios),
            "held_out_scenarios": sorted(self.held_out_scenarios),
            "repetitions": self.repetitions,
            "feature_version": self.feature_version,
            "split_strategy": self.split_strategy,
            "test_ratio": self.test_ratio,
            "seed": self.seed,
            "models": sorted(self.models),
            "algorithm": self.algorithm,
            "hyperparameters": self.hyperparameters,
        }, sort_keys=True)
        self.configuration_hash = hashlib.sha256(config_str.encode()).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)


# --------------------------------------------------------------------------- #
# Experiment results
# --------------------------------------------------------------------------- #

@dataclass
class ModelResult:
    """Results from one model variant in an experiment."""
    model_type: str  # supervised, anomaly, hybrid, rule
    model_id: str = ""
    training_metrics: Dict[str, Any] = field(default_factory=dict)
    held_out_metrics: Dict[str, Any] = field(default_factory=dict)
    unknown_metrics: Dict[str, Any] = field(default_factory=dict)
    predictions: List[Dict[str, Any]] = field(default_factory=list)
    feature_importances: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ExperimentResults:
    """Complete results from an experiment run."""
    experiment_id: str
    config: Dict[str, Any]
    dataset_info: Dict[str, Any]
    model_results: List[Dict[str, Any]]  # List of ModelResult.to_dict()
    split_info: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    created_at: str = ""
    status: str = "completed"  # completed, failed, partial

    def __post_init__(self):
        if not self.created_at:
            self.created_at = _now_iso()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)


# --------------------------------------------------------------------------- #
# Dataset version metadata
# --------------------------------------------------------------------------- #

@dataclass
class DatasetVersion:
    """Immutable-ish dataset version record."""
    dataset_id: str
    dataset_version: str  # v1, v2, v3, ...
    created_at: str
    source_experiments: List[str] = field(default_factory=list)
    session_count: int = 0
    campaign_count: int = 0
    feature_version: str = "v2"
    label_schema_version: str = "1.0"
    hash: str = ""
    description: str = ""
    label_distribution: Dict[str, int] = field(default_factory=dict)
    campaigns: List[str] = field(default_factory=list)  # campaign IDs
    label_sources: Dict[str, int] = field(default_factory=dict)  # scenario: N, synthetic: N, ...

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)
