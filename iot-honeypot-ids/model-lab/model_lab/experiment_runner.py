"""Experiment runner — proper train/test isolation.

CRITICAL FIX (Issue #1 + #2 from the research hardening spec):
  The previous architecture trained on ALL data, then evaluated on a split.
  The model saw test data during fitting → invalid held-out evaluation.

  This module implements the correct flow:
    DATASET → SPLIT → FREEZE TEST SET → TRAIN → EVALUATE → RECORD

  The test set is NEVER passed into model fitting. The experiment runner
  is the ONLY supported path for research evaluation. Direct train() +
  evaluate() calls are deprecated for research use.

Usage:
    from model_lab.experiment_runner import ExperimentRunner, ExperimentSpec, SplitProtocol
    spec = ExperimentSpec(
        dataset_path="model-lab/datasets/v1/sessions.csv",
        algorithm="random_forest",
        split_protocol=SplitProtocol.SESSION_LEVEL,
        seed=42,
        feature_version="v2",
    )
    result = ExperimentRunner.run(spec)
"""
from __future__ import annotations

import hashlib
import json
import platform
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

# Add project paths
_ROOT = Path(__file__).resolve().parents[2]
_SHARED = _ROOT / "shared"
_ML = _ROOT / "dashboard" / "ml"
_MODEL_LAB = _ROOT / "model-lab"
for p in [_SHARED, _ML, _MODEL_LAB]:
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))


class SplitProtocol(str, Enum):
    """Supported split protocols for experiment evaluation."""
    SESSION_LEVEL = "session_level"
    CAMPAIGN = "campaign"
    TEMPORAL = "temporal"
    UNKNOWN_FAMILY = "unknown_family"
    HONEYPOT = "honeypot"


class ExperimentStatus(str, Enum):
    PLANNED = "planned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    INVALID = "invalid"


@dataclass
class ExperimentSpec:
    """Specification for a single experiment run."""
    dataset_path: str
    algorithm: str = "random_forest"
    split_protocol: SplitProtocol = SplitProtocol.SESSION_LEVEL
    seed: int = 42
    feature_version: str = "v2"
    test_ratio: float = 0.2
    label_source: str = "synthetic"  # must be ground truth source
    notes: str = ""
    # Optional: held-out scenario for unknown-family evaluation
    held_out_scenarios: List[str] = field(default_factory=list)

    @property
    def experiment_id(self) -> str:
        """Deterministic experiment ID from spec parameters."""
        h = hashlib.sha1()
        h.update(self.algorithm.encode())
        h.update(str(self.seed).encode())
        h.update(self.split_protocol.value.encode())
        h.update(self.feature_version.encode())
        h.update(str(self.test_ratio).encode())
        return f"exp-{h.hexdigest()[:12]}"


@dataclass
class MetricResult:
    """Metrics from a single experiment run."""
    accuracy: float = 0.0
    precision_macro: float = 0.0
    recall_macro: float = 0.0
    f1_macro: float = 0.0
    f1_weighted: float = 0.0
    precision_weighted: float = 0.0
    recall_weighted: float = 0.0
    false_positive_rate: float = 0.0
    false_negative_rate: float = 0.0
    confusion_matrix: List[List[int]] = field(default_factory=list)
    confusion_matrix_labels: List[str] = field(default_factory=list)
    per_class: Dict[str, Dict[str, float]] = field(default_factory=dict)
    n_train: int = 0
    n_test: int = 0
    train_classes: List[str] = field(default_factory=list)
    test_classes: List[str] = field(default_factory=list)


@dataclass
class ExperimentResult:
    """Complete result of an experiment run."""
    experiment_id: str
    spec: Dict[str, Any]
    status: ExperimentStatus = ExperimentStatus.PLANNED
    metrics: Optional[MetricResult] = None
    train_ids: List[str] = field(default_factory=list)
    test_ids: List[str] = field(default_factory=list)
    train_count: int = 0
    test_count: int = 0
    start_time: str = ""
    end_time: str = ""
    git_commit: str = ""
    environment: Dict[str, str] = field(default_factory=dict)
    limitations: List[str] = field(default_factory=list)
    invalid_reasons: List[str] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        d["spec"]["split_protocol"] = self.spec.get("split_protocol", "")
        if self.metrics:
            d["metrics"] = asdict(self.metrics)
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _get_git_commit() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=5,
            cwd=str(_ROOT),
        )
        return result.stdout.strip()[:12] if result.returncode == 0 else "unknown"
    except Exception:
        return "unknown"


def _capture_environment() -> Dict[str, str]:
    """Capture the execution environment for reproducibility."""
    env = {
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "architecture": platform.machine(),
    }
    for mod_name in ["numpy", "pandas", "sklearn"]:
        try:
            mod = __import__(mod_name)
            env[f"{mod_name}_version"] = getattr(mod, "__version__", "unknown")
        except ImportError:
            env[f"{mod_name}_version"] = "not_installed"
    return env


class ExperimentRunner:
    """Runs experiments with proper train/test isolation.

    The CRITICAL invariant: the test set is NEVER passed into model fitting.
    The runner:
      1. Loads the dataset
      2. Splits into train/test (test set is FROZEN)
      3. Trains ONLY on training data
      4. Evaluates ONLY on test data
      5. Records the split, model, metrics, environment, git commit
      6. Marks the experiment VALID or INVALID
    """

    @staticmethod
    def run(spec: ExperimentSpec) -> ExperimentResult:
        """Run a single experiment with proper train/test isolation."""
        result = ExperimentResult(
            experiment_id=spec.experiment_id,
            spec={
                "dataset_path": spec.dataset_path,
                "algorithm": spec.algorithm,
                "split_protocol": spec.split_protocol.value,
                "seed": spec.seed,
                "feature_version": spec.feature_version,
                "test_ratio": spec.test_ratio,
                "label_source": spec.label_source,
                "held_out_scenarios": spec.held_out_scenarios,
                "notes": spec.notes,
            },
            start_time=_now_iso(),
            git_commit=_get_git_commit(),
            environment=_capture_environment(),
        )
        result.status = ExperimentStatus.RUNNING

        try:
            # 1. Load dataset
            ds_path = Path(spec.dataset_path)
            if not ds_path.exists():
                result.status = ExperimentStatus.FAILED
                result.error = f"dataset not found: {ds_path}"
                result.end_time = _now_iso()
                return result

            df = pd.read_csv(ds_path)
            if "label" not in df.columns or "session_id" not in df.columns:
                result.status = ExperimentStatus.INVALID
                result.invalid_reasons.append("dataset missing 'label' or 'session_id' column")
                result.end_time = _now_iso()
                return result

            # 2. Validate label provenance
            # Rule-engine labels CANNOT be used as ground truth for training
            label_source = spec.label_source
            if label_source == "rule_engine":
                result.status = ExperimentStatus.INVALID
                result.invalid_reasons.append(
                    "label_source=rule_engine — rule output is NOT ground truth. "
                    "Using it as training labels creates circular evaluation."
                )
                result.end_time = _now_iso()
                return result

            # 3. Validate features (leakage check)
            if _SHARED not in sys.path:
                sys.path.insert(0, str(_SHARED))
            from schemas.leakage_audit import validate_features_for_training, audit_feature_set
            feature_names = _get_feature_names(spec.feature_version)
            try:
                validated_features = validate_features_for_training(feature_names, allow_leaky=False)
            except ValueError as exc:
                result.status = ExperimentStatus.INVALID
                result.invalid_reasons.append(f"leaky features detected: {exc}")
                result.end_time = _now_iso()
                return result

            # 4. Split data — BEFORE training
            train_idx, test_idx = ExperimentRunner._split(df, spec)

            if not test_idx:
                result.status = ExperimentStatus.INVALID
                result.invalid_reasons.append("test set is empty after split")
                result.end_time = _now_iso()
                return result

            # 5. FREEZE test set — extract train/test subsets
            train_df = df.iloc[train_idx]
            test_df = df.iloc[test_idx]

            # Verify NO overlap between train and test session_ids
            train_session_ids = set(train_df["session_id"].tolist())
            test_session_ids = set(test_df["session_id"].tolist())
            overlap = train_session_ids & test_session_ids
            if overlap:
                result.status = ExperimentStatus.INVALID
                result.invalid_reasons.append(
                    f"train/test session overlap detected: {len(overlap)} sessions in both"
                )
                result.end_time = _now_iso()
                return result

            # 6. Check class support
            train_classes = set(train_df["label"].astype(str).tolist())
            test_classes = set(test_df["label"].astype(str).tolist())
            unseen_test_classes = test_classes - train_classes
            if unseen_test_classes and spec.split_protocol != SplitProtocol.UNKNOWN_FAMILY:
                result.limitations.append(
                    f"test set contains classes not in training: {unseen_test_classes}"
                )

            # 7. Train ONLY on training data
            from models import train as train_model, predict, load
            models_dir = _MODEL_LAB / "models"

            X_train = train_df[feature_names].to_dict(orient="records")
            y_train = train_df["label"].astype(str).tolist()

            if not X_train or not y_train:
                result.status = ExperimentStatus.INVALID
                result.invalid_reasons.append("training set is empty after split")
                result.end_time = _now_iso()
                return result

            model_id = f"{spec.algorithm}-{spec.experiment_id}"
            meta = train_model(
                X=X_train,
                y=y_train,
                algorithm=spec.algorithm,
                seed=spec.seed,
                models_dir=models_dir,
                model_id=model_id,
                dataset_version=str(spec.dataset_path),
                feature_version=spec.feature_version,
                notes=f"experiment={spec.experiment_id}, split={spec.split_protocol.value}",
            )

            # 8. Evaluate ONLY on test data
            X_test = test_df[feature_names].to_dict(orient="records")
            y_true = test_df["label"].astype(str).tolist()

            preds = predict(models_dir, model_id, X_test)
            y_pred = [p["prediction"] for p in preds]

            # 9. Compute metrics
            from sklearn.metrics import (
                accuracy_score, precision_score, recall_score, f1_score,
                confusion_matrix, classification_report,
            )

            labels = sorted(set(y_true) | set(y_pred))
            metrics = MetricResult(
                accuracy=float(accuracy_score(y_true, y_pred)),
                precision_macro=float(precision_score(y_true, y_pred, average="macro", labels=labels, zero_division=0)),
                recall_macro=float(recall_score(y_true, y_pred, average="macro", labels=labels, zero_division=0)),
                f1_macro=float(f1_score(y_true, y_pred, average="macro", labels=labels, zero_division=0)),
                f1_weighted=float(f1_score(y_true, y_pred, average="weighted", labels=labels, zero_division=0)),
                precision_weighted=float(precision_score(y_true, y_pred, average="weighted", labels=labels, zero_division=0)),
                recall_weighted=float(recall_score(y_true, y_pred, average="weighted", labels=labels, zero_division=0)),
                confusion_matrix=confusion_matrix(y_true, y_pred, labels=labels).tolist(),
                confusion_matrix_labels=labels,
                n_train=len(train_idx),
                n_test=len(test_idx),
                train_classes=sorted(train_classes),
                test_classes=sorted(test_classes),
            )

            # Per-class metrics
            report = classification_report(y_true, y_pred, labels=labels, output_dict=True, zero_division=0)
            for label in labels:
                if label in report:
                    metrics.per_class[label] = {
                        "precision": report[label]["precision"],
                        "recall": report[label]["recall"],
                        "f1": report[label]["f1-score"],
                        "support": report[label]["support"],
                    }

            # FPR/FNR
            from evaluate import _fpr, _fnr  # type: ignore
            metrics.false_positive_rate = float(_fpr(y_true, y_pred, labels))
            metrics.false_negative_rate = float(_fnr(y_true, y_pred, labels))

            result.metrics = metrics
            result.train_ids = train_df["session_id"].tolist()
            result.test_ids = test_df["session_id"].tolist()
            result.train_count = len(train_idx)
            result.test_count = len(test_idx)

            # 10. Check for class support sufficiency
            min_class_support = 2
            class_counts = train_df["label"].value_counts()
            insufficient = class_counts[class_counts < min_class_support]
            if not insufficient.empty:
                result.limitations.append(
                    f"insufficient class support in training: {dict(insufficient)} (< {min_class_support})"
                )

            # 11. Synthetic data limitation
            if "synthetic" in str(spec.dataset_path).lower() or label_source == "synthetic":
                result.limitations.append(
                    "SYNTHETIC DEVELOPMENT DATA — results are NOT evidence of real-world IDS performance"
                )

            result.status = ExperimentStatus.COMPLETED
            result.end_time = _now_iso()

        except Exception as exc:
            result.status = ExperimentStatus.FAILED
            result.error = f"{exc.__class__.__name__}: {exc}"
            result.end_time = _now_iso()

        return result

    @staticmethod
    def _split(df: pd.DataFrame, spec: ExperimentSpec) -> Tuple[List[int], List[int]]:
        """Split the dataset according to the specified protocol.

        CRITICAL: this split happens BEFORE training. The test set is frozen.
        """
        from evaluate import session_level_split  # type: ignore

        if spec.split_protocol == SplitProtocol.SESSION_LEVEL:
            train_idx, test_idx = session_level_split(
                session_ids=df["session_id"].tolist(),
                labels=df["label"].astype(str).tolist(),
                test_ratio=spec.test_ratio,
                seed=spec.seed,
            )
        elif spec.split_protocol == SplitProtocol.CAMPAIGN:
            if "campaign_id" not in df.columns:
                # Fallback to session-level if no campaign_id
                train_idx, test_idx = session_level_split(
                    session_ids=df["session_id"].tolist(),
                    labels=df["label"].astype(str).tolist(),
                    test_ratio=spec.test_ratio,
                    seed=spec.seed,
                )
            else:
                # Campaign-level split: no campaign in both train and test
                from sklearn.model_selection import train_test_split
                unique_campaigns = df["campaign_id"].unique()
                train_campaigns, test_campaigns = train_test_split(
                    unique_campaigns, test_size=spec.test_ratio, random_state=spec.seed,
                )
                train_idx = df[df["campaign_id"].isin(train_campaigns)].index.tolist()
                test_idx = df[df["campaign_id"].isin(test_campaigns)].index.tolist()
        elif spec.split_protocol == SplitProtocol.TEMPORAL:
            if "start_time" not in df.columns and "created_at" not in df.columns:
                raise ValueError("temporal split requires 'start_time' or 'created_at' column")
            ts_col = "start_time" if "start_time" in df.columns else "created_at"
            # Sort by timestamp, earlier → train, later → test
            df_sorted = df.sort_values(ts_col)
            cut = max(1, int(len(df_sorted) * (1 - spec.test_ratio)))
            train_idx = df_sorted.index[:cut].tolist()
            test_idx = df_sorted.index[cut:].tolist()
        elif spec.split_protocol == SplitProtocol.HONEYPOT:
            if "honeypot" not in df.columns:
                raise ValueError("honeypot split requires 'honeypot' column")
            unique_honeypots = df["honeypot"].unique()
            if len(unique_honeypots) < 2:
                raise ValueError("honeypot split requires at least 2 honeypot types")
            # Hold out the last honeypot for testing
            train_honeypots = unique_honeypots[:-1]
            test_honeypot = unique_honeypots[-1]
            train_idx = df[df["honeypot"].isin(train_honeypots)].index.tolist()
            test_idx = df[df["honeypot"] == test_honeypot].index.tolist()
        else:
            # Default: session-level
            train_idx, test_idx = session_level_split(
                session_ids=df["session_id"].tolist(),
                labels=df["label"].astype(str).tolist(),
                test_ratio=spec.test_ratio,
                seed=spec.seed,
            )

        return train_idx, test_idx


def _get_feature_names(feature_version: str) -> List[str]:
    """Get the feature names for the specified version."""
    from features import FEATURE_NAMES, FEATURE_NAMES_V2  # type: ignore
    if feature_version == "v2":
        return FEATURE_NAMES_V2
    return FEATURE_NAMES


def run_multi_seed(
    dataset_path: str,
    algorithm: str = "random_forest",
    split_protocol: SplitProtocol = SplitProtocol.SESSION_LEVEL,
    feature_version: str = "v2",
    label_source: str = "synthetic",
    seeds: List[int] = None,
) -> List[ExperimentResult]:
    """Run multiple seeds and return all results.

    Default seeds: [42, 123, 456, 789, 1337] (pre-registered before seeing results).
    """
    if seeds is None:
        seeds = [42, 123, 456, 789, 1337]

    results = []
    for seed in seeds:
        spec = ExperimentSpec(
            dataset_path=dataset_path,
            algorithm=algorithm,
            split_protocol=split_protocol,
            seed=seed,
            feature_version=feature_version,
            label_source=label_source,
        )
        result = ExperimentRunner.run(spec)
        results.append(result)

    return results


def aggregate_results(results: List[ExperimentResult]) -> Dict[str, Any]:
    """Aggregate multi-seed results into mean ± std for each metric."""
    if not results:
        return {"error": "no results to aggregate"}

    valid_results = [r for r in results if r.status == ExperimentStatus.COMPLETED and r.metrics]
    if not valid_results:
        return {
            "total_runs": len(results),
            "valid_runs": 0,
            "invalid_runs": len(results),
        }

    metric_names = ["accuracy", "precision_macro", "recall_macro", "f1_macro",
                    "f1_weighted", "false_positive_rate", "false_negative_rate"]

    agg = {}
    for metric_name in metric_names:
        values = [getattr(r.metrics, metric_name) for r in valid_results]
        arr = np.array(values)
        agg[metric_name] = {
            "mean": float(arr.mean()),
            "std": float(arr.std()),
            "median": float(np.median(arr)),
            "min": float(arr.min()),
            "max": float(arr.max()),
        }

    return {
        "total_runs": len(results),
        "valid_runs": len(valid_results),
        "invalid_runs": len(results) - len(valid_results),
        "seeds": [r.spec["seed"] for r in valid_results],
        "algorithm": valid_results[0].spec["algorithm"],
        "split_protocol": valid_results[0].spec["split_protocol"],
        "feature_version": valid_results[0].spec["feature_version"],
        "metrics": agg,
    }
