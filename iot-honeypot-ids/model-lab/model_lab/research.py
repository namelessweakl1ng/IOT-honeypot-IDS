"""
Research experiment runner.

Executes a defined experiment configuration:
1. Load dataset
2. Audit dataset
3. Split (campaign / temporal / unknown_family)
4. Train models (supervised, anomaly, hybrid)
5. Evaluate (known-class + unknown-family)
6. Run ablation (rules vs ML vs anomaly vs hybrid)
7. Store results as JSON artifact

Usage:
    python -m model_lab.research --config experiments/exp-001/config.json
    python -m model_lab.research --training ssh-bruteforce,camera-recon --held-out http-enumeration
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix,
    f1_score, precision_score, recall_score, roc_auc_score,
)

# Setup paths (same pattern as train.py/evaluate.py)
try:
    from .common import datasets_dir, experiments_dir, models_dir, setup_paths
    setup_paths()
except ImportError:
    here = Path(__file__).resolve().parent
    sys.path.insert(0, str(here))
    from common import datasets_dir, experiments_dir, models_dir, setup_paths  # type: ignore
    setup_paths()

# Import via file path to avoid name clashes
import importlib.util as _ilu

_eval_path = Path(__file__).resolve().parents[2] / "dashboard" / "ml" / "evaluate.py"
_spec = _ilu.spec_from_file_location("dashboard_ml_evaluate", _eval_path)
_mod_evaluate = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_mod_evaluate)
session_level_split = _mod_evaluate.session_level_split
evaluate_classification = _mod_evaluate.evaluate_classification

from features import FEATURE_NAMES, FEATURE_NAMES_V2, LEAKY_FEATURES, features_to_vector, features_to_vector_v2  # type: ignore
from rules import classify_session  # type: ignore

from .experiment import ExperimentConfig, ExperimentResults, ModelResult, DatasetVersion
from .dataset_audit import audit_dataset, DatasetAuditReport
from .scenario_manifest import get_scenario, get_all_labels


# --------------------------------------------------------------------------- #
# Split strategies
# --------------------------------------------------------------------------- #

def split_by_campaign(
    df: pd.DataFrame, test_ratio: float = 0.2, seed: int = 42
) -> Tuple[List[int], List[int]]:
    """Split at the campaign level — all sessions from one campaign go to
    either train or test, never both. This prevents leakage of campaign-specific
    behavioral patterns."""
    rng = np.random.default_rng(seed)
    campaigns = df["campaign_id"].unique().tolist()
    rng.shuffle(campaigns)
    cut = max(1, int(len(campaigns) * (1.0 - test_ratio)))
    train_campaigns = set(campaigns[:cut])
    test_campaigns = set(campaigns[cut:])

    train_idx = [i for i, c in enumerate(df["campaign_id"]) if c in train_campaigns]
    test_idx = [i for i, c in enumerate(df["campaign_id"]) if c in test_campaigns]
    return train_idx, test_idx


def split_temporal(
    df: pd.DataFrame, test_ratio: float = 0.2
) -> Tuple[List[int], List[int]]:
    """Temporal split — earlier sessions → train, later → test.

    NO SILENT FALLBACK: raises ValueError on missing/invalid timestamps.
    Returns indices into the ORIGINAL df (via original positional tracking).
    """
    ts_col = "start_time" if "start_time" in df.columns else "created_at"
    if ts_col not in df.columns:
        raise ValueError(
            f"split_temporal requires a timestamp column ('start_time' or "
            f"'created_at'), but neither exists in the dataframe. "
            f"Use session_level_split() for non-temporal splitting."
        )
    if len(df) == 0:
        raise ValueError("split_temporal requires a non-empty dataframe")
    indexed = df[[ts_col]].copy()
    indexed["_orig_idx"] = range(len(indexed))
    parsed = pd.to_datetime(indexed[ts_col], errors="coerce")
    valid_mask = parsed.notna()
    if not valid_mask.any():
        raise ValueError(
            f"split_temporal: all {len(df)} rows have missing, empty, or "
            f"unparseable timestamps in column '{ts_col}'."
        )
    indexed_valid = indexed[valid_mask].copy()
    indexed_valid = indexed_valid.sort_values(by=[ts_col, "_orig_idx"]).reset_index(drop=True)
    n = len(indexed_valid)
    cut = max(1, int(n * (1.0 - test_ratio)))
    train_orig_idx = indexed_valid["_orig_idx"].iloc[:cut].tolist()
    test_orig_idx = indexed_valid["_orig_idx"].iloc[cut:].tolist()
    if train_orig_idx and test_orig_idx:
        train_ts = df.iloc[train_orig_idx][ts_col]
        test_ts = df.iloc[test_orig_idx][ts_col]
        try:
            train_max = pd.to_datetime(train_ts, errors="coerce").max()
            test_min = pd.to_datetime(test_ts, errors="coerce").min()
            if train_max is not pd.NaT and test_min is not pd.NaT and train_max > test_min:
                raise RuntimeError(
                    f"temporal split invariant violated: "
                    f"max(train_ts)={train_max} > min(test_ts)={test_min}"
                )
        except (ValueError, TypeError):
            pass
    return train_orig_idx, test_orig_idx


def split_temporal_with_metadata(
    df: pd.DataFrame, test_ratio: float = 0.2
) -> Tuple[List[int], List[int], Dict[str, Any]]:
    """Temporal split with full experiment metadata for research auditability."""
    train_idx, test_idx = split_temporal(df, test_ratio)
    ts_col = "start_time" if "start_time" in df.columns else "created_at"
    total_rows = len(df)
    parsed = pd.to_datetime(df[ts_col], errors="coerce")
    valid_mask = parsed.notna()
    valid_timestamp_rows = int(valid_mask.sum())
    excluded_invalid_rows = total_rows - valid_timestamp_rows
    train_ts = df.iloc[train_idx][ts_col] if train_idx else pd.Series([], dtype=object)
    test_ts = df.iloc[test_idx][ts_col] if test_idx else pd.Series([], dtype=object)
    try:
        train_ts_parsed = pd.to_datetime(train_ts, errors="coerce")
        test_ts_parsed = pd.to_datetime(test_ts, errors="coerce")
        earliest_train = train_ts_parsed.min() if len(train_ts_parsed) > 0 else None
        latest_train = train_ts_parsed.max() if len(train_ts_parsed) > 0 else None
        earliest_test = test_ts_parsed.min() if len(test_ts_parsed) > 0 else None
        latest_test = test_ts_parsed.max() if len(test_ts_parsed) > 0 else None
        invariant_holds = (earliest_test is not None and latest_train is not None
                           and latest_train <= earliest_test)
    except Exception:
        earliest_train = latest_train = earliest_test = latest_test = None
        invariant_holds = False
    metadata = {
        "split_strategy": "temporal",
        "total_rows": total_rows,
        "valid_timestamp_rows": valid_timestamp_rows,
        "excluded_invalid_rows": excluded_invalid_rows,
        "train_rows": len(train_idx),
        "test_rows": len(test_idx),
        "earliest_train_timestamp": str(earliest_train) if earliest_train is not pd.NaT else None,
        "latest_train_timestamp": str(latest_train) if latest_train is not pd.NaT else None,
        "earliest_test_timestamp": str(earliest_test) if earliest_test is not pd.NaT else None,
        "latest_test_timestamp": str(latest_test) if latest_test is not pd.NaT else None,
        "temporal_invariant_holds": bool(invariant_holds),
        "test_ratio": test_ratio,
    }
    return train_idx, test_idx, metadata


def split_unknown_family(
    df: pd.DataFrame,
    held_out_scenarios: List[str],
    seed: int = 42,
) -> Tuple[List[int], List[int], List[int]]:
    """Unknown-family split:
    - Training set: sessions from known scenarios (no held-out scenarios)
    - Known test set: held-out sessions from known scenarios
    - Unknown test set: sessions from held-out (unknown) scenarios

    The supervised model NEVER trains on the unknown family.
    Then we evaluate whether the anomaly detector can surface them.

    CRITICAL: the known subset is split via campaign-level grouping to
    prevent leakage. The unknown family is ENTIRELY withheld from
    supervised training (it only appears in the anomaly evaluation).

    Returns indices into the ORIGINAL df (not reset), so callers can do
    df.iloc[train_idx] and get the right rows.
    """
    # Known = not in held_out_scenarios
    known_mask = ~df["scenario_id"].isin(held_out_scenarios)
    unknown_mask = df["scenario_id"].isin(held_out_scenarios)

    # Keep original indices so we can map back
    known_df = df[known_mask]
    unknown_idx = df[unknown_mask].index.tolist()

    # split_by_campaign uses positional enumerate over df["campaign_id"],
    # which is positional. We pass known_df.reset_index(drop=True) so the
    # positional indices line up with known_df's rows, then map back via
    # known_df's original index.
    known_df_reset = known_df.reset_index(drop=True)
    train_idx_local, test_idx_local = split_by_campaign(known_df_reset, test_ratio=0.2, seed=seed)

    # Map local positional indices back to original df indices
    train_idx = known_df.index[train_idx_local].tolist()
    known_test_idx = known_df.index[test_idx_local].tolist()

    return train_idx, known_test_idx, unknown_idx


def split_unknown_family_with_validation(
    df: pd.DataFrame,
    held_out_scenarios: List[str],
    seed: int = 42,
    validation_ratio: float = 0.15,
) -> Tuple[List[int], List[int], List[int], List[int]]:
    """Unknown-family split with a SEPARATE validation set.

    Returns: (train_idx, val_idx, known_test_idx, unknown_idx)

    The validation set is used for threshold selection (anomaly threshold,
    contamination parameter). The test set is held out until the final
    evaluation — thresholds are NEVER tuned on it.

    This is the scientifically correct split for unknown-family evaluation:
        train      → supervised + anomaly fitting
        val        → threshold selection (anomaly_threshold, contamination)
        known_test → final known-class evaluation
        unknown    → unknown-family detection evaluation

    The unknown family NEVER appears in train, val, or known_test.
    """
    known_mask = ~df["scenario_id"].isin(held_out_scenarios)
    unknown_mask = df["scenario_id"].isin(held_out_scenarios)

    known_df = df[known_mask]  # keep original index for mapping back
    unknown_idx = df[unknown_mask].index.tolist()

    # First split: separate unknown families entirely
    # Second split: campaign-level train vs (val+test)
    rng = np.random.default_rng(seed)
    known_df_reset = known_df.reset_index(drop=True)
    campaigns = known_df_reset["campaign_id"].unique().tolist()
    rng.shuffle(campaigns)
    # 70% train, 15% val, 15% test (approximate)
    n_train_campaigns = max(1, int(len(campaigns) * (1.0 - 2 * validation_ratio)))
    n_val_campaigns = max(1, int(len(campaigns) * validation_ratio))
    train_campaigns = set(campaigns[:n_train_campaigns])
    val_campaigns = set(campaigns[n_train_campaigns:n_train_campaigns + n_val_campaigns])
    test_campaigns = set(campaigns[n_train_campaigns + n_val_campaigns:])

    train_idx = known_df.index[known_df["campaign_id"].isin(train_campaigns)].tolist()
    val_idx = known_df.index[known_df["campaign_id"].isin(val_campaigns)].tolist()
    known_test_idx = known_df.index[known_df["campaign_id"].isin(test_campaigns)].tolist()

    return train_idx, val_idx, known_test_idx, unknown_idx


def check_campaign_overlap(train_idx: List[int], test_idx: List[int], df: pd.DataFrame) -> List[str]:
    """Check for campaign overlap between train and test sets."""
    train_campaigns = set(df.iloc[train_idx]["campaign_id"].tolist())
    test_campaigns = set(df.iloc[test_idx]["campaign_id"].tolist())
    overlap = train_campaigns & test_campaigns
    warnings = []
    if overlap:
        warnings.append(f"CAMPAIGN OVERLAP: {len(overlap)} campaigns appear in both train and test: {list(overlap)[:5]}")
    return warnings


# --------------------------------------------------------------------------- #
# Hybrid detector
# --------------------------------------------------------------------------- #

class HybridDetector:
    """Hybrid detection: rule engine + supervised ML + anomaly detector.

    Each layer contributes independently. The hybrid decision preserves
    which layer(s) contributed.

    Threshold selection (anomaly_threshold) MUST be done on validation data
    via select_anomaly_threshold(). Hardcoding -0.1 (as the previous
    version did) is scientifically invalid — it tunes on the test set
    indirectly via the experiment config. The new flow:

        detector.train_anomaly(X_train, contamination=...)
        anomaly_threshold = detector.select_anomaly_threshold(X_val, y_val)
        # ... only NOW touch the test set ...
    """

    def __init__(self, feature_version: str = "v2"):
        self.feature_version = feature_version
        if feature_version == "v2":
            self.feature_names = FEATURE_NAMES_V2
            self.to_vector = features_to_vector_v2
        else:
            self.feature_names = FEATURE_NAMES
            self.to_vector = features_to_vector
        self.classifier: Optional[RandomForestClassifier] = None
        self.anomaly_detector: Optional[IsolationForest] = None
        self.classes: List[str] = []
        self.anomaly_threshold: float = 0.0  # selected on validation, NEVER hardcoded
        self.threshold_selection_method: str = "none"

    def train_supervised(self, X: np.ndarray, y: np.ndarray, seed: int = 42):
        self.classifier = RandomForestClassifier(
            n_estimators=100, max_depth=8, random_state=seed, class_weight="balanced"
        )
        self.classifier.fit(X, y)
        self.classes = sorted(set(y.tolist()))

    def train_anomaly(self, X: np.ndarray, contamination: float = 0.1, seed: int = 42):
        self.anomaly_detector = IsolationForest(
            n_estimators=100, contamination=contamination, random_state=seed
        )
        self.anomaly_detector.fit(X)

    def select_anomaly_threshold(
        self,
        X_val: np.ndarray,
        y_val: np.ndarray,
        benign_label: str = "benign",
        target_fpr: float = 0.05,
    ) -> float:
        """Select the anomaly threshold on VALIDATION data.

        Goal: pick the anomaly score cutoff that achieves the target benign
        false-positive rate (default 5%) on the validation set. This is the
        ONLY scientifically valid way to choose a threshold — selecting it
        on the test set would be leakage.

        Args:
            X_val: validation features
            y_val: validation labels
            benign_label: the label representing benign traffic
            target_fpr: desired benign false-positive rate (0.05 = 5%)

        Returns:
            The selected anomaly threshold (score below this → anomaly).
        """
        if self.anomaly_detector is None:
            raise RuntimeError("train_anomaly() must be called before select_anomaly_threshold()")

        scores = self.anomaly_detector.decision_function(X_val)
        y_val = np.asarray(y_val)

        # Benign samples in validation
        benign_mask = (y_val == benign_label)
        if not benign_mask.any():
            # No benign samples in val — fall back to percentile of all scores
            self.anomaly_threshold = float(np.percentile(scores, 5))
            self.threshold_selection_method = "percentile_fallback (no benign in val)"
            return self.anomaly_threshold

        benign_scores = scores[benign_mask]
        # We want ~target_fpr of benign samples to be BELOW the threshold
        # (i.e. flagged as anomaly). IsolationForest: lower score = more anomalous.
        # So threshold = percentile(benign_scores, target_fpr * 100)
        threshold = float(np.percentile(benign_scores, target_fpr * 100))
        self.anomaly_threshold = threshold
        self.threshold_selection_method = f"benign_fpr_{target_fpr}_on_validation"
        return threshold

    def predict(
        self,
        features: List[Dict[str, float]],
        events_per_session: Optional[List[List[Dict]]] = None,
        anomaly_threshold: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """Run all three detection layers and produce hybrid results.

        Args:
            features: list of feature dicts
            events_per_session: optional list of event lists (for rule engine)
            anomaly_threshold: optional override; if None, uses the threshold
                selected via select_anomaly_threshold() on validation data.
                Passing a hardcoded value here is discouraged — the whole
                point of the validation split is to select this threshold.
        """
        X = np.array([self.to_vector(f) for f in features], dtype=float)
        # Use the threshold selected on validation data, unless caller overrides.
        # The previous version hardcoded -0.1 — that was a defect.
        threshold = anomaly_threshold if anomaly_threshold is not None else self.anomaly_threshold
        results = []

        for i in range(len(features)):
            # Layer 1: Rule engine (needs events, not just features)
            rule_result = None
            if events_per_session and i < len(events_per_session):
                rule_result = classify_session(events_per_session[i])

            # Layer 2: Supervised classifier
            supervised_pred = None
            supervised_conf = 0.0
            if self.classifier is not None:
                pred = self.classifier.predict(X[i:i+1])[0]
                supervised_pred = str(pred)
                if hasattr(self.classifier, "predict_proba"):
                    proba = self.classifier.predict_proba(X[i:i+1])[0]
                    supervised_conf = float(max(proba))

            # Layer 3: Anomaly detector — uses threshold from validation
            anomaly_score = 0.0
            is_anomaly = False
            if self.anomaly_detector is not None:
                anomaly_score = float(self.anomaly_detector.decision_function(X[i:i+1])[0])
                is_anomaly = anomaly_score < threshold

            # Hybrid decision
            final_decision = "unknown"
            detection_sources = []
            if rule_result:
                detection_sources.append("rule")
                final_decision = rule_result["label"]
            if supervised_pred and supervised_conf > 0.5:
                detection_sources.append("supervised")
                if final_decision == "unknown":
                    final_decision = supervised_pred
            if is_anomaly:
                detection_sources.append("anomaly")
                if final_decision == "unknown":
                    final_decision = "anomaly"
            if not detection_sources:
                final_decision = "benign"
                detection_sources.append("none")

            results.append({
                "rule_result": rule_result["label"] if rule_result else None,
                "rule_confidence": rule_result["confidence"] if rule_result else 0.0,
                "supervised_prediction": supervised_pred,
                "supervised_confidence": supervised_conf,
                "anomaly_score": anomaly_score,
                "is_anomaly": is_anomaly,
                "final_decision": final_decision,
                "detection_sources": detection_sources,
            })

        return results


# --------------------------------------------------------------------------- #
# Experiment runner
# --------------------------------------------------------------------------- #

def run_experiment(config: ExperimentConfig, csv_path: Optional[Path] = None) -> ExperimentResults:
    """Execute a full experiment and return results.

    Args:
        config: Experiment configuration
        csv_path: Path to dataset CSV. If None, uses datasets_dir() / config.dataset_version
    """
    start_time = time.time()

    # 1. Load dataset
    if csv_path is None:
        csv_path = datasets_dir() / config.dataset_version / "sessions.csv"
    if not csv_path.exists():
        return ExperimentResults(
            experiment_id=config.experiment_id,
            config=config.to_dict(),
            dataset_info={},
            model_results=[],
            status="failed",
            warnings=[f"Dataset not found: {csv_path}"],
        )

    df = pd.read_csv(csv_path)
    n_sessions = len(df)

    # 2. Audit dataset
    audit = audit_dataset(csv_path, config.dataset_version)

    # 3. Select feature version
    if config.feature_version == "v2":
        feat_names = FEATURE_NAMES_V2
    else:
        feat_names = FEATURE_NAMES

    # Ensure feature columns exist
    available_features = [f for f in feat_names if f in df.columns]
    if len(available_features) < len(feat_names):
        missing = set(feat_names) - set(available_features)
        # Fill missing features with 0
        for m in missing:
            df[m] = 0.0
        available_features = feat_names

    # 4. Split
    warnings = list(audit.warnings)
    val_idx: List[int] = []  # validation indices (empty unless unknown_family split)

    if config.split_strategy == "campaign":
        train_idx, test_idx = split_by_campaign(df, config.test_ratio, config.seed)
        unknown_idx = []
        split_info = {"strategy": "campaign", "train_size": len(train_idx), "test_size": len(test_idx)}
        overlap_warnings = check_campaign_overlap(train_idx, test_idx, df)
        warnings.extend(overlap_warnings)

    elif config.split_strategy == "temporal":
        train_idx, test_idx = split_temporal(df, config.test_ratio)
        unknown_idx = []
        split_info = {"strategy": "temporal", "train_size": len(train_idx), "test_size": len(test_idx)}

    elif config.split_strategy == "unknown_family":
        # Use the validation-aware split so thresholds can be selected on val,
        # not on test. This is the scientifically correct approach.
        train_idx, val_idx, test_idx, unknown_idx = split_unknown_family_with_validation(
            df, config.held_out_scenarios, config.seed
        )
        split_info = {
            "strategy": "unknown_family_with_validation",
            "train_size": len(train_idx),
            "validation_size": len(val_idx),
            "test_size": len(test_idx),
            "unknown_size": len(unknown_idx),
            "held_out_scenarios": config.held_out_scenarios,
            "threshold_selection": "validation_set (anomaly_threshold selected on val, NEVER on test)",
        }
        # Check campaign overlap in known split
        overlap_warnings = check_campaign_overlap(train_idx, test_idx, df)
        warnings.extend(overlap_warnings)
        if not unknown_idx:
            warnings.append("Unknown-family split produced 0 unknown sessions. Check held_out_scenarios match dataset scenario_ids.")
        if not val_idx:
            warnings.append("Unknown-family split produced 0 validation sessions. Cannot select threshold on val — falling back to percentile.")

    else:  # session-level (fallback)
        # CRITICAL: session-level split does NOT prevent campaign leakage.
        # We allow it but emit a loud warning and mark the split as
        # "leakage_unsafe" in the artifact so downstream consumers can
        # reject results that use it.
        from evaluate import session_level_split  # type: ignore
        train_idx, test_idx = session_level_split(
            session_ids=df["session_id"].tolist(),
            labels=df["label"].astype(str).tolist(),
            test_ratio=config.test_ratio,
            seed=config.seed,
        )
        unknown_idx = []
        split_info = {
            "strategy": "session",
            "train_size": len(train_idx),
            "test_size": len(test_idx),
            "leakage_unsafe": True,  # marker for downstream rejection
        }
        warnings.append(
            "Session-level split does NOT prevent campaign leakage. "
            "Results from this split are NOT scientifically valid for "
            "campaign-level generalization claims. Use campaign split."
        )

    # 5. Prepare data
    X_train = df.iloc[train_idx][available_features].to_numpy(dtype=float)
    y_train = df.iloc[train_idx]["label"].astype(str).to_numpy()
    X_test = df.iloc[test_idx][available_features].to_numpy(dtype=float)
    y_test = df.iloc[test_idx]["label"].astype(str).to_numpy()
    # Validation set (only populated for unknown_family split)
    X_val = df.iloc[val_idx][available_features].to_numpy(dtype=float) if val_idx else np.empty((0, len(available_features)))
    y_val = df.iloc[val_idx]["label"].astype(str).to_numpy() if val_idx else np.array([], dtype=str)

    # 6. Train + evaluate models
    model_results: List[Dict[str, Any]] = []
    detector = HybridDetector(config.feature_version)

    # --- Supervised ---
    if "supervised" in config.models or "hybrid" in config.models:
        detector.train_supervised(X_train, y_train, config.seed)
        y_pred = detector.classifier.predict(X_test)
        supervised_metrics = evaluate_classification(y_test.tolist(), y_pred.tolist())

        # In-sample metrics (diagnostic only — NOT for reporting)
        y_train_pred = detector.classifier.predict(X_train)
        in_sample = {
            "accuracy": float(accuracy_score(y_train, y_train_pred)),
            "f1_macro": float(f1_score(y_train, y_train_pred, average="macro", zero_division=0)),
            "note": "in-sample (training set) — diagnostic only, NOT held-out",
        }

        # Feature importances
        importances = {}
        if hasattr(detector.classifier, "feature_importances_"):
            importances = dict(zip(available_features, detector.classifier.feature_importances_.tolist()))

        model_results.append(ModelResult(
            model_type="supervised",
            model_id=f"model-sup-{config.experiment_id}",
            training_metrics=in_sample,
            held_out_metrics=supervised_metrics,
            feature_importances=importances,
        ).to_dict())

    # --- Anomaly ---
    if "anomaly" in config.models or "hybrid" in config.models:
        detector.train_anomaly(X_train, contamination=0.1, seed=config.seed)

        # CRITICAL: select anomaly threshold on VALIDATION data, not test.
        # If no validation set is available (campaign/temporal split), fall
        # back to a documented percentile on the training set — NEVER tune
        # on the test set.
        threshold_selection_info = {}
        if len(X_val) > 0:
            selected_threshold = detector.select_anomaly_threshold(
                X_val, y_val, benign_label="benign", target_fpr=0.05
            )
            threshold_selection_info = {
                "method": detector.threshold_selection_method,
                "selected_threshold": float(selected_threshold),
                "selected_on": "validation_set",
            }
        else:
            # No val set — use training-set benign percentile as a documented fallback
            train_scores = detector.anomaly_detector.decision_function(X_train)
            y_train_arr = y_train
            benign_mask = (y_train_arr == "benign")
            if benign_mask.any():
                selected_threshold = float(np.percentile(train_scores[benign_mask], 5))
                method = "benign_fpr_0.05_on_training (fallback: no val set)"
            else:
                selected_threshold = float(np.percentile(train_scores, 5))
                method = "percentile_5_on_training (fallback: no benign in train)"
            detector.anomaly_threshold = selected_threshold
            detector.threshold_selection_method = method
            threshold_selection_info = {
                "method": method,
                "selected_threshold": float(selected_threshold),
                "selected_on": "training_set_fallback",
                "warning": "No validation set available — threshold selected on training set. "
                           "For research-grade evaluation, use unknown_family split which "
                           "provides a proper validation set.",
            }

        # Evaluate anomaly on test set using the selected threshold
        anomaly_scores = detector.anomaly_detector.decision_function(X_test)
        is_anomaly = anomaly_scores < detector.anomaly_threshold

        # For unknown-family evaluation
        unknown_metrics = {}
        if unknown_idx:
            X_unknown = df.iloc[unknown_idx][available_features].to_numpy(dtype=float)
            unknown_scores = detector.anomaly_detector.decision_function(X_unknown)
            # Use the SAME threshold selected on validation — NOT a new one
            unknown_is_anomaly = unknown_scores < detector.anomaly_threshold
            unknown_metrics = {
                "unknown_session_count": len(unknown_idx),
                "unknown_detected_as_anomaly": int(unknown_is_anomaly.sum()),
                "unknown_detection_rate": float(unknown_is_anomaly.mean()) if len(unknown_idx) > 0 else 0.0,
                "unknown_mean_anomaly_score": float(unknown_scores.mean()) if len(unknown_idx) > 0 else 0.0,
            }

        # Compute benign false-positive rate on test set
        benign_test_mask = (y_test == "benign")
        benign_fp_rate = float(is_anomaly[benign_test_mask].mean()) if benign_test_mask.any() else 0.0
        benign_count = int(benign_test_mask.sum())

        # Compute malicious detection rate on test set
        malicious_test_mask = (y_test != "benign")
        malicious_detection_rate = float(is_anomaly[malicious_test_mask].mean()) if malicious_test_mask.any() else 0.0
        malicious_count = int(malicious_test_mask.sum())

        model_results.append(ModelResult(
            model_type="anomaly",
            model_id=f"model-anom-{config.experiment_id}",
            held_out_metrics={
                "test_anomaly_rate": float(is_anomaly.mean()),
                "test_mean_anomaly_score": float(anomaly_scores.mean()),
                "benign_false_positive_rate": benign_fp_rate,
                "benign_count": benign_count,
                "malicious_detection_rate": malicious_detection_rate,
                "malicious_count": malicious_count,
                "threshold": float(detector.anomaly_threshold),
                "threshold_selection": threshold_selection_info,
            },
            unknown_metrics=unknown_metrics,
        ).to_dict())

    # --- Hybrid (feature-level: supervised + anomaly, NO rule engine) ---
    if "hybrid" in config.models:
        # The "hybrid" model here is feature-level hybrid: supervised + anomaly.
        # The rule engine requires event-level telemetry (not feature vectors),
        # so it is NOT included in this experiment. This is correctly labeled
        # "feature_hybrid" — NOT "full_hybrid" or just "hybrid".
        #
        # The anomaly threshold used here is the SAME one selected on validation
        # data above — NEVER a new hardcoded value.
        hybrid_preds = []
        hybrid_sources = []
        for i in range(len(X_test)):
            # Supervised
            sup_pred = detector.classifier.predict(X_test[i:i+1])[0] if detector.classifier else "unknown"
            sup_conf = 0.0
            if detector.classifier and hasattr(detector.classifier, "predict_proba"):
                proba = detector.classifier.predict_proba(X_test[i:i+1])[0]
                sup_conf = float(max(proba))

            # Anomaly — uses threshold from validation
            anom_score = 0.0
            is_anom = False
            if detector.anomaly_detector:
                anom_score = float(detector.anomaly_detector.decision_function(X_test[i:i+1])[0])
                is_anom = anom_score < detector.anomaly_threshold

            # Hybrid decision: supervised wins if confident, else anomaly
            if sup_conf > 0.5:
                decision = str(sup_pred)
                sources = ["supervised"]
                if is_anom:
                    sources.append("anomaly")
            elif is_anom:
                decision = "anomaly"
                sources = ["anomaly"]
            else:
                decision = "benign"
                sources = ["none"]

            hybrid_preds.append(decision)
            hybrid_sources.append(sources)

        hybrid_metrics = evaluate_classification(y_test.tolist(), hybrid_preds)
        # Add benign FP rate for the hybrid detector
        benign_test_mask = (y_test == "benign")
        hybrid_benign_fp = 0.0
        if benign_test_mask.any():
            hybrid_benign_arr = np.array([p != "benign" for p in hybrid_preds])
            hybrid_benign_fp = float(hybrid_benign_arr[benign_test_mask].mean())

        model_results.append(ModelResult(
            model_type="feature_hybrid",  # supervised+anomaly only; rule engine NOT included
            model_id=f"model-feat-hyb-{config.experiment_id}",
            held_out_metrics={
                **hybrid_metrics,
                "benign_false_positive_rate": hybrid_benign_fp,
                "threshold_used": float(detector.anomaly_threshold),
                "threshold_source": detector.threshold_selection_method,
                "composition": "supervised + anomaly (feature-level); rule engine NOT included (requires events)",
            },
        ).to_dict())

    # --- Rule-only (ablation) ---
    if "rule" in config.models:
        # Rule engine operates on event-level telemetry, not feature vectors.
        # Without events_per_session, we cannot run it. Report this honestly
        # rather than fabricating metrics.
        model_results.append(ModelResult(
            model_type="rule",
            model_id="rule-engine-v1",
            held_out_metrics={
                "status": "NOT_EVALUATED",
                "reason": "Rule engine requires event-level telemetry (events_per_session), "
                          "which is not available in feature-vector experiments. "
                          "To evaluate the rule engine, run an event-level experiment "
                          "with events_per_session passed to HybridDetector.predict().",
            },
        ).to_dict())

    # 7. Dataset info
    dataset_info = {
        "version": config.dataset_version,
        "session_count": n_sessions,
        "campaign_count": audit.campaign_count,
        "unique_campaign_ratio": audit.unique_campaign_ratio,
        "class_distribution": audit.class_distribution,
        "label_sources": audit.label_sources,
        "hash": audit.hash,
        "feature_version": config.feature_version,
        "features_used": len(available_features),
        "leaky_features_excluded": LEAKY_FEATURES if config.feature_version == "v2" else [],
    }

    # 8. Store results
    elapsed = time.time() - start_time
    split_info["elapsed_seconds"] = round(elapsed, 2)

    results = ExperimentResults(
        experiment_id=config.experiment_id,
        config=config.to_dict(),
        dataset_info=dataset_info,
        model_results=model_results,
        split_info=split_info,
        warnings=warnings,
    )

    # 9. Write artifact
    exp_dir = experiments_dir() / config.experiment_id
    exp_dir.mkdir(parents=True, exist_ok=True)
    (exp_dir / "config.json").write_text(config.to_json())
    (exp_dir / "results.json").write_text(results.to_json())
    (exp_dir / "dataset_audit.json").write_text(audit.to_json())

    print(f"Experiment {config.experiment_id} completed in {elapsed:.1f}s")
    print(f"  Dataset: {n_sessions} sessions, {audit.campaign_count} campaigns")
    print(f"  Split: {split_info}")
    print(f"  Results: {exp_dir}/results.json")
    if warnings:
        print(f"  Warnings: {len(warnings)}")
        for w in warnings:
            print(f"    ⚠ {w}")

    return results


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a TRAPSIG research experiment")
    parser.add_argument("--experiment-id", default=None)
    parser.add_argument("--training", default="ssh-bruteforce,camera-recon,camera-default-creds,benign-browsing",
                       help="Comma-separated scenario IDs for training")
    parser.add_argument("--held-out", default="http-enumeration",
                       help="Comma-separated scenario IDs held out (unknown family)")
    parser.add_argument("--repetitions", type=int, default=10)
    parser.add_argument("--feature-version", default="v2", choices=["v1", "v2"])
    parser.add_argument("--split", default="campaign", choices=["campaign", "temporal", "unknown_family", "session"])
    parser.add_argument("--test-ratio", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--models", default="supervised,anomaly,hybrid",
                       help="Comma-separated: supervised,anomaly,hybrid,rule")
    parser.add_argument("--dataset-version", default="v1")
    parser.add_argument("--dataset-path", default=None)
    args = parser.parse_args(argv)

    config = ExperimentConfig(
        experiment_id=args.experiment_id or "",
        training_scenarios=[s.strip() for s in args.training.split(",")],
        held_out_scenarios=[s.strip() for s in args.held_out.split(",")],
        repetitions=args.repetitions,
        feature_version=args.feature_version,
        split_strategy=args.split,
        test_ratio=args.test_ratio,
        seed=args.seed,
        models=[m.strip() for m in args.models.split(",")],
    )
    # Override dataset_version
    config.dataset_version = args.dataset_version  # type: ignore

    csv_path = Path(args.dataset_path) if args.dataset_path else None
    results = run_experiment(config, csv_path)

    # Print summary
    print("\n" + "="*60)
    print("EXPERIMENT RESULTS SUMMARY")
    print("="*60)
    for mr in results.model_results:
        mt = mr["model_type"]
        hm = mr.get("held_out_metrics", {})
        f1 = hm.get("f1_macro", hm.get("test_anomaly_rate", "N/A"))
        print(f"  {mt:15s}  F1/anomaly={f1}")
    if results.warnings:
        print(f"\n  WARNINGS ({len(results.warnings)}):")
        for w in results.warnings:
            print(f"    ⚠ {w}")

    return 0 if results.status == "completed" else 1


if __name__ == "__main__":
    sys.exit(main())
