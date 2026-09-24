"""
Model training — interpretable baselines.

Algorithms supported (all from scikit-learn so they are reproducible and
inspectable):

  - logistic_regression   : linear baseline, fast, explainable via coefficients
  - random_forest         : nonlinear, robust, gives feature importances
  - gradient_boosting     : nonlinear, often best raw accuracy
  - isolation_forest       : unsupervised anomaly detector (no labels needed)

Models are persisted with joblib. Each model gets its own directory under
`model-lab/models/<id>/` containing:

  - model.joblib          (the trained estimator)
  - features.joblib       (the fitted feature scaler, if any)
  - metadata.json         (algorithm, hyperparameters, metrics, seed, ...)
  - README.md             (human-readable summary)

Never overwrite — caller is responsible for picking a unique model_id.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier, IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.preprocessing import StandardScaler

# features is imported lazily inside functions to support both:
#   - import as part of the `dashboard.ml` package (relative)
#   - import as top-level module after sys.path manipulation (absolute)
try:
    from .features import FEATURE_NAMES, FEATURE_NAMES_V2, LEAKY_FEATURES, features_to_vector, features_to_vector_v2
except ImportError:
    from features import FEATURE_NAMES, FEATURE_NAMES_V2, LEAKY_FEATURES, features_to_vector, features_to_vector_v2  # type: ignore


def _select_features(feature_version: str):
    """Return (names, to_vector_fn) for the given feature version.

    v1 = all 25 features (includes 3 leaky ones — keep for rule engine + diagnostics).
    v2 = 22 features (leaky ones removed — use for honest classifier training).
    """
    if feature_version == "v2":
        return FEATURE_NAMES_V2, features_to_vector_v2
    return FEATURE_NAMES, features_to_vector

# --------------------------------------------------------------------------- #
# Algorithm registry — each entry contains the constructor + default params.
# --------------------------------------------------------------------------- #

ALGORITHMS: Dict[str, Dict[str, Any]] = {
    "logistic_regression": {
        "class": LogisticRegression,
        "params": {"max_iter": 1000, "class_weight": "balanced"},
        "type": "classifier",
    },
    "random_forest": {
        "class": RandomForestClassifier,
        "params": {"n_estimators": 100, "max_depth": 8, "random_state": 42, "class_weight": "balanced"},
        "type": "classifier",
    },
    "gradient_boosting": {
        "class": GradientBoostingClassifier,
        "params": {"n_estimators": 100, "max_depth": 3, "random_state": 42},
        "type": "classifier",
    },
    "isolation_forest": {
        "class": IsolationForest,
        "params": {"n_estimators": 100, "contamination": 0.1, "random_state": 42},
        "type": "anomaly",
    },
}


def list_algorithms() -> List[str]:
    return list(ALGORITHMS.keys())


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


# --------------------------------------------------------------------------- #
# Train
# --------------------------------------------------------------------------- #


def train(
    *,
    X: List[Dict[str, float]],
    y: List[str],
    algorithm: str = "random_forest",
    seed: int = 42,
    hyperparameters: Dict[str, Any] | None = None,
    models_dir: Path,
    model_id: str,
    dataset_version: str,
    feature_version: str = "v1",
    notes: str = "",
) -> Dict[str, Any]:
    """Train one model and persist its artifact + metadata.

    X is a list of feature dicts (as produced by features.extract_features).
    y is a parallel list of labels (strings).
    """
    if algorithm not in ALGORITHMS:
        raise ValueError(f"unknown algorithm: {algorithm}")

    if not X or not y:
        return {
            "status": "INSUFFICIENT DATA",
            "reason": "training set is empty",
            "model_id": model_id,
        }

    if algorithm == "isolation_forest" and any(lbl == "benign" for lbl in y):
        # IsolationForest is unsupervised — works with or without labels, but
        # we still persist the contamination parameter so the operator can tune.
        pass

    # Select the feature vector (v1 = 25 features including 3 leaky ones;
    # v2 = 22 features, leaky ones removed — preferred for classifier training).
    feature_names, to_vector = _select_features(feature_version)
    X_vec = np.array([to_vector(f) for f in X], dtype=float)
    y_arr = np.array(y)

    # Scale features for logistic_regression; tree-based don't need scaling.
    scaler: StandardScaler | None = None
    if algorithm == "logistic_regression":
        scaler = StandardScaler()
        X_vec = scaler.fit_transform(X_vec)

    algo_meta = ALGORITHMS[algorithm]
    params = {**algo_meta["params"], "random_state": seed, **(hyperparameters or {})}

    estimator = algo_meta["class"](**params)
    estimator.fit(X_vec, y_arr)

    # Save artifacts
    model_dir = Path(models_dir) / model_id
    model_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(estimator, model_dir / "model.joblib")
    if scaler is not None:
        joblib.dump(scaler, model_dir / "scaler.joblib")

    # In-sample metrics — caller should re-evaluate on a held-out set.
    y_pred = estimator.predict(X_vec)
    metrics: Dict[str, Any] = {
        "in_sample_accuracy": float(accuracy_score(y_arr, y_pred)),
        "in_sample_precision_macro": float(precision_score(y_arr, y_pred, average="macro", zero_division=0)),
        "in_sample_recall_macro": float(recall_score(y_arr, y_pred, average="macro", zero_division=0)),
        "in_sample_f1_macro": float(f1_score(y_arr, y_pred, average="macro", zero_division=0)),
        "n_samples": int(len(y_arr)),
        "n_features": int(X_vec.shape[1]),
        "classes": sorted(set(y_arr.tolist())),
    }

    # Confusion matrix
    labels = sorted(set(y_arr.tolist()) | set(y_pred.tolist()))
    cm = confusion_matrix(y_arr, y_pred, labels=labels)
    metrics["confusion_matrix"] = cm.tolist()
    metrics["confusion_matrix_labels"] = labels

    # Per-class report (string for human, dict for machine)
    report = classification_report(y_arr, y_pred, output_dict=True, zero_division=0)
    metrics["per_class"] = report

    # ROC-AUC where applicable (binary or multiclass with probabilities)
    try:
        if hasattr(estimator, "predict_proba"):
            proba = estimator.predict_proba(X_vec)
            if proba.shape[1] == 2:
                metrics["in_sample_roc_auc"] = float(roc_auc_score(y_arr, proba[:, 1]))
            else:
                metrics["in_sample_roc_auc_ovr"] = float(
                    roc_auc_score(y_arr, proba, multi_class="ovr", average="macro")
                )
    except Exception:
        pass  # ROC-AUC is best-effort

    # Feature importances for tree-based models
    if hasattr(estimator, "feature_importances_"):
        metrics["feature_importances"] = dict(zip(feature_names, estimator.feature_importances_.tolist()))

    metadata = {
        "model_id": model_id,
        "algorithm": algorithm,
        "dataset_version": dataset_version,
        "feature_version": feature_version,
        "features": feature_names,  # the actual features used (v1=25, v2=22)
        "leaky_features_excluded": LEAKY_FEATURES if feature_version == "v2" else [],
        "hyperparameters": {k: v for k, v in params.items()},
        "metrics": metrics,
        "seed": seed,
        "status": "experimental",
        "notes": notes,
        "created_at": int(time.time()),
        "created_at_iso": _iso_now(),
    }
    (model_dir / "metadata.json").write_text(json.dumps(metadata, indent=2))
    return metadata


def load(models_dir: Path, model_id: str) -> Tuple[Any, StandardScaler | None, Dict[str, Any]]:
    """Load a model artifact + scaler + metadata."""
    model_dir = Path(models_dir) / model_id
    if not model_dir.exists():
        raise FileNotFoundError(f"model not found: {model_id}")
    estimator = joblib.load(model_dir / "model.joblib")
    scaler_path = model_dir / "scaler.joblib"
    scaler = joblib.load(scaler_path) if scaler_path.exists() else None
    metadata = json.loads((model_dir / "metadata.json").read_text())
    return estimator, scaler, metadata


def predict(models_dir: Path, model_id: str, feature_dicts: List[Dict[str, float]]) -> List[Dict[str, Any]]:
    """Predict on a batch of feature dicts. Returns a list of result dicts."""
    estimator, scaler, metadata = load(models_dir, model_id)
    # Use the same feature version the model was trained with
    fv = metadata.get("feature_version", "v1")
    _, to_vector = _select_features(fv)
    X = np.array([to_vector(f) for f in feature_dicts], dtype=float)
    if scaler is not None:
        X = scaler.transform(X)
    preds = estimator.predict(X)
    out: List[Dict[str, Any]] = []
    for i, p in enumerate(preds):
        item: Dict[str, Any] = {"prediction": str(p), "model_id": model_id}
        if hasattr(estimator, "predict_proba"):
            proba = estimator.predict_proba(X[i : i + 1])[0]
            classes = list(estimator.classes_)
            item["probabilities"] = dict(zip(classes, proba.tolist()))
        # Anomaly score for IsolationForest
        if hasattr(estimator, "decision_function"):
            item["anomaly_score"] = float(estimator.decision_function(X[i : i + 1])[0])
        out.append(item)
    return out
