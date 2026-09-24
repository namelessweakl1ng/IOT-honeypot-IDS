"""
Evaluation helpers — grouped (session-level) train/test split to avoid leakage,
plus a small set of well-defined metrics.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Set, Tuple

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)


def session_level_split(
    *,
    session_ids: List[str],
    labels: List[str],
    test_ratio: float = 0.2,
    seed: int = 42,
) -> Tuple[List[int], List[int]]:
    """Split at the session level so events of one session never appear in
    both train and test (prevents leakage of attack patterns).

    Returns (train_idx, test_idx) — indexes into the original list.
    """
    rng = np.random.default_rng(seed)
    by_label: Dict[str, List[str]] = defaultdict(list)
    for sid, lbl in zip(session_ids, labels):
        by_label[lbl].append(sid)

    train_sids: Set[str] = set()
    test_sids: Set[str] = set()

    for lbl, sids in by_label.items():
        sids = list(set(sids))  # dedupe
        rng.shuffle(sids)
        cut = max(1, int(len(sids) * (1.0 - test_ratio)))
        train_sids.update(sids[:cut])
        test_sids.update(sids[cut:])

    train_idx = [i for i, sid in enumerate(session_ids) if sid in train_sids]
    test_idx = [i for i, sid in enumerate(session_ids) if sid in test_sids]
    return train_idx, test_idx


def evaluate_classification(
    y_true: List[str],
    y_pred: List[str],
    *,
    classes: List[str] | None = None,
) -> Dict[str, object]:
    """Compute the platform's canonical metrics."""
    labels = classes or sorted(set(y_true) | set(y_pred))
    metrics = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision_macro": float(precision_score(y_true, y_pred, average="macro", labels=labels, zero_division=0)),
        "recall_macro": float(recall_score(y_true, y_pred, average="macro", labels=labels, zero_division=0)),
        "f1_macro": float(f1_score(y_true, y_pred, average="macro", labels=labels, zero_division=0)),
        "false_positive_rate": _fpr(y_true, y_pred, labels),
        "false_negative_rate": _fnr(y_true, y_pred, labels),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=labels).tolist(),
        "confusion_matrix_labels": labels,
        "per_class": classification_report(y_true, y_pred, output_dict=True, zero_division=0, labels=labels),
    }
    return metrics


def _fpr(y_true: List[str], y_pred: List[str], labels: List[str]) -> float:
    """Macro false-positive rate."""
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    fprs = []
    for i in range(len(labels)):
        fp = cm[:, i].sum() - cm[i, i]
        tn = cm.sum() - cm[i, :].sum() - cm[:, i].sum() + cm[i, i]
        denom = fp + tn
        if denom > 0:
            fprs.append(fp / denom)
    return float(np.mean(fprs)) if fprs else 0.0


def _fnr(y_true: List[str], y_pred: List[str], labels: List[str]) -> float:
    """Macro false-negative rate."""
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    fnrs = []
    for i in range(len(labels)):
        fn = cm[i, :].sum() - cm[i, i]
        tp = cm[i, i]
        denom = tp + fn
        if denom > 0:
            fnrs.append(fn / denom)
    return float(np.mean(fnrs)) if fnrs else 0.0


def roc_auc(y_true, y_score) -> float:  # noqa: ANN001
    """Best-effort ROC-AUC for binary or multiclass."""
    try:
        return float(roc_auc_score(y_true, y_score, multi_class="ovr", average="macro"))
    except Exception:
        return float("nan")
