"""Unit tests for model serialization round-trip.

Verifies that a trained model can be saved + loaded + used for prediction.
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "dashboard" / "ml"))

from models import load, predict, train  # type: ignore  # noqa: E402
from features import extract_features, FEATURE_NAMES  # type: ignore  # noqa: E402


def _make_session(label: str, n_events: int = 5) -> tuple[list, str]:
    """Build a synthetic session's events + label."""
    events = []
    for i in range(n_events):
        events.append({
            "@timestamp": f"2025-01-01T12:00:{i:02d}.000Z",
            "event_id": f"evt-{label}-{i}",
            "session_id": f"sess-{label}-{i}",
            "source": {"ip": "192.168.1.20", "port": 54321},
            "device": {"id": "camera-01", "type": "camera"},
            "protocol": "http",
            "event": {"type": "http_request", "category": "network", "action": "get"},
            "authentication": {"attempted": False, "username": None, "success": False},
            "http": {"method": "GET", "uri": f"/{label}/{i}", "status": 200,
                      "user_agent": "test", "bytes_in": 0, "bytes_out": 100},
            "honeypot": {"name": "camera"},
            "attack": {"session_id": "sess-1", "stage": None,
                        "classification": label if label != "benign" else None,
                        "confidence": 0.5},
        })
    return events, label


def test_train_save_load_predict_roundtrip():
    with tempfile.TemporaryDirectory() as tmp:
        models_dir = Path(tmp)

        # Build a tiny synthetic dataset
        sessions = []
        labels = []
        for label in ["benign", "reconnaissance", "brute_force", "command_injection"]:
            for _ in range(8):
                events, lbl = _make_session(label, n_events=5)
                feats = extract_features(events)
                sessions.append(feats)
                labels.append(lbl)

        # Train
        meta = train(
            X=sessions,
            y=labels,
            algorithm="random_forest",
            seed=42,
            models_dir=models_dir,
            model_id="test-model-001",
            dataset_version="v1-test",
        )
        assert "metrics" in meta
        assert meta["metrics"]["n_samples"] == 32

        # Load + predict
        feats = extract_features(_make_session("brute_force", 10)[0])
        preds = predict(models_dir, "test-model-001", [feats])
        assert len(preds) == 1
        assert "prediction" in preds[0]
        # Predictions should be one of the training labels
        assert preds[0]["prediction"] in {"benign", "reconnaissance", "brute_force", "command_injection"}


def test_train_returns_insufficient_data_for_empty():
    with tempfile.TemporaryDirectory() as tmp:
        models_dir = Path(tmp)
        result = train(
            X=[],
            y=[],
            algorithm="random_forest",
            seed=42,
            models_dir=models_dir,
            model_id="empty-model",
            dataset_version="v1-empty",
        )
        assert result["status"] == "INSUFFICIENT DATA"
