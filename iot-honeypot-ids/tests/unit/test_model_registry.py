"""Tests for the model registry — covers both the flat and grouped layouts.

Bug history:
- Pass 2 discovered that list_models() only scanned top-level dirs, missing
  models organized under a group subdir (e.g. legacy-demo/model-v001/).
- This test verifies both layouts work and that legacy-demo models are
  never accidentally marked status=active.
"""
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "dashboard" / "api"))


@pytest.fixture
def temp_models_dir(tmp_path, monkeypatch):
    """Point MODEL_PATH at a temp dir and clear settings cache.

    The model_registry module reads settings.model_path, which is populated
    by pydantic-settings from the MODEL_PATH env var. We clear the lru_cache
    AND reload model_registry so it picks up the new settings instance.
    """
    models_dir = tmp_path / "models"
    models_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("MODEL_PATH", str(models_dir))
    from app.config import get_settings
    get_settings.cache_clear()
    # Reload so model_registry.settings points to the fresh settings instance
    import importlib
    from app import model_registry
    importlib.reload(model_registry)
    # Patch the module-level settings reference directly (lru_cache returns
    # the same instance, but the module imported `settings` at load time)
    monkeypatch.setattr(model_registry, "settings", get_settings(), raising=False)
    return models_dir


def _write_model(models_dir, model_id, status="experimental", provenance=None, group=None):
    """Write a minimal valid model metadata.json under models_dir."""
    if group:
        d = models_dir / group / model_id
    else:
        d = models_dir / model_id
    d.mkdir(parents=True, exist_ok=True)
    meta = {
        "model_id": model_id,
        "algorithm": "random_forest",
        "dataset_version": "v1",
        "feature_version": "v2",
        "features": ["event_count", "duration_s"],
        "hyperparameters": {"n_estimators": 100},
        "metrics": {"in_sample_accuracy": 0.95},
        "seed": 42,
        "status": status,
        "notes": "",
        "created_at": 1700000000,
        "created_at_iso": "2023-11-14T22:13:20Z",
    }
    if provenance:
        meta["provenance"] = provenance
    (d / "metadata.json").write_text(json.dumps(meta))


class TestListModels:
    def test_empty_dir_returns_empty_list(self, temp_models_dir):
        from app import model_registry
        assert model_registry.list_models() == []

    def test_flat_layout(self, temp_models_dir):
        from app import model_registry
        _write_model(temp_models_dir, "model-a", status="validated")
        _write_model(temp_models_dir, "model-b", status="experimental")
        models = model_registry.list_models()
        ids = {m["model_id"] for m in models}
        assert ids == {"model-a", "model-b"}

    def test_grouped_layout(self, temp_models_dir):
        """Critical: models under legacy-demo/ must be visible."""
        from app import model_registry
        _write_model(temp_models_dir, "model-v001", status="validated", group="legacy-demo")
        _write_model(temp_models_dir, "model-v002", status="validated", group="legacy-demo")
        _write_model(temp_models_dir, "model-prod-001", status="active")
        models = model_registry.list_models()
        ids = {m["model_id"] for m in models}
        assert ids == {"model-v001", "model-v002", "model-prod-001"}

    def test_mixed_flat_and_grouped(self, temp_models_dir):
        from app import model_registry
        _write_model(temp_models_dir, "model-flat", status="validated")
        _write_model(temp_models_dir, "model-grouped", status="validated", group="experiments")
        models = model_registry.list_models()
        ids = {m["model_id"] for m in models}
        assert ids == {"model-flat", "model-grouped"}

    def test_skips_readme(self, temp_models_dir):
        from app import model_registry
        (temp_models_dir).mkdir(parents=True, exist_ok=True)
        (temp_models_dir / "README.md").write_text("# Models")
        _write_model(temp_models_dir, "model-a", status="validated")
        models = model_registry.list_models()
        assert len(models) == 1
        assert models[0]["model_id"] == "model-a"

    def test_invalid_json_skipped(self, temp_models_dir):
        from app import model_registry
        d = temp_models_dir / "broken-model"
        d.mkdir(parents=True)
        (d / "metadata.json").write_text("{invalid json")
        _write_model(temp_models_dir, "good-model", status="validated")
        models = model_registry.list_models()
        assert len(models) == 1
        assert models[0]["model_id"] == "good-model"

    def test_depth_limit(self, temp_models_dir):
        """Metadata nested >3 levels deep should be skipped."""
        from app import model_registry
        deep = temp_models_dir / "a" / "b" / "c" / "d"
        deep.mkdir(parents=True)
        (deep / "metadata.json").write_text(json.dumps({"model_id": "too-deep"}))
        _write_model(temp_models_dir, "shallow", status="validated")
        models = model_registry.list_models()
        # Only the shallow model should be found
        ids = {m["model_id"] for m in models}
        assert "shallow" in ids
        assert "too-deep" not in ids


class TestGetModel:
    def test_flat_layout(self, temp_models_dir):
        from app import model_registry
        _write_model(temp_models_dir, "model-a", status="validated")
        m = model_registry.get_model("model-a")
        assert m is not None
        assert m["model_id"] == "model-a"

    def test_grouped_layout(self, temp_models_dir):
        from app import model_registry
        _write_model(temp_models_dir, "model-v001", status="validated", group="legacy-demo")
        m = model_registry.get_model("model-v001")
        assert m is not None
        assert m["model_id"] == "model-v001"

    def test_not_found_returns_none(self, temp_models_dir):
        from app import model_registry
        _write_model(temp_models_dir, "model-a", status="validated")
        assert model_registry.get_model("nonexistent") is None

    def test_empty_dir_returns_none(self, temp_models_dir):
        from app import model_registry
        assert model_registry.get_model("anything") is None


class TestModelsDirNotCreatable:
    def test_no_500_when_models_dir_uncreatable(self, monkeypatch):
        """Critical regression: if MODEL_PATH points to an uncreatable
        location (e.g. /app/models when not running as root outside Docker),
        list_models() must return [] NOT raise 500.
        """
        monkeypatch.setenv("MODEL_PATH", "/app/nonexistent-models-dir")
        from app.config import get_settings
        get_settings.cache_clear()
        import importlib
        from app import model_registry
        importlib.reload(model_registry)
        # Must NOT raise
        result = model_registry.list_models()
        assert result == []
        # /models endpoint should also return 200 with empty list, not 500


class TestLegacyDemoNotActive:
    """Critical research integrity invariant: legacy-demo models must never
    be status=active. They are trained on SYNTHETIC data and their metrics
    reflect dataset design, not real-world performance.
    """

    def test_repo_legacy_demo_models_not_active(self):
        """Scan the actual committed model metadata files."""
        repo_models = REPO_ROOT / "model-lab" / "models" / "legacy-demo"
        if not repo_models.exists():
            pytest.skip("legacy-demo dir not found")
        for meta_file in repo_models.glob("*/metadata.json"):
            meta = json.loads(meta_file.read_text())
            assert meta.get("status") != "active", (
                f"{meta_file.name}: legacy-demo model {meta.get('model_id')} "
                f"has status=active — this is forbidden (synthetic data)"
            )
            assert meta.get("provenance") == "legacy-demo", (
                f"{meta_file.name}: legacy-demo model missing provenance tag"
            )

    def test_no_active_model_in_repo(self):
        """The repo should have NO active model by default. Activating a
        model is an explicit operator action (POST /models/{id}/status).
        """
        repo_models = REPO_ROOT / "model-lab" / "models"
        if not repo_models.exists():
            pytest.skip("models dir not found")
        active_count = 0
        for meta_file in repo_models.rglob("metadata.json"):
            meta = json.loads(meta_file.read_text())
            if meta.get("status") == "active":
                active_count += 1
                print(f"  ACTIVE: {meta_file} ({meta.get('model_id')})")
        assert active_count == 0, (
            f"Found {active_count} active model(s) in repo — "
            f"should be 0 (operator must explicitly activate)"
        )
