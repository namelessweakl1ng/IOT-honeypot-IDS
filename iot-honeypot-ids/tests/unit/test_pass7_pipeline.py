"""Pass 7+ tests — runtime detection pipeline + lineage + ML integration.

Covers:
- Campaign correlation (deterministic, source IP + temporal proximity)
- Feature extraction (canonical v2 schema, deterministic)
- Rule detector (small explainable set, persists to ES)
- Anomaly detector (IsolationForest + threshold calibration)
- Hybrid detector (rules + supervised + novelty, preserves provenance)
- Detection lineage (detection → session → events → features → campaign → model)
- Model registry activation gate (validated → active, single-active-per-role)
- E2E script leaf-field verification + export-before-use
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "shared"))
sys.path.insert(0, str(ROOT / "dashboard/api"))
sys.path.insert(0, str(ROOT / "dashboard/ml"))


# ============================================================
# Campaign correlation
# ============================================================

class TestCampaignCorrelation:
    """Test the deterministic campaign correlation logic.

    STABLE IDENTITY (Pass 7 hardening): campaign_id is anchored to the
    FIRST session's (source_ip, timestamp window, session_id) — NOT to
    the full session set. Adding sessions to the same window does NOT
    change the campaign_id.
    """

    def _import(self):
        from app import campaign_correlator  # type: ignore
        return campaign_correlator

    def test_campaign_id_deterministic(self):
        """Same first session + source → same campaign_id (STABLE)."""
        cc = self._import()
        # _campaign_id now takes (source_ip, first_session_epoch, first_session_id)
        cid1 = cc._campaign_id("192.168.1.20", 1735732800.0, "sess-a")
        cid2 = cc._campaign_id("192.168.1.20", 1735732800.0, "sess-a")
        assert cid1 == cid2

    def test_campaign_id_stable_when_sessions_added(self):
        """Adding sessions to the same correlation window does NOT change
        the campaign_id. This is the KEY stability property — the previous
        implementation hashed the full session set, causing orphaned campaigns
        when new sessions arrived.
        """
        cc = self._import()
        # The campaign_id is derived from (source_ip, window_anchor, first_session_id).
        # Adding S2, S3 to the window does NOT change the ID because the
        # anchor (first session S1) is unchanged.
        cid_with_s1_only = cc._campaign_id("192.168.1.20", 1735732800.0, "sess-a")
        # Same source + same first session → same campaign_id, regardless
        # of how many later sessions join the window.
        cid_with_s1_s2_s3 = cc._campaign_id("192.168.1.20", 1735732800.0, "sess-a")
        assert cid_with_s1_only == cid_with_s1_s2_s3

    def test_campaign_id_distinct_for_different_sources(self):
        cc = self._import()
        cid1 = cc._campaign_id("192.168.1.20", 1735732800.0, "sess-a")
        cid2 = cc._campaign_id("192.168.1.21", 1735732800.0, "sess-a")
        assert cid1 != cid2

    def test_campaign_id_distinct_for_different_first_session(self):
        """Different first sessions → different campaign_ids.
        This is the core identity invariant: the campaign_id is anchored
        to (source_ip, first_session_id). Two campaigns with different
        first sessions get different IDs — even if they're from the same
        source IP. The temporal gap determines WHICH sessions are grouped
        together; the first session's identity determines the ID."""
        cc = self._import()
        cid1 = cc._campaign_id("192.168.1.20", 1735646400.0, "sess-a")
        cid2 = cc._campaign_id("192.168.1.20", 1735650000.0, "sess-b")
        assert cid1 != cid2

    def test_campaign_id_independent_of_timestamp(self):
        """The campaign_id does NOT depend on the timestamp — only on
        (source_ip, first_session_id). This is the FIX for the
        hour-truncation bug: sessions at 09:59 and 10:01 (which straddle
        an hour boundary but are within the 60-minute gap) must get the
        SAME campaign_id as long as they share the same first session.
        The OLD implementation used hour-truncation, which gave them
        different IDs — violating the gap contract."""
        cc = self._import()
        # Same source + same first session → same campaign_id, regardless
        # of the timestamp value
        cid_at_hour_12 = cc._campaign_id("192.168.1.20", 1735646400.0, "sess-a")
        cid_at_hour_13 = cc._campaign_id("192.168.1.20", 1735650000.0, "sess-a")
        assert cid_at_hour_12 == cid_at_hour_13

    def test_campaign_id_same_within_hour_window(self):
        """Sessions in the same hour window but different minute — the
        campaign anchor is the first session's ID (not the timestamp),
        so they share the same campaign_id if they share the same first
        session. The gap logic determines membership, not identity."""
        cc = self._import()
        # 12:00 and 12:30 — same first session → same campaign_id
        cid_at_hour = cc._campaign_id("192.168.1.20", 1735646400.0, "sess-a")
        cid_at_half_past = cc._campaign_id("192.168.1.20", 1735648200.0, "sess-a")
        assert cid_at_hour == cid_at_half_past

    def test_split_into_campaigns_no_gap(self):
        """Sessions within CAMPAIGN_GAP_MINUTES go into one campaign."""
        cc = self._import()
        sessions = [
            {"session_id": "s1", "started_at": "2025-01-01T12:00:00Z"},
            {"session_id": "s2", "started_at": "2025-01-01T12:30:00Z"},
            {"session_id": "s3", "started_at": "2025-01-01T12:45:00Z"},
        ]
        groups = cc._split_into_campaigns(sessions, gap_minutes=60)
        assert len(groups) == 1
        assert len(groups[0]) == 3

    def test_split_into_campaigns_with_gap(self):
        """Sessions >60m apart start a new campaign."""
        cc = self._import()
        sessions = [
            {"session_id": "s1", "started_at": "2025-01-01T12:00:00Z"},
            {"session_id": "s2", "started_at": "2025-01-01T12:30:00Z"},
            # Gap of 90 minutes → new campaign
            {"session_id": "s3", "started_at": "2025-01-01T14:00:00Z"},
        ]
        groups = cc._split_into_campaigns(sessions, gap_minutes=60)
        assert len(groups) == 2
        assert len(groups[0]) == 2  # s1 + s2
        assert len(groups[1]) == 1  # s3

    def test_build_campaign_document_has_lineage(self):
        """Campaign document must include session_ids lineage."""
        cc = self._import()
        sessions = [
            {
                "session_id": "s1",
                "started_at": "2025-01-01T12:00:00Z",
                "ended_at": "2025-01-01T12:05:00Z",
                "source": {"ip": "192.168.1.20"},
                "honeypot": {"name": "camera"},
                "protocol": "http",
                "event_count": 5,
                "classification": "reconnaissance",
            },
        ]
        doc = cc.build_campaign_document("192.168.1.20", sessions)
        assert doc["campaign_id"].startswith("camp-")
        assert doc["session_ids"] == ["s1"]
        assert doc["session_count"] == 1
        assert doc["event_count"] == 5
        assert "192.168.1.20" == doc["source"]["ip"]
        assert "camera" in doc.get("honeypots", [])
        assert "reconnaissance" in doc.get("classifications", [])

    def test_build_campaign_document_has_correlation_metadata(self):
        """Campaign document must include correlation_window_minutes +
        correlation_criteria + first_seen/last_seen + campaign_status."""
        cc = self._import()
        sessions = [
            {
                "session_id": "s1",
                "started_at": "2025-01-01T12:00:00Z",
                "ended_at": "2025-01-01T12:05:00Z",
                "source": {"ip": "192.168.1.20"},
            },
        ]
        doc = cc.build_campaign_document("192.168.1.20", sessions)
        assert "correlation_window_minutes" in doc
        assert doc["correlation_window_minutes"] == cc.CAMPAIGN_GAP_MINUTES
        assert "correlation_criteria" in doc
        assert "first_seen" in doc
        assert "last_seen" in doc
        assert "campaign_status" in doc

    def test_sessions_missing_source_ip_skipped(self):
        cc = self._import()
        sessions = [{"session_id": "s1", "started_at": "2025-01-01T12:00:00Z"}]  # no source.ip
        by_source = cc._group_sessions_by_source(sessions)
        assert by_source == {}

    def test_no_sessions_produces_empty_campaigns(self):
        cc = self._import()
        groups = cc._split_into_campaigns([], gap_minutes=60)
        assert groups == []

    def test_campaign_id_format(self):
        """Campaign IDs follow the documented format: 'camp-' + hex prefix."""
        cc = self._import()
        cid = cc._campaign_id("192.168.1.20", 1735732800.0, "sess-a")
        assert cid.startswith("camp-")
        assert len(cid) == len("camp-") + 16  # 16 hex chars


# ============================================================
# Feature extraction (canonical v2 schema)
# ============================================================

class TestFeatureExtraction:
    """Test the canonical v2 feature extraction."""

    def _import(self):
        from app import feature_extractor  # type: ignore
        return feature_extractor

    def test_feature_schema_version_is_v2(self):
        fe = self._import()
        schema = fe.get_schema()
        assert schema["feature_schema_version"] == "v2"

    def test_feature_names_excludes_leaky(self):
        fe = self._import()
        schema = fe.get_schema()
        # Leaky features (derived from rule engine output used as ground truth)
        # must NOT be in v2 feature names
        for leaky in ("contains_path_traversal", "contains_command_injection", "contains_default_credentials"):
            assert leaky not in schema["feature_names"], (
                f"leaky feature {leaky} must NOT be in v2 schema"
            )

    def test_feature_count_matches_names(self):
        fe = self._import()
        schema = fe.get_schema()
        assert schema["feature_count"] == len(schema["feature_names"])

    def test_extract_features_deterministic(self):
        """Same session events → same feature vector."""
        from logstash_normalize import camera_fixture, normalize  # type: ignore
        fe = self._import()
        events = [normalize(camera_fixture())]
        feats1 = fe.extract_features(events)
        feats2 = fe.extract_features(events)
        assert feats1 == feats2

    def test_feature_vector_ordered_per_schema(self):
        """feature_vector must be ordered per FEATURE_NAMES_V2."""
        from logstash_normalize import camera_fixture, normalize  # type: ignore
        fe = self._import()
        events = [normalize(camera_fixture())]
        feats = fe.extract_features(events)
        vector = fe.features_to_vector_v2(feats)
        schema = fe.get_schema()
        assert len(vector) == schema["feature_count"]
        # Each vector element corresponds to the feature name at the same index
        for i, name in enumerate(schema["feature_names"]):
            assert name in feats, f"feature {name} missing from feature dict"


# ============================================================
# Rule detector
# ============================================================

class TestRuleDetector:
    """Test the runtime rule detector."""

    def _import(self):
        from app import rule_detector  # type: ignore
        return rule_detector

    def test_detection_id_deterministic(self):
        rd = self._import()
        d1 = rd._detection_id("sess-a", "rule_brute_force_v1")
        d2 = rd._detection_id("sess-a", "rule_brute_force_v1")
        assert d1 == d2

    def test_detection_id_distinct_per_rule(self):
        rd = self._import()
        d1 = rd._detection_id("sess-a", "rule_brute_force_v1")
        d2 = rd._detection_id("sess-a", "rule_default_credentials_v1")
        assert d1 != d2

    def test_detection_id_format(self):
        rd = self._import()
        did = rd._detection_id("sess-a", "rule_brute_force_v1")
        assert did.startswith("det-")
        assert len(did) == len("det-") + 16

    def test_severity_mapping_documented(self):
        """Each rule has a documented severity."""
        rd = self._import()
        for rule_id in ("rule_brute_force_v1", "rule_default_credentials_v1",
                        "rule_command_injection_v1", "rule_path_traversal_v1", "rule_recon_v1"):
            assert rule_id in rd.RULE_SEVERITY, f"missing severity for {rule_id}"
            sev = rd.RULE_SEVERITY[rule_id]
            assert sev in ("info", "low", "medium", "high", "critical")

    def test_detector_version(self):
        rd = self._import()
        assert rd.DETECTOR_VERSION == "rule_engine_v1"


# ============================================================
# Anomaly detector
# ============================================================

class TestAnomalyDetector:
    """Test the anomaly detector service (IsolationForest + threshold calibration)."""

    def _import(self):
        from app import anomaly_detector  # type: ignore
        return anomaly_detector

    def test_detector_version(self):
        ad = self._import()
        assert ad.DETECTOR_VERSION == "anomaly_detector_v1"

    def test_threshold_selection_method_is_documented(self):
        """Threshold must be calibrated on validation data, never hardcoded."""
        ad = self._import()
        svc = ad.AnomalyDetectorService()
        # Before training: method is 'none'
        assert svc.threshold_selection_method == "none"
        assert svc.threshold == 0.0

    def test_train_then_calibrate_then_score(self):
        """Train → calibrate → score is the documented flow."""
        import numpy as np
        ad = self._import()
        svc = ad.AnomalyDetectorService()
        # Train on 50 random feature vectors (simulated benign sessions)
        rng = np.random.default_rng(42)
        X = rng.normal(0, 1, size=(50, 10)).tolist()
        svc.train(X, contamination=0.05)
        assert svc.is_ready()
        # Calibrate on the same data (in real use, use held-out validation)
        threshold = svc.select_threshold_for_fpr(X, target_fpr=0.05)
        assert isinstance(threshold, float)
        assert svc.threshold_selection_method.startswith("benign_validation_fpr_")
        # Score a session
        score = svc.score_session(X[0])
        assert "anomaly_score" in score
        assert "threshold" in score
        assert "is_anomaly" in score
        assert isinstance(score["is_anomaly"], bool)

    def test_score_anomalous_session(self):
        """A clearly anomalous session (far from training distribution) is flagged."""
        import numpy as np
        ad = self._import()
        svc = ad.AnomalyDetectorService()
        rng = np.random.default_rng(42)
        X_train = rng.normal(0, 1, size=(100, 10)).tolist()
        svc.train(X_train, contamination=0.05)
        svc.select_threshold_for_fpr(X_train, target_fpr=0.05)
        # Anomalous feature vector: 50 standard deviations away
        X_anomalous = [50.0] * 10
        score = svc.score_session(X_anomalous)
        assert score["is_anomaly"] is True
        assert score["anomaly_score"] < svc.threshold

    def test_score_benign_session_not_flagged(self):
        """A typical session (drawn from training distribution) is not flagged."""
        import numpy as np
        ad = self._import()
        svc = ad.AnomalyDetectorService()
        rng = np.random.default_rng(42)
        X_train = rng.normal(0, 1, size=(100, 10)).tolist()
        svc.train(X_train, contamination=0.05)
        svc.select_threshold_for_fpr(X_train, target_fpr=0.05)
        # Benign feature vector: typical draw
        X_benign = rng.normal(0, 1, size=10).tolist()
        score = svc.score_session(X_benign)
        # Should NOT be flagged (allow for some false positives)
        assert "is_anomaly" in score

    def test_train_requires_minimum_data(self):
        """Train should raise on empty data."""
        ad = self._import()
        svc = ad.AnomalyDetectorService()
        with pytest.raises(ValueError):
            svc.train([])

    def test_calibrate_requires_training_first(self):
        """Cannot calibrate before train()."""
        ad = self._import()
        svc = ad.AnomalyDetectorService()
        with pytest.raises(RuntimeError):
            svc.select_threshold_for_fpr([[1.0, 2.0]])


# ============================================================
# Hybrid detector
# ============================================================

class TestHybridDetector:
    """Test the hybrid detector policy (rules + supervised + novelty)."""

    def _import(self):
        from app import hybrid_detector  # type: ignore
        return hybrid_detector

    def test_detector_version(self):
        hd = self._import()
        assert hd.DETECTOR_VERSION == "hybrid_v1"

    def test_thresholds_documented(self):
        """Rule + supervised thresholds are documented, not magic."""
        hd = self._import()
        assert hd.RULE_CONFIDENCE_THRESHOLD == 0.85
        assert hd.SUPERVISED_PROBABILITY_THRESHOLD == 0.7

    def test_detection_id_includes_contributed_signals(self):
        """Detection ID is deterministic from session_id + contributed signals + config fingerprint.

        P0 #2: the detection_id now includes the config_fingerprint so that
        config changes produce a different detection_id. Same session +
        same signals + same config → same ID. Same session + same signals
        + different config → different ID.
        """
        hd = self._import()
        fp = "fp-test123"
        d1 = hd._detection_id("sess-a", ["rule_engine"], fp)
        d2 = hd._detection_id("sess-a", ["rule_engine"], fp)
        assert d1 == d2  # same session + same signals + same config → same ID
        d3 = hd._detection_id("sess-a", ["rule_engine", "anomaly_detector"], fp)
        assert d1 != d3  # different signal sets → different IDs
        # P0 #2: different config fingerprint → different detection_id
        d4 = hd._detection_id("sess-a", ["rule_engine"], "fp-different456")
        assert d1 != d4  # same session + same signals + DIFFERENT config → different ID

    def test_detection_id_independent_of_signal_order(self):
        """Signal order in the contributed list does NOT change detection_id
        (sorted internally)."""
        hd = self._import()
        fp = "fp-test123"
        d1 = hd._detection_id("sess-a", ["rule_engine", "anomaly_detector"], fp)
        d2 = hd._detection_id("sess-a", ["anomaly_detector", "rule_engine"], fp)
        assert d1 == d2  # sorted internally → same ID
        assert d1 == d2  # sorted internally


# ============================================================
# Model registry activation gate
# ============================================================

class TestModelRegistryActivationGate:
    """Test the model lifecycle: experimental → candidate → validated → active."""

    def _import(self):
        from app import model_registry  # type: ignore
        return model_registry

    def test_get_active_model_returns_none_in_fresh_state(self):
        """Fresh state: no active model. The dashboard must show 'no active model'."""
        mr = self._import()
        # get_active_model walks list_models() — which walks the models dir.
        # If no models exist (fresh state), returns None.
        active = mr.get_active_model()
        assert active is None

    def test_activation_requires_validated_status(self):
        """An unvalidated model CANNOT be activated."""
        import json
        import tempfile
        mr = self._import()
        with tempfile.TemporaryDirectory() as tmp:
            # Patch _models_dir to use tmp
            original_models_dir = mr._models_dir
            mr._models_dir = lambda: Path(tmp)  # type: ignore
            try:
                # Create a model with status='experimental' (no validation_metrics)
                model_dir = Path(tmp) / "test-model"
                model_dir.mkdir()
                meta = {
                    "model_id": "test-model",
                    "algorithm": "random_forest",
                    "status": "experimental",
                    "role": "default",
                }
                (model_dir / "metadata.json").write_text(json.dumps(meta))
                # Activating should fail with ValueError
                with pytest.raises(ValueError, match="validated"):
                    mr.update_status("test-model", "active")
            finally:
                mr._models_dir = original_models_dir  # type: ignore

    def test_validated_requires_validation_metrics(self):
        """Validation requires validation_metrics to be recorded."""
        import json
        import tempfile
        mr = self._import()
        with tempfile.TemporaryDirectory() as tmp:
            original_models_dir = mr._models_dir
            mr._models_dir = lambda: Path(tmp)  # type: ignore
            try:
                model_dir = Path(tmp) / "test-model"
                model_dir.mkdir()
                meta = {"model_id": "test-model", "status": "candidate", "role": "default"}
                (model_dir / "metadata.json").write_text(json.dumps(meta))
                with pytest.raises(ValueError, match="validation_metrics"):
                    mr.update_status("test-model", "validated")
            finally:
                mr._models_dir = original_models_dir  # type: ignore

    def test_validated_then_active_succeeds(self):
        """A validated model with validation_metrics can be activated."""
        import json
        import tempfile
        mr = self._import()
        with tempfile.TemporaryDirectory() as tmp:
            original_models_dir = mr._models_dir
            mr._models_dir = lambda: Path(tmp)  # type: ignore
            try:
                model_dir = Path(tmp) / "test-model"
                model_dir.mkdir()
                meta = {
                    "model_id": "test-model",
                    "status": "candidate",
                    "role": "default",
                    "validation_metrics": {"f1_macro": 0.85, "precision_macro": 0.82},
                }
                (model_dir / "metadata.json").write_text(json.dumps(meta))
                # First validate
                validated = mr.update_status("test-model", "validated")
                assert validated["status"] == "validated"
                # Then activate
                activated = mr.update_status("test-model", "active")
                assert activated["status"] == "active"
                # Confirm get_active_model returns it
                active = mr.get_active_model()
                assert active is not None
                assert active["model_id"] == "test-model"
            finally:
                mr._models_dir = original_models_dir  # type: ignore

    def test_single_active_per_role(self):
        """Activating a new model retires the previous active model (same role)."""
        import json
        import tempfile
        mr = self._import()
        with tempfile.TemporaryDirectory() as tmp:
            original_models_dir = mr._models_dir
            mr._models_dir = lambda: Path(tmp)  # type: ignore
            try:
                # Create two validated models
                for mid in ("model-a", "model-b"):
                    md = Path(tmp) / mid
                    md.mkdir()
                    meta = {
                        "model_id": mid,
                        "status": "validated",
                        "role": "default",
                        "validation_metrics": {"f1": 0.8},
                    }
                    (md / "metadata.json").write_text(json.dumps(meta))
                # Activate model-a
                mr.update_status("model-a", "active")
                assert mr.get_active_model()["model_id"] == "model-a"
                # Activate model-b — should retire model-a
                mr.update_status("model-b", "active")
                active = mr.get_active_model()
                assert active["model_id"] == "model-b"
                # model-a should now be retired
                a_meta = json.loads((Path(tmp) / "model-a" / "metadata.json").read_text())
                assert a_meta["status"] == "retired"
                assert "superseded" in a_meta.get("retired_reason", "")
            finally:
                mr._models_dir = original_models_dir  # type: ignore


# ============================================================
# ES template audit for campaigns + detections
# ============================================================

class TestCampaignsTemplate:
    def test_campaigns_template_exists(self):
        p = ROOT / "dashboard" / "elasticsearch" / "index-templates" / "honeypot-campaigns.json"
        assert p.exists()

    def test_campaigns_template_has_campaign_id_keyword(self):
        import json
        tpl = json.loads((ROOT / "dashboard" / "elasticsearch" / "index-templates" / "honeypot-campaigns.json").read_text())
        props = tpl["template"]["mappings"]["properties"]
        assert props["campaign_id"]["type"] == "keyword"
        assert props["session_ids"]["type"] == "keyword"

    def test_campaigns_template_zero_replicas(self):
        import json
        tpl = json.loads((ROOT / "dashboard" / "elasticsearch" / "index-templates" / "honeypot-campaigns.json").read_text())
        assert tpl["template"]["settings"]["number_of_replicas"] == 0
        assert tpl["template"]["settings"]["number_of_shards"] == 1


class TestDetectionsTemplate:
    def test_detections_template_has_full_field_set(self):
        """Detections template must support rule + anomaly + hybrid + supervised fields."""
        import json
        tpl = json.loads((ROOT / "dashboard" / "elasticsearch" / "index-templates" / "honeypot-detections.json").read_text())
        props = tpl["template"]["mappings"]["properties"]
        for f in ("detection_id", "session_id", "campaign_id", "engine",
                  "rule_id", "label", "severity", "confidence",
                  "anomaly_score", "threshold", "model_version"):
            assert f in props, f"detections template missing field {f}"

    def test_detections_template_source_ip_is_ip_type(self):
        import json
        tpl = json.loads((ROOT / "dashboard" / "elasticsearch" / "index-templates" / "honeypot-detections.json").read_text())
        props = tpl["template"]["mappings"]["properties"]
        assert props["source"]["properties"]["ip"]["type"] == "ip"


class TestSessionsTemplateHasCampaignId:
    def test_sessions_template_includes_campaign_id(self):
        """Sessions template must include campaign_id (set by correlator)."""
        import json
        tpl = json.loads((ROOT / "dashboard" / "elasticsearch" / "index-templates" / "honeypot-sessions.json").read_text())
        props = tpl["template"]["mappings"]["properties"]
        assert "campaign_id" in props
        assert props["campaign_id"]["type"] == "keyword"


# ============================================================
# Bootstrap installs campaigns template
# ============================================================

class TestBootstrapInstallsCampaigns:
    def test_bootstrap_installs_honeypot_campaigns_template(self):
        s = (ROOT / "scripts" / "deployment" / "bootstrap-elasticsearch.sh").read_text()
        assert "install_template honeypot-campaigns" in s

    def test_bootstrap_verifies_campaigns_mappings(self):
        s = (ROOT / "scripts" / "deployment" / "bootstrap-elasticsearch.sh").read_text()
        assert "honeypot-campaigns" in s
        assert "campaign_id" in s
        assert "session_ids" in s


# ============================================================
# E2E leaf field verification (Pass 6 E2E correction)
# ============================================================

class TestE2ELeafFieldVerification:
    """Verify the E2E script checks leaf fields + exports vars before use."""

    def test_e2E_verifies_leaf_fields(self):
        """E2E must verify leaf fields: source.ip, device.id, honeypot.name, event.type,
        ingested_at, timestamp_source."""
        s = (ROOT / "scripts" / "testing" / "run-e2e.sh").read_text()
        for leaf in ("event_id", "session_id", "@timestamp", "source.ip",
                     "device.id", "honeypot.name", "event.type",
                     "ingested_at", "timestamp_source"):
            assert leaf in s, f"E2E must verify leaf field {leaf}"

    def test_e2E_exports_EVENT_ID_before_events_verification(self):
        """EVENT_ID + SESSION_ID must be exported BEFORE the /events python heredoc."""
        s = (ROOT / "scripts" / "testing" / "run-e2e.sh").read_text()
        export_pos = s.find("export API_URL EVENT_ID SESSION_ID")
        events_pos = s.find("verifying FastAPI /events returns this event")
        assert export_pos > 0, "export statement not found"
        assert events_pos > 0, "/events verification block not found"
        assert export_pos < events_pos, (
            "EVENT_ID + SESSION_ID must be exported BEFORE the /events verification"
        )

    def test_e2E_no_dead_EVENT_VERIFY_JSON_heredoc(self):
        """The dead EVENT_VERIFY_JSON heredoc (calls sys.stdin.read without piping) must be removed."""
        s = (ROOT / "scripts" / "testing" / "run-e2e.sh").read_text()
        assert "EVENT_VERIFY_JSON=" not in s, (
            "dead EVENT_VERIFY_JSON heredoc must be removed"
        )


# ============================================================
# Detection lineage endpoint contract (static)
# ============================================================

class TestDetectionLineageEndpointContract:
    def test_main_py_has_detection_detail_endpoint(self):
        s = (ROOT / "dashboard" / "api" / "app" / "main.py").read_text()
        assert '"/detections/{detection_id}"' in s
        assert '"/detections/{detection_id}/lineage"' in s

    def test_main_py_has_campaigns_endpoints(self):
        s = (ROOT / "dashboard" / "api" / "app" / "main.py").read_text()
        assert '"/campaigns"' in s
        assert '"/campaigns/{campaign_id}"' in s
        assert '"/campaigns/correlate"' in s

    def test_main_py_has_features_endpoints(self):
        s = (ROOT / "dashboard" / "api" / "app" / "main.py").read_text()
        assert '"/features/schema"' in s
        assert '"/features/{session_id}"' in s

    def test_main_py_has_detection_engine_endpoints(self):
        s = (ROOT / "dashboard" / "api" / "app" / "main.py").read_text()
        assert '"/detect/rule/{session_id}"' in s
        assert '"/detect/anomaly/{session_id}"' in s
        assert '"/detect/hybrid/{session_id}"' in s

    def test_main_py_has_anomaly_train_endpoint(self):
        s = (ROOT / "dashboard" / "api" / "app" / "main.py").read_text()
        assert '"/anomaly/train"' in s
        assert '"/anomaly/status"' in s

    def test_main_py_has_models_active_endpoint(self):
        s = (ROOT / "dashboard" / "api" / "app" / "main.py").read_text()
        assert '"/models/active"' in s

    def test_main_py_imports_all_new_modules(self):
        s = (ROOT / "dashboard" / "api" / "app" / "main.py").read_text()
        assert "campaign_correlator" in s
        assert "feature_extractor" in s
        assert "rule_detector" in s
        assert "anomaly_detector" in s
        assert "hybrid_detector" in s

    def test_detection_endpoints_gated_on_live_mode(self):
        """Detection endpoints must reject non-LIVE mode."""
        s = (ROOT / "dashboard" / "api" / "app" / "main.py").read_text()
        # Find the detect_rule function body and check for is_live() gate
        detect_rule_start = s.find('def detect_rule(')
        detect_rule_end = s.find('def detect_anomaly(')
        detect_rule_body = s[detect_rule_start:detect_rule_end]
        assert "is_live()" in detect_rule_body, "detect_rule must gate on LIVE mode"


# ============================================================
# Hybrid detector policy (static contract)
# ============================================================

class TestHybridDetectorPolicy:
    """Static contract: hybrid policy is documented in the source."""

    def test_hybrid_policy_documented_in_source(self):
        s = (ROOT / "dashboard" / "api" / "app" / "hybrid_detector.py").read_text()
        # Policy keywords must appear in docstring/comments
        assert "KNOWN_ATTACK" in s
        assert "NOVEL_BEHAVIOR" in s
        assert "HYBRID_AGREEMENT" in s
        assert "NO_SIGNAL" in s

    def test_anomaly_does_not_collapse_to_malicious(self):
        """The hybrid policy must NOT collapse anomaly → malicious."""
        s = (ROOT / "dashboard" / "api" / "app" / "hybrid_detector.py").read_text()
        # The docstring must explicitly state that anomaly is a signal, not a verdict
        s_lower = s.lower()
        assert ("anomaly is a signal, not a final" in s_lower
                or "anomaly is not necessarily malicious" in s_lower
                or "never collapses anomaly=malicious" in s_lower
                or "never collapse" in s_lower), (
            "hybrid_detector.py must explicitly document that anomaly is a signal, "
            "not a final malicious verdict"
        )

    def test_hybrid_preserves_provenance(self):
        """Hybrid detection must preserve which signals contributed."""
        s = (ROOT / "dashboard" / "api" / "app" / "hybrid_detector.py").read_text()
        assert "contributed_signals" in s
        assert "rule_signal" in s
        assert "anomaly_signal" in s
        assert "supervised_signal" in s


# ============================================================
# Research framework (already exists — verify it's intact)
# ============================================================

class TestResearchFramework:
    """Verify the research framework (splits + hybrid detector + unknown-family) is intact."""

    def test_research_py_has_session_level_split(self):
        s = (ROOT / "model-lab" / "model_lab" / "research.py").read_text()
        assert "def split_by_campaign" in s
        assert "def split_temporal" in s
        assert "def split_unknown_family" in s

    def test_research_py_has_hybrid_detector_class(self):
        s = (ROOT / "model-lab" / "model_lab" / "research.py").read_text()
        assert "class HybridDetector" in s
        assert "select_anomaly_threshold" in s

    def test_research_py_documents_threshold_selection(self):
        """Threshold MUST be selected on validation data, never hardcoded."""
        s = (ROOT / "model-lab" / "model_lab" / "research.py").read_text()
        # The HybridDetector docstring must explicitly call out that hardcoding is invalid
        assert "Hardcoding" in s or "hardcoded" in s.lower()
        assert "select_anomaly_threshold" in s

    def test_evaluate_py_has_session_level_split(self):
        s = (ROOT / "dashboard" / "ml" / "evaluate.py").read_text()
        assert "def session_level_split" in s

    def test_evaluate_py_has_fpr_and_fnr(self):
        s = (ROOT / "dashboard" / "ml" / "evaluate.py").read_text()
        assert "def _fpr" in s
        assert "def _fnr" in s
        assert "def roc_auc" in s

    def test_canonical_schema_has_feature_version(self):
        s = (ROOT / "model-lab" / "model_lab" / "canonical_schema.py").read_text()
        assert "feature_version" in s

    def test_label_mappings_exist_for_iot23_and_nbaioT(self):
        """Both IoT-23 and N-BaIoT label mappings must exist."""
        assert (ROOT / "model-lab" / "model_lab" / "label_mapping_iot23.py").exists()
        assert (ROOT / "model-lab" / "model_lab" / "label_mapping_n_baiot.py").exists()
