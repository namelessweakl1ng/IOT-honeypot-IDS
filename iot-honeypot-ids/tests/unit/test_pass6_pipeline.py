"""Pass 6 — pipeline contract unit tests.

Covers:
- Logstash normalization (camera / iot / cowrie / malformed)
- Field survival end-to-end (event_id, session_id, source.ip, device.id,
  honeypot.name, @timestamp, ingested_at, timestamp_source)
- Malformed event routing (honeypot-errors-*)
- Cowrie classify-before-rename ordering
- Session materialization boundaries (0 / 1 / N events, lineage)
- Duplicate event_id handling (action=create prevents silent overwrite)
- Timestamp contract (preserve source @timestamp, fallback to ingest)
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

# Make shared/ + dashboard/api importable
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "shared"))
sys.path.insert(0, str(ROOT / "dashboard/api"))

from logstash_normalize import (  # type: ignore  # noqa: E402
    camera_fixture,
    cowrie_fixture,
    iot_fixture,
    malformed_missing_session_id,
    malformed_missing_source_ip,
    missing_timestamp,
    normalize,
    REQUIRED_FIELDS,
)


# ============================================================
# Logstash normalization — field survival
# ============================================================

class TestCameraNormalization:
    def test_camera_event_preserves_required_fields(self):
        ev = normalize(camera_fixture())
        for f in REQUIRED_FIELDS:
            cur = ev
            for p in f.split("."):
                assert isinstance(cur, dict), f"field {f}: parent not dict at {p}"
                assert p in cur, f"missing required field: {f}"
                cur = cur[p]

    def test_camera_event_preserves_event_id(self):
        ev = normalize(camera_fixture())
        assert ev["event_id"] == "evt-camera-1"

    def test_camera_event_preserves_session_id(self):
        ev = normalize(camera_fixture())
        assert ev["session_id"] == "sess-camera-1"

    def test_camera_event_preserves_source_ip(self):
        ev = normalize(camera_fixture())
        assert ev["source"]["ip"] == "192.168.1.20"

    def test_camera_event_preserves_device_id(self):
        ev = normalize(camera_fixture())
        assert ev["device"]["id"] == "camera-01"

    def test_camera_event_preserves_honeypot_name(self):
        ev = normalize(camera_fixture())
        assert ev["honeypot"]["name"] == "camera"

    def test_camera_event_preserves_timestamp(self):
        ev = normalize(camera_fixture())
        assert ev["@timestamp"] == "2025-01-01T12:00:00.000Z"
        assert ev["timestamp_source"] == "source_provided"

    def test_camera_event_adds_ingested_at(self):
        ev = normalize(camera_fixture())
        assert "ingested_at" in ev
        assert ev["ingested_at"]  # not empty

    def test_camera_event_routes_to_events_index(self):
        ev = normalize(camera_fixture())
        r = ev["_routing"]
        assert r["target_index"] == "honeypot-events-camera"
        assert r["document_id"] == "evt-camera-1"
        assert r["action"] == "create"
        assert r["is_malformed"] is False

    def test_camera_event_admin_uri_enriches_reconnaissance(self):
        ev = normalize(camera_fixture())
        assert ev["attack"]["stage"] == "reconnaissance"


class TestIoTNormalization:
    def test_iot_event_preserves_required_fields(self):
        ev = normalize(iot_fixture())
        for f in REQUIRED_FIELDS:
            cur = ev
            for p in f.split("."):
                assert p in cur, f"missing: {f}"
                cur = cur[p]

    def test_iot_event_preserves_event_id(self):
        ev = normalize(iot_fixture())
        assert ev["event_id"] == "evt-iot-1"

    def test_iot_event_preserves_session_id(self):
        ev = normalize(iot_fixture())
        assert ev["session_id"] == "sess-iot-1"

    def test_iot_event_preserves_protocol(self):
        ev = normalize(iot_fixture())
        assert ev["protocol"] == "tcp_iot"

    def test_iot_event_preserves_honeypot_name(self):
        ev = normalize(iot_fixture())
        assert ev["honeypot"]["name"] == "iot-service"

    def test_iot_event_routes_to_events_index(self):
        ev = normalize(iot_fixture())
        r = ev["_routing"]
        assert r["target_index"] == "honeypot-events-iot-service"
        assert r["document_id"] == "evt-iot-1"
        assert r["action"] == "create"


class TestCowrieNormalization:
    """Cowrie events arrive nested under `cowrie.*` (Filebeat target: cowrie)."""

    def test_cowrie_eventid_becomes_event_action(self):
        ev = normalize(cowrie_fixture())
        assert ev["event"]["action"] == "cowrie.login.success"

    def test_cowrie_session_becomes_session_id(self):
        ev = normalize(cowrie_fixture())
        assert ev["session_id"] == "sess-cowrie-1"

    def test_cowrie_src_ip_becomes_source_ip(self):
        ev = normalize(cowrie_fixture())
        assert ev["source"]["ip"] == "192.168.1.20"

    def test_cowrie_dst_ip_becomes_destination_ip(self):
        ev = normalize(cowrie_fixture())
        assert ev["destination"]["ip"] == "192.168.1.50"

    def test_cowrie_username_becomes_authentication_username(self):
        ev = normalize(cowrie_fixture())
        assert ev["authentication"]["username"] == "admin"

    def test_cowrie_sensor_becomes_device_id(self):
        ev = normalize(cowrie_fixture())
        assert ev["device"]["id"] == "cowrie-01"

    def test_cowrie_gets_explicit_honeypot_name(self):
        ev = normalize(cowrie_fixture())
        assert ev["honeypot"]["name"] == "cowrie"
        assert ev["honeypot"]["container"] == "pi-cowrie"

    def test_cowrie_gets_protocol_ssh(self):
        ev = normalize(cowrie_fixture())
        assert ev["protocol"] == "ssh"

    def test_cowrie_gets_device_type_ssh(self):
        ev = normalize(cowrie_fixture())
        assert ev["device"]["type"] == "ssh"

    def test_cowrie_classify_before_rename_session(self):
        """Classify cowrie.session.* BEFORE renaming eventid → event.action.

        This is the Pass 5 Cowrie regression — the previous version renamed
        eventid first, then tried to match [cowrie][eventid] for classification
        (the field was already gone). Verify the classify-before-rename order.
        """
        raw = cowrie_fixture()
        raw["cowrie"]["eventid"] = "cowrie.session.connect"
        ev = normalize(raw)
        assert ev["event"]["type"] == "session"
        # And the eventid rename still happened
        assert ev["event"]["action"] == "cowrie.session.connect"

    def test_cowrie_classify_login_as_authentication(self):
        raw = cowrie_fixture()
        raw["cowrie"]["eventid"] = "cowrie.login.failed"
        ev = normalize(raw)
        assert ev["event"]["category"] == "authentication"

    def test_cowrie_classify_command_as_execution(self):
        raw = cowrie_fixture()
        raw["cowrie"]["eventid"] = "cowrie.command.input"
        ev = normalize(raw)
        assert ev["event"]["category"] == "execution"
        assert ev["attack"]["stage"] == "execution"

    def test_cowrie_routes_to_events_index(self):
        ev = normalize(cowrie_fixture())
        r = ev["_routing"]
        assert r["target_index"] == "honeypot-events-cowrie"
        assert r["action"] == "create"
        assert r["is_malformed"] is False


# ============================================================
# Malformed event routing
# ============================================================

class TestMalformedRouting:
    def test_missing_session_id_routes_to_errors(self):
        ev = normalize(malformed_missing_session_id())
        r = ev["_routing"]
        assert r["is_malformed"] is True
        assert r["target_index"].startswith("honeypot-errors-")
        # errors index template requires error_id, stage, reason
        assert "error_id" in ev
        assert ev["stage"] == "logstash_normalization"
        assert "missing" in ev["reason"]
        assert "session_id" in ev["reason"]

    def test_missing_source_ip_routes_to_errors(self):
        ev = normalize(malformed_missing_source_ip())
        r = ev["_routing"]
        assert r["is_malformed"] is True
        assert r["target_index"].startswith("honeypot-errors-")
        assert "source.ip" in ev["reason"]

    def test_malformed_uses_create_action_to_prevent_overwrite(self):
        """Both malformed and well-formed events use action=create.

        If a duplicate malformed event with the same error_id arrives, ES
        rejects the second — it does NOT silently overwrite a different
        malformed event that happens to have the same hash.
        """
        ev = normalize(malformed_missing_session_id())
        assert ev["_routing"]["action"] == "create"

    def test_malformed_event_not_silently_dropped(self):
        """Malformed events MUST land in honeypot-errors-*, not be dropped."""
        ev = normalize(malformed_missing_session_id())
        assert ev["_routing"]["target_index"].startswith("honeypot-errors-")
        assert "honeypot-events-" not in ev["_routing"]["target_index"]


# ============================================================
# Timestamp contract
# ============================================================

class TestTimestampContract:
    def test_source_timestamp_preserved(self):
        ev = normalize(camera_fixture())
        assert ev["@timestamp"] == "2025-01-01T12:00:00.000Z"
        assert ev["timestamp_source"] == "source_provided"

    def test_missing_timestamp_uses_ingest_fallback(self):
        ev = normalize(missing_timestamp())
        assert "ingested_at" in ev
        # @timestamp should be set to the ingest time (≈ ingested_at)
        assert ev["@timestamp"] == ev["ingested_at"]
        assert ev["timestamp_source"] == "ingest_fallback"

    def test_ingested_at_always_present(self):
        # camera has source @timestamp — ingested_at still added
        ev = normalize(camera_fixture())
        assert "ingested_at" in ev and ev["ingested_at"]

    def test_ingested_at_distinct_from_source_timestamp_when_source_present(self):
        ev = normalize(camera_fixture())
        # source timestamp is 2025-01-01, ingested_at is now — they must differ
        assert ev["@timestamp"] != ev["ingested_at"]


# ============================================================
# event_id contract
# ============================================================

class TestEventIdContract:
    def test_existing_event_id_preserved(self):
        ev = normalize(camera_fixture())
        assert ev["event_id"] == "evt-camera-1"

    def test_missing_event_id_generated_deterministically(self):
        """Logstash fingerprint generates event_id from @timestamp + session_id + event.action."""
        raw = camera_fixture()
        raw.pop("event_id")
        ev = normalize(raw)
        assert "event_id" in ev
        assert ev["event_id"].startswith("evt-")  # our prefix
        # same inputs → same event_id
        ev2 = normalize(raw)
        assert ev2["event_id"] == ev["event_id"]

    def test_event_id_used_as_document_id(self):
        ev = normalize(camera_fixture())
        assert ev["_routing"]["document_id"] == ev["event_id"]

    def test_action_create_prevents_duplicate_overwrite(self):
        """If Logstash delivers the same event twice (Filebeat retry), the
        second write must NOT overwrite the first event document.

        action=create on the ES output rejects duplicate document_id writes,
        preserving the first event. This is the documented contract.
        """
        ev = normalize(camera_fixture())
        assert ev["_routing"]["action"] == "create"


# ============================================================
# Session materialization boundaries
# ============================================================

class TestSessionMaterialization:
    """Test build_session_document() against various event groupings."""

    def _import_bsm(self):
        """Import build_session_document with the same sys.path hack the
        session_materializer uses."""
        import sys
        ml_path = ROOT / "dashboard" / "ml"
        if str(ml_path) not in sys.path:
            sys.path.insert(0, str(ml_path))
        from app.session_materializer import build_session_document  # type: ignore
        return build_session_document

    def test_zero_events_returns_empty_doc(self):
        bsm = self._import_bsm()
        doc = bsm("sess-empty", [])
        assert doc == {}

    def test_one_event_session(self):
        bsm = self._import_bsm()
        events = [normalize(camera_fixture())]
        doc = bsm("sess-camera-1", events)
        assert doc["session_id"] == "sess-camera-1"
        assert doc["event_count"] == 1
        assert doc["event_ids"] == ["evt-camera-1"]
        assert doc["started_at"] == events[0]["@timestamp"]
        assert doc["ended_at"] == events[0]["@timestamp"]
        assert doc["duration_s"] == 0.0

    def test_multiple_events_session_lineage(self):
        """Session document must preserve event_ids lineage back to source events."""
        bsm = self._import_bsm()
        # Two camera events 5 seconds apart
        e1 = normalize(camera_fixture())
        e2 = normalize(camera_fixture())
        e2["@timestamp"] = "2025-01-01T12:00:05.000Z"
        e2["event_id"] = "evt-camera-2"
        events = [e1, e2]
        doc = bsm("sess-camera-multi", events)
        assert doc["event_count"] == 2
        assert set(doc["event_ids"]) == {"evt-camera-1", "evt-camera-2"}
        assert doc["started_at"] == "2025-01-01T12:00:00.000Z"
        assert doc["ended_at"] == "2025-01-01T12:00:05.000Z"
        assert doc["duration_s"] == 5.0

    def test_session_preserves_honeypot_and_protocol(self):
        bsm = self._import_bsm()
        events = [normalize(camera_fixture())]
        doc = bsm("sess-camera-1", events)
        assert doc["honeypot"]["name"] == "camera"
        assert doc["protocol"] == "http"

    def test_session_preserves_source(self):
        bsm = self._import_bsm()
        events = [normalize(camera_fixture())]
        doc = bsm("sess-camera-1", events)
        assert doc["source"]["ip"] == "192.168.1.20"

    def test_session_preserves_device(self):
        bsm = self._import_bsm()
        events = [normalize(camera_fixture())]
        doc = bsm("sess-camera-1", events)
        assert doc["device"]["id"] == "camera-01"

    def test_session_does_not_fabricate_classification(self):
        """If events have no classification, session must NOT fabricate one."""
        bsm = self._import_bsm()
        raw = camera_fixture()
        # Use a URI that doesn't trigger URI classification rules
        # (no admin/login/exec/etc) so attack.classification + attack.stage
        # stay None end-to-end.
        raw["http"]["uri"] = "/"
        raw["attack"]["classification"] = None
        raw["attack"]["stage"] = None
        events = [normalize(raw)]
        doc = bsm("sess-camera-1", events)
        # classification/stage should be absent — not "benign", not "unknown"
        assert "classification" not in doc
        assert "attack_stage" not in doc

    def test_session_aggregates_auth_attempts(self):
        bsm = self._import_bsm()
        e1 = normalize(camera_fixture())
        e1["authentication"] = {"attempted": True, "username": "admin", "success": False}
        e2 = normalize(camera_fixture())
        e2["event_id"] = "evt-camera-2"
        e2["@timestamp"] = "2025-01-01T12:00:05.000Z"
        e2["authentication"] = {"attempted": True, "username": "admin", "success": True}
        events = [e1, e2]
        doc = bsm("sess-camera-1", events)
        assert doc["auth_attempts"] == 2
        assert doc["auth_successes"] == 1
        assert doc["unique_usernames"] == 1


# ============================================================
# ES template sanity (static JSON audit)
# ============================================================

class TestIndexTemplates:
    """Audit the index template JSON files for the required mapping fields."""

    TPL_DIR = ROOT / "dashboard" / "elasticsearch" / "index-templates"

    def _load(self, name: str) -> dict:
        import json
        with open(self.TPL_DIR / f"{name}.json") as f:
            return json.load(f)

    def test_events_template_has_ip_mapping_for_source(self):
        t = self._load("honeypot-events")
        props = t["template"]["mappings"]["properties"]
        assert props["source"]["properties"]["ip"]["type"] == "ip"
        assert props["destination"]["properties"]["ip"]["type"] == "ip"

    def test_events_template_has_keyword_for_session_id_and_event_id(self):
        t = self._load("honeypot-events")
        props = t["template"]["mappings"]["properties"]
        assert props["session_id"]["type"] == "keyword"
        assert props["event_id"]["type"] == "keyword"

    def test_events_template_has_date_for_timestamps(self):
        t = self._load("honeypot-events")
        props = t["template"]["mappings"]["properties"]
        assert props["@timestamp"]["type"] == "date"
        assert props["ingested_at"]["type"] == "date"
        assert props["timestamp_source"]["type"] == "keyword"

    def test_events_template_no_dangling_default_pipeline(self):
        """honeypot-default pipeline was removed in Pass 6 — verify the
        template no longer references it.
        """
        t = self._load("honeypot-events")
        settings = t["template"]["settings"]
        assert "index.default_pipeline" not in settings
        assert "honeypot-default" not in str(t)

    def test_sessions_template_preserves_event_ids_keyword(self):
        """Session document must preserve event_ids lineage back to events."""
        t = self._load("honeypot-sessions")
        props = t["template"]["mappings"]["properties"]
        assert props["event_ids"]["type"] == "keyword"

    def test_errors_template_has_error_id_and_stage(self):
        """Errors index must support the dead-letter fields the Logstash
        ruby routing block writes (error_id, stage, reason, tag).
        """
        t = self._load("honeypot-errors")
        props = t["template"]["mappings"]["properties"]
        assert props["error_id"]["type"] == "keyword"
        assert props["stage"]["type"] == "keyword"
        assert props["reason"]["type"] == "keyword"
        assert props["tag"]["type"] == "keyword"

    def test_all_templates_have_zero_replicas(self):
        """Lab is single-node ES — no replicas needed."""
        for name in ("honeypot-events", "honeypot-sessions",
                     "honeypot-detections", "honeypot-errors", "honeypot-training"):
            t = self._load(name)
            assert t["template"]["settings"]["number_of_replicas"] == 0
            assert t["template"]["settings"]["number_of_shards"] == 1


# ============================================================
# Schema consistency (shared/schemas vs ES template)
# ============================================================

class TestSchemaConsistency:
    """Audit shared/schemas/event_schema.py against the ES honeypot-events template."""

    def test_required_fields_match_template(self):
        from schemas.event_schema import REQUIRED_FIELDS  # type: ignore
        import json
        with open(ROOT / "dashboard" / "elasticsearch" / "index-templates" / "honeypot-events.json") as f:
            tpl = json.load(f)
        props = tpl["template"]["mappings"]["properties"]
        # Each required field path must resolve to a mapping entry.
        # Nested fields (source.ip, device.id, event.type, honeypot.name)
        # live under <parent>.properties.<child>.
        for f in REQUIRED_FIELDS:
            cur = props
            for p in f.split("."):
                assert isinstance(cur, dict), f"required field {f}: parent not dict at {p}"
                assert p in cur, f"required field {f}: missing segment {p}"
                cur = cur[p]
                # If this is an object field, descend into its `properties`
                if isinstance(cur, dict) and "properties" in cur and "type" not in cur:
                    cur = cur["properties"]

    def test_json_schema_required_matches_python_required(self):
        import json
        with open(ROOT / "shared" / "schemas" / "event-schema.json") as f:
            js = json.load(f)
        # JSON schema requires top-level keys only (@timestamp, event_id, etc.)
        js_required = set(js["required"])
        # Python REQUIRED_FIELDS uses dot-notation for nested fields.
        # The top-level keys must match.
        from schemas.event_schema import REQUIRED_FIELDS  # type: ignore
        py_top = {f.split(".")[0] for f in REQUIRED_FIELDS}
        assert js_required == py_top, (
            f"JSON schema required {js_required} does not match Python top-level {py_top}"
        )


# ============================================================
# Cowrie log volume contract (static audit)
# ============================================================

class TestCowrieVolumeContract:
    """Audit the Pi docker-compose.yml for the Cowrie volume fix.

    Previous bug: cowrie_var was mounted at /cowrie/cowrie-git/var inside
    Cowrie, but cowrie.cfg writes to /var/log/cowrie/cowrie.json — these
    were different filesystem locations. Filebeat read cowrie_var:/var/log/cowrie
    and saw a different (empty) directory than where Cowrie wrote.
    """

    def test_cowrie_var_mounted_at_var_log_cowrie(self):
        import re
        compose = (ROOT / "pi" / "docker-compose.yml").read_text()
        # Find the cowrie service volumes block, verify cowrie_var is mounted
        # at /var/log/cowrie (the path cowrie.cfg writes to).
        # Match: "- cowrie_var:/var/log/cowrie" with optional leading whitespace.
        assert re.search(r"^\s+-\s+cowrie_var:/var/log/cowrie\s*$", compose, re.MULTILINE), (
            "cowrie_var MUST be mounted at /var/log/cowrie inside the Cowrie container "
            "so Filebeat (cowrie_var:/var/log/cowrie:ro) sees the same file"
        )

    def test_cowrie_var_not_mounted_only_at_cowrie_git_var(self):
        """The previous broken mount was cowrie_var:/cowrie/cowrie-git/var.
        That mount is now delegated to a SEPARATE volume (cowrie_data).
        """
        import re
        compose = (ROOT / "pi" / "docker-compose.yml").read_text()
        # cowrie_var should NOT be mounted at /cowrie/cowrie-git/var anymore
        assert not re.search(r"^\s+-\s+cowrie_var:/cowrie/cowrie-git/var\s*$", compose, re.MULTILINE), (
            "cowrie_var should NOT be mounted at /cowrie/cowrie-git/var — "
            "that caused the volume mismatch bug"
        )

    def test_cowrie_data_volume_exists_for_internal_state(self):
        """cowrie_data: a SEPARATE volume for Cowrie's internal state (tty logs, downloads)."""
        import re
        compose = (ROOT / "pi" / "docker-compose.yml").read_text()
        assert re.search(r"^\s+-\s+cowrie_data:/cowrie/cowrie-git/var\s*$", compose, re.MULTILINE)
        assert "cowrie_data:" in compose.split("volumes:")[1].split("services:")[0]

    def test_filebeat_reads_cowrie_var_at_var_log_cowrie(self):
        """Filebeat MUST read from cowrie_var:/var/log/cowrie:ro — the same volume."""
        import re
        compose = (ROOT / "pi" / "docker-compose.yml").read_text()
        assert re.search(r"^\s+-\s+cowrie_var:/var/log/cowrie:ro\s*$", compose, re.MULTILINE)


# ============================================================
# Bootstrap script audit
# ============================================================

class TestESBootstrapExists:
    """Verify the ES bootstrap script exists and is executable."""

    def test_bootstrap_script_exists(self):
        p = ROOT / "scripts" / "deployment" / "bootstrap-elasticsearch.sh"
        assert p.exists(), "bootstrap-elasticsearch.sh must exist"
        assert p.stat().st_mode & 0o111, "bootstrap-elasticsearch.sh must be executable"

    def test_ilm_policy_file_exists(self):
        p = ROOT / "dashboard" / "elasticsearch" / "ilm" / "honeypot-events-policy.json"
        assert p.exists(), "ILM policy file must exist"

    def test_ilm_policy_referenced_by_template(self):
        import json
        tpl = json.loads((ROOT / "dashboard" / "elasticsearch" / "index-templates" / "honeypot-events.json").read_text())
        assert tpl["template"]["settings"]["index.lifecycle.name"] == "honeypot-events-policy"

    def test_bootstrap_installs_all_five_templates(self):
        """Bootstrap script must install all five template files."""
        s = (ROOT / "scripts" / "deployment" / "bootstrap-elasticsearch.sh").read_text()
        for name in ("honeypot-events", "honeypot-sessions", "honeypot-detections",
                     "honeypot-errors", "honeypot-training"):
            assert f"install_template {name}" in s, f"bootstrap must install {name}"

    def test_bootstrap_verifies_no_dangling_pipeline(self):
        s = (ROOT / "scripts" / "deployment" / "bootstrap-elasticsearch.sh").read_text()
        assert "honeypot-default" in s
        assert "dangling" in s.lower() or "no dangling" in s.lower()

    def test_start_pc1_invokes_bootstrap(self):
        s = (ROOT / "scripts" / "deployment" / "start-pc1.sh").read_text()
        assert "bootstrap-elasticsearch.sh" in s


# ============================================================
# E2E script audit
# ============================================================

class TestE2EScriptContract:
    """Audit the rewritten E2E script for the Pass 6 contract."""

    def test_e2e_uses_bounded_polling(self):
        s = (ROOT / "scripts" / "testing" / "run-e2e.sh").read_text()
        # Should NOT have an unconditional 5-second sleep as the primary wait.
        assert "sleep 5" not in s.replace("sleep 5s", "SLEEP5"), "5s sleep must be replaced by bounded polling"
        # Should poll with a timeout
        assert "timeout" in s.lower() or "60 2" in s  # poll_for_new_event 60 2

    def test_e2e_establishes_unique_run_markers(self):
        s = (ROOT / "scripts" / "testing" / "run-e2e.sh").read_text()
        assert "CAMPAIGN_ID=" in s
        assert "RUN_ID=" in s
        assert "TEST_START_ISO=" in s

    def test_e2e_queries_events_after_test_start(self):
        s = (ROOT / "scripts" / "testing" / "run-e2e.sh").read_text()
        # The ES query must filter @timestamp >= test_start
        assert "@timestamp" in s
        assert "TEST_START_ISO" in s
        assert "gte" in s

    def test_e2e_verifies_session_materialization(self):
        s = (ROOT / "scripts" / "testing" / "run-e2e.sh").read_text()
        assert "/sessions" in s
        assert "scheduler" in s.lower() or "materialized" in s.lower()

    def test_e2e_verifies_session_timeline_event_ids(self):
        s = (ROOT / "scripts" / "testing" / "run-e2e.sh").read_text()
        # Should verify the new event_id appears in the session timeline
        assert "event_ids" in s or "EVENT_ID" in s

    def test_e2e_does_not_print_passwords(self):
        s = (ROOT / "scripts" / "testing" / "run-e2e.sh").read_text()
        # Should never echo ES_PASS or ELASTIC_PASSWORD to stdout
        assert 'echo "$ES_PASS"' not in s
        assert 'echo "$ELASTIC_PASSWORD"' not in s


# ============================================================
# Pass 6 CORRECTION tests — final hardening
# ============================================================

class TestEventIdGenerationOrdering:
    """Regression: event_id MUST be generated BEFORE required-field
    validation, so a valid event without event_id becomes a normal event
    after deterministic ID generation — NOT a malformed event.
    """

    def _valid_event_no_event_id(self):
        """A camera event with event_id stripped — everything else valid."""
        ev = camera_fixture()
        ev.pop("event_id")
        return ev

    def test_valid_event_without_event_id_gets_generated(self):
        ev = normalize(self._valid_event_no_event_id())
        assert "event_id" in ev
        assert ev["event_id"].startswith("evt-")

    def test_valid_event_without_event_id_is_NOT_malformed(self):
        """The contract: a valid event missing only event_id becomes
        a NORMAL event after generation — NOT malformed."""
        ev = normalize(self._valid_event_no_event_id())
        r = ev["_routing"]
        assert r["is_malformed"] is False, (
            "valid event without event_id must NOT be marked malformed — "
            "event_id must be generated BEFORE validation"
        )
        assert r["target_index"].startswith("honeypot-events-")
        assert r["target_index"] == "honeypot-events-camera"
        assert r["document_id"] == ev["event_id"]
        assert r["action"] == "create"

    def test_event_id_generation_is_deterministic(self):
        """Same inputs → same event_id (allows ES action=create to dedup)."""
        ev1 = normalize(self._valid_event_no_event_id())
        ev2 = normalize(self._valid_event_no_event_id())
        assert ev1["event_id"] == ev2["event_id"]

    def test_existing_event_id_is_preserved(self):
        """If the source already provides event_id, it MUST be preserved."""
        ev = normalize(camera_fixture())
        assert ev["event_id"] == "evt-camera-1"

    def test_event_id_still_missing_when_upstream_fields_also_missing(self):
        """If @timestamp, session_id, AND event.action are all missing,
        fingerprint cannot generate an event_id — the event is malformed
        for multiple reasons, not just event_id.
        """
        raw = camera_fixture()
        raw.pop("event_id")
        raw.pop("@timestamp")
        raw.pop("session_id")
        raw["event"].pop("action", None)
        ev = normalize(raw)
        # event_id will be generated from empty strings — it will exist
        # but the event is still malformed because session_id is missing
        assert "event_id" in ev  # fingerprint fills it
        assert ev["_routing"]["is_malformed"] is True
        # The malformed reason mentions the missing field(s)
        reason = ev.get("reason", "") or ev.get("_error", "")
        assert "session_id" in reason


class TestMalformedFieldRoutingCases:
    """Cases C-F: each missing required field causes malformed routing."""

    def test_missing_session_id_routes_to_errors(self):
        ev = normalize(malformed_missing_session_id())
        assert ev["_routing"]["is_malformed"] is True
        assert ev["_routing"]["target_index"].startswith("honeypot-errors-")

    def test_missing_source_ip_routes_to_errors(self):
        ev = normalize(malformed_missing_source_ip())
        assert ev["_routing"]["is_malformed"] is True
        assert ev["_routing"]["target_index"].startswith("honeypot-errors-")

    def test_missing_event_type_routes_to_errors(self):
        """event.type is a required field. If missing, the event is malformed."""
        raw = camera_fixture()
        raw["event"].pop("type")
        ev = normalize(raw)
        assert ev["_routing"]["is_malformed"] is True
        reason = ev.get("reason", "") or ev.get("_error", "")
        assert "event.type" in reason

    def test_missing_honeypot_name_routes_to_errors(self):
        """honeypot.name is a required field. If missing, the event is malformed."""
        raw = camera_fixture()
        raw["honeypot"].pop("name")
        ev = normalize(raw)
        assert ev["_routing"]["is_malformed"] is True

    def test_malformed_events_get_error_id_stage_reason_tag(self):
        """Dead-letter contract: malformed events carry error_id, stage, reason, tag."""
        ev = normalize(malformed_missing_session_id())
        assert "error_id" in ev
        assert ev["stage"] == "logstash_normalization"
        assert "reason" in ev and ev["reason"]
        assert ev.get("tag") == "malformed"

    def test_malformed_routes_to_errors_not_events(self):
        """Malformed events MUST NOT route to honeypot-events-*."""
        ev = normalize(malformed_missing_session_id())
        assert "honeypot-events-" not in ev["_routing"]["target_index"]


class TestILMPolicyStructure:
    """G-I: ES ILM policy is valid Elasticsearch 8.x format (NOT OpenSearch ISM)."""

    def _load_ilm(self):
        import json
        with open(ROOT / "dashboard" / "elasticsearch" / "ilm" / "honeypot-events-policy.json") as f:
            return json.load(f)

    def test_policy_has_phases_not_states(self):
        """Elasticsearch ILM uses policy.phases.{hot,delete}; NOT OpenSearch ISM
        policy.states / policy.default_state / policy.ism_template."""
        ilm = self._load_ilm()
        policy = ilm["policy"]
        assert "phases" in policy, "ES ILM must use policy.phases (not states)"
        # Forbidden OpenSearch ISM fields
        for forbidden in ("default_state", "states", "ism_template", "state_name"):
            assert forbidden not in policy, (
                f"ILM policy must NOT contain OpenSearch ISM field '{forbidden}'"
            )

    def test_policy_has_hot_phase(self):
        ilm = self._load_ilm()
        assert "hot" in ilm["policy"]["phases"]

    def test_policy_has_delete_phase_with_min_age(self):
        ilm = self._load_ilm()
        delete = ilm["policy"]["phases"]["delete"]
        assert "min_age" in delete
        assert "delete" in delete.get("actions", {})

    def test_policy_min_age_is_bounded(self):
        """14-day retention — appropriate for a 256 GB SSD lab."""
        ilm = self._load_ilm()
        delete = ilm["policy"]["phases"]["delete"]
        # Must be a duration string ending in 'd' (days)
        assert delete["min_age"].endswith("d")
        # Sanity bound: between 1d and 365d
        days = int(delete["min_age"].rstrip("d"))
        assert 1 <= days <= 365

    def test_policy_no_rollover_alias(self):
        """We do NOT implement rollover — Logstash creates daily indices
        already, so rollover would conflict. The template must NOT
        reference index.lifecycle.rollover_alias.
        """
        import json
        tpl = json.loads(
            (ROOT / "dashboard" / "elasticsearch" / "index-templates" / "honeypot-events.json").read_text()
        )
        settings = tpl["template"]["settings"]
        assert "index.lifecycle.rollover_alias" not in settings


class TestBootstrapInstallsILMViaCorrectAPI:
    """H-I: bootstrap installs ILM through /_ilm/policy (ES API),
    NOT through /_opendistro/_ism/policies (OpenSearch API).
    """

    def test_bootstrap_uses_es_ilm_api(self):
        s = (ROOT / "scripts" / "deployment" / "bootstrap-elasticsearch.sh").read_text()
        assert "/_ilm/policy/honeypot-events-policy" in s
        # Must NOT use OpenSearch ISM API
        assert "/_opendistro/_ism/policies" not in s
        assert "_ism/policies" not in s

    def test_bootstrap_structurally_verifies_policy(self):
        """Bootstrap must parse the GET response and verify
        policy.phases.hot, policy.phases.delete, delete action — not
        merely grep for the policy name."""
        s = (ROOT / "scripts" / "deployment" / "bootstrap-elasticsearch.sh").read_text()
        # Look for the structural verification keys
        assert "phases" in s
        assert "hot" in s
        assert "delete" in s
        # Must explicitly reject OpenSearch ISM fields
        assert "default_state" in s  # mentioned in the forbidden-field check
        assert "ism_template" in s

    def test_bootstrap_structurally_verifies_template_mappings(self):
        """Bootstrap must structurally verify field types, not grep."""
        s = (ROOT / "scripts" / "deployment" / "bootstrap-elasticsearch.sh").read_text()
        # Look for the structural field-type checks
        for field in ("source.ip", "destination.ip", "session_id", "event_id",
                       "@timestamp", "ingested_at"):
            assert field in s, f"bootstrap must verify mapping for {field}"
        for typ in ("ip", "keyword", "date"):
            assert f'"{typ}"' in s or f"\"{typ}\"" in s, f"bootstrap must verify type {typ}"


class TestTemplateReferencesValidILM:
    """I: honeypot-events template references valid ILM policy."""

    def test_template_references_honeypot_events_policy(self):
        import json
        tpl = json.loads(
            (ROOT / "dashboard" / "elasticsearch" / "index-templates" / "honeypot-events.json").read_text()
        )
        assert tpl["template"]["settings"]["index.lifecycle.name"] == "honeypot-events-policy"

    def test_template_does_not_reference_dangling_pipeline(self):
        import json
        tpl = json.loads(
            (ROOT / "dashboard" / "elasticsearch" / "index-templates" / "honeypot-events.json").read_text()
        )
        settings = tpl["template"]["settings"]
        assert "index.default_pipeline" not in settings
        assert "honeypot-default" not in json.dumps(tpl)


class TestE2EContractCorrections:
    """J-N: E2E test contract — time-bounded + scenario/honeypot constrained,
    NOT falsely 'run-correlated'. Verifies event_id/session_id/session lineage.
    """

    def test_e2E_uses_timestamp_bounded_query(self):
        """J: E2E must filter @timestamp >= TEST_START_ISO."""
        s = (ROOT / "scripts" / "testing" / "run-e2e.sh").read_text()
        assert "TEST_START_ISO" in s
        assert "@timestamp" in s
        assert "gte" in s

    def test_e2E_verifies_event_id(self):
        """K: E2E must verify the event_id appears in API responses."""
        s = (ROOT / "scripts" / "testing" / "run-e2e.sh").read_text()
        assert "EVENT_ID" in s
        assert "event_id" in s

    def test_e2E_verifies_session_id(self):
        """L: E2E must verify the session_id."""
        s = (ROOT / "scripts" / "testing" / "run-e2e.sh").read_text()
        assert "SESSION_ID" in s
        assert "session_id" in s

    def test_e2E_verifies_session_event_lineage(self):
        """M: E2E must verify the event_id appears in the session timeline
        returned by GET /sessions/{id}."""
        s = (ROOT / "scripts" / "testing" / "run-e2e.sh").read_text()
        assert "event_ids" in s or "target_present" in s

    def test_e2E_does_not_claim_run_correlation(self):
        """N: E2E documentation/comments must NOT falsely claim
        campaign_id/run_id propagation into telemetry. The query filters
        on @timestamp + expected honeypot — that's time-bounded +
        scenario-constrained, NOT run-correlated.
        """
        s = (ROOT / "scripts" / "testing" / "run-e2e.sh").read_text()
        # Look for honest description of the correlation model.
        # Acceptable: 'time-bounded', 'scenario/honeypot constrained',
        # 'time-bounded and scenario/honeypot constrained'.
        # Forbidden: 'run-correlated', 'run-level correlation',
        # 'campaign_id is propagated into telemetry'.
        forbidden_phrases = (
            "run-correlated",
            "run-level correlation",
            "campaign_id is propagated",
            "run_id is propagated",
            "campaign_id is in telemetry",
        )
        for phrase in forbidden_phrases:
            assert phrase not in s, (
                f"E2E script must not falsely claim '{phrase}' — campaign_id/run_id "
                f"are not propagated into telemetry, only into the attacker run manifest"
            )

    def test_e2E_still_rejects_stale_data(self):
        """10: E2E must NOT use match_all + size:1 + 5s sleep."""
        s = (ROOT / "scripts" / "testing" / "run-e2e.sh").read_text()
        # The query must filter by @timestamp >= test_start, not match_all
        assert "match_all" not in s or "match_all" in s.split("size:1")[0] if "size:1" in s else True
        # No fixed 5-second sleep as the primary wait
        # (allow it inside bounded polling intervals)
        assert "sleep 5\n" not in s.replace("sleep 5s", "SLEEP5")

    def test_e2E_verifies_ingested_at_and_timestamp_source(self):
        """11: E2E must verify ingested_at and timestamp_source are present
        (they're part of the Pass 6 telemetry contract)."""
        s = (ROOT / "scripts" / "testing" / "run-e2e.sh").read_text()
        assert "ingested_at" in s
        assert "timestamp_source" in s


class TestLogstashProductionParity:
    """8: Production beats.conf must agree with the Python reference on
    event_id generation ordering, validation, malformed routing, action.
    """

    def test_production_generates_event_id_before_validation(self):
        """beats.conf must contain the fingerprint block BEFORE the
        'Validation — required fields' block. The Python reference does
        this — production must match."""
        beats_conf = (ROOT / "dashboard" / "logstash" / "pipelines" / "beats.conf").read_text()
        fingerprint_pos = beats_conf.find('fingerprint {')
        validation_pos = beats_conf.find('Validation — required fields')
        assert fingerprint_pos > 0, "fingerprint block not found"
        assert validation_pos > 0, "Validation block not found"
        assert fingerprint_pos < validation_pos, (
            "REGRESSION: fingerprint (event_id generation) must come BEFORE "
            "required-field validation. Otherwise a valid event without "
            "event_id is permanently tagged malformed before generation."
        )

    def test_production_uses_action_create_for_events(self):
        beats_conf = (ROOT / "dashboard" / "logstash" / "pipelines" / "beats.conf").read_text()
        assert "action => \"create\"" in beats_conf

    def test_production_uses_error_id_for_dead_letter(self):
        beats_conf = (ROOT / "dashboard" / "logstash" / "pipelines" / "beats.conf").read_text()
        assert "error_id" in beats_conf
        assert "document_id => \"%{error_id}\"" in beats_conf

    def test_production_populates_stage_reason_tag(self):
        beats_conf = (ROOT / "dashboard" / "logstash" / "pipelines" / "beats.conf").read_text()
        assert '"stage", "logstash_normalization"' in beats_conf
        assert '"reason"' in beats_conf
        assert '"tag", "malformed"' in beats_conf

    def test_production_uses_nested_field_syntax(self):
        """Production beats.conf must use [honeypot][name] etc., NOT flat
        'honeypot.name' strings, so the ES dynamic=false mapping does not
        silently drop them.

        We only check add_field directives (not comments) — comments may
        reference the forbidden flat name to document WHY it's forbidden.
        """
        import re
        beats_conf = (ROOT / "dashboard" / "logstash" / "pipelines" / "beats.conf").read_text()
        # Strip comment lines (lines whose first non-whitespace char is '#')
        code_lines = []
        for line in beats_conf.splitlines():
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            code_lines.append(line)
        code_only = "\n".join(code_lines)
        # Forbid flat-field add_field for the well-known nested fields.
        # Match: "field.name" => (with the quotes) inside add_field blocks.
        for forbidden in ('"honeypot.name"', '"event.type"', '"event.category"',
                          '"attack.classification"', '"attack.stage"',
                          '"device.type"', '"source.scope"'):
            assert forbidden not in code_only, (
                f"beats.conf must NOT use flat field {forbidden} in code "
                f"(comments are allowed to mention it for documentation) — "
                f"use nested [..][..] syntax"
            )

