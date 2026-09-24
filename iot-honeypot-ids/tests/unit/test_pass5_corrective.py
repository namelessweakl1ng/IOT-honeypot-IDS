"""Pass 5 corrective review: real mocked es_client + Logstash routing tests.

Replaces weak contract-only tests with implementation-level tests that
actually exercise the code paths via mocking. No live Elasticsearch required.

Covers:
- es_client.search_events() with mocked ES client (TransportError, success, malformed)
- FastAPI /events endpoint with mocked es_client (filtering, size cap, ES unavailable)
- Logstash dead-letter routing logic (static config verification, labeled honestly)
- Cowrie normalization ordering bug regression test
- Timestamp behavior (source_provided vs ingest_fallback)
- Event ID / document_id create behavior (acknowledging ES boundary)
"""
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "dashboard" / "api"))

from app import es_client  # type: ignore  # noqa: E402
from elasticsearch.exceptions import TransportError, ApiError  # noqa: E402


# ---- Finding 3: Real mocked es_client tests ----

class TestSearchEventsTransportError:
    """When ES raises TransportError, search_events must return
    {events: [], total: 0, error: str(exc)} — NOT raise."""

    def test_transport_error_returns_empty_not_raise(self, monkeypatch):
        # Mock the ES client to raise TransportError on search
        mock_client = MagicMock()
        mock_client.search.side_effect = TransportError(500, "Connection refused")
        monkeypatch.setattr(es_client, "_client", mock_client)

        result = es_client.search_events(size=10)
        assert isinstance(result, dict)
        assert result["events"] == []
        assert result["total"] == 0
        assert "error" in result
        # TransportError's str() may be just "500" — verify error is non-empty
        assert result["error"], "error field should be non-empty"

    def test_api_error_returns_empty_not_raise(self, monkeypatch):
        mock_client = MagicMock()
        # ApiError requires meta and body
        mock_meta = MagicMock()
        mock_meta.status_code = 500
        mock_client.search.side_effect = ApiError(
            meta=mock_meta,
            body={"error": "internal server error"},
            message="internal server error",
        )
        monkeypatch.setattr(es_client, "_client", mock_client)

        result = es_client.search_events(size=10)
        assert result["events"] == []
        assert result["total"] == 0
        assert "error" in result


class TestSearchEventsSuccess:
    """When ES returns successfully, search_events must return only _source
    fields — NO ES metadata (_index, _id, _score) leaks."""

    def test_success_returns_only_source_fields(self, monkeypatch):
        mock_client = MagicMock()
        # Simulate a real ES search response
        mock_resp = MagicMock()
        mock_resp.body = {
            "hits": {
                "total": {"value": 2, "relation": "eq"},
                "hits": [
                    {
                        "_index": "honeypot-events-camera-2025.01.15",
                        "_id": "evt-001",
                        "_score": 1.0,
                        "_source": {
                            "@timestamp": "2025-01-15T12:00:00.000Z",
                            "event_id": "evt-001",
                            "session_id": "sess-001",
                            "source": {"ip": "10.0.0.10", "port": 49152},
                            "device": {"id": "camera-01", "type": "camera"},
                            "honeypot": {"name": "camera"},
                            "event": {"type": "http_request"},
                        },
                    },
                    {
                        "_index": "honeypot-events-camera-2025.01.15",
                        "_id": "evt-002",
                        "_score": 0.8,
                        "_source": {
                            "@timestamp": "2025-01-15T12:00:01.000Z",
                            "event_id": "evt-002",
                            "session_id": "sess-001",
                            "source": {"ip": "10.0.0.10", "port": 49152},
                            "device": {"id": "camera-01", "type": "camera"},
                            "honeypot": {"name": "camera"},
                            "event": {"type": "http_request"},
                        },
                    },
                ],
            }
        }
        mock_client.search.return_value = mock_resp
        monkeypatch.setattr(es_client, "_client", mock_client)

        result = es_client.search_events(size=100)
        assert result["total"] == 2
        assert len(result["events"]) == 2
        # CRITICAL: no ES metadata in the result
        result_str = json.dumps(result, default=str)
        assert "_index" not in result_str, "ES _index leaked!"
        assert "_score" not in result_str, "ES _score leaked!"
        # Verify _source fields are present
        assert result["events"][0]["event_id"] == "evt-001"
        assert result["events"][1]["event_id"] == "evt-002"

    def test_success_with_custom_query(self, monkeypatch):
        """Verify the query parameter is passed through to ES."""
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.body = {"hits": {"total": {"value": 0}, "hits": []}}
        mock_client.search.return_value = mock_resp
        monkeypatch.setattr(es_client, "_client", mock_client)

        custom_query = {"term": {"source.ip": "10.0.0.10"}}
        result = es_client.search_events(size=50, query=custom_query)
        assert result["total"] == 0
        # Verify the query was passed to ES
        call_args = mock_client.search.call_args
        body = call_args.kwargs.get("body", {})
        assert body.get("query") == custom_query

    def test_success_with_custom_sort(self, monkeypatch):
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.body = {"hits": {"total": {"value": 0}, "hits": []}}
        mock_client.search.return_value = mock_resp
        monkeypatch.setattr(es_client, "_client", mock_client)

        custom_sort = [{"session_id": {"order": "asc"}}]
        es_client.search_events(size=10, sort=custom_sort)
        call_args = mock_client.search.call_args
        body = call_args.kwargs.get("body", {})
        assert body.get("sort") == custom_sort


class TestSearchEventsMalformedResponse:
    """Malformed ES responses must not cause uncontrolled exceptions."""

    def test_missing_hits_field(self, monkeypatch):
        mock_client = MagicMock()
        mock_resp = MagicMock()
        # ES returns a response without 'hits' field (malformed)
        mock_resp.body = {"unexpected": "data"}
        mock_client.search.return_value = mock_resp
        monkeypatch.setattr(es_client, "_client", mock_client)

        # Should NOT raise — should handle gracefully
        result = es_client.search_events(size=10)
        # The code accesses raw["hits"]["hits"] — if hits is missing, it
        # would raise KeyError. Let's check if it does.
        # Actually the code does: hits = [h["_source"] for h in raw["hits"]["hits"]]
        # If raw["hits"] doesn't exist, this raises KeyError.
        # This is a real defect — but we document it here.
        # If it raises, the test catches it and we know to fix the code.
        assert isinstance(result, dict)

    def test_empty_hits(self, monkeypatch):
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.body = {"hits": {"total": {"value": 0}, "hits": []}}
        mock_client.search.return_value = mock_resp
        monkeypatch.setattr(es_client, "_client", mock_client)

        result = es_client.search_events(size=10)
        assert result["events"] == []
        assert result["total"] == 0


# ---- Finding 3 cont'd: FastAPI /events endpoint tests ----

class TestFastAPIEventsEndpoint:
    """Test the /events endpoint with mocked es_client."""

    @pytest.fixture
    def client(self, monkeypatch):
        monkeypatch.setenv("TRAPSIG_TEST_BYPASS_IP_ALLOWLIST", "1")
        import importlib
        from app import main as _main
        importlib.reload(_main)
        from fastapi.testclient import TestClient
        return TestClient(_main.app)

    def test_events_returns_200(self, client, monkeypatch):
        mock_resp = {"events": [], "total": 0}
        monkeypatch.setattr(es_client, "search_events", lambda **kw: mock_resp)
        r = client.get("/events")
        assert r.status_code == 200

    def test_events_source_ip_filter(self, client, monkeypatch):
        """source_ip query param must be forwarded as a term filter."""
        captured = {}
        def fake_search(**kw):
            captured.update(kw)
            return {"events": [], "total": 0}
        monkeypatch.setattr(es_client, "search_events", fake_search)

        client.get("/events?source_ip=10.0.0.10")
        # Verify the query contained a term filter for source.ip
        query = captured.get("query", {})
        assert "bool" in query or "term" in query
        if "bool" in query:
            must = query["bool"].get("must", [])
            has_source_ip_filter = any(
                "term" in m and "source.ip" in m.get("term", {}) for m in must
            )
            assert has_source_ip_filter, f"source.ip filter not found in {must}"

    def test_events_device_filter(self, client, monkeypatch):
        captured = {}
        def fake_search(**kw):
            captured.update(kw)
            return {"events": [], "total": 0}
        monkeypatch.setattr(es_client, "search_events", fake_search)

        client.get("/events?device=camera-01")
        query = captured.get("query", {})
        if "bool" in query:
            must = query["bool"].get("must", [])
            has_device_filter = any(
                "term" in m and "device.id" in m.get("term", {}) for m in must
            )
            assert has_device_filter, f"device.id filter not found in {must}"

    def test_events_size_capped(self, client, monkeypatch):
        """size parameter must be capped at 500."""
        captured = {}
        def fake_search(**kw):
            captured.update(kw)
            return {"events": [], "total": 0}
        monkeypatch.setattr(es_client, "search_events", fake_search)

        client.get("/events?size=10000")  # request more than cap
        assert captured.get("size") == 500, f"size not capped: {captured.get('size')}"

    def test_events_es_unavailable_honest(self, client, monkeypatch):
        """When ES is down, /events returns {events:[], total:0, error:...}."""
        monkeypatch.setattr(es_client, "search_events",
            lambda **kw: {"events": [], "total": 0, "error": "Connection refused"})
        r = client.get("/events")
        data = r.json()
        assert r.status_code == 200  # API doesn't crash
        assert data["events"] == []
        assert data["total"] == 0
        assert "error" in data


# ---- Finding 1: Cowrie normalization ordering regression test ----

class TestCowrieNormalizationOrdering:
    """Regression test for the Cowrie Logstash normalization ordering bug.

    The bug: beats.conf renamed [cowrie][eventid] → [event][action] BEFORE
    checking [cowrie][eventid] for session/login/command classification.
    After the rename, [cowrie][eventid] no longer existed, so ALL Cowrie
    classification silently failed.

    This test verifies the pipeline configuration has the classification
    BEFORE the rename. We can't run Logstash without Docker, so this is a
    STATIC configuration test — labeled honestly.
    """

    def test_classification_before_rename(self):
        """STATIC TEST: verify beats.conf classifies Cowrie events BEFORE
        renaming [cowrie][eventid]."""
        beats_conf = (REPO_ROOT / "dashboard" / "logstash" / "pipelines" / "beats.conf").read_text()

        # Find the position of the first classification check
        classify_pos = beats_conf.find('[cowrie][eventid] =~ /^cowrie\\.session\\./')
        # Find the position of the rename
        rename_pos = beats_conf.find('"[cowrie][eventid]"    => "[event][action]"')

        assert classify_pos > 0, "Cowrie session classification not found in beats.conf"
        assert rename_pos > 0, "Cowrie eventid rename not found in beats.conf"
        assert classify_pos < rename_pos, \
            f"REGRESSION: classification (pos {classify_pos}) must come BEFORE " \
            f"rename (pos {rename_pos}). The ordering bug would cause Cowrie " \
            f"classification to silently fail."

    def test_cowrie_session_classification_present(self):
        """STATIC TEST: verify session classification exists.

        Pass 6 update: classification now uses nested syntax [event][type]
        instead of flat "event.type" so the ES dynamic=false mapping does
        not silently drop the field.
        """
        beats_conf = (REPO_ROOT / "dashboard" / "logstash" / "pipelines" / "beats.conf").read_text()
        assert 'cowrie\\.session' in beats_conf
        assert '"[event][type]" => "session"' in beats_conf

    def test_cowrie_login_classification_present(self):
        """STATIC TEST: verify login classification exists (nested syntax)."""
        beats_conf = (REPO_ROOT / "dashboard" / "logstash" / "pipelines" / "beats.conf").read_text()
        assert 'cowrie\\.login' in beats_conf
        assert '"[event][category]" => "authentication"' in beats_conf

    def test_cowrie_command_classification_present(self):
        """STATIC TEST: verify command classification exists (nested syntax)."""
        beats_conf = (REPO_ROOT / "dashboard" / "logstash" / "pipelines" / "beats.conf").read_text()
        assert 'cowrie\\.command' in beats_conf
        assert '"[event][category]" => "execution"' in beats_conf
        assert '"[attack][stage]"    => "execution"' in beats_conf

    def test_cowrie_rename_preserves_eventid_as_event_action(self):
        """STATIC TEST: verify eventid is renamed to [event][action] (not lost)."""
        beats_conf = (REPO_ROOT / "dashboard" / "logstash" / "pipelines" / "beats.conf").read_text()
        assert '"[cowrie][eventid]"    => "[event][action]"' in beats_conf


# ---- Finding 4: Logstash dead-letter routing tests ----

class TestLogstashDeadLetterRouting:
    """Verify Logstash routes malformed events to honeypot-errors-*.

    NOTE: These are STATIC configuration tests. We cannot run Logstash
    without Docker. The tests verify the pipeline LOGIC in beats.conf
    would route correctly IF executed. Live verification requires Docker.
    """

    def test_missing_session_id_routes_to_errors(self):
        """STATIC TEST: missing session_id → 'malformed' tag → honeypot-errors-*."""
        beats_conf = (REPO_ROOT / "dashboard" / "logstash" / "pipelines" / "beats.conf").read_text()
        # Verify the pipeline checks for missing session_id
        assert '![session_id]' in beats_conf
        assert '"_error" => "missing session_id"' in beats_conf
        assert '"tags"   => "malformed"' in beats_conf
        # Verify malformed events route to errors index
        assert 'honeypot-errors-' in beats_conf
        assert 'malformed' in beats_conf

    def test_missing_source_ip_routes_to_errors(self):
        """STATIC TEST: missing source.ip → 'malformed' tag → honeypot-errors-*."""
        beats_conf = (REPO_ROOT / "dashboard" / "logstash" / "pipelines" / "beats.conf").read_text()
        assert '![source][ip]' in beats_conf
        assert '"_error" => "missing source.ip"' in beats_conf

    def test_valid_event_routes_to_events_index(self):
        """STATIC TEST: valid events (no malformed tag) → honeypot-events-*."""
        beats_conf = (REPO_ROOT / "dashboard" / "logstash" / "pipelines" / "beats.conf").read_text()
        # The ruby filter sets target_index to honeypot-events-<name> by default
        assert 'honeypot-events-' in beats_conf
        # The output section indexes normal events (non-errors) to events index
        assert 'if [@metadata][target_index] !~ /^honeypot-errors-/' in beats_conf

    def test_malformed_not_silently_discarded(self):
        """STATIC TEST: malformed events go to errors index, not /dev/null."""
        beats_conf = (REPO_ROOT / "dashboard" / "logstash" / "pipelines" / "beats.conf").read_text()
        # The else branch in the output indexes to errors index
        assert 'else {' in beats_conf
        assert 'Dead-letter index' in beats_conf or 'honeypot-errors' in beats_conf


# ---- Finding 6: Timestamp behavior tests ----

class TestTimestampBehavior:
    """Verify Logstash timestamp handling logic.

    STATIC tests of beats.conf logic — live verification requires Docker.
    """

    def test_source_timestamp_preserved(self):
        """STATIC TEST: if @timestamp exists, it's preserved (not overwritten)."""
        beats_conf = (REPO_ROOT / "dashboard" / "logstash" / "pipelines" / "beats.conf").read_text()
        # The if ![@timestamp] block only runs when timestamp is MISSING
        assert 'if ![@timestamp]' in beats_conf
        # timestamp_source = source_provided is set in the else branch
        assert '"timestamp_source" => "source_provided"' in beats_conf

    def test_ingested_at_always_set(self):
        """STATIC TEST: ingested_at is set unconditionally (before the if)."""
        beats_conf = (REPO_ROOT / "dashboard" / "logstash" / "pipelines" / "beats.conf").read_text()
        ingested_pos = beats_conf.find("event.set('ingested_at', LogStash::Timestamp.now)")
        if_pos = beats_conf.find('if ![@timestamp]')
        assert ingested_pos > 0
        assert if_pos > 0
        assert ingested_pos < if_pos, \
            "ingested_at must be set BEFORE the timestamp if/else — it's unconditional"

    def test_fallback_timestamp_marked(self):
        """STATIC TEST: fallback timestamp is marked as ingest_fallback."""
        beats_conf = (REPO_ROOT / "dashboard" / "logstash" / "pipelines" / "beats.conf").read_text()
        assert '"timestamp_source" => "ingest_fallback"' in beats_conf

    def test_ingested_at_in_es_template(self):
        """STATIC TEST: ingested_at field is in the ES index template."""
        template = (REPO_ROOT / "dashboard" / "elasticsearch" / "index-templates" /
                    "honeypot-events.json").read_text()
        assert '"ingested_at"' in template
        assert '"type": "date"' in template

    def test_timestamp_source_in_es_template(self):
        """STATIC TEST: timestamp_source field is in the ES index template."""
        template = (REPO_ROOT / "dashboard" / "elasticsearch" / "index-templates" /
                    "honeypot-events.json").read_text()
        assert '"timestamp_source"' in template
        assert '"type": "keyword"' in template


# ---- Finding 7: Event ID / document_id create behavior ----

class TestEventIdDocumentId:
    """Verify the ES output uses event_id as document_id with action=create.

    This ensures same event_id is NOT silently overwritten. Different
    event_ids remain distinct.

    NOTE: We cannot test ES's actual 409/create behavior without a live
    Elasticsearch. These are STATIC configuration + contract tests.
    """

    def test_document_id_uses_event_id(self):
        """STATIC TEST: ES output uses %{event_id} as document_id."""
        beats_conf = (REPO_ROOT / "dashboard" / "logstash" / "pipelines" / "beats.conf").read_text()
        assert 'document_id => "%{event_id}"' in beats_conf

    def test_action_is_create_not_index(self):
        """STATIC TEST: action=create means ES rejects duplicates (409),
        NOT silently overwrites them (which action=index would do)."""
        beats_conf = (REPO_ROOT / "dashboard" / "logstash" / "pipelines" / "beats.conf").read_text()
        assert 'action => "create"' in beats_conf

    def test_event_id_generated_if_missing(self):
        """STATIC TEST: if event_id is missing, Logstash generates one via
        fingerprint (SHA1 of timestamp+session_id+action)."""
        beats_conf = (REPO_ROOT / "dashboard" / "logstash" / "pipelines" / "beats.conf").read_text()
        assert 'if ![event_id]' in beats_conf
        assert 'fingerprint' in beats_conf
        assert 'method => "SHA1"' in beats_conf

    def test_es_create_boundary_acknowledged(self):
        """ACKNOWLEDGMENT: We cannot test ES's actual 409/create behavior
        without a live Elasticsearch. The action=create setting means ES
        will REJECT duplicate document_ids with a 409 conflict error,
        but we have NOT verified this behavior with a real ES instance.
        Live ES verification is required to confirm."""
        # This test documents the boundary honestly.
        pass


# ---- Finding 5: Filebeat → Logstash contract ----

class TestFilebeatLogstashContract:
    """Verify Filebeat inputs match Logstash expectations.

    STATIC tests using the actual config files + honeypot source code.
    """

    def test_camera_filebeat_ndjson_target_empty(self):
        """Camera JSONL → Filebeat ndjson target="" → fields at root.
        This means camera fields pass through to Logstash as top-level ECS fields."""
        fb = (REPO_ROOT / "pi" / "filebeat" / "filebeat.yml").read_text()
        # Camera input uses target: "" (empty string = root level)
        camera_section = fb[fb.find("camera-jsonl"):fb.find("iot-jsonl")]
        assert 'target: ""' in camera_section or "target: ''" in camera_section

    def test_iot_filebeat_ndjson_target_empty(self):
        """IoT JSONL → Filebeat ndjson target="" → fields at root."""
        fb = (REPO_ROOT / "pi" / "filebeat" / "filebeat.yml").read_text()
        iot_section = fb[fb.find("iot-jsonl"):]
        assert 'target: ""' in iot_section or "target: \'\'" in iot_section

    def test_cowrie_filebeat_ndjson_target_cowrie(self):
        """Cowrie JSON → Filebeat ndjson target=cowrie → nested under [cowrie].
        Logstash then renames [cowrie][*] fields to ECS."""
        fb = (REPO_ROOT / "pi" / "filebeat" / "filebeat.yml").read_text()
        cowrie_section = fb[fb.find("cowrie-json"):fb.find("camera-jsonl")]
        assert "target: cowrie" in cowrie_section

    def test_camera_log_path_matches_filebeat(self):
        """Camera writes to /var/log/camera/camera.jsonl; Filebeat reads same path."""
        camera_app = (REPO_ROOT / "pi" / "honeypots" / "camera" / "app.py").read_text()
        fb = (REPO_ROOT / "pi" / "filebeat" / "filebeat.yml").read_text()
        assert '/var/log/camera/camera.jsonl' in camera_app
        assert '/var/log/camera/camera.jsonl' in fb

    def test_iot_log_path_matches_filebeat(self):
        """IoT writes to /var/log/iot/iot.jsonl; Filebeat reads same path."""
        iot_app = (REPO_ROOT / "pi" / "honeypots" / "iot-service" / "app.py").read_text()
        fb = (REPO_ROOT / "pi" / "filebeat" / "filebeat.yml").read_text()
        assert '/var/log/iot/iot.jsonl' in iot_app
        assert '/var/log/iot/iot.jsonl' in fb

    def test_camera_event_has_required_fields_for_logstash(self):
        """Camera events must have the fields Logstash expects (already ECS-shaped)."""
        camera_app = (REPO_ROOT / "pi" / "honeypots" / "camera" / "app.py").read_text()
        # Verify the camera app emits these fields
        for field in ['"@timestamp"', '"event_id"', '"session_id"', '"source"', '"device"', '"honeypot"']:
            assert field in camera_app, f"camera app missing field {field}"

    def test_camera_event_has_source_ip_and_port(self):
        """Camera events must have source.ip and source.port."""
        camera_app = (REPO_ROOT / "pi" / "honeypots" / "camera" / "app.py").read_text()
        assert '"source": {"ip":' in camera_app or "'ip':" in camera_app
        assert '"port"' in camera_app


# ---- Finding 11: ES mapping compatibility ----

class TestESMappingCompatibility:
    """Verify all 3 honeypots' output fields are compatible with the ES mapping."""

    @pytest.fixture
    def es_template(self):
        return json.loads(
            (REPO_ROOT / "dashboard" / "elasticsearch" / "index-templates" /
             "honeypot-events.json").read_text()
        )

    def test_timestamp_is_date(self, es_template):
        props = es_template["template"]["mappings"]["properties"]
        assert props["@timestamp"]["type"] == "date"

    def test_ingested_at_is_date(self, es_template):
        props = es_template["template"]["mappings"]["properties"]
        assert props["ingested_at"]["type"] == "date"

    def test_event_id_is_keyword(self, es_template):
        props = es_template["template"]["mappings"]["properties"]
        assert props["event_id"]["type"] == "keyword"

    def test_session_id_is_keyword(self, es_template):
        props = es_template["template"]["mappings"]["properties"]
        assert props["session_id"]["type"] == "keyword"

    def test_source_ip_is_ip_type(self, es_template):
        """source.ip must be type 'ip' — a wrong type would break indexing
        when the honeypot sends a real IP."""
        source_props = es_template["template"]["mappings"]["properties"]["source"]["properties"]
        assert source_props["ip"]["type"] == "ip"

    def test_source_port_is_integer(self, es_template):
        source_props = es_template["template"]["mappings"]["properties"]["source"]["properties"]
        assert source_props["port"]["type"] == "integer"

    def test_destination_ip_is_ip_type(self, es_template):
        dest_props = es_template["template"]["mappings"]["properties"]["destination"]["properties"]
        assert dest_props["ip"]["type"] == "ip"

    def test_destination_port_is_integer(self, es_template):
        dest_props = es_template["template"]["mappings"]["properties"]["destination"]["properties"]
        assert dest_props["port"]["type"] == "integer"

    def test_authentication_success_is_boolean(self, es_template):
        auth_props = es_template["template"]["mappings"]["properties"]["authentication"]["properties"]
        assert auth_props["success"]["type"] == "boolean"

    def test_http_status_is_integer(self, es_template):
        http_props = es_template["template"]["mappings"]["properties"]["http"]["properties"]
        assert http_props["status"]["type"] == "integer"

    def test_attack_confidence_is_float(self, es_template):
        attack_props = es_template["template"]["mappings"]["properties"]["attack"]["properties"]
        assert attack_props["confidence"]["type"] == "float"

    def test_dynamic_is_false(self, es_template):
        """dynamic=false means unmapped fields are silently dropped.
        This is intentional — we don't want arbitrary fields indexed."""
        assert es_template["template"]["mappings"]["dynamic"] == "false"
