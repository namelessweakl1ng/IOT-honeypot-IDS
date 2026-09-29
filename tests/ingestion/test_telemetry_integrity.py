import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

from backend.app.services.normalizer import normalize
from backend.app.services.processor import EventProcessor
from backend.app.services.telemetry import is_internal_event
from backend.app.tools.cleanup_internal_derived import TARGET_INDICES, cleanup

ROOT = Path(__file__).parents[2]


def event(ip, service="camera", identifier="x"):
    return normalize(
        {
            "timestamp": "2026-01-01T00:00:00Z",
            "event_id": identifier,
            "category": "network",
            "type": "info",
            "action": "request",
            "outcome": "unknown",
            "source_ip": ip,
            "source_port": "1234",
            "destination_ip": "192.168.50.10",
            "destination_port": "80",
            "protocol": "http",
            "service": service,
        },
        service,
        service + "-01",
        "pi-01",
        now=lambda: datetime(2026, 1, 2, tzinfo=timezone.utc),
    )


def test_normalizer_integrity_fields_and_typed_values():
    item = event("192.168.50.20")
    assert item["trapsig"] == {"sensor_id": "pi-01", "schema_version": "1", "internal": False}
    assert item["event"]["ingested"] == "2026-01-02T00:00:00Z"
    assert item["source"]["port"] == 1234


def test_loopback_classification_does_not_include_private_labs():
    assert is_internal_event(event("127.8.9.10"))
    assert is_internal_event(event("::1"))
    assert not is_internal_event(event("192.168.50.20"))


class Store:
    def __init__(self, events):
        self.events, self.documents = events, {}

    async def search(self, *args, **kwargs):
        return self.events

    async def save(self, index, identifier, document):
        self.documents[(index, identifier)] = document
        return document


def test_processor_keeps_raw_but_excludes_loopback_multiservice():
    raw = [event("127.0.0.2", "camera", "i1"), event("127.0.0.2", "router", "i2"), event("127.0.0.2", "mqtt", "i3"), event("192.168.50.20", "camera", "e")]
    store = Store(raw)
    result = asyncio.run(EventProcessor(store).process_once())
    assert store.events == raw and result["sessions"] == 1
    assert all(doc.get("source_ip") != "127.0.0.2" for doc in store.documents.values())
    assert not any(doc.get("type") == "MULTI_SERVICE_ACTIVITY" for doc in store.documents.values())


def test_external_multiservice_still_detects(monkeypatch):
    raw = [event("192.168.50.20", "camera", "a"), event("192.168.50.20", "router", "b"), event("192.168.50.20", "mqtt", "c")]
    store = Store(raw)
    asyncio.run(EventProcessor(store).process_once())
    assert any(doc.get("type") == "MULTI_SERVICE_ACTIVITY" for doc in store.documents.values())


def test_templates_are_typed_and_single_node():
    files = list((ROOT / "elk/elasticsearch/index-templates").glob("*.json"))
    docs = {f.stem: json.loads(f.read_text()) for f in files}
    assert set(docs) == {"trapsig-events", "trapsig-dead-letter", "trapsig-sessions", "trapsig-detections", "trapsig-experiments"}
    assert all(d["template"]["settings"]["number_of_replicas"] == 0 for d in docs.values())
    p = docs["trapsig-events"]["template"]["mappings"]["properties"]
    assert p["source"]["properties"]["ip"]["type"] == "ip" and p["source"]["properties"]["port"]["type"] == "integer"
    assert p["@timestamp"]["type"] == p["event"]["properties"]["ingested"]["type"] == "date"
    assert docs["trapsig-detections"]["template"]["mappings"]["properties"]["severity"]["fields"]["keyword"]["type"] == "keyword"


def test_logstash_routes_validation_failures_and_preserves_raw():
    validation = (ROOT / "elk/logstash/pipelines/90-validation.conf").read_text()
    output = (ROOT / "elk/logstash/pipelines/99-output.conf").read_text()
    assert "_trapsig_validation_failure" in validation and "unresolved_interpolation" in validation
    assert "trapsig-dead-letter-" in output and 'remove_field => ["raw"' in output
    assert '"_trapsig_validation_failure" not in [tags]' in output


class Indices:
    def __init__(self):
        self.refreshed = []

    async def refresh(self, **kwargs):
        self.refreshed.append(kwargs)


class CleanupClient:
    def __init__(self, values):
        self.values = values
        self.deleted = []
        self.indices = Indices()

    async def search(self, **kwargs):
        return {"hits": {"hits": [{"_id": str(i), "_source": {"source_ip": value}, "sort": [i]} for i, value in enumerate(self.values)]}}

    async def delete(self, **kwargs):
        self.deleted.append(kwargs)


class CleanupStore:
    def __init__(self, values):
        self.client = CleanupClient(values)


def test_cleanup_is_mapping_independent_dry_run_and_confirm_is_derived_only():
    # These strings are returned identically by historical text/keyword and new ip mappings.
    for mapping_shape in ("historical_text", "new_ip"):
        store = CleanupStore(["127.9.8.7", "::1", "192.168.50.20"])
        counts = asyncio.run(cleanup(False, store))
        assert counts == {index: 2 for index in TARGET_INDICES}, mapping_shape
        assert not store.client.deleted
        asyncio.run(cleanup(True, store))
        assert {x["index"] for x in store.client.deleted} == set(TARGET_INDICES)
        assert all(x["id"] in {"0", "1"} for x in store.client.deleted)
    assert not {"trapsig-events-*", "trapsig-experiments"} & set(TARGET_INDICES)


def test_analytics_uses_historical_compatible_multifields():
    source = (ROOT / "backend/app/api/analytics.py").read_text()
    assert all(path in source for path in ("severity.keyword", "type.keyword", "honeypots_touched.keyword"))
    docs = {f.stem: json.loads(f.read_text()) for f in (ROOT / "elk/elasticsearch/index-templates").glob("*.json")}
    detections = docs["trapsig-detections"]["template"]["mappings"]["properties"]
    sessions = docs["trapsig-sessions"]["template"]["mappings"]["properties"]
    assert detections["severity"]["fields"]["keyword"]["type"] == "keyword"
    assert detections["type"]["fields"]["keyword"]["type"] == "keyword"
    assert sessions["honeypots_touched"]["fields"]["keyword"]["type"] == "keyword"


def test_system_status_missing_dead_letter_is_zero(monkeypatch):
    from backend.app.api import health as module

    calls = []

    async def count(index, missing_index_is_empty=False):
        calls.append((index, missing_index_is_empty))
        return 0 if index == "trapsig-dead-letter-*" else 1

    async def healthy():
        return {"status": "green"}

    async def statuses():
        return {}

    monkeypatch.setattr(module.store, "count", count)
    monkeypatch.setattr(module.store, "health", healthy)
    monkeypatch.setattr(module.pi_manager, "statuses", statuses)
    result = asyncio.run(module.status())
    assert result["counts"]["dead_letter"] == 0
    assert all(flag for _, flag in calls)


def test_system_status_does_not_hide_real_count_errors(monkeypatch):
    from backend.app.api import health as module

    async def broken(*args, **kwargs):
        raise RuntimeError("connection failed")

    async def healthy():
        return {"status": "green"}

    async def statuses():
        return {}

    monkeypatch.setattr(module.store, "count", broken)
    monkeypatch.setattr(module.store, "health", healthy)
    monkeypatch.setattr(module.pi_manager, "statuses", statuses)
    import pytest

    with pytest.raises(RuntimeError, match="connection failed"):
        asyncio.run(module.status())


def test_logstash_validates_mapping_types_timestamp_and_original_input():
    validation = (ROOT / "elk/logstash/pipelines/90-validation.conf").read_text()
    input_conf = (ROOT / "elk/logstash/pipelines/00-input.conf").read_text()
    assert 'require "ipaddr"' in validation
    assert "invalid_source_ip" in validation and "invalid_destination_ip" in validation
    assert "_dateparsefailure" in validation and "invalid_timestamp" in validation
    assert "[raw][original]" in validation and "[@metadata][trapsig_original]" in input_conf
    assert "invalid_mqtt_packet_type" in validation and "invalid_port" in validation


def test_setup_updates_only_known_existing_trapsig_replicas():
    setup = (ROOT / "elk/elasticsearch/setup/install-templates.sh").read_text()
    assert '"number_of_replicas":0' in setup and "/_settings?allow_no_indices=true" in setup
    assert "trapsig-events-*" in setup and "trapsig-experiments" in setup
    assert "_all" not in setup


def test_reference_normalizer_rejects_missing_or_invalid_destination_ip():
    import pytest

    raw = {"timestamp": "2026-01-01T00:00:00Z", "event_id": "x", "source_ip": "192.168.50.20", "protocol": "http", "service": "camera"}
    with pytest.raises(ValueError):
        normalize(raw, "camera", "camera-01", "pi-01")
    raw["destination_ip"] = "sensor"
    with pytest.raises(ValueError):
        normalize(raw, "camera", "camera-01", "pi-01")
    assert event("2001:db8::20")["destination"]["ip"] == "192.168.50.10"


def test_reference_normalizer_accepts_valid_ipv4_and_ipv6_rejects_invalid_ips():
    import pytest

    assert event("198.51.100.20")["source"]["ip"] == "198.51.100.20"
    assert event("2001:db8::20")["source"]["ip"] == "2001:db8::20"
    for invalid in ("999.1.2.3", "2001:::bad"):
        with pytest.raises(ValueError, match="valid IPv4 or IPv6"):
            event(invalid)


def test_elastic_count_only_swallows_not_found_when_requested(monkeypatch):
    import backend.app.elastic as elastic

    class Missing(Exception):
        pass

    class Client:
        async def count(self, **kwargs):
            raise Missing()

    instance = object.__new__(elastic.ElasticStore)
    instance.client = Client()
    monkeypatch.setattr(elastic, "NotFoundError", Missing)
    assert asyncio.run(instance.count("missing", missing_index_is_empty=True)) == 0
    import pytest

    with pytest.raises(Missing):
        asyncio.run(instance.count("missing"))


def test_analytics_executes_compatible_aggregation_paths(monkeypatch):
    from backend.app.api import analytics

    calls = {}

    async def aggregate(index, query, aggregations, **kwargs):
        calls[index] = aggregations
        return {"hits": {"total": {"value": 0}, "hits": []}, "aggregations": {}}

    monkeypatch.setattr(analytics.store, "aggregate", aggregate)
    asyncio.run(analytics.overview(60))
    assert calls["trapsig-detections"]["severity"]["terms"]["field"] == "severity.keyword"
    assert calls["trapsig-detections"]["types"]["terms"]["field"] == "type.keyword"
    script = calls["trapsig-sessions"]["multi_service"]["filter"]["script"]["script"]
    assert "doc['honeypots_touched.keyword']" in script
