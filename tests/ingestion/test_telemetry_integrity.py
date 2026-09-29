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
    return normalize({"timestamp":"2026-01-01T00:00:00Z","event_id":identifier,"category":"network","type":"info","action":"request","outcome":"unknown","source_ip":ip,"source_port":"1234","destination_ip":"192.168.50.10","destination_port":"80","protocol":"http","service":service}, service, service+"-01", "pi-01", now=lambda: datetime(2026,1,2,tzinfo=timezone.utc))

def test_normalizer_integrity_fields_and_typed_values():
    item=event("192.168.50.20")
    assert item["trapsig"] == {"sensor_id":"pi-01","schema_version":"1","internal":False}
    assert item["event"]["ingested"] == "2026-01-02T00:00:00Z"
    assert item["source"]["port"] == 1234

def test_loopback_classification_does_not_include_private_labs():
    assert is_internal_event(event("127.8.9.10"))
    assert is_internal_event(event("::1"))
    assert not is_internal_event(event("192.168.50.20"))

class Store:
    def __init__(self, events): self.events, self.documents = events, {}
    async def search(self, *args, **kwargs): return self.events
    async def save(self,index,identifier,document): self.documents[(index,identifier)]=document; return document

def test_processor_keeps_raw_but_excludes_loopback_multiservice():
    raw=[event("127.0.0.2","camera","i1"),event("127.0.0.2","router","i2"),event("127.0.0.2","mqtt","i3"),event("192.168.50.20","camera","e")]
    store=Store(raw); result=asyncio.run(EventProcessor(store).process_once())
    assert store.events == raw and result["sessions"] == 1
    assert all(doc.get("source_ip") != "127.0.0.2" for doc in store.documents.values())
    assert not any(doc.get("type") == "MULTI_SERVICE_ACTIVITY" for doc in store.documents.values())

def test_external_multiservice_still_detects(monkeypatch):
    raw=[event("192.168.50.20","camera","a"),event("192.168.50.20","router","b"),event("192.168.50.20","mqtt","c")]
    store=Store(raw); asyncio.run(EventProcessor(store).process_once())
    assert any(doc.get("type") == "MULTI_SERVICE_ACTIVITY" for doc in store.documents.values())

def test_templates_are_typed_and_single_node():
    files=list((ROOT/'elk/elasticsearch/index-templates').glob('*.json'))
    docs={f.stem:json.loads(f.read_text()) for f in files}
    assert set(docs)=={'trapsig-events','trapsig-dead-letter','trapsig-sessions','trapsig-detections','trapsig-experiments'}
    assert all(d['template']['settings']['number_of_replicas']==0 for d in docs.values())
    p=docs['trapsig-events']['template']['mappings']['properties']
    assert p['source']['properties']['ip']['type']=='ip' and p['source']['properties']['port']['type']=='integer'
    assert p['@timestamp']['type']==p['event']['properties']['ingested']['type']=='date'
    assert docs['trapsig-detections']['template']['mappings']['properties']['severity']['type']=='keyword'

def test_logstash_routes_validation_failures_and_preserves_raw():
    validation=(ROOT/'elk/logstash/pipelines/90-validation.conf').read_text()
    output=(ROOT/'elk/logstash/pipelines/99-output.conf').read_text()
    assert '_trapsig_validation_failure' in validation and 'unresolved_interpolation' in validation
    assert 'trapsig-dead-letter-' in output and 'remove_field => ["raw"' in output
    assert '"_trapsig_validation_failure" not in [tags]' in output

class CleanupStore:
    def __init__(self): self.client=self; self.deleted=[]
    async def count(self,index,query=None): return 2
    async def delete_by_query(self,**kwargs): self.deleted.append(kwargs)

def test_cleanup_is_dry_run_and_confirm_is_derived_only():
    store=CleanupStore(); asyncio.run(cleanup(False,store)); assert not store.deleted
    asyncio.run(cleanup(True,store)); assert {x['index'] for x in store.deleted}==set(TARGET_INDICES)
    assert not {'trapsig-events-*','trapsig-experiments'} & set(TARGET_INDICES)

def test_analytics_matches_explicit_keyword_contract():
    source=(ROOT/'backend/app/api/analytics.py').read_text()
    assert 'severity.keyword' not in source and 'type.keyword' not in source and 'honeypots_touched.keyword' not in source
    assert '"field": "severity"' in source and '"field": "type"' in source

def test_system_status_missing_dead_letter_is_zero(monkeypatch):
    from backend.app.api import health as module
    async def unavailable_count(index):
        if index == 'trapsig-dead-letter-*': raise RuntimeError('missing')
        return 1
    async def healthy(): return {'status':'green'}
    async def statuses(): return {}
    monkeypatch.setattr(module.store,'count',unavailable_count)
    monkeypatch.setattr(module.store,'health',healthy)
    monkeypatch.setattr(module.pi_manager,'statuses',statuses)
    result=asyncio.run(module.status())
    assert result['counts']['dead_letter'] == 0
