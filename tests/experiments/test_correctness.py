import asyncio
import json
from pathlib import Path

import pytest

from backend.app.services.experiments import correlate, validate_lab_host
from backend.app.services.processor import EventProcessor
from backend.app.services.scenarios import SERVICE_TO_HONEYPOT, ScenarioCatalog, ScenarioCatalogError


def test_catalog_discovers_every_repository_manifest_and_stable_hash():
    directory = Path("attacks/scenarios")
    first = ScenarioCatalog(directory).load()
    second = ScenarioCatalog(directory).load()
    assert len(first) == len(list(directory.glob("*.yaml"))) == 14
    assert {key: item.manifest_sha256 for key, item in first.items()} == {key: item.manifest_sha256 for key, item in second.items()}


@pytest.mark.parametrize("service,honeypot", [("ssh", "cowrie"), ("telnet", "cowrie"), ("http", "camera"), ("iot", "iot-service")])
def test_canonical_mapping(service, honeypot):
    assert SERVICE_TO_HONEYPOT[service] == honeypot


def manifest(tmp_path, filename="one.yaml", **changes):
    data = {
        "id": "one",
        "name": "One",
        "description": "test",
        "target_services": ["ssh"],
        "expected_detection": "BRUTE_FORCE",
        "severity": "high",
        "steps": [{"service": "ssh"}],
    }
    data.update(changes)
    (tmp_path / filename).write_text(json.dumps(data))


def test_filename_mismatch_unknown_service_and_detection_fail(tmp_path):
    manifest(tmp_path, id="different")
    with pytest.raises(ScenarioCatalogError, match="filename"):
        ScenarioCatalog(tmp_path).load()
    (tmp_path / "one.yaml").unlink()
    manifest(tmp_path, target_services=["smtp"], steps=[{"service": "smtp"}])
    with pytest.raises(ScenarioCatalogError, match="unknown step service"):
        ScenarioCatalog(tmp_path).load()
    (tmp_path / "one.yaml").unlink()
    manifest(tmp_path, expected_detection="MAGIC")
    with pytest.raises(ScenarioCatalogError, match="unknown expected"):
        ScenarioCatalog(tmp_path).load()


def test_duplicate_ids_fail(tmp_path, monkeypatch):
    manifest(tmp_path)
    scenario_path = tmp_path / "one.yaml"
    original_glob = Path.glob
    monkeypatch.setattr(Path, "glob", lambda path, pattern: [scenario_path, scenario_path] if path == tmp_path else original_glob(path, pattern))
    with pytest.raises(ScenarioCatalogError, match="duplicate"):
        ScenarioCatalog(tmp_path).load()


@pytest.mark.parametrize("value", ["127.0.0.1", "192.168.51.2", "192.168.50.0", "192.168.50.255"])
def test_invalid_lab_hosts(value):
    with pytest.raises(ValueError):
        validate_lab_host(value, "192.168.50.0/24", "target_ip")


def test_scientific_results_require_ground_truth_and_telemetry():
    base = {
        "start_time": "2026-01-01T00:00:00Z",
        "end_time": "2026-01-01T00:01:00Z",
        "attacker_ip": "192.168.50.20",
        "target_ip": "192.168.50.10",
        "target_honeypots": ["cowrie"],
        "expected_detection": "BRUTE_FORCE",
        "telemetry_settled": True,
    }
    assert correlate(base, [], [], [], scientific=True)["result_reason"] == "NO_GROUND_TRUTH"
    base["ground_truth_valid"] = True
    assert correlate(base, [], [], [], scientific=True)["result_reason"] == "NO_TELEMETRY"
    event = {
        "@timestamp": "2026-01-01T00:00:10Z",
        "event": {"id": "e1"},
        "source": {"ip": base["attacker_ip"]},
        "destination": {"ip": base["target_ip"]},
        "service": {"name": "cowrie"},
    }
    session = {"session_id": "s1", "event_ids": ["e1"]}
    assert correlate(base, [event], [session], [], scientific=True)["result"] == "FN"
    detection = {
        "detection_id": "d1",
        "session_id": "s1",
        "type": "BRUTE_FORCE",
        "timestamp": "2026-01-01T00:00:10Z",
        "evidence_end_time": "2026-01-01T00:00:10Z",
        "detected_at": "2026-01-01T00:00:12Z",
    }
    result = correlate(base, [event], [session], [detection], scientific=True)
    assert result["result"] == "TP"
    assert (result["evidence_latency_seconds"], result["detection_latency_seconds"], result["processing_latency_seconds"]) == (10, 12, 2)


class DetectionStore:
    def __init__(self, events):
        self.events, self.docs = events, {}

    async def search(self, *_a, **_kw):
        return self.events

    async def get(self, index, identifier):
        return self.docs.get((index, identifier))

    async def save(self, index, identifier, document):
        self.docs[(index, identifier)] = dict(document)
        return document


def test_processor_preserves_first_detected_at():
    events = []
    for i in range(5):
        events.append(
            {
                "@timestamp": f"2026-01-01T00:00:0{i}Z",
                "event": {"id": f"e{i}", "category": "authentication", "outcome": "failure"},
                "source": {"ip": "192.168.50.20"},
                "destination": {"ip": "192.168.50.10"},
                "service": {"name": "cowrie"},
                "honeypot": {"id": "cowrie"},
                "network": {"protocol": "ssh"},
            }
        )
    store = DetectionStore(events)
    processor = EventProcessor(store)
    asyncio.run(processor.process_once())
    key = next(key for key in store.docs if key[0] == "trapsig-detections")
    first = store.docs[key]["detected_at"]
    asyncio.run(processor.process_once())
    assert store.docs[key]["detected_at"] == first
    assert store.docs[key]["evidence_end_time"] == store.docs[key]["timestamp"]
