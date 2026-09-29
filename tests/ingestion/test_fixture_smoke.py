import json
from pathlib import Path

from backend.app.services.normalizer import normalize


def test_fixture_ingestion_smoke():
    raw = json.loads((Path(__file__).parents[1] / "fixtures/events.json").read_text())
    normalized = [normalize(item, item["service"], item["service"] + "-01", "pi-test") for item in raw]
    assert len(normalized) == 3 and all(item["event"]["id"] for item in normalized)
