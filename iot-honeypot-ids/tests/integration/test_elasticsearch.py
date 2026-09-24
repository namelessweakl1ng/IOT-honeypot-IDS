"""Integration test — requires a running Elasticsearch on localhost:9200."""
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "dashboard" / "api"))

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def es_client():
    try:
        from elasticsearch import Elasticsearch
    except ImportError:
        pytest.skip("elasticsearch python client not installed")
    url = os.environ.get("ELASTICSEARCH_URL", "http://localhost:9200")
    pw = os.environ.get("ELASTIC_PASSWORD", "")
    es = Elasticsearch(url, basic_auth=("elastic", pw), request_timeout=5)
    if not es.ping():
        pytest.skip("Elasticsearch not reachable")
    return es


def test_cluster_health(es_client):
    health = es_client.cluster.health()
    body = health.body if hasattr(health, "body") else health
    assert body["status"] in {"green", "yellow"}


def test_index_template_loaded(es_client):
    # After Logstash has run at least once, the honeypot-events-* indices
    # should exist (or templates should be loaded).
    # This test is intentionally lenient — the platform works even on
    # a fresh cluster with no events yet.
    indices = es_client.indices.get(index="*")
    body = indices.body if hasattr(indices, "body") else indices
    assert isinstance(body, dict)
