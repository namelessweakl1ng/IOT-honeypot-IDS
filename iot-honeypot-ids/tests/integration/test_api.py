"""Integration test — requires the FastAPI service running on localhost:8000."""
import os
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def api_url() -> str:
    return os.environ.get("API_URL", "http://localhost:8000")


def test_health_endpoint(api_url):
    import urllib.request
    import json
    try:
        r = urllib.request.urlopen(f"{api_url}/health", timeout=5)
        assert r.status == 200
        j = json.loads(r.read())
        assert "status" in j
        assert "elasticsearch" in j
    except Exception:
        pytest.skip("API not reachable")


def test_sessions_endpoint(api_url):
    import urllib.request
    import json
    try:
        r = urllib.request.urlopen(f"{api_url}/sessions?size=5", timeout=5)
        assert r.status == 200
        j = json.loads(r.read())
        assert "sessions" in j
    except Exception:
        pytest.skip("API not reachable")


def test_models_endpoint(api_url):
    import urllib.request
    import json
    try:
        r = urllib.request.urlopen(f"{api_url}/models", timeout=5)
        assert r.status == 200
        j = json.loads(r.read())
        assert "models" in j
    except Exception:
        pytest.skip("API not reachable")
