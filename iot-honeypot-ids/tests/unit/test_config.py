"""Unit tests for the FastAPI settings module."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "dashboard" / "api"))

# Import the config module — it should work without env vars set
from app.config import Settings  # type: ignore  # noqa: E402


def test_settings_defaults():
    s = Settings()
    assert s.elasticsearch_url.startswith("http://")
    assert s.api_secret_key == ""  # missing deployment secret must fail closed
    assert s.default_random_seed == 42
    assert 0 < s.default_train_test_split < 1


def test_allowed_networks_parses_cidrs():
    s = Settings(api_allowed_cidrs="192.168.1.0/24,127.0.0.0/8")
    nets = s.allowed_networks
    assert len(nets) == 2


def test_allowed_networks_skips_garbage():
    s = Settings(api_allowed_cidrs="192.168.1.0/24,garbage,10.0.0.0/8")
    nets = s.allowed_networks
    assert len(nets) == 2


def test_allowed_networks_empty_string():
    s = Settings(api_allowed_cidrs="")
    assert s.allowed_networks == []


def test_allowed_networks_recognizes_lab_ip():
    import ipaddress
    s = Settings(api_allowed_cidrs="192.168.1.0/24,127.0.0.0/8")
    assert ipaddress.ip_address("192.168.1.50") in s.allowed_networks[0]
    assert ipaddress.ip_address("127.0.0.1") in s.allowed_networks[1]
    assert not any(ipaddress.ip_address("8.8.8.8") in n for n in s.allowed_networks)
