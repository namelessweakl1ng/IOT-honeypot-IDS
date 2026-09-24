"""Safety layer tests — every safety constraint must fail-closed."""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "attacker"))

from sim.safety import SafetyConfig, SafetyRefusal, validate_target, validate_port, validate_scenario, validate_limits


def make_config(**kw):
    defaults = dict(
        allowed_cidrs=["192.168.1.0/24"],
        allowed_ports=[2222, 8080, 9000],
        allowed_scenarios=["recon_basic", "ssh_probe", "web_recon", "iot_probe", "ssh_interaction", "multi_stage"],
        require_private_target=True,
        require_explicit_target=True,
        allow_localhost=False,
        max_connections=30,
        max_requests=50,
        max_auth_attempts=10,
        scenario_timeout_seconds=120,
    )
    defaults.update(kw)
    return SafetyConfig(**defaults)


class TestTargetSafety:
    def test_private_target_in_cidr_accepted(self):
        cfg = make_config()
        assert validate_target("192.168.1.50", cfg) == "192.168.1.50"

    def test_public_target_rejected(self):
        cfg = make_config()
        with pytest.raises(SafetyRefusal, match="public IP"):
            validate_target("8.8.8.8", cfg)

    def test_target_outside_cidr_rejected(self):
        cfg = make_config()
        with pytest.raises(SafetyRefusal, match="outside the configured"):
            validate_target("192.168.2.50", cfg)

    def test_invalid_ip_rejected(self):
        cfg = make_config()
        with pytest.raises(SafetyRefusal, match="not a valid IP"):
            validate_target("not-an-ip", cfg)

    def test_hostname_rejected(self):
        cfg = make_config()
        with pytest.raises(SafetyRefusal, match="not a valid IP"):
            validate_target("example.com", cfg)

    def test_localhost_rejected_by_default(self):
        cfg = make_config()
        with pytest.raises(SafetyRefusal, match="loopback"):
            validate_target("127.0.0.1", cfg)

    def test_localhost_allowed_when_configured(self):
        cfg = make_config(allow_localhost=True)
        assert validate_target("127.0.0.1", cfg) == "127.0.0.1"

    def test_link_local_rejected(self):
        cfg = make_config(allow_localhost=True)
        with pytest.raises(SafetyRefusal, match="link-local"):
            validate_target("169.254.1.1", cfg)

    def test_multicast_rejected(self):
        cfg = make_config(allow_localhost=True)
        with pytest.raises(SafetyRefusal, match="multicast"):
            validate_target("224.0.0.1", cfg)

    def test_unspecified_rejected(self):
        cfg = make_config()
        with pytest.raises(SafetyRefusal, match="unspecified"):
            validate_target("0.0.0.0", cfg)

    def test_empty_target_rejected(self):
        cfg = make_config()
        with pytest.raises(SafetyRefusal, match="no target"):
            validate_target("", cfg)

    def test_private_target_not_required_allows_public(self):
        cfg = make_config(require_private_target=False, allowed_cidrs=["0.0.0.0/0"])
        # With require_private_target=False + 0.0.0.0/0 CIDR, 8.8.8.8 passes
        assert validate_target("8.8.8.8", cfg) == "8.8.8.8"


class TestPortSafety:
    def test_allowed_port_accepted(self):
        cfg = make_config()
        assert validate_port(2222, cfg) == 2222

    def test_unauthorized_port_rejected(self):
        cfg = make_config()
        with pytest.raises(SafetyRefusal, match="not in the allowed ports"):
            validate_port(22, cfg)

    def test_port_80_rejected(self):
        cfg = make_config()
        with pytest.raises(SafetyRefusal):
            validate_port(80, cfg)


class TestScenarioSafety:
    def test_allowed_scenario_accepted(self):
        cfg = make_config()
        assert validate_scenario("recon_basic", cfg) == "recon_basic"

    def test_unknown_scenario_rejected(self):
        cfg = make_config()
        with pytest.raises(SafetyRefusal, match="not in the allowed scenarios"):
            validate_scenario("arbitrary_attack", cfg)


class TestLimitsSafety:
    def test_hard_ceiling_on_connections(self):
        with pytest.raises(SafetyRefusal, match="hard safety ceiling"):
            make_config(max_connections=101)

    def test_hard_ceiling_on_requests(self):
        with pytest.raises(SafetyRefusal, match="hard safety ceiling"):
            make_config(max_requests=201)

    def test_hard_ceiling_on_auth_attempts(self):
        with pytest.raises(SafetyRefusal, match="hard safety ceiling"):
            make_config(max_auth_attempts=21)

    def test_hard_ceiling_on_timeout(self):
        with pytest.raises(SafetyRefusal, match="hard safety ceiling"):
            make_config(scenario_timeout_seconds=601)

    def test_zero_connections_rejected(self):
        cfg = make_config(max_connections=0)
        with pytest.raises(SafetyRefusal, match="must be positive"):
            validate_limits(cfg)

    def test_zero_requests_rejected(self):
        cfg = make_config(max_requests=0)
        with pytest.raises(SafetyRefusal, match="must be positive"):
            validate_limits(cfg)
