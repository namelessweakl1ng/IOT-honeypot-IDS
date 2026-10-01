"""Repository contracts for the fictional Cowrie embedded-gateway persona."""

from configparser import ConfigParser
from pathlib import Path

ROOT = Path(__file__).parents[2]
COWRIE = ROOT / "sensor/honeypots/cowrie"
HONEYFS = COWRIE / "honeyfs"
CFG_PATH = COWRIE / "cowrie.cfg"
COMPOSE_PATH = ROOT / "sensor/docker-compose.yml"
FORBIDDEN = ("trapsig", "honeypot", "cowrie", "research", "lab", "python", "twisted")


def _config() -> ConfigParser:
    config = ConfigParser(interpolation=None)
    config.read(CFG_PATH)
    return config


def _content(path: str) -> str:
    return (HONEYFS / path.lstrip("/")).read_text(encoding="utf-8")


def test_transport_identity_and_json_logging_contract() -> None:
    config = _config()

    assert config.getboolean("ssh", "enabled")
    assert config["ssh"]["listen_endpoints"] == "tcp:2222:interface=0.0.0.0"
    assert config["ssh"]["version"].startswith("SSH-2.0-OpenSSH_")
    assert config.getboolean("telnet", "enabled")
    assert config["telnet"]["listen_endpoints"] == "tcp:2223:interface=0.0.0.0"
    assert config.getboolean("output_jsonlog", "enabled")
    assert config["output_jsonlog"]["logfile"] == "var/log/cowrie/cowrie.json"

    identity = config["honeypot"]
    assert identity["hostname"] == "VE-GW-01"
    assert identity["kernel_version"] == "4.14.98-velora"
    assert identity["hardware_platform"] == "armv7l"
    assert identity["operating_system"] == "GNU/Linux"
    assert identity["contents_path"] == "honeyfs"


def test_authentication_contract_is_unchanged() -> None:
    rules = (COWRIE / "userdb.txt").read_text(encoding="utf-8").splitlines()
    assert rules == ["root:x:root", "*:x:!*"]


def test_filesystem_identity_is_consistent_and_synthetic() -> None:
    hostname = _content("/etc/hostname")
    os_release = _content("/etc/os-release")
    issue = _content("/etc/issue.net")
    motd = _content("/etc/motd")
    version = _content("/proc/version")
    cpuinfo = _content("/proc/cpuinfo")

    assert hostname == "VE-GW-01\n"
    assert 'NAME="Velora Embedded Linux"' in os_release
    assert 'VERSION_ID="2.7.4"' in os_release
    assert "Velora Edge Gateway VEG-200" in issue
    assert "VEG-200" in motd and "2.7.4" in motd and "VE-GW-01" in motd
    assert "4.14.98-velora" in version
    assert cpuinfo.count("ARMv7 Processor rev 5") == 4
    assert "Hardware\t: Velora VEG2 Embedded Platform" in cpuinfo


def test_attacker_facing_content_has_no_disclosure_markers() -> None:
    files = [path for path in HONEYFS.rglob("*") if path.is_file()]
    content = "\n".join(path.read_text(encoding="utf-8") for path in files).lower()
    for marker in FORBIDDEN:
        assert marker not in content

    ssh_banner = _config()["ssh"]["version"].lower()
    for marker in FORBIDDEN:
        assert marker not in ssh_banner


def test_compose_mounts_overlay_read_only_and_retains_hardening() -> None:
    compose = COMPOSE_PATH.read_text(encoding="utf-8")
    cowrie_service = compose.split("  cowrie:\n", 1)[1].split("  camera:\n", 1)[0]

    assert '"2222:2222"' in cowrie_service
    assert '"2223:2223"' in cowrie_service
    assert "./honeypots/cowrie/honeyfs:/cowrie/cowrie-git/honeyfs:ro" in cowrie_service
    assert "cap_drop: [ALL]" in cowrie_service
    assert "no-new-privileges:true" in cowrie_service
    assert "pids_limit:" in cowrie_service
    assert "mem_limit:" in cowrie_service
    assert "cpus:" in cowrie_service
    assert "privileged:" not in cowrie_service
    assert "/var/run/docker.sock" not in cowrie_service


def test_no_high_interaction_backend_is_configured() -> None:
    config = _config()
    forbidden_sections = {"ssh_proxy", "telnet_proxy", "proxy", "qemu", "llm"}
    assert forbidden_sections.isdisjoint(section.lower() for section in config.sections())
