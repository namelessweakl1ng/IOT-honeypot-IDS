import asyncio
from types import SimpleNamespace

import pytest

from backend.app.services import pi_manager as module


class Process:
    returncode = 0

    async def communicate(self):
        return b"camera=running\n", b""


def test_ssh_uses_strict_dedicated_host_keys_and_fixed_script(monkeypatch):
    captured = []

    async def create(*arguments, **kwargs):
        captured.extend(arguments)
        return Process()

    settings = SimpleNamespace(
        pi_host="192.168.50.10",
        pi_user="trapsig",
        pi_ssh_key="/home/trapsig/.ssh/pi_ssh_key",
        pi_known_hosts="/home/trapsig/.ssh/known_hosts",
    )
    monkeypatch.setattr(module, "get_settings", lambda: settings)
    monkeypatch.setattr(module.asyncio, "create_subprocess_exec", create)

    asyncio.run(module.PiManager().action("camera", "restart"))

    assert captured[0] == "ssh"
    assert "StrictHostKeyChecking=yes" in captured
    assert "UserKnownHostsFile=/home/trapsig/.ssh/known_hosts" in captured
    assert "IdentitiesOnly=yes" in captured
    assert captured[-3:] == [
        module.MANAGE_SCRIPT,
        "restart",
        "camera",
    ]


@pytest.mark.parametrize(
    "arguments",
    [("status",)] + [(action, service) for service in module.HONEYPOTS for action in ("start", "stop", "restart")],
)
def test_backend_remote_command_matches_forced_command_contract(monkeypatch, arguments):
    captured = []

    async def create(*command, **kwargs):
        captured.extend(command)
        return Process()

    settings = SimpleNamespace(
        pi_host="192.168.50.10",
        pi_user="trapsig",
        pi_ssh_key="/home/trapsig/.ssh/pi_ssh_key",
        pi_known_hosts="/home/trapsig/.ssh/known_hosts",
    )
    monkeypatch.setattr(module, "get_settings", lambda: settings)
    monkeypatch.setattr(module.asyncio, "create_subprocess_exec", create)

    asyncio.run(module.PiManager()._ssh(*arguments))

    assert captured[-(len(arguments) + 1) :] == [module.MANAGE_SCRIPT, *arguments]


@pytest.mark.parametrize("action", ["shell", "exec", "status", "remove"])
def test_public_action_rejects_non_management_operations(action):
    with pytest.raises(ValueError):
        asyncio.run(module.PiManager().action("camera", action))


def test_public_action_rejects_unknown_service():
    with pytest.raises(ValueError):
        asyncio.run(module.PiManager().action("arbitrary", "start"))
