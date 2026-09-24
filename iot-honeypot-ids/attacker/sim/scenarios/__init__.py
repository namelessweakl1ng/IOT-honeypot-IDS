"""Scenario registry."""
from .recon_basic import ReconBasicScenario
from .ssh_banner_probe import SshBannerProbeScenario
from .ssh_interaction import SshInteractionScenario
from .web_recon import WebReconScenario
from .iot_probe import IotProbeScenario
from .multi_stage import MultiStageScenario

SCENARIOS = {
    "recon_basic": ReconBasicScenario,
    "ssh_banner_probe": SshBannerProbeScenario,
    "ssh_interaction": SshInteractionScenario,
    "web_recon": WebReconScenario,
    "iot_probe": IotProbeScenario,
    "multi_stage": MultiStageScenario,
}

__all__ = ["SCENARIOS"]
