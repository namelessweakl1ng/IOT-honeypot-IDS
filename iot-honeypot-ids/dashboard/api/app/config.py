"""Application configuration — env-driven, no secrets in source."""
from __future__ import annotations

import os
from functools import lru_cache
from ipaddress import ip_network
from typing import List

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # ---- ES -----------------------------------------------------------
    elasticsearch_url: str = "http://elasticsearch:9200"
    elastic_user: str = "elastic"
    elastic_password: str = "changeme-elastic"

    # ---- API ---------------------------------------------------------
    api_secret_key: str = ""
    api_allowed_cidrs: str = "192.168.1.0/24,127.0.0.0/8"

    # ---- Pi control plane -------------------------------------------
    # EMPTY defaults mean NOT_CONFIGURED — never silently target 192.168.1.50.
    # Set these in .env when a Pi is actually deployed.
    pi_ip: str = ""                              # e.g. "192.168.1.50"
    pi_ssh_user: str = ""                        # e.g. "pi"
    pi_ssh_key_path: str = ""                    # e.g. "/app/ssh-keys/id_ed25519"
    pi_known_hosts_path: str = "/app/known_hosts"
    pi_ssh_accept_new_host_key: bool = False    # lab bootstrap only
    pi_ssh_connect_timeout: int = 3              # seconds (-o ConnectTimeout=)
    pi_ssh_command_timeout: int = 15            # seconds (per ssh command)
    pi_deploy_path: str = "~/iot-honeypot-ids/pi"  # path on Pi to docker-compose.yml

    # ---- Paths -------------------------------------------------------
    model_path: str = "/app/model-lab/models"
    data_path: str = "/app/data"
    ml_code_path: str = "/app/ml"

    # ---- ML defaults -------------------------------------------------
    default_random_seed: int = 42
    default_train_test_split: float = 0.2
    default_feature_version: str = "v2"  # v2 = leakage-safe (excludes 3 label-derived features)

    # ---- Logging -----------------------------------------------------
    log_level: str = "INFO"

    @property
    def allowed_networks(self) -> List[ip_network]:
        out: List[ip_network] = []
        for raw in (self.api_allowed_cidrs or "").split(","):
            raw = raw.strip()
            if not raw:
                continue
            try:
                out.append(ip_network(raw, strict=False))
            except ValueError:
                continue
        return out


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
