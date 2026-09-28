import os
from dataclasses import dataclass
from functools import lru_cache


@dataclass(frozen=True)
class Settings:
    elasticsearch_url: str = os.getenv("ELASTICSEARCH_URL", "http://elasticsearch:9200")
    elastic_password: str = os.getenv("ELASTIC_PASSWORD", "")
    kibana_url: str = os.getenv("KIBANA_URL", "http://localhost:5601")
    pi_host: str = os.getenv("PI_HOST", "")
    pi_user: str = os.getenv("PI_USER", "trapsig")
    pi_ssh_key: str = os.getenv("PI_SSH_KEY", "/run/secrets/pi_ssh_key")
    lab_subnet: str = os.getenv("LAB_SUBNET", "192.168.50.0/24")
    session_timeout_seconds: int = int(os.getenv("SESSION_TIMEOUT_SECONDS", "300"))
    brute_force_threshold: int = int(os.getenv("BRUTE_FORCE_THRESHOLD", "5"))
    web_enumeration_threshold: int = int(os.getenv("WEB_ENUMERATION_THRESHOLD", "4"))
    multi_service_threshold: int = int(os.getenv("MULTI_SERVICE_THRESHOLD", "3"))
    processing_interval_seconds: int = int(os.getenv("PROCESSING_INTERVAL_SECONDS", "10"))
    processing_event_limit: int = int(os.getenv("PROCESSING_EVENT_LIMIT", "10000"))
    cors_origins: str = os.getenv("CORS_ORIGINS", "http://localhost:3000")


@lru_cache
def get_settings() -> Settings:
    return Settings()
