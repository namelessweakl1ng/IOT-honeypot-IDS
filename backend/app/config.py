from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    elasticsearch_url: str = "http://elasticsearch:9200"
    elastic_password: str = ""
    kibana_url: str = "http://localhost:5601"
    pi_host: str = ""
    pi_user: str = "trapsig"
    pi_ssh_key: str = "/run/secrets/pi_ssh_key"
    lab_subnet: str = "192.168.50.0/24"
    session_timeout_seconds: int = 300
    brute_force_threshold: int = 5
    web_enumeration_threshold: int = 4
    multi_service_threshold: int = 3
    cors_origins: str = "http://localhost:3000"

@lru_cache
def get_settings() -> Settings:
    return Settings()
