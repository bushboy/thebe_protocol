"""Configuration for the Rules Management service."""

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class RulesManagementConfig(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Service
    service_name: str = "rules-management"
    host: str = "0.0.0.0"
    port: int = 8010
    log_level: str = "INFO"

    # CORS — comma-separated list of allowed origins
    cors_origins: str = "http://localhost:3000"

    # OPA REST API
    opa_url: str = "http://localhost:8181"
    opa_timeout: float = 10.0

    # Persistence
    rules_store_path: Path = Path("/shared/rules_store.json")

    # Path to the monolithic OPA policy file (for one-time initialisation)
    opa_policy_file: Path = Path("infra/opa/policies.rego")

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


config = RulesManagementConfig()
