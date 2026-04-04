"""Configuration for Executor Agent service."""

from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class ExecutorConfig(BaseSettings):
    """Configuration settings for Executor Agent."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Service settings
    host: str = "0.0.0.0"
    port: int = 8005

    # Auth0 settings
    auth0_domain: str = "dev-example.auth0.com"
    auth0_client_id: str = ""
    auth0_client_secret: str = ""

    # Certificate paths
    root_ca_path: Path = Path("infra/certificates/root_ca/ca.crt")
    client_cert_path: Path = Path("infra/certificates/executor/client.crt")
    client_key_path: Path = Path("infra/certificates/executor/client.key")

    # DPoP key path
    dpop_private_key_path: Path = Path("infra/auth0/executor_dpop_key.pem")

    # Redis settings for replay prevention
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    redis_password: str = ""

    # Audit Service URL
    audit_service_url: str = "https://localhost:8006"

    # Provider API settings
    github_api_url: str = "https://api.github.com"
    slack_api_url: str = "https://slack.com/api"
    google_workspace_api_url: str = "https://www.googleapis.com"

config = ExecutorConfig()
