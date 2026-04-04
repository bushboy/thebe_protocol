"""Configuration for Planner service.

This module handles loading configuration from environment variables
and configuration files.

Requirements: 5.1, 5.6
"""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path


class PlannerConfig(BaseSettings):
    """Configuration for Planner service."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Service configuration
    service_name: str = "planner"
    host: str = "0.0.0.0"
    port: int = 8000

    # Authentication configuration
    auth0_domain: str = ""
    auth0_client_id: str = ""
    auth0_client_secret: str = ""
    auth0_audience: str = ""

    # Certificate paths
    server_cert_path: Path = Field(
        default=Path("infra/certificates/planner/server.crt"),
        validation_alias="MTLS_SERVER_CERT",
    )
    server_key_path: Path = Field(
        default=Path("infra/certificates/planner/server.key"),
        validation_alias="MTLS_SERVER_KEY",
    )
    client_cert_path: Path = Field(
        default=Path("infra/certificates/planner/client.crt"),
        validation_alias="MTLS_CLIENT_CERT",
    )
    client_key_path: Path = Field(
        default=Path("infra/certificates/planner/client.key"),
        validation_alias="MTLS_CLIENT_KEY",
    )
    root_ca_path: Path = Field(
        default=Path("infra/certificates/root_ca.crt"),
        validation_alias="MTLS_CA_CERT",
    )

    # DPoP configuration
    dpop_private_key_path: Path = Field(
        default=Path("infra/auth0/keys/planner-dpop.key"),
        validation_alias="DPOP_PRIVATE_KEY_PATH",
    )

    # Service URLs
    intent_engine_url: str = "http://intent-engine:8001"
    audit_service_url: str = "https://audit:8005"

# Global config instance
config = PlannerConfig()
