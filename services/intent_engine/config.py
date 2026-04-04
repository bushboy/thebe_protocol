"""Configuration for Intent Engine service.

This module handles loading configuration from environment variables
and configuration files.

Requirements: 6.1, 6.2
"""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path


class IntentEngineConfig(BaseSettings):
    """Configuration for Intent Engine service."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        protected_namespaces=("settings_",),
        extra="ignore"
    )

    # Service configuration
    service_name: str = "intent-engine"
    host: str = "0.0.0.0"
    port: int = 8001

    # Model configuration
    model_name: str = "all-MiniLM-L6-v2"
    similarity_threshold: float = 0.7

    # Authentication configuration
    auth0_domain: str = ""
    auth0_client_id: str = ""
    auth0_client_secret: str = ""
    auth0_audience: str = ""

    # Certificate paths
    server_cert_path: Path = Field(
        default=Path("infra/certificates/intent-engine/server.crt"),
        validation_alias="MTLS_SERVER_CERT",
    )
    server_key_path: Path = Field(
        default=Path("infra/certificates/intent-engine/server.key"),
        validation_alias="MTLS_SERVER_KEY",
    )
    client_cert_path: Path = Field(
        default=Path("infra/certificates/intent-engine/client.crt"),
        validation_alias="MTLS_CLIENT_CERT",
    )
    client_key_path: Path = Field(
        default=Path("infra/certificates/intent-engine/client.key"),
        validation_alias="MTLS_CLIENT_KEY",
    )
    root_ca_path: Path = Field(
        default=Path("infra/certificates/root_ca.crt"),
        validation_alias="MTLS_CA_CERT",
    )

    # DPoP configuration
    dpop_private_key_path: Path = Field(
        default=Path("infra/auth0/keys/intent-engine-dpop.key"),
        validation_alias="DPOP_PRIVATE_KEY_PATH",
    )

    # Signing key for intent signatures
    signing_key_path: Path = Field(
        default=Path("infra/certificates/intent-engine/server.key"),
        validation_alias="MTLS_SERVER_KEY",
    )

    # Audit service URL
    audit_service_url: str = "https://audit:8005"

# Global config instance
config = IntentEngineConfig()
