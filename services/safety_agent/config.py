"""Configuration for Safety Agent service.

This module handles loading configuration from environment variables
and configuration files.

Requirements: 7.1, 7.2
"""

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path


class SafetyAgentConfig(BaseSettings):
    """Configuration for Safety Agent service."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # Service configuration
    service_name: str = "safety-agent"
    host: str = "0.0.0.0"
    port: int = 8002

    # OPA configuration
    opa_url: str = "http://localhost:8181"
    opa_policy_path: str = "agentic_guardian/decision"
    opa_timeout: float = 5.0

    # Authentication configuration
    auth0_domain: str = ""
    auth0_client_id: str = ""
    auth0_client_secret: str = ""
    auth0_audience: str = ""

    # Certificate paths
    server_cert_path: Path = Path("infra/certificates/safety-agent/server.crt")
    server_key_path: Path = Path("infra/certificates/safety-agent/server.key")
    client_cert_path: Path = Path("infra/certificates/safety-agent/client.crt")
    client_key_path: Path = Path("infra/certificates/safety-agent/client.key")
    root_ca_path: Path = Path("infra/certificates/root_ca.crt")

    # DPoP configuration
    dpop_private_key_path: Path = Path("infra/auth0/keys/safety-agent-dpop.key")

    # Signing key for policy approvals
    signing_key_path: Path = Field(
        default=Path("infra/certificates/safety-agent/server.key"),
        validation_alias=AliasChoices("SIGNING_PRIVATE_KEY_PATH", "SIGNING_KEY_PATH")
    )

    # Audit service URL
    audit_service_url: str = "https://audit:8005"

# Global config instance
config = SafetyAgentConfig()
