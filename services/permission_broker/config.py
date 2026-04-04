"""Configuration for Permission Broker service.

This module handles loading configuration from environment variables
and configuration files.

Requirements: 8.1, 8.7, 6.1, 6.2, 6.3, 6.4, 7.6
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path
from typing import Optional, Dict, Any, Literal
from pydantic import Field, field_validator, model_validator


class PermissionBrokerConfig(BaseSettings):
    """Configuration for Permission Broker service."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # Service configuration
    service_name: str = "permission-broker"
    host: str = "0.0.0.0"
    port: int = 8003

    # Legacy Auth0 configuration (backward compatibility)
    auth0_domain: str = ""
    auth0_client_id: str = ""
    auth0_client_secret: str = ""
    auth0_audience: str = ""
    auth0_token_vault_url: str = ""

    # IAL configuration (new format)
    identity_provider: Optional[Literal["auth0", "keycloak", "aws_secrets", "openfga"]] = None

    # Auth0 IAL configuration
    ial_auth0_domain: Optional[str] = None
    ial_auth0_client_id: Optional[str] = None
    ial_auth0_client_secret: Optional[str] = None
    ial_auth0_token_vault_url: Optional[str] = None
    ial_auth0_timeout: float = 10.0

    # Keycloak IAL configuration
    ial_keycloak_server_url: Optional[str] = None
    ial_keycloak_realm: Optional[str] = None
    ial_keycloak_client_id: Optional[str] = None
    ial_keycloak_client_secret: Optional[str] = None
    ial_keycloak_scope_mapping: Optional[str] = None  # JSON string
    ial_keycloak_timeout: float = 10.0

    # AWS Secrets Manager IAL configuration
    ial_aws_region: Optional[str] = None
    ial_aws_secret_name_prefix: Optional[str] = None
    ial_aws_session_table_name: Optional[str] = None
    ial_aws_timeout: float = 10.0

    # OpenFGA IAL configuration
    ial_openfga_api_url: Optional[str] = None
    ial_openfga_store_id: Optional[str] = None
    ial_openfga_authorization_model_id: Optional[str] = None
    ial_openfga_api_token: Optional[str] = None
    ial_openfga_relation_mapping: Optional[str] = None  # JSON string
    ial_openfga_timeout: float = 10.0

    # Certificate paths
    server_cert_path: Path = Field(
        default=Path("infra/certificates/permission-broker/server.crt"),
        validation_alias="MTLS_SERVER_CERT",
    )
    server_key_path: Path = Field(
        default=Path("infra/certificates/permission-broker/server.key"),
        validation_alias="MTLS_SERVER_KEY",
    )
    client_cert_path: Path = Field(
        default=Path("infra/certificates/permission-broker/client.crt"),
        validation_alias="MTLS_CLIENT_CERT",
    )
    client_key_path: Path = Field(
        default=Path("infra/certificates/permission-broker/client.key"),
        validation_alias="MTLS_CLIENT_KEY",
    )
    root_ca_path: Path = Field(
        default=Path("infra/certificates/root_ca.crt"),
        validation_alias="MTLS_CA_CERT",
    )

    # DPoP configuration
    dpop_private_key_path: Path = Field(
        default=Path("infra/auth0/keys/permission-broker-dpop.key"),
        validation_alias="DPOP_PRIVATE_KEY_PATH",
    )

    # Signing key for ZT-AT
    signing_key_path: Path = Field(
        default=Path("infra/certificates/permission-broker/server.key"),
        validation_alias="SIGNING_PRIVATE_KEY_PATH",
    )

    # Public keys for verification
    safety_agent_public_key_path: Path = Field(
        default=Path("infra/certificates/safety-agent/server.crt"),
        validation_alias="SAFETY_AGENT_PUBLIC_KEY_PATH",
    )
    intent_engine_public_key_path: Path = Field(
        default=Path("infra/certificates/intent-engine/server.crt"),
        validation_alias="INTENT_ENGINE_PUBLIC_KEY_PATH",
    )

    # Service URLs
    audit_service_url: str = "http://audit:8006"

    # Token configuration
    zt_at_lifetime_seconds: int = 300  # 5 minutes

    @field_validator("identity_provider", mode="before")
    @classmethod
    def normalize_identity_provider(cls, value):
        """Treat blank identity_provider env values as unset."""
        if value is None:
            return None
        if isinstance(value, str) and value.strip() == "":
            return None
        return value

    @field_validator("ial_auth0_timeout", mode="before")
    @classmethod
    def normalize_auth0_timeout(cls, value):
        """Treat blank timeout env values as default timeout."""
        if value is None:
            return 10.0
        if isinstance(value, str) and value.strip() == "":
            return 10.0
        return value

    @model_validator(mode='after')
    def validate_identity_configuration(self) -> 'PermissionBrokerConfig':
        """Validate identity provider configuration at startup.

        Supports both legacy Auth0 configuration and new IAL configuration.
        If identity_provider is not set, attempts to use legacy Auth0 config.

        Requirements: 6.1, 6.2, 6.3, 6.4, 7.6
        """
        # If identity_provider is explicitly set, validate IAL configuration
        if self.identity_provider:
            if self.identity_provider == "auth0":
                if not self.ial_auth0_domain or not self.ial_auth0_client_id or not self.ial_auth0_client_secret:
                    raise ValueError(
                        "IAL Auth0 configuration incomplete: ial_auth0_domain, ial_auth0_client_id, "
                        "and ial_auth0_client_secret are required when identity_provider is 'auth0'"
                    )
            elif self.identity_provider == "keycloak":
                if not self.ial_keycloak_server_url or not self.ial_keycloak_realm or \
                   not self.ial_keycloak_client_id or not self.ial_keycloak_client_secret:
                    raise ValueError(
                        "IAL Keycloak configuration incomplete: ial_keycloak_server_url, ial_keycloak_realm, "
                        "ial_keycloak_client_id, and ial_keycloak_client_secret are required when "
                        "identity_provider is 'keycloak'"
                    )
            elif self.identity_provider == "aws_secrets":
                if not self.ial_aws_region or not self.ial_aws_secret_name_prefix or \
                   not self.ial_aws_session_table_name:
                    raise ValueError(
                        "IAL AWS Secrets configuration incomplete: ial_aws_region, ial_aws_secret_name_prefix, "
                        "and ial_aws_session_table_name are required when identity_provider is 'aws_secrets'"
                    )
            elif self.identity_provider == "openfga":
                if not self.ial_openfga_api_url or not self.ial_openfga_store_id or \
                   not self.ial_openfga_authorization_model_id:
                    raise ValueError(
                        "IAL OpenFGA configuration incomplete: ial_openfga_api_url, ial_openfga_store_id, "
                        "and ial_openfga_authorization_model_id are required when identity_provider is 'openfga'"
                    )
        else:
            # Legacy mode: check if old Auth0 config is present
            # If present, we'll auto-migrate to IAL Auth0 adapter
            if self.auth0_domain and self.auth0_client_id and self.auth0_client_secret:
                # Auto-migrate legacy config to IAL format
                self.identity_provider = "auth0"
                self.ial_auth0_domain = self.auth0_domain
                self.ial_auth0_client_id = self.auth0_client_id
                self.ial_auth0_client_secret = self.auth0_client_secret
                self.ial_auth0_token_vault_url = self.auth0_token_vault_url or None

        return self

    def get_ial_config(self) -> Dict[str, Any]:
        """Get IAL configuration dictionary for VaultFactory.

        Returns:
            Dictionary containing IAL configuration in the format expected by VaultFactory

        Requirements: 6.1, 6.2, 6.3, 6.4
        """
        import json

        if not self.identity_provider:
            raise ValueError("Identity provider not configured")

        ial_config: Dict[str, Any] = {
            "identity_provider": self.identity_provider
        }

        if self.identity_provider == "auth0":
            ial_config["auth0_config"] = {
                "domain": self.ial_auth0_domain,
                "client_id": self.ial_auth0_client_id,
                "client_secret": self.ial_auth0_client_secret,
                "token_vault_url": self.ial_auth0_token_vault_url,
                "timeout": self.ial_auth0_timeout
            }
        elif self.identity_provider == "keycloak":
            scope_mapping = {}
            if self.ial_keycloak_scope_mapping:
                try:
                    scope_mapping = json.loads(self.ial_keycloak_scope_mapping)
                except json.JSONDecodeError:
                    raise ValueError("Invalid JSON in ial_keycloak_scope_mapping")

            ial_config["keycloak_config"] = {
                "server_url": self.ial_keycloak_server_url,
                "realm": self.ial_keycloak_realm,
                "client_id": self.ial_keycloak_client_id,
                "client_secret": self.ial_keycloak_client_secret,
                "scope_mapping": scope_mapping,
                "timeout": self.ial_keycloak_timeout
            }
        elif self.identity_provider == "aws_secrets":
            ial_config["aws_secrets_config"] = {
                "region": self.ial_aws_region,
                "secret_name_prefix": self.ial_aws_secret_name_prefix,
                "session_table_name": self.ial_aws_session_table_name,
                "timeout": self.ial_aws_timeout
            }
        elif self.identity_provider == "openfga":
            relation_mapping = {}
            if self.ial_openfga_relation_mapping:
                try:
                    relation_mapping = json.loads(self.ial_openfga_relation_mapping)
                except json.JSONDecodeError:
                    raise ValueError("Invalid JSON in ial_openfga_relation_mapping")

            ial_config["openfga_config"] = {
                "api_url": self.ial_openfga_api_url,
                "store_id": self.ial_openfga_store_id,
                "authorization_model_id": self.ial_openfga_authorization_model_id,
                "api_token": self.ial_openfga_api_token,
                "relation_mapping": relation_mapping,
                "timeout": self.ial_openfga_timeout,
            }

        return ial_config

# Global config instance
config = PermissionBrokerConfig()
