"""Configuration models for Identity Abstraction Layer.

This module defines Pydantic models for configuring identity provider adapters.
Each provider has its own configuration model with validation rules.
"""

from typing import Optional, Dict, Any, Literal
from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic_core.core_schema import ValidationInfo


class Auth0Config(BaseModel):
    """Configuration for Auth0 Token Vault adapter.

    Attributes:
        domain: Auth0 domain (e.g., 'myapp.auth0.com')
        client_id: M2M application client ID
        client_secret: M2M application client secret
        token_vault_url: Optional custom Token Vault URL
        timeout: Request timeout in seconds (default: 10.0)
    """
    domain: str = Field(..., min_length=1, description="Auth0 domain")
    client_id: str = Field(..., min_length=1, description="Client ID")
    client_secret: str = Field(..., min_length=1, description="Client secret")
    token_vault_url: Optional[str] = Field(None, description="Custom Token Vault URL")
    timeout: float = Field(10.0, gt=0, description="Request timeout in seconds")

    @field_validator('domain')
    @classmethod
    def validate_domain(cls, v: str) -> str:
        """Validate Auth0 domain format."""
        if not v or v.isspace():
            raise ValueError("domain must be a non-empty string")
        return v.strip()

    @field_validator('client_id', 'client_secret')
    @classmethod
    def validate_non_empty(cls, v: str) -> str:
        """Validate required fields are non-empty."""
        if not v or v.isspace():
            raise ValueError("field must be a non-empty string")
        return v.strip()

    @field_validator('token_vault_url')
    @classmethod
    def validate_url(cls, v: Optional[str]) -> Optional[str]:
        """Validate URL format if provided."""
        if v is None:
            return v
        v = v.strip()
        if not v.startswith(('http://', 'https://')):
            raise ValueError("token_vault_url must start with http:// or https://")
        return v

    @field_validator('timeout')
    @classmethod
    def validate_timeout(cls, v: float) -> float:
        """Validate timeout is positive."""
        if v <= 0:
            raise ValueError("timeout must be a positive number")
        return v


class KeycloakConfig(BaseModel):
    """Configuration for Keycloak adapter.

    Attributes:
        server_url: Keycloak server URL (e.g., 'https://keycloak.example.com')
        realm: Keycloak realm name
        client_id: Client ID
        client_secret: Client secret
        scope_mapping: Optional dict mapping RAR actions to Keycloak scopes
        timeout: Request timeout in seconds (default: 10.0)
    """
    server_url: str = Field(..., min_length=1, description="Keycloak server URL")
    realm: str = Field(..., min_length=1, description="Keycloak realm name")
    client_id: str = Field(..., min_length=1, description="Client ID")
    client_secret: str = Field(..., min_length=1, description="Client secret")
    scope_mapping: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Mapping of RAR actions to Keycloak scopes"
    )
    timeout: float = Field(10.0, gt=0, description="Request timeout in seconds")

    @field_validator('server_url')
    @classmethod
    def validate_server_url(cls, v: str) -> str:
        """Validate server URL format."""
        if not v or v.isspace():
            raise ValueError("server_url must be a non-empty string")
        v = v.strip()
        if not v.startswith(('http://', 'https://')):
            raise ValueError("server_url must start with http:// or https://")
        return v

    @field_validator('realm', 'client_id', 'client_secret')
    @classmethod
    def validate_non_empty(cls, v: str) -> str:
        """Validate required fields are non-empty."""
        if not v or v.isspace():
            raise ValueError("field must be a non-empty string")
        return v.strip()

    @field_validator('scope_mapping')
    @classmethod
    def validate_scope_mapping(cls, v: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Validate scope mapping is a valid dictionary."""
        if v is None:
            return {}
        if not isinstance(v, dict):
            raise ValueError("scope_mapping must be a dictionary")
        return v

    @field_validator('timeout')
    @classmethod
    def validate_timeout(cls, v: float) -> float:
        """Validate timeout is positive."""
        if v <= 0:
            raise ValueError("timeout must be a positive number")
        return v


class AWSSecretsConfig(BaseModel):
    """Configuration for AWS Secrets Manager adapter.

    Attributes:
        region: AWS region (e.g., 'us-east-1')
        secret_name_prefix: Prefix for secret names
        session_table_name: DynamoDB table name for session tracking
        timeout: Request timeout in seconds (default: 10.0)
    """
    region: str = Field(..., min_length=1, description="AWS region")
    secret_name_prefix: str = Field(..., min_length=1, description="Secret name prefix")
    session_table_name: str = Field(..., min_length=1, description="DynamoDB table name")
    timeout: float = Field(10.0, gt=0, description="Request timeout in seconds")

    @field_validator('region', 'secret_name_prefix', 'session_table_name')
    @classmethod
    def validate_non_empty(cls, v: str) -> str:
        """Validate required fields are non-empty."""
        if not v or v.isspace():
            raise ValueError("field must be a non-empty string")
        return v.strip()

    @field_validator('timeout')
    @classmethod
    def validate_timeout(cls, v: float) -> float:
        """Validate timeout is positive."""
        if v <= 0:
            raise ValueError("timeout must be a positive number")
        return v


class OpenFGAConfig(BaseModel):
    """Configuration for OpenFGA adapter.

    Attributes:
        api_url: OpenFGA API base URL (e.g., 'https://openfga.example.com')
        store_id: OpenFGA store identifier
        authorization_model_id: Authorization model ID used for check queries
        api_token: Optional API token for OpenFGA authentication
        relation_mapping: Optional dict mapping RAR actions to OpenFGA relations
        timeout: Request timeout in seconds (default: 10.0)
    """

    api_url: str = Field(..., min_length=1, description="OpenFGA API base URL")
    store_id: str = Field(..., min_length=1, description="OpenFGA store ID")
    authorization_model_id: str = Field(..., min_length=1, description="OpenFGA model ID")
    api_token: Optional[str] = Field(None, description="OpenFGA API token")
    relation_mapping: Optional[Dict[str, str]] = Field(
        default_factory=dict,
        description="Mapping of RAR actions to OpenFGA relations"
    )
    timeout: float = Field(10.0, gt=0, description="Request timeout in seconds")

    @field_validator("api_url")
    @classmethod
    def validate_api_url(cls, v: str) -> str:
        """Validate OpenFGA API URL format."""
        if not v or v.isspace():
            raise ValueError("api_url must be a non-empty string")
        v = v.strip().rstrip("/")
        if not v.startswith(("http://", "https://")):
            raise ValueError("api_url must start with http:// or https://")
        return v

    @field_validator("store_id", "authorization_model_id")
    @classmethod
    def validate_non_empty(cls, v: str) -> str:
        """Validate required fields are non-empty."""
        if not v or v.isspace():
            raise ValueError("field must be a non-empty string")
        return v.strip()

    @field_validator("api_token")
    @classmethod
    def validate_token(cls, v: Optional[str]) -> Optional[str]:
        """Validate optional API token."""
        if v is None:
            return v
        if not v.strip():
            raise ValueError("api_token cannot be blank when provided")
        return v.strip()

    @field_validator("relation_mapping")
    @classmethod
    def validate_relation_mapping(cls, v: Optional[Dict[str, str]]) -> Dict[str, str]:
        """Validate relation mapping is a dictionary."""
        if v is None:
            return {}
        if not isinstance(v, dict):
            raise ValueError("relation_mapping must be a dictionary")
        return v

    @field_validator("timeout")
    @classmethod
    def validate_timeout(cls, v: float) -> float:
        """Validate timeout is positive."""
        if v <= 0:
            raise ValueError("timeout must be a positive number")
        return v


class IALConfig(BaseModel):
    """Root configuration model for Identity Abstraction Layer.

    Attributes:
        identity_provider: Provider type (auth0, keycloak, aws_secrets, openfga)
        auth0_config: Auth0 configuration (required if identity_provider is auth0)
        keycloak_config: Keycloak configuration (required if identity_provider is keycloak)
        aws_secrets_config: AWS Secrets configuration (required if identity_provider is aws_secrets)
        openfga_config: OpenFGA configuration (required if identity_provider is openfga)
    """
    identity_provider: Literal["auth0", "keycloak", "aws_secrets", "openfga"] = Field(
        ...,
        description="Identity provider type"
    )
    auth0_config: Optional[Auth0Config] = Field(None, description="Auth0 configuration")
    keycloak_config: Optional[KeycloakConfig] = Field(None, description="Keycloak configuration")
    aws_secrets_config: Optional[AWSSecretsConfig] = Field(None, description="AWS Secrets configuration")
    openfga_config: Optional[OpenFGAConfig] = Field(None, description="OpenFGA configuration")

    @model_validator(mode='after')
    def validate_provider_config(self) -> 'IALConfig':
        """Validate that the configuration section matching identity_provider is present."""
        provider = self.identity_provider

        if provider == "auth0" and self.auth0_config is None:
            raise ValueError("auth0_config is required when identity_provider is 'auth0'")

        if provider == "keycloak" and self.keycloak_config is None:
            raise ValueError("keycloak_config is required when identity_provider is 'keycloak'")

        if provider == "aws_secrets" and self.aws_secrets_config is None:
            raise ValueError("aws_secrets_config is required when identity_provider is 'aws_secrets'")

        if provider == "openfga" and self.openfga_config is None:
            raise ValueError("openfga_config is required when identity_provider is 'openfga'")

        return self

    def get_active_config(self) -> Auth0Config | KeycloakConfig | AWSSecretsConfig | OpenFGAConfig:
        """Get the active provider configuration.

        Returns:
            The configuration object for the selected identity provider.

        Raises:
            ValueError: If no configuration is available for the selected provider.
        """
        if self.identity_provider == "auth0":
            if self.auth0_config is None:
                raise ValueError("auth0_config is not configured")
            return self.auth0_config
        elif self.identity_provider == "keycloak":
            if self.keycloak_config is None:
                raise ValueError("keycloak_config is not configured")
            return self.keycloak_config
        elif self.identity_provider == "aws_secrets":
            if self.aws_secrets_config is None:
                raise ValueError("aws_secrets_config is not configured")
            return self.aws_secrets_config
        elif self.identity_provider == "openfga":
            if self.openfga_config is None:
                raise ValueError("openfga_config is not configured")
            return self.openfga_config
        else:
            raise ValueError(f"Unknown identity provider: {self.identity_provider}")
