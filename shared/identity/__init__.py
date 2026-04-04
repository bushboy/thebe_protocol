"""Identity Abstraction Layer (IAL) module.

This module provides a provider-agnostic interface for identity provider
operations, enabling the Zero-Trust Agentic Guardian system to work with
multiple identity providers (Auth0, Keycloak, AWS Secrets Manager) without
modifying core authorization logic.
"""

from .exceptions import (
    VaultError,
    VaultProviderError,
    VaultAuthenticationError,
    VaultValidationError,
    VaultTimeoutError,
    VaultConfigurationError,
)
from .config_models import (
    Auth0Config,
    KeycloakConfig,
    AWSSecretsConfig,
    OpenFGAConfig,
    IALConfig,
)
from .token_models import ProviderToken
from .ivault_provider import IVaultProvider
from .auth0_adapter import Auth0Adapter
from .keycloak_adapter import KeycloakAdapter
from .aws_secrets_adapter import AWSSecretsAdapter
from .openfga_adapter import OpenFGAAdapter
from .vault_factory import VaultFactory
from .config_parser import ConfigurationParser
from .config_printer import pretty_print_config
from .token_printer import pretty_print_token

__all__ = [
    # Exceptions
    "VaultError",
    "VaultProviderError",
    "VaultAuthenticationError",
    "VaultValidationError",
    "VaultTimeoutError",
    "VaultConfigurationError",
    # Configuration models
    "Auth0Config",
    "KeycloakConfig",
    "AWSSecretsConfig",
    "OpenFGAConfig",
    "IALConfig",
    # Token models
    "ProviderToken",
    # Interface
    "IVaultProvider",
    # Adapters
    "Auth0Adapter",
    "KeycloakAdapter",
    "AWSSecretsAdapter",
    "OpenFGAAdapter",
    # Factory
    "VaultFactory",
    # Configuration utilities
    "ConfigurationParser",
    "pretty_print_config",
    # Token utilities
    "pretty_print_token",
]
