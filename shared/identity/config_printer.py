"""Configuration pretty printer for Identity Abstraction Layer.

This module provides functionality to format IAL configuration as human-readable
JSON with sensitive field redaction.
"""

import json
from typing import Dict, Any, Set

from .config_models import IALConfig, Auth0Config, KeycloakConfig, AWSSecretsConfig, OpenFGAConfig


# Sensitive field names that should be redacted
SENSITIVE_FIELDS: Set[str] = {
    'client_secret',
    'access_key',
    'secret_key',
    'access_token',
    'refresh_token',
    'api_key',
    'private_key',
    'password',
}


def pretty_print_config(config: IALConfig, redact_sensitive: bool = True) -> str:
    """Format IAL configuration as human-readable indented JSON.

    Args:
        config: IALConfig object to format
        redact_sensitive: Whether to redact sensitive fields (default: True)

    Returns:
        Formatted JSON string with proper indentation
    """
    # Build configuration dictionary
    config_dict: Dict[str, Any] = {
        "identity_provider": config.identity_provider,
    }

    # Add active provider configuration
    if config.identity_provider == "auth0" and config.auth0_config:
        config_dict["auth0_config"] = _format_auth0_config(
            config.auth0_config, redact_sensitive
        )
    elif config.identity_provider == "keycloak" and config.keycloak_config:
        config_dict["keycloak_config"] = _format_keycloak_config(
            config.keycloak_config, redact_sensitive
        )
    elif config.identity_provider == "aws_secrets" and config.aws_secrets_config:
        config_dict["aws_secrets_config"] = _format_aws_secrets_config(
            config.aws_secrets_config, redact_sensitive
        )
    elif config.identity_provider == "openfga" and config.openfga_config:
        config_dict["openfga_config"] = _format_openfga_config(
            config.openfga_config, redact_sensitive
        )

    # Format as indented JSON
    return json.dumps(config_dict, indent=2, sort_keys=False)


def _format_auth0_config(config: Auth0Config, redact_sensitive: bool) -> Dict[str, Any]:
    """Format Auth0 configuration.

    Args:
        config: Auth0Config object
        redact_sensitive: Whether to redact sensitive fields

    Returns:
        Dictionary representation with optional redaction
    """
    config_dict = {
        "domain": config.domain,
        "client_id": config.client_id,
        "client_secret": _redact_value(config.client_secret, redact_sensitive),
        "timeout": config.timeout,
    }

    if config.token_vault_url:
        config_dict["token_vault_url"] = config.token_vault_url

    return config_dict


def _format_keycloak_config(config: KeycloakConfig, redact_sensitive: bool) -> Dict[str, Any]:
    """Format Keycloak configuration.

    Args:
        config: KeycloakConfig object
        redact_sensitive: Whether to redact sensitive fields

    Returns:
        Dictionary representation with optional redaction
    """
    config_dict = {
        "server_url": config.server_url,
        "realm": config.realm,
        "client_id": config.client_id,
        "client_secret": _redact_value(config.client_secret, redact_sensitive),
        "timeout": config.timeout,
    }

    if config.scope_mapping:
        config_dict["scope_mapping"] = config.scope_mapping

    return config_dict


def _format_aws_secrets_config(config: AWSSecretsConfig, redact_sensitive: bool) -> Dict[str, Any]:
    """Format AWS Secrets Manager configuration.

    Args:
        config: AWSSecretsConfig object
        redact_sensitive: Whether to redact sensitive fields

    Returns:
        Dictionary representation with optional redaction
    """
    return {
        "region": config.region,
        "secret_name_prefix": config.secret_name_prefix,
        "session_table_name": config.session_table_name,
        "timeout": config.timeout,
    }


def _format_openfga_config(config: OpenFGAConfig, redact_sensitive: bool) -> Dict[str, Any]:
    """Format OpenFGA configuration.

    Args:
        config: OpenFGAConfig object
        redact_sensitive: Whether to redact sensitive fields

    Returns:
        Dictionary representation with optional redaction
    """
    config_dict = {
        "api_url": config.api_url,
        "store_id": config.store_id,
        "authorization_model_id": config.authorization_model_id,
        "timeout": config.timeout,
    }

    if config.api_token:
        config_dict["api_token"] = _redact_value(config.api_token, redact_sensitive)

    if config.relation_mapping:
        config_dict["relation_mapping"] = config.relation_mapping

    return config_dict


def _redact_value(value: str, redact: bool) -> str:
    """Redact a sensitive value if redaction is enabled.

    Args:
        value: Original value
        redact: Whether to redact

    Returns:
        Redacted value (first 4 chars + "***") or original value
    """
    if not redact:
        return value

    if len(value) <= 4:
        return "***"

    return value[:4] + "***"


def _redact_dict(obj: Any, redact_sensitive: bool) -> Any:
    """Recursively redact sensitive fields in a dictionary.

    Args:
        obj: Object to redact (dict, list, or other)
        redact_sensitive: Whether to redact sensitive fields

    Returns:
        Object with sensitive fields redacted
    """
    if not redact_sensitive:
        return obj

    if isinstance(obj, dict):
        return {
            key: _redact_value(value, True) if key in SENSITIVE_FIELDS and isinstance(value, str)
            else _redact_dict(value, redact_sensitive)
            for key, value in obj.items()
        }
    elif isinstance(obj, list):
        return [_redact_dict(item, redact_sensitive) for item in obj]
    else:
        return obj
