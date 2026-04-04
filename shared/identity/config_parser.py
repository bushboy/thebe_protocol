"""Configuration parser for Identity Abstraction Layer.

This module provides functionality to load and parse IAL configuration from
JSON or YAML files with environment variable substitution and validation.
"""

import os
import re
import json
from pathlib import Path
from typing import Dict, Any, Union
from pydantic import ValidationError

from .config_models import IALConfig, Auth0Config, KeycloakConfig, AWSSecretsConfig, OpenFGAConfig
from .exceptions import VaultConfigurationError


class ConfigurationParser:
    """Parser for IAL configuration files with environment variable substitution."""

    ENV_VAR_PATTERN = re.compile(r'\$\{([A-Za-z_][A-Za-z0-9_]*)\}')

    def __init__(self):
        """Initialize the configuration parser."""
        pass

    def load(self, config_path: Union[str, Path]) -> IALConfig:
        """Load and parse configuration from a file.

        Args:
            config_path: Path to JSON or YAML configuration file

        Returns:
            Validated IALConfig object

        Raises:
            VaultConfigurationError: If file not found, invalid format, or validation fails
        """
        config_path = Path(config_path)

        if not config_path.exists():
            raise VaultConfigurationError(f"Configuration file not found: {config_path}")

        # Read file content
        try:
            content = config_path.read_text()
        except Exception as e:
            raise VaultConfigurationError(f"Failed to read configuration file: {e}")

        # Parse based on file extension
        if config_path.suffix.lower() in ['.json']:
            config_dict = self._parse_json(content)
        elif config_path.suffix.lower() in ['.yaml', '.yml']:
            config_dict = self._parse_yaml(content)
        else:
            raise VaultConfigurationError(
                f"Unsupported file format: {config_path.suffix}. "
                "Supported formats: .json, .yaml, .yml"
            )

        # Substitute environment variables
        config_dict = self._substitute_env_vars(config_dict)

        # Validate and construct IALConfig
        try:
            return IALConfig(**config_dict)
        except ValidationError as e:
            raise VaultConfigurationError(f"Configuration validation failed: {e}")

    def load_from_dict(self, config_dict: Dict[str, Any]) -> IALConfig:
        """Load and parse configuration from a dictionary.

        Args:
            config_dict: Configuration dictionary

        Returns:
            Validated IALConfig object

        Raises:
            VaultConfigurationError: If validation fails
        """
        # Substitute environment variables
        config_dict = self._substitute_env_vars(config_dict)

        # Validate and construct IALConfig
        try:
            return IALConfig(**config_dict)
        except ValidationError as e:
            raise VaultConfigurationError(f"Configuration validation failed: {e}")

    def _parse_json(self, content: str) -> Dict[str, Any]:
        """Parse JSON content.

        Args:
            content: JSON string

        Returns:
            Parsed dictionary

        Raises:
            VaultConfigurationError: If JSON is invalid
        """
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            raise VaultConfigurationError(f"Invalid JSON: {e}")

    def _parse_yaml(self, content: str) -> Dict[str, Any]:
        """Parse YAML content.

        Args:
            content: YAML string

        Returns:
            Parsed dictionary

        Raises:
            VaultConfigurationError: If YAML is invalid or PyYAML not installed
        """
        try:
            import yaml
        except ImportError:
            raise VaultConfigurationError(
                "PyYAML is required to parse YAML files. Install with: pip install pyyaml"
            )

        try:
            return yaml.safe_load(content)
        except yaml.YAMLError as e:
            raise VaultConfigurationError(f"Invalid YAML: {e}")

    def _substitute_env_vars(self, obj: Any) -> Any:
        """Recursively substitute environment variables in configuration.

        Replaces ${VAR_NAME} with the value of environment variable VAR_NAME.

        Args:
            obj: Configuration object (dict, list, str, or other)

        Returns:
            Object with environment variables substituted

        Raises:
            VaultConfigurationError: If referenced environment variable is not set
        """
        if isinstance(obj, dict):
            return {key: self._substitute_env_vars(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._substitute_env_vars(item) for item in obj]
        elif isinstance(obj, str):
            return self._substitute_string(obj)
        else:
            return obj

    def _substitute_string(self, value: str) -> str:
        """Substitute environment variables in a string.

        Args:
            value: String potentially containing ${VAR_NAME} references

        Returns:
            String with environment variables substituted

        Raises:
            VaultConfigurationError: If referenced environment variable is not set
        """
        def replace_var(match):
            var_name = match.group(1)
            env_value = os.environ.get(var_name)

            if env_value is None:
                raise VaultConfigurationError(
                    f"Environment variable '{var_name}' is not set"
                )

            return env_value

        return self.ENV_VAR_PATTERN.sub(replace_var, value)
