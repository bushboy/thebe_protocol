"""Factory for creating identity provider adapters.

This module provides a factory class that instantiates the appropriate
identity provider adapter based on configuration. The factory implements
a singleton pattern to ensure a single adapter instance per application.
"""

from typing import Optional, Dict, Any, Union
from .ivault_provider import IVaultProvider
from .auth0_adapter import Auth0Adapter
from .keycloak_adapter import KeycloakAdapter
from .aws_secrets_adapter import AWSSecretsAdapter
from .openfga_adapter import OpenFGAAdapter
from .config_models import IALConfig, Auth0Config, KeycloakConfig, AWSSecretsConfig, OpenFGAConfig
from .exceptions import VaultConfigurationError
from shared.logging import JSONLogger


logger = JSONLogger(__name__)


class VaultFactory:
    """Factory for creating identity provider adapters.

    This factory implements a singleton pattern to ensure only one adapter
    instance exists per application lifecycle. The factory reads configuration
    and instantiates the appropriate adapter based on the identity_provider field.

    Example:
        >>> config = IALConfig(
        ...     identity_provider="auth0",
        ...     auth0_config=Auth0Config(
        ...         domain="myapp.auth0.com",
        ...         client_id="...",
        ...         client_secret="..."
        ...     )
        ... )
        >>> provider = VaultFactory.create_provider(config)
        >>> token = await provider.get_token(rar, "github")
    """

    _instance: Optional[IVaultProvider] = None
    _config_hash: Optional[int] = None

    @classmethod
    def create_provider(
        cls,
        config: Union[IALConfig, Dict[str, Any]]
    ) -> IVaultProvider:
        """Create or return existing identity provider adapter.

        This method implements a singleton pattern. If an adapter has already
        been created with the same configuration, it returns the existing instance.
        Otherwise, it creates a new adapter based on the identity_provider field.

        Args:
            config: IALConfig object or dictionary containing configuration

        Returns:
            IVaultProvider instance for the configured identity provider

        Raises:
            VaultConfigurationError: If configuration is invalid or incomplete

        Example:
            >>> config = {"identity_provider": "auth0", "auth0_config": {...}}
            >>> provider = VaultFactory.create_provider(config)
        """
        # Parse configuration if dictionary provided
        if isinstance(config, dict):
            try:
                config = IALConfig(**config)
            except Exception as e:
                logger.error(f"Configuration parsing failed: {str(e)}")
                raise VaultConfigurationError(
                    f"Invalid configuration format: {str(e)}"
                )

        # Validate configuration type
        if not isinstance(config, IALConfig):
            raise VaultConfigurationError(
                f"Configuration must be IALConfig or dict, got {type(config).__name__}"
            )

        # Check if we can reuse existing instance
        config_hash = hash(str(config.model_dump()))
        if cls._instance is not None and cls._config_hash == config_hash:
            logger.info(
                f"Reusing existing {config.identity_provider} adapter instance"
            )
            return cls._instance

        # Create new adapter based on provider type
        logger.info(
            f"Creating new adapter for identity provider: {config.identity_provider}"
        )

        try:
            if config.identity_provider == "auth0":
                cls._instance = cls._create_auth0_adapter(config)
            elif config.identity_provider == "keycloak":
                cls._instance = cls._create_keycloak_adapter(config)
            elif config.identity_provider == "aws_secrets":
                cls._instance = cls._create_aws_secrets_adapter(config)
            elif config.identity_provider == "openfga":
                cls._instance = cls._create_openfga_adapter(config)
            else:
                raise VaultConfigurationError(
                    f"Unrecognized identity provider: {config.identity_provider}. "
                    f"Supported providers: auth0, keycloak, aws_secrets, openfga"
                )

            cls._config_hash = config_hash
            logger.info(
                f"Successfully created {config.identity_provider} adapter"
            )
            return cls._instance

        except VaultConfigurationError:
            raise
        except Exception as e:
            logger.error(
                f"Failed to create {config.identity_provider} adapter: {str(e)}"
            )
            raise VaultConfigurationError(
                f"Adapter creation failed: {str(e)}"
            )

    @classmethod
    def _create_auth0_adapter(cls, config: IALConfig) -> Auth0Adapter:
        """Create Auth0 adapter with configuration validation.

        Args:
            config: IALConfig with auth0_config section

        Returns:
            Configured Auth0Adapter instance

        Raises:
            VaultConfigurationError: If auth0_config is missing or invalid
        """
        if config.auth0_config is None:
            raise VaultConfigurationError(
                "auth0_config section is required when identity_provider is 'auth0'"
            )

        # Validate required fields
        auth0_config = config.auth0_config
        cls._validate_required_fields(
            auth0_config,
            ["domain", "client_id", "client_secret"],
            "auth0_config"
        )

        logger.info(
            f"Creating Auth0Adapter for domain: {auth0_config.domain}"
        )

        # Convert Pydantic model to dict for adapter
        config_dict = auth0_config.model_dump()
        return Auth0Adapter(config_dict)

    @classmethod
    def _create_keycloak_adapter(cls, config: IALConfig) -> KeycloakAdapter:
        """Create Keycloak adapter with configuration validation.

        Args:
            config: IALConfig with keycloak_config section

        Returns:
            Configured KeycloakAdapter instance

        Raises:
            VaultConfigurationError: If keycloak_config is missing or invalid
        """
        if config.keycloak_config is None:
            raise VaultConfigurationError(
                "keycloak_config section is required when identity_provider is 'keycloak'"
            )

        # Validate required fields
        keycloak_config = config.keycloak_config
        cls._validate_required_fields(
            keycloak_config,
            ["server_url", "realm", "client_id", "client_secret"],
            "keycloak_config"
        )

        logger.info(
            f"Creating KeycloakAdapter for realm: {keycloak_config.realm} "
            f"at {keycloak_config.server_url}"
        )

        # Convert Pydantic model to dict for adapter
        config_dict = keycloak_config.model_dump()
        return KeycloakAdapter(config_dict)

    @classmethod
    def _create_aws_secrets_adapter(cls, config: IALConfig) -> AWSSecretsAdapter:
        """Create AWS Secrets Manager adapter with configuration validation.

        Args:
            config: IALConfig with aws_secrets_config section

        Returns:
            Configured AWSSecretsAdapter instance

        Raises:
            VaultConfigurationError: If aws_secrets_config is missing or invalid
        """
        if config.aws_secrets_config is None:
            raise VaultConfigurationError(
                "aws_secrets_config section is required when identity_provider is 'aws_secrets'"
            )

        # Validate required fields
        aws_config = config.aws_secrets_config
        cls._validate_required_fields(
            aws_config,
            ["region", "secret_name_prefix", "session_table_name"],
            "aws_secrets_config"
        )

        logger.info(
            f"Creating AWSSecretsAdapter for region: {aws_config.region}"
        )

        # Convert Pydantic model to dict for adapter
        config_dict = aws_config.model_dump()
        return AWSSecretsAdapter(config_dict)

    @classmethod
    def _create_openfga_adapter(cls, config: IALConfig) -> OpenFGAAdapter:
        """Create OpenFGA adapter with configuration validation.

        Args:
            config: IALConfig with openfga_config section

        Returns:
            Configured OpenFGAAdapter instance

        Raises:
            VaultConfigurationError: If openfga_config is missing or invalid
        """
        if config.openfga_config is None:
            raise VaultConfigurationError(
                "openfga_config section is required when identity_provider is 'openfga'"
            )

        openfga_config = config.openfga_config
        cls._validate_required_fields(
            openfga_config,
            ["api_url", "store_id", "authorization_model_id"],
            "openfga_config"
        )

        logger.info(
            f"Creating OpenFGAAdapter for store: {openfga_config.store_id} "
            f"at {openfga_config.api_url}"
        )

        config_dict = openfga_config.model_dump()
        return OpenFGAAdapter(config_dict)

    @classmethod
    def _validate_required_fields(
        cls,
        config: Union[Auth0Config, KeycloakConfig, AWSSecretsConfig, OpenFGAConfig],
        required_fields: list[str],
        config_name: str
    ) -> None:
        """Validate that required configuration fields are present and non-empty.

        Args:
            config: Configuration object to validate
            required_fields: List of required field names
            config_name: Name of configuration section for error messages

        Raises:
            VaultConfigurationError: If any required field is missing or empty
        """
        config_dict = config.model_dump()

        for field in required_fields:
            if field not in config_dict:
                raise VaultConfigurationError(
                    f"Required field '{field}' is missing from {config_name}"
                )

            value = config_dict[field]

            # Check for None or empty string
            if value is None or (isinstance(value, str) and not value.strip()):
                raise VaultConfigurationError(
                    f"Required field '{field}' in {config_name} cannot be empty"
                )

    @classmethod
    def reset(cls) -> None:
        """Reset the factory singleton instance.

        This method clears the cached adapter instance and configuration hash,
        forcing the next call to create_provider() to create a new adapter.

        This method is primarily intended for testing purposes to ensure
        test isolation.

        Example:
            >>> VaultFactory.reset()
            >>> # Next create_provider() call will create a new instance
        """
        cls._instance = None
        cls._config_hash = None
        logger.info("VaultFactory singleton instance reset")
