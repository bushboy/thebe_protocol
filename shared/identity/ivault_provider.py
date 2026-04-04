"""Abstract interface for identity provider adapters.

This module defines the IVaultProvider interface that all identity provider
adapters must implement. This abstraction enables the Identity Abstraction Layer
to support multiple identity providers (Auth0, Keycloak, AWS Secrets Manager)
through a unified interface.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any
from shared.schemas.models import RichAuthorizationRequest


class IVaultProvider(ABC):
    """Abstract interface for identity provider adapters.

    All concrete adapters must implement this interface to ensure
    consistent behavior across different identity providers. The interface
    defines five core operations: token retrieval, token exchange, session
    revocation, health checking, and provider identification.

    Implementations must handle provider-specific protocols while presenting
    a uniform interface to the Permission Broker.
    """

    @abstractmethod
    async def get_token(
        self,
        rar: RichAuthorizationRequest,
        provider: str
    ) -> Dict[str, Any]:
        """Request a provider-specific access token.

        This method retrieves an access token from the identity provider for
        the specified external provider (e.g., GitHub, Slack, Google Workspace).
        The token enables the Executor Agent to make authenticated API calls
        to the external provider.

        Args:
            rar: Rich Authorization Request containing:
                - type: Action type identifier
                - actions: Required OAuth scopes/permissions
                - locations: Resource URLs being accessed
                - purpose: Purpose of access (e.g., "task_execution")
                - context: Additional context (plan_id, task_id, etc.)
            provider: Target provider identifier (e.g., "github", "slack",
                "google_workspace"). Used to determine which provider credentials
                to retrieve and which OAuth audience to request.

        Returns:
            Dictionary containing token information with the following keys:
                - access_token (str): Provider access token for API authentication
                - token_type (str): Token type, typically "Bearer"
                - expires_in (int): Token expiration time in seconds
                - scope (str): Space-separated list of granted scopes

        Raises:
            VaultProviderError: Network errors, provider unavailability, or
                5xx server errors from the identity provider. These errors
                are typically transient and may be retried.
            VaultAuthenticationError: Invalid credentials, expired client
                secrets, or 401 Unauthorized responses. These errors indicate
                configuration issues requiring manual intervention.
            VaultValidationError: Invalid RAR structure, missing required
                fields, or malformed provider responses. These errors indicate
                programming errors or data quality issues.
            VaultTimeoutError: Request exceeded configured timeout. May indicate
                network issues or provider performance problems.

        Example:
            >>> rar = RichAuthorizationRequest(
            ...     type="github_action",
            ...     actions=["repo:write"],
            ...     locations=["https://github.com/org/repo"],
            ...     purpose="task_execution",
            ...     context={"plan_id": "plan_123"}
            ... )
            >>> token = await adapter.get_token(rar, "github")
            >>> print(token["access_token"])
            'gho_abc123...'
        """
        pass

    @abstractmethod
    async def exchange_token(
        self,
        existing_token: str,
        new_scopes: list[str],
        provider: str
    ) -> Dict[str, Any]:
        """Exchange an existing token for a new token with different scopes.

        This method implements OAuth 2.0 Token Exchange (RFC 8693) or
        provider-specific token exchange protocols. It allows obtaining a new
        token with different permissions without re-authenticating.

        Args:
            existing_token: Current access token to be exchanged. Must be a
                valid, non-expired token previously issued by the identity provider.
            new_scopes: List of OAuth scopes requested for the new token.
                The identity provider may grant a subset of requested scopes
                based on client permissions.
            provider: Target provider identifier for the new token.

        Returns:
            Dictionary containing new token information with the same structure
            as get_token():
                - access_token (str): New provider access token
                - token_type (str): Token type, typically "Bearer"
                - expires_in (int): Token expiration time in seconds
                - scope (str): Space-separated list of granted scopes

        Raises:
            VaultProviderError: Network errors or provider-side failures during
                token exchange.
            VaultAuthenticationError: Invalid or expired existing_token, or
                insufficient permissions for requested scopes.
            VaultValidationError: Invalid scope format or malformed response.
            VaultTimeoutError: Token exchange request exceeded timeout.

        Example:
            >>> new_token = await adapter.exchange_token(
            ...     existing_token="gho_abc123...",
            ...     new_scopes=["repo:read", "issues:write"],
            ...     provider="github"
            ... )
        """
        pass

    @abstractmethod
    async def revoke_session(self, session_id: str) -> bool:
        """Revoke an active session or token.

        This method invalidates a session or token, preventing further use.
        It should be called when a task completes, when an authorization is
        explicitly revoked, or when suspicious activity is detected.

        Args:
            session_id: Unique session identifier or token to revoke. The format
                depends on the identity provider:
                - Auth0: Access token or refresh token
                - Keycloak: Refresh token or session ID
                - AWS Secrets Manager: Session ID stored in DynamoDB

        Returns:
            True if revocation succeeded, False if revocation failed or the
            session was already revoked. A False return value does not necessarily
            indicate an error - the session may have already expired.

        Raises:
            VaultProviderError: Network errors or provider-side failures during
                revocation. Note that revocation failures are often non-critical
                since tokens typically have short expiration times.

        Example:
            >>> success = await adapter.revoke_session("session_abc123")
            >>> if success:
            ...     print("Session revoked successfully")
        """
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """Check if the identity provider is accessible and healthy.

        This method performs a lightweight check to verify that the identity
        provider is reachable and responding. It should not perform full
        authentication but should verify basic connectivity.

        The health check is used by:
        - Permission Broker /health endpoint to report overall system health
        - Startup validation to detect configuration issues early
        - Monitoring systems to track identity provider availability

        Returns:
            True if the identity provider is accessible and responding to
            requests, False if the provider is unreachable or returning errors.

        Raises:
            This method should not raise exceptions. All errors should be caught
            and result in a False return value. Exceptions indicate a bug in
            the adapter implementation.

        Example:
            >>> is_healthy = await adapter.health_check()
            >>> if not is_healthy:
            ...     logger.warning("Identity provider is unavailable")
        """
        pass

    @abstractmethod
    def get_provider_name(self) -> str:
        """Get the identity provider type identifier.

        This method returns a string identifying the type of identity provider
        this adapter implements. The provider name is used for:
        - Logging and debugging to identify which adapter is in use
        - Metrics labeling to track performance per provider type
        - Configuration validation to ensure correct adapter instantiation

        Returns:
            Provider type identifier. Must be one of:
                - "auth0": Auth0 Token Vault adapter
                - "keycloak": Keycloak identity provider adapter
                - "aws_secrets": AWS Secrets Manager adapter
                - "openfga": OpenFGA relationship-based authorization adapter

        Example:
            >>> provider_name = adapter.get_provider_name()
            >>> logger.info(f"Using identity provider: {provider_name}")
        """
        pass
