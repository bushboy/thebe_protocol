"""Auth0 Token Vault adapter implementation.

This module implements the IVaultProvider interface for Auth0 Token Vault,
refactoring the existing TokenVaultClient functionality into the Identity
Abstraction Layer architecture.

Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7
"""

import httpx
from typing import Dict, Any
import inspect
from .ivault_provider import IVaultProvider
from .exceptions import (
    VaultProviderError,
    VaultAuthenticationError,
    VaultValidationError,
    VaultTimeoutError,
)
from .token_models import ProviderToken
from .retry import with_retry
from .metrics import record_metrics, record_revoke_session_metrics
from shared.schemas.models import RichAuthorizationRequest
from shared.logging import JSONLogger
from shared.pendo import track_event


logger = JSONLogger(__name__)


async def _read_response_json(response: httpx.Response) -> Dict[str, Any]:
    """Read response JSON supporting both sync and async-mocked json() methods."""
    try:
        payload = response.json()
        if inspect.isawaitable(payload):
            payload = await payload
        if isinstance(payload, dict):
            return payload
    except Exception:
        return {}
    return {}


class Auth0Adapter(IVaultProvider):
    """Auth0 Token Vault adapter implementation.

    This adapter refactors the existing TokenVaultClient into the IAL architecture
    while preserving all existing functionality including Auth0 Token Vault
    integration, RAR construction, timeout handling, and error responses.

    Attributes:
        domain: Auth0 domain
        client_id: M2M application client ID
        client_secret: M2M application client secret
        token_vault_url: Auth0 Token Vault URL
        timeout: Request timeout in seconds
    """

    def __init__(self, config: Dict[str, Any]):
        """Initialize Auth0 adapter with configuration.

        Args:
            config: Configuration dictionary with keys:
                - domain: Auth0 domain (required)
                - client_id: M2M application client ID (required)
                - client_secret: M2M application client secret (required)
                - token_vault_url: Optional custom Token Vault URL
                - timeout: Optional request timeout (default: 10.0)

        Raises:
            VaultConfigurationError: If required configuration is missing or invalid

        Requirements: 2.1, 2.7, 15.1
        """
        # Validate required configuration fields
        if not config.get("domain"):
            raise VaultValidationError("Auth0 domain is required")
        if not config.get("client_id"):
            raise VaultValidationError("Auth0 client_id is required")
        if not config.get("client_secret"):
            raise VaultValidationError("Auth0 client_secret is required")

        self.domain = config["domain"].strip()
        self.client_id = config["client_id"].strip()
        self.client_secret = config["client_secret"].strip()
        self.token_vault_url = config.get("token_vault_url") or f"https://{self.domain}/oauth/token"
        self.timeout = config.get("timeout", 10.0)

        # Validate timeout is positive
        if self.timeout <= 0:
            raise VaultValidationError("Timeout must be a positive number")

        logger.info(
            f"Initialized Auth0Adapter",
            extra={
                "domain": self.domain,
                "token_vault_url": self.token_vault_url,
                "timeout": self.timeout
            }
        )

    @record_metrics('get_token')
    @with_retry(max_attempts=3, base_delay=1.0)
    async def get_token(
        self,
        rar: RichAuthorizationRequest,
        provider: str
    ) -> Dict[str, Any]:
        """Request provider token from Auth0 Token Vault.

        Constructs an Auth0 Token Vault request with RAR authorization_details
        and returns the provider token. Preserves all existing TokenVaultClient
        functionality including timeout handling and error responses.

        Args:
            rar: Rich Authorization Request containing action details
            provider: Target provider (github, slack, google_workspace)

        Returns:
            Dictionary with token information:
                - access_token: Provider access token
                - token_type: Token type (normalized to "Bearer")
                - expires_in: Token expiration in seconds
                - scope: Granted scopes

        Raises:
            VaultProviderError: Network or provider errors
            VaultAuthenticationError: Invalid credentials (401)
            VaultValidationError: Invalid RAR or response
            VaultTimeoutError: Request timeout

        Requirements: 2.2, 2.6, 17.1, 17.4, 17.5, 17.6
        """
        logger.info(f"Requesting token for provider: {provider}")

        # Map provider to OAuth audience
        audience = self._get_provider_audience(provider)

        # Construct token request with RAR authorization_details
        token_request = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "audience": audience,
            "scope": " ".join(rar.actions),
            "authorization_details": [
                {
                    "type": rar.type,
                    "actions": rar.actions,
                    "locations": rar.locations,
                    "purpose": rar.purpose,
                    "context": rar.context
                }
            ]
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.token_vault_url,
                    json=token_request,
                    headers={"Content-Type": "application/json"}
                )

                # Handle Auth0-specific error responses
                if response.status_code == 401:
                    error_detail = await _read_response_json(response) if response.text else {}
                    auth_error = error_detail.get("error", "unauthorized")
                    auth_error_description = error_detail.get("error_description", "Unauthorized")
                    logger.error(
                        f"Auth0 authentication failed (401): {auth_error} - {auth_error_description}"
                    )
                    raise VaultAuthenticationError(
                        f"Auth0 authentication failed: {auth_error_description}"
                    )

                if response.status_code >= 400 and response.status_code < 500:
                    error_detail = await _read_response_json(response) if response.text else {}
                    error_msg = error_detail.get('error_description', 'Unknown client error')
                    logger.error(f"Auth0 client error ({response.status_code}): {error_msg}")
                    raise VaultProviderError(
                        f"Auth0 returned {response.status_code}: {error_msg}"
                    )

                if response.status_code >= 500:
                    error_detail = await _read_response_json(response) if response.text else {}
                    error_msg = error_detail.get('error_description', 'Unknown server error')
                    logger.error(f"Auth0 server error ({response.status_code}): {error_msg}")
                    raise VaultProviderError(
                        f"Auth0 returned {response.status_code}: {error_msg}"
                    )

                if response.status_code != 200:
                    logger.error(f"Auth0 unexpected status code: {response.status_code}")
                    raise VaultProviderError(
                        f"Auth0 returned unexpected status code: {response.status_code}"
                    )

                # Parse and validate token response
                token_data = await _read_response_json(response)

                # Validate required fields are present
                if "access_token" not in token_data:
                    logger.error("Auth0 response missing access_token")
                    raise VaultValidationError("Auth0 response missing required field: access_token")

                if "expires_in" not in token_data:
                    logger.error("Auth0 response missing expires_in")
                    raise VaultValidationError("Auth0 response missing required field: expires_in")

                # Validate access_token is non-empty
                if not token_data["access_token"] or not token_data["access_token"].strip():
                    logger.error("Auth0 returned empty access_token")
                    raise VaultValidationError("Auth0 returned empty access_token")

                # Validate expires_in is positive
                try:
                    expires_in = int(token_data["expires_in"])
                    if expires_in <= 0:
                        logger.error(f"Auth0 returned non-positive expires_in: {expires_in}")
                        raise VaultValidationError(f"Auth0 returned non-positive expires_in: {expires_in}")
                except (ValueError, TypeError) as e:
                    logger.error(f"Auth0 returned invalid expires_in: {token_data.get('expires_in')}")
                    raise VaultValidationError(f"Auth0 returned invalid expires_in: {str(e)}")

                logger.info(f"Provider token obtained successfully for {provider}")

                result_scope = token_data.get("scope", " ".join(rar.actions))

                await track_event(
                    "provider_token_acquired",
                    properties={
                        "provider": provider,
                        "identity_provider": "auth0",
                        "token_type": token_data.get("token_type", "Bearer"),
                        "expires_in": expires_in,
                        "scope": result_scope[:200],
                        "grant_type": "client_credentials",
                    },
                )

                # Return normalized token response
                return {
                    "access_token": token_data["access_token"],
                    "token_type": token_data.get("token_type", "Bearer"),
                    "expires_in": expires_in,
                    "scope": result_scope
                }

        except httpx.TimeoutException:
            logger.error(f"Auth0 request timed out after {self.timeout}s")
            raise VaultTimeoutError(f"Auth0 request timed out after {self.timeout}s")

        except httpx.RequestError as e:
            logger.error(f"Auth0 request failed: {str(e)}")
            raise VaultProviderError(f"Auth0 request failed: {str(e)}")

        except (VaultAuthenticationError, VaultValidationError, VaultTimeoutError, VaultProviderError):
            # Re-raise IAL exceptions as-is
            raise

        except Exception as e:
            logger.error(f"Unexpected error requesting Auth0 token: {str(e)}", exc_info=True)
            raise VaultProviderError(f"Unexpected error: {str(e)}")

    @record_metrics('exchange_token')
    @with_retry(max_attempts=3, base_delay=1.0)
    async def exchange_token(
        self,
        existing_token: str,
        new_scopes: list[str],
        provider: str
    ) -> Dict[str, Any]:
        """Exchange token using Auth0 token exchange endpoint.

        Uses Auth0's token exchange protocol (RFC 8693) to obtain a new token
        with different scopes.

        Args:
            existing_token: Current access token
            new_scopes: Requested scopes for new token
            provider: Target provider

        Returns:
            Dictionary with new token information

        Raises:
            VaultProviderError: Exchange failed
            VaultAuthenticationError: Invalid token
            VaultTimeoutError: Request timeout

        Requirements: 2.3
        """
        logger.info(f"Exchanging token for provider: {provider}")

        exchange_request = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "subject_token": existing_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "scope": " ".join(new_scopes),
            "audience": self._get_provider_audience(provider)
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.token_vault_url,
                    json=exchange_request,
                    headers={"Content-Type": "application/json"}
                )

                if response.status_code == 401:
                    logger.error("Auth0 token exchange authentication failed (401)")
                    raise VaultAuthenticationError("Token exchange failed: Invalid token")

                if response.status_code != 200:
                    error_detail = await _read_response_json(response) if response.text else {}
                    error_msg = error_detail.get('error_description', 'Unknown error')
                    logger.error(f"Auth0 token exchange failed ({response.status_code}): {error_msg}")
                    raise VaultProviderError(f"Token exchange failed: {error_msg}")

                token_data = await _read_response_json(response)

                logger.info(f"Token exchanged successfully for {provider}")

                await track_event(
                    "token_exchange_completed",
                    properties={
                        "provider": provider,
                        "identity_provider": "auth0",
                        "new_scopes": " ".join(new_scopes)[:200],
                        "expires_in": token_data.get("expires_in", 3600),
                    },
                )

                return {
                    "access_token": token_data["access_token"],
                    "token_type": token_data.get("token_type", "Bearer"),
                    "expires_in": token_data.get("expires_in", 3600),
                    "scope": token_data.get("scope", " ".join(new_scopes))
                }

        except httpx.TimeoutException:
            logger.error(f"Auth0 token exchange timed out after {self.timeout}s")
            raise VaultTimeoutError(f"Token exchange timed out after {self.timeout}s")

        except httpx.RequestError as e:
            logger.error(f"Auth0 token exchange request failed: {str(e)}")
            raise VaultProviderError(f"Token exchange request failed: {str(e)}")

        except (VaultAuthenticationError, VaultTimeoutError, VaultProviderError):
            raise

        except Exception as e:
            logger.error(f"Unexpected error during token exchange: {str(e)}", exc_info=True)
            raise VaultProviderError(f"Unexpected error: {str(e)}")

    @record_revoke_session_metrics
    async def revoke_session(self, session_id: str) -> bool:
        """Revoke session using Auth0 revocation endpoint.

        Calls Auth0's OAuth 2.0 token revocation endpoint to invalidate
        the specified token or session.

        Args:
            session_id: Token or session identifier to revoke

        Returns:
            True if revocation succeeded, False otherwise

        Requirements: 2.4
        """
        logger.info(f"Revoking session: {session_id[:8]}...")

        revoke_url = f"https://{self.domain}/oauth/revoke"

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    revoke_url,
                    json={
                        "client_id": self.client_id,
                        "client_secret": self.client_secret,
                        "token": session_id
                    },
                    headers={"Content-Type": "application/json"}
                )

                success = response.status_code == 200

                if success:
                    logger.info("Session revoked successfully")
                else:
                    logger.warning(f"Session revocation returned status {response.status_code}")

                await track_event(
                    "session_revoked",
                    properties={
                        "identity_provider": "auth0",
                        "success": success,
                        "response_status_code": response.status_code,
                    },
                )

                return success

        except Exception as e:
            logger.error(f"Session revocation failed: {str(e)}")
            return False

    async def health_check(self) -> bool:
        """Check Auth0 availability using OpenID configuration endpoint.

        Verifies connectivity to Auth0's well-known OpenID configuration
        endpoint to ensure the identity provider is accessible.

        Returns:
            True if Auth0 is accessible, False otherwise

        Requirements: 2.5
        """
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(
                    f"https://{self.domain}/.well-known/openid-configuration"
                )

                is_healthy = response.status_code == 200

                if is_healthy:
                    logger.debug("Auth0 health check passed")
                else:
                    logger.warning(f"Auth0 health check failed with status {response.status_code}")

                return is_healthy

        except Exception as e:
            logger.error(f"Auth0 health check failed: {str(e)}")
            return False

    def get_provider_name(self) -> str:
        """Return provider name.

        Returns:
            "auth0"

        Requirements: 2.1
        """
        return "auth0"

    def _get_provider_audience(self, provider: str) -> str:
        """Map provider name to OAuth audience.

        Maps external provider names (github, slack, google_workspace) to
        their corresponding OAuth audience URLs. This mapping is used to
        construct token requests with the correct audience parameter.

        Args:
            provider: Provider name (github, slack, google_workspace, etc.)

        Returns:
            OAuth audience URL for the provider

        Requirements: 2.6
        """
        audiences = {
            "github": "https://api.github.com",
            "slack": "https://slack.com/api",
            "google_workspace": "https://www.googleapis.com"
        }

        # Return mapped audience or construct default
        return audiences.get(provider, f"https://{provider}.com/api")
