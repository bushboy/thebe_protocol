"""Keycloak identity provider adapter implementation.

This module implements the IVaultProvider interface for Keycloak identity provider,
enabling the Identity Abstraction Layer to support Keycloak as an alternative to
Auth0 Token Vault.

Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 21.3, 21.4, 21.7
"""

import httpx
from typing import Dict, Any, List, Union
import inspect
from .ivault_provider import IVaultProvider
from .exceptions import (
    VaultProviderError,
    VaultAuthenticationError,
    VaultValidationError,
    VaultTimeoutError,
)
from .retry import with_retry
from .metrics import record_metrics, record_revoke_session_metrics
from shared.schemas.models import RichAuthorizationRequest
from shared.logging.json_logger import JSONLogger


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


class KeycloakAdapter(IVaultProvider):
    """Keycloak identity provider adapter implementation.

    This adapter implements the IVaultProvider interface for Keycloak, supporting
    client credentials flow, token exchange, session revocation, and configurable
    scope mapping from RAR actions to Keycloak scopes.

    Attributes:
        server_url: Keycloak server URL
        realm: Keycloak realm name
        client_id: Client ID
        client_secret: Client secret
        scope_mapping: Dictionary mapping RAR actions to Keycloak scopes
        timeout: Request timeout in seconds
        token_url: Constructed token endpoint URL
    """

    def __init__(self, config: Dict[str, Any]):
        """Initialize Keycloak adapter with configuration.

        Args:
            config: Configuration dictionary with keys:
                - server_url: Keycloak server URL (required)
                - realm: Keycloak realm name (required)
                - client_id: Client ID (required)
                - client_secret: Client secret (required)
                - scope_mapping: Dict mapping RAR actions to Keycloak scopes (optional)
                - timeout: Request timeout in seconds (optional, default: 10.0)

        Raises:
            VaultValidationError: If required configuration is missing or invalid

        Requirements: 3.1, 15.2, 21.1, 21.2
        """
        # Validate required configuration fields
        if not config.get("server_url"):
            raise VaultValidationError("Keycloak server_url is required")
        if not config.get("realm"):
            raise VaultValidationError("Keycloak realm is required")
        if not config.get("client_id"):
            raise VaultValidationError("Keycloak client_id is required")
        if not config.get("client_secret"):
            raise VaultValidationError("Keycloak client_secret is required")

        self.server_url = config["server_url"].strip().rstrip("/")
        self.realm = config["realm"].strip()
        self.client_id = config["client_id"].strip()
        self.client_secret = config["client_secret"].strip()
        self.scope_mapping = config.get("scope_mapping", {})
        self.timeout = config.get("timeout", 10.0)

        # Validate timeout is positive
        if self.timeout <= 0:
            raise VaultValidationError("Timeout must be a positive number")

        # Construct token URL from server_url and realm
        self.token_url = f"{self.server_url}/realms/{self.realm}/protocol/openid-connect/token"

        logger.info(
            f"Initialized KeycloakAdapter",
            extra={
                "server_url": self.server_url,
                "realm": self.realm,
                "token_url": self.token_url,
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
        """Request provider token from Keycloak using client credentials flow.

        Constructs a Keycloak token request with client credentials grant type,
        translates RAR actions to Keycloak scopes using the configured scope_mapping,
        and returns the provider token.

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

        Requirements: 3.2, 3.7, 21.3, 21.4, 21.7
        """
        logger.info(f"Requesting token for provider: {provider}")

        # Map RAR actions to Keycloak scopes using configured mapping
        keycloak_scopes = self._map_scopes(rar.actions, provider)

        logger.debug(
            f"Mapped RAR actions to Keycloak scopes",
            extra={
                "rar_actions": rar.actions,
                "keycloak_scopes": keycloak_scopes,
                "provider": provider
            }
        )

        # Construct token request with client credentials flow
        # Keycloak expects application/x-www-form-urlencoded content type
        token_request = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": " ".join(keycloak_scopes)
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.token_url,
                    data=token_request,
                    headers={"Content-Type": "application/x-www-form-urlencoded"}
                )

                # Handle Keycloak-specific error responses
                if response.status_code == 401:
                    logger.error("Keycloak authentication failed (401)")
                    raise VaultAuthenticationError("Keycloak authentication failed: Invalid credentials")

                if response.status_code >= 400 and response.status_code < 500:
                    error_detail = await _read_response_json(response) if response.text else {}
                    error_msg = error_detail.get('error_description', error_detail.get('error', 'Unknown client error'))
                    logger.error(f"Keycloak client error ({response.status_code}): {error_msg}")
                    raise VaultProviderError(
                        f"Keycloak returned {response.status_code}: {error_msg}"
                    )

                if response.status_code >= 500:
                    error_detail = await _read_response_json(response) if response.text else {}
                    error_msg = error_detail.get('error_description', error_detail.get('error', 'Unknown server error'))
                    logger.error(f"Keycloak server error ({response.status_code}): {error_msg}")
                    raise VaultProviderError(
                        f"Keycloak returned {response.status_code}: {error_msg}"
                    )

                if response.status_code != 200:
                    logger.error(f"Keycloak unexpected status code: {response.status_code}")
                    raise VaultProviderError(
                        f"Keycloak returned unexpected status code: {response.status_code}"
                    )

                # Parse and validate token response
                token_data = await _read_response_json(response)

                # Validate required fields are present
                if "access_token" not in token_data:
                    logger.error("Keycloak response missing access_token")
                    raise VaultValidationError("Keycloak response missing required field: access_token")

                if "expires_in" not in token_data:
                    logger.error("Keycloak response missing expires_in")
                    raise VaultValidationError("Keycloak response missing required field: expires_in")

                # Validate access_token is non-empty
                if not token_data["access_token"] or not token_data["access_token"].strip():
                    logger.error("Keycloak returned empty access_token")
                    raise VaultValidationError("Keycloak returned empty access_token")

                # Validate expires_in is positive
                try:
                    expires_in = int(token_data["expires_in"])
                    if expires_in <= 0:
                        logger.error(f"Keycloak returned non-positive expires_in: {expires_in}")
                        raise VaultValidationError(f"Keycloak returned non-positive expires_in: {expires_in}")
                except (ValueError, TypeError) as e:
                    logger.error(f"Keycloak returned invalid expires_in: {token_data.get('expires_in')}")
                    raise VaultValidationError(f"Keycloak returned invalid expires_in: {str(e)}")

                logger.info(f"Provider token obtained successfully for {provider}")

                # Return normalized token response
                return {
                    "access_token": token_data["access_token"],
                    "token_type": token_data.get("token_type", "Bearer"),
                    "expires_in": expires_in,
                    "scope": token_data.get("scope", " ".join(keycloak_scopes))
                }

        except httpx.TimeoutException:
            logger.error(f"Keycloak request timed out after {self.timeout}s")
            raise VaultTimeoutError(f"Keycloak request timed out after {self.timeout}s")

        except httpx.RequestError as e:
            logger.error(f"Keycloak request failed: {str(e)}")
            raise VaultProviderError(f"Keycloak request failed: {str(e)}")

        except (VaultAuthenticationError, VaultValidationError, VaultTimeoutError, VaultProviderError):
            # Re-raise IAL exceptions as-is
            raise

        except Exception as e:
            logger.error(f"Unexpected error requesting Keycloak token: {str(e)}", exc_info=True)
            raise VaultProviderError(f"Unexpected error: {str(e)}")

    @record_metrics('exchange_token')
    @with_retry(max_attempts=3, base_delay=1.0)
    async def exchange_token(
        self,
        existing_token: str,
        new_scopes: list[str],
        provider: str
    ) -> Dict[str, Any]:
        """Exchange token using Keycloak token exchange protocol.

        Uses Keycloak's token exchange protocol (RFC 8693) to obtain a new token
        with different scopes.

        Args:
            existing_token: Current access token to be exchanged
            new_scopes: Requested scopes for new token
            provider: Target provider

        Returns:
            Dictionary with new token information

        Raises:
            VaultProviderError: Exchange failed
            VaultAuthenticationError: Invalid token
            VaultTimeoutError: Request timeout

        Requirements: 3.3
        """
        logger.info(f"Exchanging token for provider: {provider}")

        # Map new scopes to Keycloak scopes
        keycloak_scopes = self._map_scopes(new_scopes, provider)

        # Construct token exchange request
        exchange_request = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "subject_token": existing_token,
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "scope": " ".join(keycloak_scopes)
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.token_url,
                    data=exchange_request,
                    headers={"Content-Type": "application/x-www-form-urlencoded"}
                )

                if response.status_code == 401:
                    logger.error("Keycloak token exchange authentication failed (401)")
                    raise VaultAuthenticationError("Token exchange failed: Invalid token")

                if response.status_code != 200:
                    error_detail = await _read_response_json(response) if response.text else {}
                    error_msg = error_detail.get('error_description', error_detail.get('error', 'Unknown error'))
                    logger.error(f"Keycloak token exchange failed ({response.status_code}): {error_msg}")
                    raise VaultProviderError(f"Token exchange failed: {error_msg}")

                token_data = await _read_response_json(response)

                logger.info(f"Token exchanged successfully for {provider}")

                return {
                    "access_token": token_data["access_token"],
                    "token_type": token_data.get("token_type", "Bearer"),
                    "expires_in": token_data.get("expires_in", 3600),
                    "scope": token_data.get("scope", " ".join(keycloak_scopes))
                }

        except httpx.TimeoutException:
            logger.error(f"Keycloak token exchange timed out after {self.timeout}s")
            raise VaultTimeoutError(f"Token exchange timed out after {self.timeout}s")

        except httpx.RequestError as e:
            logger.error(f"Keycloak token exchange request failed: {str(e)}")
            raise VaultProviderError(f"Token exchange request failed: {str(e)}")

        except (VaultAuthenticationError, VaultTimeoutError, VaultProviderError):
            raise

        except Exception as e:
            logger.error(f"Unexpected error during token exchange: {str(e)}", exc_info=True)
            raise VaultProviderError(f"Unexpected error: {str(e)}")

    @record_revoke_session_metrics
    async def revoke_session(self, session_id: str) -> bool:
        """Revoke session using Keycloak logout endpoint.

        Calls Keycloak's logout endpoint to invalidate the specified refresh token
        or session.

        Args:
            session_id: Refresh token or session identifier to revoke

        Returns:
            True if revocation succeeded, False otherwise

        Requirements: 3.4
        """
        logger.info(f"Revoking session: {session_id[:8]}...")

        logout_url = f"{self.server_url}/realms/{self.realm}/protocol/openid-connect/logout"

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    logout_url,
                    data={
                        "client_id": self.client_id,
                        "client_secret": self.client_secret,
                        "refresh_token": session_id
                    },
                    headers={"Content-Type": "application/x-www-form-urlencoded"}
                )

                # Keycloak returns 204 No Content on successful logout
                success = response.status_code == 204

                if success:
                    logger.info("Session revoked successfully")
                else:
                    logger.warning(f"Session revocation returned status {response.status_code}")

                return success

        except Exception as e:
            logger.error(f"Session revocation failed: {str(e)}")
            return False

    async def health_check(self) -> bool:
        """Check Keycloak availability using realm endpoint.

        Verifies connectivity to Keycloak's realm endpoint to ensure the
        identity provider is accessible.

        Returns:
            True if Keycloak is accessible, False otherwise

        Requirements: 3.5
        """
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(
                    f"{self.server_url}/realms/{self.realm}"
                )

                is_healthy = response.status_code == 200

                if is_healthy:
                    logger.debug("Keycloak health check passed")
                else:
                    logger.warning(f"Keycloak health check failed with status {response.status_code}")

                return is_healthy

        except Exception as e:
            logger.error(f"Keycloak health check failed: {str(e)}")
            return False

    def get_provider_name(self) -> str:
        """Return provider name.

        Returns:
            "keycloak"

        Requirements: 3.6
        """
        return "keycloak"

    def _map_scopes(self, rar_actions: List[str], provider: str) -> List[str]:
        """Map RAR actions to Keycloak scopes using configured mapping.

        Translates RAR actions to Keycloak scopes using the scope_mapping
        configuration. If an action has a mapping, uses the mapped scope(s).
        If no mapping exists, falls back to "{provider}:{action}" format.
        Supports multiple scopes per action (list values in scope_mapping).

        Args:
            rar_actions: List of RAR action names
            provider: Target provider name

        Returns:
            List of Keycloak scope strings

        Requirements: 3.7, 21.3, 21.4, 21.7
        """
        keycloak_scopes = []

        for action in rar_actions:
            # Check if there's a specific mapping for this action
            mapped_scope = self.scope_mapping.get(action)

            if mapped_scope:
                # Support multiple scopes per action (list values)
                if isinstance(mapped_scope, list):
                    keycloak_scopes.extend(mapped_scope)
                else:
                    keycloak_scopes.append(mapped_scope)
            else:
                # Default: use provider:action format
                keycloak_scopes.append(f"{provider}:{action}")

        logger.debug(
            f"Scope mapping result",
            extra={
                "rar_actions": rar_actions,
                "keycloak_scopes": keycloak_scopes,
                "provider": provider
            }
        )

        return keycloak_scopes
