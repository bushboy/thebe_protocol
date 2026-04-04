"""Auth0 Token Vault client for Permission Broker.

This module handles requesting provider-specific tokens from Auth0 Token Vault
using Rich Authorization Requests (RAR).

Requirements: 8.5
"""

import httpx
from typing import Dict, Any, Optional
import inspect

from shared.schemas import RichAuthorizationRequest
from shared.logging import JSONLogger
from .config import config


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


class TokenVaultError(Exception):
    """Exception raised when Token Vault operations fail."""
    pass


class TokenVaultClient:
    """Client for Auth0 Token Vault operations."""

    def __init__(self):
        """Initialize Token Vault client."""
        self.auth0_domain = config.auth0_domain
        self.client_id = config.auth0_client_id
        self.client_secret = config.auth0_client_secret
        self.token_vault_url = config.auth0_token_vault_url or f"https://{self.auth0_domain}/oauth/token"
        self.timeout = 10.0

    async def request_provider_token(
        self,
        rar: RichAuthorizationRequest,
        provider: str
    ) -> Dict[str, Any]:
        """Request a provider-specific token from Auth0 Token Vault.

        Args:
            rar: Rich Authorization Request
            provider: Target provider (github, slack, google_workspace)

        Returns:
            Dictionary with provider token information:
            - access_token: Provider access token
            - token_type: Token type (usually "Bearer")
            - expires_in: Token expiration in seconds
            - scope: Granted scopes

        Raises:
            TokenVaultError: If token request fails

        Requirements: 8.5
        """
        logger.info(f"Requesting provider token for: {provider}")

        # In production, this would make an actual request to Auth0 Token Vault
        # For now, we'll simulate the token request

        if not self.auth0_domain or not self.client_id or not self.client_secret:
            logger.error("Auth0 Token Vault is not fully configured")
            raise TokenVaultError(
                "Auth0 Token Vault is not configured: auth0_domain, auth0_client_id, and auth0_client_secret are required"
            )

        try:
            # Construct token request
            token_request = {
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "audience": self._get_provider_audience(provider),
                "scope": " ".join(rar.actions)
            }

            # Add RAR parameters (Auth0 Token Vault extension)
            token_request["authorization_details"] = [
                {
                    "type": rar.type,
                    "actions": rar.actions,
                    "locations": rar.locations,
                    "purpose": rar.purpose,
                    "context": rar.context
                }
            ]

            # Make request to Auth0 Token Vault
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.token_vault_url,
                    json=token_request,
                    headers={"Content-Type": "application/json"}
                )

                if response.status_code != 200:
                    error_detail = await _read_response_json(response) if response.text else {}
                    logger.error(f"Token Vault request failed: {response.status_code} - {error_detail}")
                    raise TokenVaultError(
                        f"Token Vault returned {response.status_code}: {error_detail.get('error_description', 'Unknown error')}"
                    )

                token_data = await _read_response_json(response)

                logger.info(f"Provider token obtained successfully for {provider}")

                return {
                    "access_token": token_data.get("access_token"),
                    "token_type": token_data.get("token_type", "Bearer"),
                    "expires_in": token_data.get("expires_in", 3600),
                    "scope": token_data.get("scope", " ".join(rar.actions))
                }

        except httpx.TimeoutException as e:
            logger.error(f"Token Vault request timed out: {str(e)}")
            raise TokenVaultError("Token Vault request timed out")
        except httpx.RequestError as e:
            logger.error(f"Token Vault request failed: {str(e)}")
            raise TokenVaultError(f"Token Vault request failed: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error requesting provider token: {str(e)}", exc_info=True)
            raise TokenVaultError(f"Unexpected error: {str(e)}")

    def _get_provider_audience(self, provider: str) -> str:
        """Get the OAuth audience for a provider.

        Args:
            provider: Target provider

        Returns:
            OAuth audience string
        """
        audiences = {
            "github": "https://api.github.com",
            "slack": "https://slack.com/api",
            "google_workspace": "https://www.googleapis.com"
        }
        return audiences.get(provider, f"https://{provider}.com/api")

    async def health_check(self) -> bool:
        """Check if Auth0 Token Vault is accessible.

        Returns:
            True if healthy, False otherwise
        """
        if not self.auth0_domain:
            logger.warning("Auth0 not configured")
            return False

        try:
            # Try to reach Auth0 domain
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"https://{self.auth0_domain}/.well-known/openid-configuration")
                return response.status_code == 200
        except Exception as e:
            logger.error(f"Auth0 health check failed: {str(e)}")
            return False
