"""OpenFGA identity provider adapter implementation.

This module implements the IVaultProvider interface for OpenFGA-backed
relationship authorization checks.
"""

from typing import Dict, Any

import httpx

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
from shared.logging import JSONLogger


logger = JSONLogger(__name__)


class OpenFGAAdapter(IVaultProvider):
    """OpenFGA relationship-based authorization adapter.

    OpenFGA is used as an authorization decision source. When authorization
    checks pass, this adapter returns a token-shaped response to keep behavior
    compatible with the existing IVaultProvider contract.
    """

    def __init__(self, config: Dict[str, Any]):
        """Initialize OpenFGA adapter with configuration.

        Args:
            config: Configuration dictionary with keys:
                - api_url: OpenFGA API base URL (required)
                - store_id: OpenFGA store ID (required)
                - authorization_model_id: Model ID for check requests (required)
                - api_token: Optional API token for OpenFGA
                - relation_mapping: Optional action->relation mapping
                - timeout: Request timeout in seconds (optional, default 10.0)

        Raises:
            VaultValidationError: If required configuration is missing or invalid
        """
        if not config.get("api_url"):
            raise VaultValidationError("OpenFGA api_url is required")
        if not config.get("store_id"):
            raise VaultValidationError("OpenFGA store_id is required")
        if not config.get("authorization_model_id"):
            raise VaultValidationError("OpenFGA authorization_model_id is required")

        self.api_url = str(config["api_url"]).strip().rstrip("/")
        self.store_id = str(config["store_id"]).strip()
        self.authorization_model_id = str(config["authorization_model_id"]).strip()
        self.api_token = str(config.get("api_token")).strip() if config.get("api_token") else None
        self.relation_mapping = config.get("relation_mapping", {}) or {}
        self.timeout = float(config.get("timeout", 10.0))

        if self.timeout <= 0:
            raise VaultValidationError("Timeout must be a positive number")

        self.check_url = f"{self.api_url}/stores/{self.store_id}/check"

        logger.info(
            "Initialized OpenFGAAdapter",
            extra={
                "api_url": self.api_url,
                "store_id": self.store_id,
                "timeout": self.timeout,
            },
        )

    @record_metrics("get_token")
    @with_retry(max_attempts=3, base_delay=1.0)
    async def get_token(self, rar: RichAuthorizationRequest, provider: str) -> Dict[str, Any]:
        """Authorize request using OpenFGA and return token-shaped output.

        The adapter evaluates each requested action as an OpenFGA check:
        user-relation-object. If any check fails, authorization is denied.
        """
        subject = self._resolve_subject(rar, provider)
        obj = self._resolve_object(rar, provider)

        for action in rar.actions:
            relation = self.relation_mapping.get(action, action.replace(":", "_"))
            allowed = await self._check_relation(subject=subject, relation=relation, obj=obj)
            if not allowed:
                raise VaultAuthenticationError(
                    f"OpenFGA denied relation check for subject='{subject}', relation='{relation}', object='{obj}'"
                )

        context = rar.context or {}
        token = context.get("delegated_access_token") or context.get("access_token")
        if not token:
            # Keep compatibility with IVaultProvider while signaling this came from OpenFGA.
            token = f"openfga_authorized:{provider}:{context.get('plan_id', 'unknown')}"

        expires_in = context.get("expires_in", 300)
        try:
            expires_in = int(expires_in)
        except (TypeError, ValueError):
            expires_in = 300
        if expires_in <= 0:
            expires_in = 300

        return {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": expires_in,
            "scope": " ".join(rar.actions),
        }

    @record_metrics("exchange_token")
    @with_retry(max_attempts=3, base_delay=1.0)
    async def exchange_token(
        self,
        existing_token: str,
        new_scopes: list[str],
        provider: str,
    ) -> Dict[str, Any]:
        """Return exchanged token metadata for requested scopes.

        OpenFGA is authorization-only, so exchange keeps the original token.
        """
        if not existing_token or not existing_token.strip():
            raise VaultValidationError("existing_token must be a non-empty string")

        return {
            "access_token": existing_token,
            "token_type": "Bearer",
            "expires_in": 300,
            "scope": " ".join(new_scopes),
        }

    @record_revoke_session_metrics
    async def revoke_session(self, session_id: str) -> bool:
        """Revoke session placeholder for OpenFGA.

        OpenFGA does not issue OAuth sessions; this is a no-op success.
        """
        if not session_id:
            return False
        return True

    async def health_check(self) -> bool:
        """Check OpenFGA availability."""
        headers = self._headers()

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                health_response = await client.get(f"{self.api_url}/healthz", headers=headers)
                if health_response.status_code == 200:
                    return True

                # Fallback check for deployments that disable /healthz.
                store_response = await client.get(
                    f"{self.api_url}/stores/{self.store_id}",
                    headers=headers,
                )
                return store_response.status_code == 200
        except Exception as exc:
            logger.error(f"OpenFGA health check failed: {str(exc)}")
            return False

    def get_provider_name(self) -> str:
        """Return provider name."""
        return "openfga"

    async def _check_relation(self, subject: str, relation: str, obj: str) -> bool:
        """Evaluate a single OpenFGA relation check."""
        payload = {
            "tuple_key": {
                "user": subject,
                "relation": relation,
                "object": obj,
            },
            "authorization_model_id": self.authorization_model_id,
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(self.check_url, json=payload, headers=self._headers())

            if response.status_code == 401:
                raise VaultAuthenticationError("OpenFGA authentication failed")
            if 400 <= response.status_code < 500:
                raise VaultValidationError(f"OpenFGA check rejected request: {response.text}")
            if response.status_code >= 500:
                raise VaultProviderError(f"OpenFGA returned {response.status_code}: {response.text}")
            if response.status_code != 200:
                raise VaultProviderError(f"OpenFGA returned unexpected status code: {response.status_code}")

            data = response.json()
            allowed = data.get("allowed")
            if not isinstance(allowed, bool):
                raise VaultValidationError("OpenFGA check response missing boolean 'allowed'")
            return allowed

        except httpx.TimeoutException as exc:
            raise VaultTimeoutError(f"OpenFGA request timed out after {self.timeout}s") from exc
        except httpx.RequestError as exc:
            raise VaultProviderError(f"OpenFGA request failed: {str(exc)}") from exc

    def _resolve_subject(self, rar: RichAuthorizationRequest, provider: str) -> str:
        """Resolve subject for OpenFGA tuple checks."""
        context = rar.context or {}
        subject = context.get("subject") or context.get("user") or context.get("principal")
        if subject:
            return str(subject)

        plan_id = context.get("plan_id")
        if plan_id:
            return f"plan:{plan_id}"

        return f"provider:{provider}"

    def _resolve_object(self, rar: RichAuthorizationRequest, provider: str) -> str:
        """Resolve object for OpenFGA tuple checks."""
        context = rar.context or {}
        obj = context.get("resource") or context.get("object")
        if obj:
            return str(obj)

        if rar.locations:
            return str(rar.locations[0])

        return f"provider:{provider}"

    def _headers(self) -> Dict[str, str]:
        """Build HTTP headers for OpenFGA requests."""
        headers = {"Content-Type": "application/json"}
        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"
        return headers
