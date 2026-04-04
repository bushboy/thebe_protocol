"""Intent Engine client for Planner service.

This module provides a client for communicating with the Intent Engine service
to obtain intent signatures.

Requirements: 5.4, 5.5
"""

import httpx
import asyncio
from typing import List, Dict, Any
from pathlib import Path
from urllib.parse import urlparse

from shared.schemas import IntentSignature
from shared.dpop import DPoPProofGenerator
from shared.logging import JSONLogger
from .config import config


logger = JSONLogger(__name__)


class IntentEngineClient:
    """Client for communicating with Intent Engine service."""

    def __init__(self):
        """Initialize Intent Engine client."""
        # Load DPoP private key for generating proofs
        dpop_key_path = config.dpop_private_key_path
        if dpop_key_path.exists():
            with open(dpop_key_path, 'r') as f:
                dpop_private_key_pem = f.read()
            self.dpop_generator = DPoPProofGenerator(dpop_private_key_pem)
        else:
            logger.warning(f"DPoP private key not found at {dpop_key_path}")
            self.dpop_generator = None

        # Load client certificate for mTLS
        self.client_cert_path = config.client_cert_path
        self.client_key_path = config.client_key_path

        # Intent Engine service URL
        self.intent_engine_url = config.intent_engine_url
        self.max_retries = 5
        self.retry_delay_seconds = 1.0

    def _build_httpx_client(self) -> httpx.AsyncClient:
        """Build an HTTP client compatible with HTTP and HTTPS backends.

        Only attach mTLS cert material for HTTPS targets. Using certs with
        a plain HTTP upstream can trigger SSL handshake failures.
        """
        parsed_url = urlparse(self.intent_engine_url)
        if parsed_url.scheme == "https":
            return httpx.AsyncClient(
                cert=(str(self.client_cert_path), str(self.client_key_path)),
                verify=False  # In production, verify with root CA
            )

        return httpx.AsyncClient()

    async def sign_intent(
        self,
        user_goal: str,
        allowed_actions: List[str],
        access_token: str
    ) -> IntentSignature:
        """Request intent signature from Intent Engine.

        Args:
            user_goal: User's stated goal
            allowed_actions: List of permitted action types
            access_token: JWT access token for authentication

        Returns:
            IntentSignature object

        Raises:
            httpx.HTTPError: If request fails

        Requirements: 5.4, 5.5
        """
        logger.info(f"Requesting intent signature for goal: {user_goal[:50]}...")

        # Prepare request
        url = f"{self.intent_engine_url}/sign-intent"
        payload = {
            "user_goal": user_goal,
            "allowed_actions": allowed_actions
        }

        # Generate DPoP proof
        dpop_proof = None
        if self.dpop_generator:
            dpop_proof = self.dpop_generator.generate_proof(
                access_token=access_token,
                http_method="POST",
                http_uri=url
            )

        # Prepare headers
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }

        if dpop_proof:
            headers["DPoP"] = dpop_proof

        last_error: Exception | None = None
        for attempt in range(1, self.max_retries + 1):
            try:
                # Make request with transport compatible to target scheme
                async with self._build_httpx_client() as client:
                    response = await client.post(
                        url,
                        json=payload,
                        headers=headers,
                        timeout=30.0
                    )

                    response.raise_for_status()

                    # Parse response
                    response_data = response.json()
                    intent_signature = IntentSignature(**response_data["intent_signature"])

                    logger.info(f"Received intent signature with hash: {intent_signature.hash}")

                    return intent_signature
            except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout) as e:
                last_error = e
                if attempt == self.max_retries:
                    break
                logger.warning(
                    f"Intent Engine request attempt {attempt}/{self.max_retries} failed: {str(e)}. "
                    f"Retrying in {self.retry_delay_seconds:.1f}s"
                )
                await asyncio.sleep(self.retry_delay_seconds)

        # Preserve existing behavior for callers while surfacing the last transport error.
        if last_error:
            raise last_error
        raise httpx.RequestError("Failed to request intent signature")

    async def verify_intent(
        self,
        intent_signature: IntentSignature,
        proposed_action: str,
        access_token: str
    ) -> Dict[str, Any]:
        """Verify intent alignment with Intent Engine.

        Args:
            intent_signature: Intent signature to verify against
            proposed_action: Proposed action to verify
            access_token: JWT access token for authentication

        Returns:
            Dictionary with alignment result

        Raises:
            httpx.HTTPError: If request fails
        """
        logger.info(f"Verifying intent for action: {proposed_action[:50]}...")

        # Prepare request
        url = f"{self.intent_engine_url}/verify-intent"
        payload = {
            "intent_signature": intent_signature.model_dump(),
            "proposed_action": proposed_action
        }

        # Generate DPoP proof
        dpop_proof = None
        if self.dpop_generator:
            dpop_proof = self.dpop_generator.generate_proof(
                access_token=access_token,
                http_method="POST",
                http_uri=url
            )

        # Prepare headers
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }

        if dpop_proof:
            headers["DPoP"] = dpop_proof

        last_error: Exception | None = None
        for attempt in range(1, self.max_retries + 1):
            try:
                # Make request with transport compatible to target scheme
                async with self._build_httpx_client() as client:
                    response = await client.post(
                        url,
                        json=payload,
                        headers=headers,
                        timeout=30.0
                    )

                    response.raise_for_status()

                    # Parse response
                    result = response.json()

                    logger.info(
                        f"Intent verification complete: aligned={result['aligned']}, "
                        f"similarity={result['similarity_score']:.3f}"
                    )

                    return result
            except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout) as e:
                last_error = e
                if attempt == self.max_retries:
                    break
                logger.warning(
                    f"Intent Engine verification attempt {attempt}/{self.max_retries} failed: {str(e)}. "
                    f"Retrying in {self.retry_delay_seconds:.1f}s"
                )
                await asyncio.sleep(self.retry_delay_seconds)

        if last_error:
            raise last_error
        raise httpx.RequestError("Failed to verify intent")
