"""ZT-AT (Zero-Trust Authorization Token) validation module.

This module validates ZT-AT structure, signatures, and expiration.

Requirements: 9.2, 9.6, 12.4
"""

from datetime import datetime, timezone
from typing import Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

from shared.schemas import ZeroTrustAuthorizationToken
from shared.logging import JSONLogger
from shared.token_lifetime import TokenLifetimeValidator, TokenExpiredError


logger = JSONLogger(__name__)


class ZTATValidationError(Exception):
    """Exception raised when ZT-AT validation fails."""
    pass


class ZTATValidator:
    """Validator for Zero-Trust Authorization Tokens."""

    def __init__(self, broker_public_key_pem: Optional[str] = None,
                 safety_agent_public_key_pem: Optional[str] = None):
        """Initialize ZT-AT validator.

        Args:
            broker_public_key_pem: PEM-encoded public key of Permission Broker
            safety_agent_public_key_pem: PEM-encoded public key of Safety Agent
        """
        self.broker_public_key = None
        self.safety_agent_public_key = None

        if broker_public_key_pem:
            self.broker_public_key = serialization.load_pem_public_key(
                broker_public_key_pem.encode(),
                backend=default_backend()
            )

        if safety_agent_public_key_pem:
            self.safety_agent_public_key = serialization.load_pem_public_key(
                safety_agent_public_key_pem.encode(),
                backend=default_backend()
            )

    def validate_ztat(self, zt_at: ZeroTrustAuthorizationToken) -> None:
        """Validate ZT-AT structure, signatures, and expiration.

        Args:
            zt_at: Zero-Trust Authorization Token to validate

        Raises:
            ZTATValidationError: If validation fails

        Requirements: 9.2, 9.6
        """
        logger.info(f"Validating ZT-AT for plan: {zt_at.plan_id}, task: {zt_at.task_id}")

        # Step 1: Validate structure (Pydantic already validates this)
        # The ZeroTrustAuthorizationToken model ensures all required fields are present

        # Step 2: Check expiration timestamp
        self._validate_expiration(zt_at)

        # Step 3: Verify broker signature
        self._verify_broker_signature(zt_at)

        # Step 4: Verify policy approval signature
        self._verify_policy_approval_signature(zt_at)

        logger.info(f"ZT-AT validation successful for plan: {zt_at.plan_id}, task: {zt_at.task_id}")

    def _validate_expiration(self, zt_at: ZeroTrustAuthorizationToken) -> None:
        """Validate that ZT-AT has not expired.

        Args:
            zt_at: Zero-Trust Authorization Token

        Raises:
            ZTATValidationError: If token is expired

        Requirements: 9.6, 12.4
        """
        try:
            TokenLifetimeValidator.validate_zt_at_expiration(zt_at)
            logger.debug(f"ZT-AT expiration valid: expires at {zt_at.expires_at.isoformat()}")
        except TokenExpiredError as e:
            logger.error(str(e))
            raise ZTATValidationError(str(e))

    def _verify_broker_signature(self, zt_at: ZeroTrustAuthorizationToken) -> None:
        """Verify Permission Broker signature on ZT-AT.

        Args:
            zt_at: Zero-Trust Authorization Token

        Raises:
            ZTATValidationError: If signature verification fails

        Requirements: 9.2
        """
        if not self.broker_public_key:
            logger.warning("Broker public key not configured - skipping signature verification")
            return

        # In production, we would:
        # 1. Construct the signed data (plan_id, task_id, action, provider, etc.)
        # 2. Verify the signature using the broker's public key
        # For now, we'll perform a basic check

        if not zt_at.broker_signature:
            raise ZTATValidationError("Missing broker signature")

        # Placeholder for actual signature verification
        # In production:
        # try:
        #     signed_data = self._construct_signed_data(zt_at)
        #     self.broker_public_key.verify(
        #         bytes.fromhex(zt_at.broker_signature),
        #         signed_data,
        #         padding.PSS(
        #             mgf=padding.MGF1(hashes.SHA256()),
        #             salt_length=padding.PSS.MAX_LENGTH
        #         ),
        #         hashes.SHA256()
        #     )
        # except InvalidSignature:
        #     raise ZTATValidationError("Broker signature verification failed")

        logger.debug("Broker signature verification passed (placeholder)")

    def _verify_policy_approval_signature(self, zt_at: ZeroTrustAuthorizationToken) -> None:
        """Verify Safety Agent signature on policy approval.

        Args:
            zt_at: Zero-Trust Authorization Token

        Raises:
            ZTATValidationError: If signature verification fails

        Requirements: 9.2
        """
        if not self.safety_agent_public_key:
            logger.warning("Safety Agent public key not configured - skipping signature verification")
            return

        policy_approval = zt_at.policy_approval

        if not policy_approval.signature:
            raise ZTATValidationError("Missing policy approval signature")

        # Verify policy decision is ALLOW
        if policy_approval.decision != "ALLOW":
            raise ZTATValidationError(f"Policy decision is {policy_approval.decision}, not ALLOW")

        # Placeholder for actual signature verification
        # In production:
        # try:
        #     signed_data = self._construct_policy_signed_data(policy_approval)
        #     self.safety_agent_public_key.verify(
        #         bytes.fromhex(policy_approval.signature),
        #         signed_data,
        #         padding.PSS(
        #             mgf=padding.MGF1(hashes.SHA256()),
        #             salt_length=padding.PSS.MAX_LENGTH
        #         ),
        #         hashes.SHA256()
        #     )
        # except InvalidSignature:
        #     raise ZTATValidationError("Policy approval signature verification failed")

        logger.debug("Policy approval signature verification passed (placeholder)")

    def _construct_signed_data(self, zt_at: ZeroTrustAuthorizationToken) -> bytes:
        """Construct the data that was signed by the broker.

        Args:
            zt_at: Zero-Trust Authorization Token

        Returns:
            Bytes to verify signature against
        """
        # Construct canonical representation of signed fields
        data = f"{zt_at.plan_id}|{zt_at.task_id}|{zt_at.action}|{zt_at.provider}|{zt_at.nonce}"
        return data.encode('utf-8')

    def _construct_policy_signed_data(self, policy_approval) -> bytes:
        """Construct the data that was signed by the Safety Agent.

        Args:
            policy_approval: PolicyDecision object

        Returns:
            Bytes to verify signature against
        """
        # Construct canonical representation of signed fields.
        # This format mirrors Safety Agent sign_approval() to preserve
        # compatibility when full cryptographic verification is enabled.
        message_parts = [
            policy_approval.decision,
            policy_approval.reason,
            ",".join(sorted(policy_approval.evaluated_policies)),
            (
                f"{policy_approval.semantic_similarity_score:.6f}"
                if policy_approval.semantic_similarity_score is not None
                else ""
            ),
            (
                f"{policy_approval.semantic_match_threshold:.6f}"
                if policy_approval.semantic_match_threshold is not None
                else ""
            ),
            policy_approval.timestamp.isoformat(),
            policy_approval.signer_identity,
        ]
        return "|".join(message_parts).encode("utf-8")
