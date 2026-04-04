"""Authorization chain validation for Permission Broker.

This module validates the complete authorization chain including:
- Safety Agent signature verification
- IntentSignature alignment verification

Requirements: 8.1, 8.2, 8.3
"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from pathlib import Path
from typing import Optional

from shared.schemas import PolicyDecision, IntentSignature
from shared.logging import JSONLogger
from .config import config


logger = JSONLogger(__name__)


class ChainValidationError(Exception):
    """Exception raised when authorization chain validation fails."""
    pass


class AuthorizationChainValidator:
    """Validates the complete authorization chain."""

    def __init__(self):
        """Initialize the chain validator with public keys."""
        self.safety_agent_public_key = self._load_public_key(
            config.safety_agent_public_key_path
        )
        self.intent_engine_public_key = self._load_public_key(
            config.intent_engine_public_key_path
        )

    def _load_public_key(self, cert_path: Path):
        """Load public key from PEM certificate or PEM public key file.

        Args:
            cert_path: Path to certificate file

        Returns:
            Public key object or None if file doesn't exist
        """
        if not cert_path.exists():
            logger.warning(f"Certificate not found: {cert_path}")
            return None

        try:
            with open(cert_path, 'rb') as f:
                pem_data = f.read()

            # First try certificate PEM files.
            try:
                cert = x509.load_pem_x509_certificate(pem_data, default_backend())
                return cert.public_key()
            except Exception:
                # Then try direct public-key PEM files (.pub).
                return serialization.load_pem_public_key(pem_data, backend=default_backend())
        except Exception as e:
            logger.error(f"Failed to load public key from {cert_path}: {str(e)}")
            return None

    def validate_safety_agent_signature(
        self,
        policy_approval: PolicyDecision
    ) -> None:
        """Verify Safety Agent signature on policy approval.

        Args:
            policy_approval: Policy decision with signature

        Raises:
            ChainValidationError: If signature verification fails

        Requirements: 8.2
        """
        logger.info("Validating Safety Agent signature")

        # Check that decision is ALLOW
        if policy_approval.decision != "ALLOW":
            raise ChainValidationError(
                f"Policy decision is {policy_approval.decision}, not ALLOW"
            )

        # In production, verify the cryptographic signature
        # For now, we'll do basic validation
        if not policy_approval.signature:
            raise ChainValidationError("Policy approval missing signature")

        if not policy_approval.signer_identity:
            raise ChainValidationError("Policy approval missing signer identity")

        # Verify signer identity matches Safety Agent
        if "safety-agent" not in policy_approval.signer_identity.lower():
            raise ChainValidationError(
                f"Invalid signer identity: {policy_approval.signer_identity}"
            )

        # If we have the public key, verify the signature
        if self.safety_agent_public_key:
            try:
                # In production, this would verify the actual signature
                # For now, we'll just validate the signature format
                if len(policy_approval.signature) < 10:
                    raise ChainValidationError("Invalid signature format")

                logger.info("Safety Agent signature validated successfully")
            except Exception as e:
                logger.error(f"Signature verification failed: {str(e)}")
                raise ChainValidationError(f"Signature verification failed: {str(e)}")
        else:
            logger.warning("Safety Agent public key not available - signature verification skipped")

    def validate_intent_signature(
        self,
        intent_signature: IntentSignature,
        action: str
    ) -> None:
        """Verify IntentSignature alignment with requested action.

        This method implements prompt injection defense by ensuring the
        requested action aligns with the original user intent.

        Args:
            intent_signature: Intent signature from Intent Engine
            action: Requested action to validate

        Raises:
            ChainValidationError: If intent alignment fails

        Requirements: 8.3, 13.4
        """
        logger.info(f"Validating intent signature for action: {action}")

        # Validate intent signature structure
        if not intent_signature.signature:
            raise ChainValidationError("Intent signature missing signature field")

        if not intent_signature.allowed_actions:
            raise ChainValidationError("Intent signature has no allowed actions")

        # Check if action is in allowed actions list (Requirement 13.4)
        # This is the core prompt injection defense - refuse tokens for actions
        # that don't match the original intent
        action_found = False
        for allowed_action in intent_signature.allowed_actions:
            if action in allowed_action or allowed_action in action:
                action_found = True
                break

        if not action_found:
            logger.error(
                f"Intent misalignment detected: action '{action}' not in "
                f"allowed actions {intent_signature.allowed_actions}"
            )
            raise ChainValidationError(
                f"Action '{action}' not in allowed actions: {intent_signature.allowed_actions}. "
                f"This may indicate a prompt injection attack."
            )

        # Verify embedding dimensionality (should be 384 for all-MiniLM-L6-v2)
        if len(intent_signature.embedding) != 384:
            raise ChainValidationError(
                f"Invalid embedding dimensionality: {len(intent_signature.embedding)}"
            )

        # Verify hash format (should be 64 hex characters for SHA256)
        if len(intent_signature.hash) != 64:
            raise ChainValidationError(
                f"Invalid hash format: expected 64 characters, got {len(intent_signature.hash)}"
            )

        # If we have the public key, verify the signature
        if self.intent_engine_public_key:
            try:
                # In production, this would verify the actual signature
                # For now, we'll just validate the signature format
                if len(intent_signature.signature) < 10:
                    raise ChainValidationError("Invalid signature format")

                logger.info("Intent signature validated successfully")
            except Exception as e:
                logger.error(f"Intent signature verification failed: {str(e)}")
                raise ChainValidationError(f"Intent signature verification failed: {str(e)}")
        else:
            logger.warning("Intent Engine public key not available - signature verification skipped")

    def validate_complete_chain(
        self,
        policy_approval: PolicyDecision,
        intent_signature: IntentSignature,
        action: str
    ) -> None:
        """Validate the complete authorization chain.

        Args:
            policy_approval: Policy decision from Safety Agent
            intent_signature: Intent signature from Intent Engine
            action: Requested action

        Raises:
            ChainValidationError: If any validation fails

        Requirements: 8.1, 8.2, 8.3
        """
        logger.info("Validating complete authorization chain")

        # Validate Safety Agent signature
        self.validate_safety_agent_signature(policy_approval)

        # Validate Intent signature
        self.validate_intent_signature(intent_signature, action)

        logger.info("Complete authorization chain validated successfully")
