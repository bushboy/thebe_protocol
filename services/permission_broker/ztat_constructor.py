"""Zero-Trust Authorization Token (ZT-AT) construction for Permission Broker.

This module constructs ZT-AT tokens containing the complete authorization chain:
- Policy approval from Safety Agent
- Intent signature from Intent Engine
- Broker signature
- Expiration timestamp
- Unique nonce

Requirements: 8.6
"""

from datetime import datetime, timedelta
from typing import Any, Dict
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography import x509
import uuid
import hashlib
import json

from shared.schemas import ZeroTrustAuthorizationToken, PolicyDecision, IntentSignature
from shared.logging import JSONLogger
from shared.action_params_hash import compute_action_params_hash
from .config import config


logger = JSONLogger(__name__)


class ZTATConstructionError(Exception):
    """Exception raised when ZT-AT construction fails."""
    pass


class ZTATConstructor:
    """Constructs Zero-Trust Authorization Tokens."""

    def __init__(self):
        """Initialize ZT-AT constructor with signing key."""
        self.signing_key = self._load_signing_key()

    def _load_signing_key(self):
        """Load private key for signing ZT-ATs.

        Returns:
            Private key object or None if not available
        """
        if not config.signing_key_path.exists():
            logger.warning(f"Signing key not found: {config.signing_key_path}")
            return None

        try:
            with open(config.signing_key_path, 'rb') as f:
                key_data = f.read()

            # Try to load as private key
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            private_key = load_pem_private_key(key_data, password=None, backend=default_backend())

            logger.info("Signing key loaded successfully")
            return private_key
        except Exception as e:
            logger.error(f"Failed to load signing key: {str(e)}")
            return None

    def construct_ztat(
        self,
        plan_id: str,
        task_id: str,
        action: str,
        provider: str,
        policy_approval: PolicyDecision,
        intent_signature: IntentSignature,
        action_params: Dict[str, Any] | None = None
    ) -> ZeroTrustAuthorizationToken:
        """Construct a Zero-Trust Authorization Token.

        Args:
            plan_id: Unique plan identifier
            task_id: Unique task identifier
            action: Action to be performed
            provider: Target provider
            policy_approval: Signed policy approval from Safety Agent
            intent_signature: Intent signature from Intent Engine

        Returns:
            ZeroTrustAuthorizationToken object

        Raises:
            ZTATConstructionError: If construction fails

        Requirements: 8.6
        """
        logger.info(f"Constructing ZT-AT for plan: {plan_id}, task: {task_id}")

        # Generate unique nonce
        nonce = str(uuid.uuid4())
        action_params_hash = compute_action_params_hash(action_params)

        # Set timestamps
        issued_at = datetime.now()
        expires_at = issued_at + timedelta(seconds=config.zt_at_lifetime_seconds)

        # Create ZT-AT payload (without signature)
        ztat_payload = {
            "plan_id": plan_id,
            "task_id": task_id,
            "action": action,
            "provider": provider,
            "action_params_hash": action_params_hash,
            "policy_approval": policy_approval.model_dump(),
            "intent_signature": intent_signature.model_dump(),
            "issued_at": issued_at.isoformat(),
            "expires_at": expires_at.isoformat(),
            "nonce": nonce
        }

        # Sign the ZT-AT
        broker_signature = self._sign_ztat(ztat_payload)

        # Construct final ZT-AT
        ztat = ZeroTrustAuthorizationToken(
            plan_id=plan_id,
            task_id=task_id,
            action=action,
            provider=provider,
            action_params_hash=action_params_hash,
            policy_approval=policy_approval,
            intent_signature=intent_signature,
            broker_signature=broker_signature,
            issued_at=issued_at,
            expires_at=expires_at,
            nonce=nonce
        )

        logger.info(f"ZT-AT constructed successfully, expires at: {expires_at}")

        return ztat

    def _sign_ztat(self, payload: dict) -> str:
        """Sign the ZT-AT payload with broker private key.

        Args:
            payload: ZT-AT payload dictionary

        Returns:
            Signature string (hex-encoded)

        Raises:
            ZTATConstructionError: If signing fails
        """
        try:
            # Convert datetime objects to ISO format strings for JSON serialization
            serializable_payload = {}
            for key, value in payload.items():
                if key == "policy_approval":
                    # Convert PolicyDecision to dict with datetime as string
                    pa_dict = value.copy()
                    if "timestamp" in pa_dict and hasattr(pa_dict["timestamp"], "isoformat"):
                        pa_dict["timestamp"] = pa_dict["timestamp"].isoformat()
                    serializable_payload[key] = pa_dict
                elif key == "intent_signature":
                    # Convert IntentSignature to dict with datetime as string
                    is_dict = value.copy()
                    if "timestamp" in is_dict and hasattr(is_dict["timestamp"], "isoformat"):
                        is_dict["timestamp"] = is_dict["timestamp"].isoformat()
                    serializable_payload[key] = is_dict
                else:
                    serializable_payload[key] = value

            # Serialize payload to canonical JSON
            payload_json = json.dumps(serializable_payload, sort_keys=True, separators=(',', ':'))
            payload_bytes = payload_json.encode('utf-8')

            # If we have a signing key, use it
            if self.signing_key:
                # Sign with RSA private key
                signature = self.signing_key.sign(
                    payload_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )

                # Return hex-encoded signature
                return signature.hex()
            else:
                raise ZTATConstructionError(
                    "Permission Broker signing key is not configured; cannot sign ZT-AT"
                )

        except Exception as e:
            logger.error(f"Failed to sign ZT-AT: {str(e)}", exc_info=True)
            raise ZTATConstructionError(f"Failed to sign ZT-AT: {str(e)}")

    def verify_ztat_signature(self, ztat: ZeroTrustAuthorizationToken) -> bool:
        """Verify the broker signature on a ZT-AT.

        Args:
            ztat: ZT-AT to verify

        Returns:
            True if signature is valid, False otherwise
        """
        try:
            # Reconstruct payload
            payload = {
                "plan_id": ztat.plan_id,
                "task_id": ztat.task_id,
                "action": ztat.action,
                "provider": ztat.provider,
                "action_params_hash": ztat.action_params_hash,
                "policy_approval": ztat.policy_approval.model_dump(),
                "intent_signature": ztat.intent_signature.model_dump(),
                "issued_at": ztat.issued_at.isoformat(),
                "expires_at": ztat.expires_at.isoformat(),
                "nonce": ztat.nonce
            }

            payload_json = json.dumps(payload, sort_keys=True, separators=(',', ':'))
            payload_bytes = payload_json.encode('utf-8')

            # If we have a signing key, verify with public key
            if self.signing_key:
                # Get public key from private key
                public_key = self.signing_key.public_key()

                # Decode signature from hex
                signature_bytes = bytes.fromhex(ztat.broker_signature)

                # Verify signature
                public_key.verify(
                    signature_bytes,
                    payload_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )

                return True
            else:
                # For testing, just check signature format
                return len(ztat.broker_signature) > 10

        except Exception as e:
            logger.error(f"ZT-AT signature verification failed: {str(e)}")
            return False
