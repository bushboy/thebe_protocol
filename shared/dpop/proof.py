"""DPoP proof generation and verification module.

This module provides DPoP (Demonstrating Proof-of-Possession) functionality:
- Generate DPoP proof JWTs bound to HTTP requests
- Verify DPoP proofs including token binding and request matching

Requirements: 4.3, 4.4, 12.5
"""

import hashlib
import time
import uuid
from typing import Dict, Any
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa


class DPoPValidationError(Exception):
    """Raised when DPoP proof validation fails."""
    pass


class DPoPProofGenerator:
    """Generates DPoP proof tokens bound to HTTP requests."""

    def __init__(self, private_key_pem: str):
        """Initialize DPoP proof generator.

        Args:
            private_key_pem: PEM-encoded private key for signing proofs
        """
        self.private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None,
            backend=default_backend()
        )
        self.jwt_algorithm = self._resolve_jwt_algorithm()

    def _resolve_jwt_algorithm(self) -> str:
        """Resolve JWT algorithm based on private key type.

        DPoP deployments commonly use EC keys (ES256), but some setups
        still use RSA keys (RS256). Select the algorithm dynamically.
        """
        if isinstance(self.private_key, rsa.RSAPrivateKey):
            return "RS256"
        if isinstance(self.private_key, ec.EllipticCurvePrivateKey):
            return "ES256"
        raise DPoPValidationError(
            f"Unsupported private key type for DPoP proof signing: {type(self.private_key).__name__}"
        )

    def generate_proof(
        self,
        access_token: str,
        http_method: str,
        http_uri: str
    ) -> str:
        """Generate DPoP proof JWT bound to HTTP request.

        The proof includes:
        - jti: Unique token identifier
        - htm: HTTP method (GET, POST, etc.)
        - htu: HTTP URI (without query parameters or fragments)
        - iat: Issued at timestamp
        - ath: Access token hash (SHA256)

        Args:
            access_token: JWT access token to bind to
            http_method: HTTP method (e.g., "POST")
            http_uri: HTTP URI (e.g., "https://api.example.com/resource")

        Returns:
            DPoP proof JWT string
        """
        # Compute access token hash
        token_hash = hashlib.sha256(access_token.encode()).hexdigest()

        # Create proof payload
        payload = {
            "jti": str(uuid.uuid4()),
            "htm": http_method.upper(),
            "htu": http_uri,
            "iat": int(time.time()),
            "ath": token_hash
        }

        # Sign with private key
        proof = jwt.encode(
            payload,
            self.private_key,
            algorithm=self.jwt_algorithm,
            headers={"typ": "dpop+jwt"}
        )

        return proof


class DPoPProofVerifier:
    """Verifies DPoP proof tokens."""

    def __init__(self, public_key_pem: str, freshness_window_seconds: int = 60):
        """Initialize DPoP proof verifier.

        Args:
            public_key_pem: PEM-encoded public key for signature verification
            freshness_window_seconds: Maximum age of proof in seconds (default: 60)
        """
        self.public_key = serialization.load_pem_public_key(
            public_key_pem.encode(),
            backend=default_backend()
        )
        self.allowed_algorithms = self._resolve_allowed_algorithms()
        self.freshness_window_seconds = freshness_window_seconds

    def _resolve_allowed_algorithms(self) -> list[str]:
        """Resolve allowed JWT algorithms based on public key type."""
        if isinstance(self.public_key, rsa.RSAPublicKey):
            return ["RS256"]
        if isinstance(self.public_key, ec.EllipticCurvePublicKey):
            return ["ES256"]
        raise DPoPValidationError(
            f"Unsupported public key type for DPoP proof verification: {type(self.public_key).__name__}"
        )

    def verify_proof(
        self,
        proof: str,
        access_token: str,
        http_method: str,
        http_uri: str
    ) -> Dict[str, Any]:
        """Verify DPoP proof.

        Validates:
        - Signature using public key
        - Token binding (ath matches access token hash)
        - Request matching (htm and htu match actual request)
        - Timestamp freshness

        Args:
            proof: DPoP proof JWT string
            access_token: JWT access token that should be bound
            http_method: Actual HTTP method of the request
            http_uri: Actual HTTP URI of the request

        Returns:
            Decoded proof payload

        Raises:
            DPoPValidationError: If any validation check fails
        """
        try:
            # Verify signature and decode
            payload = jwt.decode(
                proof,
                self.public_key,
                algorithms=self.allowed_algorithms,
                options={"verify_exp": False}  # DPoP proofs don't have exp claim
            )
        except jwt.InvalidSignatureError:
            raise DPoPValidationError("DPoP proof signature verification failed")
        except jwt.DecodeError as e:
            raise DPoPValidationError(f"DPoP proof decode error: {str(e)}")

        # Validate required fields
        required_fields = ["jti", "htm", "htu", "iat", "ath"]
        for field in required_fields:
            if field not in payload:
                raise DPoPValidationError(f"DPoP proof missing required field: {field}")

        # Validate token binding (ath matches access token hash)
        expected_hash = hashlib.sha256(access_token.encode()).hexdigest()
        if payload["ath"] != expected_hash:
            raise DPoPValidationError(
                "DPoP proof token binding failed: ath does not match access token hash"
            )

        # Validate request matching (htm matches HTTP method)
        if payload["htm"] != http_method.upper():
            raise DPoPValidationError(
                f"DPoP proof request mismatch: htm={payload['htm']}, expected={http_method.upper()}"
            )

        # Validate request matching (htu matches HTTP URI)
        if payload["htu"] != http_uri:
            raise DPoPValidationError(
                f"DPoP proof request mismatch: htu={payload['htu']}, expected={http_uri}"
            )

        # Validate timestamp freshness
        current_time = int(time.time())
        proof_age = current_time - payload["iat"]

        if proof_age > self.freshness_window_seconds:
            raise DPoPValidationError(
                f"DPoP proof is too old (age: {proof_age}s, max: {self.freshness_window_seconds}s)"
            )

        if proof_age < -60:  # Allow 60 seconds clock skew
            raise DPoPValidationError("DPoP proof issued in the future")

        return payload
