"""JWT token validation module.

This module provides JWT validation functionality including:
- Signature verification using PyJWT
- Issuer, audience, and expiration validation
- Nonce tracking for replay prevention
- Timestamp freshness validation

Requirements: 4.1, 4.2, 12.3
"""

import time
from typing import Dict, Any, Set, Optional
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


class JWTValidationError(Exception):
    """Raised when JWT validation fails."""
    pass


class JWTValidator:
    """Validates JWT tokens with replay prevention and freshness checks."""
    
    def __init__(
        self,
        public_key_pem: str,
        expected_issuer: str,
        expected_audience: str,
        freshness_window_seconds: int = 300
    ):
        """Initialize JWT validator.
        
        Args:
            public_key_pem: PEM-encoded public key for signature verification
            expected_issuer: Expected 'iss' claim value
            expected_audience: Expected 'aud' claim value
            freshness_window_seconds: Maximum age of token in seconds (default: 5 minutes)
        """
        self.public_key = serialization.load_pem_public_key(
            public_key_pem.encode(),
            backend=default_backend()
        )
        self.expected_issuer = expected_issuer
        self.expected_audience = expected_audience
        self.freshness_window_seconds = freshness_window_seconds
        self._used_nonces: Set[str] = set()
    
    def validate(self, token: str) -> Dict[str, Any]:
        """Validate JWT token.
        
        Validates:
        - Signature using public key
        - Issuer matches expected value
        - Audience matches expected value
        - Token has not expired
        - Nonce has not been used before (replay prevention)
        - Token timestamp is fresh
        
        Args:
            token: JWT token string
            
        Returns:
            Decoded token payload
            
        Raises:
            JWTValidationError: If any validation check fails
        """
        try:
            # Verify signature and decode
            payload = jwt.decode(
                token,
                self.public_key,
                algorithms=["RS256"],
                issuer=self.expected_issuer,
                audience=self.expected_audience
            )
        except jwt.InvalidSignatureError:
            raise JWTValidationError("JWT signature verification failed")
        except jwt.ExpiredSignatureError:
            raise JWTValidationError("JWT token has expired")
        except jwt.InvalidIssuerError:
            raise JWTValidationError(f"Invalid issuer, expected {self.expected_issuer}")
        except jwt.InvalidAudienceError:
            raise JWTValidationError(f"Invalid audience, expected {self.expected_audience}")
        except jwt.DecodeError as e:
            raise JWTValidationError(f"JWT decode error: {str(e)}")
        
        # Validate nonce uniqueness (replay prevention)
        nonce = payload.get("jti")
        if not nonce:
            raise JWTValidationError("JWT missing 'jti' (nonce) claim")
        
        if nonce in self._used_nonces:
            raise JWTValidationError(f"JWT nonce {nonce} has already been used (replay attack detected)")
        
        self._used_nonces.add(nonce)
        
        # Validate timestamp freshness
        issued_at = payload.get("iat")
        if not issued_at:
            raise JWTValidationError("JWT missing 'iat' (issued at) claim")
        
        current_time = int(time.time())
        token_age = current_time - issued_at
        
        if token_age > self.freshness_window_seconds:
            raise JWTValidationError(
                f"JWT token is too old (age: {token_age}s, max: {self.freshness_window_seconds}s)"
            )
        
        if token_age < -60:  # Allow 60 seconds clock skew
            raise JWTValidationError("JWT token issued in the future")
        
        return payload
    
    def clear_nonce_cache(self):
        """Clear the nonce cache. Use with caution - only for testing or maintenance."""
        self._used_nonces.clear()
