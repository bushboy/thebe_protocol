"""Token lifetime enforcement module.

This module provides comprehensive token expiration validation for:
- JWT tokens (exp claim)
- ZT-AT tokens (expires_at field)
- DPoP proofs (iat timestamp freshness)

Requirements: 12.2, 12.3, 12.4, 12.5
"""

import time
from datetime import datetime, timezone
from typing import Dict, Any
from shared.schemas.models import ZeroTrustAuthorizationToken


class TokenExpiredError(Exception):
    """Raised when a token has expired."""
    pass


class TokenLifetimeValidator:
    """Validates token expiration across all token types."""
    
    @staticmethod
    def validate_jwt_expiration(jwt_payload: Dict[str, Any]) -> None:
        """
        Validate JWT token expiration (Requirement 12.2, 12.3)
        
        Args:
            jwt_payload: Decoded JWT payload containing 'exp' claim
            
        Raises:
            TokenExpiredError: If token has expired
        """
        exp = jwt_payload.get("exp")
        if not exp:
            raise TokenExpiredError("JWT missing 'exp' (expiration) claim")
        
        current_time = int(time.time())
        
        if current_time >= exp:
            exp_datetime = datetime.fromtimestamp(exp, tz=timezone.utc)
            raise TokenExpiredError(
                f"JWT token expired at {exp_datetime.isoformat()} "
                f"(current time: {datetime.fromtimestamp(current_time, tz=timezone.utc).isoformat()})"
            )
    
    @staticmethod
    def validate_zt_at_expiration(zt_at: ZeroTrustAuthorizationToken) -> None:
        """
        Validate ZT-AT token expiration (Requirement 12.4)
        
        Args:
            zt_at: Zero-Trust Authorization Token
            
        Raises:
            TokenExpiredError: If ZT-AT has expired
        """
        current_time = datetime.now(timezone.utc)
        
        # Ensure expires_at is timezone-aware
        expires_at = zt_at.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        
        if current_time >= expires_at:
            raise TokenExpiredError(
                f"ZT-AT expired at {expires_at.isoformat()} "
                f"(current time: {current_time.isoformat()})"
            )
    
    @staticmethod
    def validate_dpop_timestamp_freshness(
        dpop_payload: Dict[str, Any],
        freshness_window_seconds: int = 60
    ) -> None:
        """
        Validate DPoP proof timestamp freshness (Requirement 12.5)
        
        Args:
            dpop_payload: Decoded DPoP proof payload containing 'iat' claim
            freshness_window_seconds: Maximum age in seconds (default: 60)
            
        Raises:
            TokenExpiredError: If DPoP proof is too old
        """
        iat = dpop_payload.get("iat")
        if not iat:
            raise TokenExpiredError("DPoP proof missing 'iat' (issued at) claim")
        
        current_time = int(time.time())
        proof_age = current_time - iat
        
        if proof_age > freshness_window_seconds:
            raise TokenExpiredError(
                f"DPoP proof is too old (age: {proof_age}s, max: {freshness_window_seconds}s)"
            )
        
        # Allow 60 seconds clock skew for future timestamps
        if proof_age < -60:
            raise TokenExpiredError("DPoP proof issued in the future")
    
    @staticmethod
    def validate_all_tokens(
        jwt_payload: Dict[str, Any],
        zt_at: ZeroTrustAuthorizationToken,
        dpop_payload: Dict[str, Any],
        dpop_freshness_seconds: int = 60
    ) -> None:
        """
        Validate expiration for all token types (Requirements 12.2, 12.3, 12.4, 12.5)
        
        This is a convenience method that validates JWT, ZT-AT, and DPoP
        expiration in a single call.
        
        Args:
            jwt_payload: Decoded JWT payload
            zt_at: Zero-Trust Authorization Token
            dpop_payload: Decoded DPoP proof payload
            dpop_freshness_seconds: DPoP freshness window (default: 60)
            
        Raises:
            TokenExpiredError: If any token has expired
        """
        # Validate JWT expiration
        TokenLifetimeValidator.validate_jwt_expiration(jwt_payload)
        
        # Validate ZT-AT expiration
        TokenLifetimeValidator.validate_zt_at_expiration(zt_at)
        
        # Validate DPoP timestamp freshness
        TokenLifetimeValidator.validate_dpop_timestamp_freshness(
            dpop_payload,
            dpop_freshness_seconds
        )
