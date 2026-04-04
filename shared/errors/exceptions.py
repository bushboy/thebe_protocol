"""Custom exception classes for Zero-Trust Agentic Guardian.

This module defines all custom exceptions used throughout the system,
organized by error category.

Requirements: 24.1, 24.2, 24.3, 24.4, 24.5
"""

from typing import Optional, Dict, Any


class BaseServiceError(Exception):
    """Base exception for all service errors."""
    
    def __init__(
        self,
        message: str,
        error_code: str,
        status_code: int,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.status_code = status_code
        self.details = details or {}


# Authentication Errors (401)
class AuthenticationError(BaseServiceError):
    """Base class for authentication errors."""
    
    def __init__(self, message: str, error_code: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code, 401, details)


class InvalidCertificateError(AuthenticationError):
    """Raised when mTLS certificate validation fails."""
    
    def __init__(self, message: str = "Client certificate not signed by trusted CA", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "invalid_certificate", details)


class InvalidTokenError(AuthenticationError):
    """Raised when JWT token validation fails."""
    
    def __init__(self, message: str = "JWT signature verification failed", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "invalid_token", details)


class InvalidDPoPError(AuthenticationError):
    """Raised when DPoP proof validation fails."""
    
    def __init__(self, message: str = "DPoP proof does not match request", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "invalid_dpop", details)


class TokenExpiredError(AuthenticationError):
    """Raised when a token has expired."""
    
    def __init__(self, message: str = "Token has expired", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "token_expired", details)


# Authorization Errors (403)
class AuthorizationError(BaseServiceError):
    """Base class for authorization errors."""
    
    def __init__(self, message: str, error_code: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code, 403, details)


class PolicyDeniedError(AuthorizationError):
    """Raised when OPA policy denies an action."""
    
    def __init__(self, message: str, policy_name: str, details: Optional[Dict[str, Any]] = None):
        details = details or {}
        details["policy"] = policy_name
        super().__init__(message, "policy_denied", details)


class IntentMisalignedError(AuthorizationError):
    """Raised when action does not match original intent."""
    
    def __init__(self, message: str = "Action does not match original intent", similarity_score: Optional[float] = None, details: Optional[Dict[str, Any]] = None):
        details = details or {}
        if similarity_score is not None:
            details["similarity_score"] = similarity_score
        super().__init__(message, "intent_misaligned", details)


class InvalidSignatureError(AuthorizationError):
    """Raised when signature verification fails."""
    
    def __init__(self, message: str = "Signature verification failed", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "invalid_signature", details)


class ActionNotAllowedError(AuthorizationError):
    """Raised when action is not in ZT-AT allowed actions list."""
    
    def __init__(self, message: str = "Action not in ZT-AT allowed actions list", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "action_not_allowed", details)


# Execution Errors (409, 502)
class ExecutionError(BaseServiceError):
    """Base class for execution errors."""
    
    def __init__(self, message: str, error_code: str, status_code: int, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code, status_code, details)


class ZTATReplayError(ExecutionError):
    """Raised when ZT-AT has already been used."""
    
    def __init__(self, message: str = "ZT-AT has already been used for execution", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "token_reused", 409, details)


class ProviderAPIError(ExecutionError):
    """Raised when provider API call fails."""
    
    def __init__(self, provider: str, error_message: str, details: Optional[Dict[str, Any]] = None):
        message = f"{provider} API returned error: {error_message}"
        details = details or {}
        details["provider"] = provider
        super().__init__(message, "provider_error", 502, details)


# System Errors (500, 503)
class SystemError(BaseServiceError):
    """Base class for system errors."""
    
    def __init__(self, message: str, error_code: str, status_code: int, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code, status_code, details)


class ServiceUnavailableError(SystemError):
    """Raised when a downstream service is unavailable."""
    
    def __init__(self, service_name: str, details: Optional[Dict[str, Any]] = None):
        message = f"{service_name} is currently unavailable"
        details = details or {}
        details["service"] = service_name
        super().__init__(message, "service_unavailable", 503, details)


class InternalError(SystemError):
    """Raised for unexpected internal errors."""
    
    def __init__(self, message: str = "An unexpected error occurred", correlation_id: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        details = details or {}
        if correlation_id:
            details["correlation_id"] = correlation_id
        super().__init__(message, "internal_error", 500, details)


class AuditIntegrityError(SystemError):
    """Raised when audit log hash chain verification fails."""
    
    def __init__(self, message: str = "Hash chain verification failed", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "audit_integrity_error", 500, details)
