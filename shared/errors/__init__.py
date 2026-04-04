"""Shared error handling module for Zero-Trust Agentic Guardian.

This module provides standardized error handling middleware and exception classes
for all services in the system.

Requirements: 24.1, 24.2, 24.3, 24.4, 24.5
"""

from .exceptions import (
    AuthenticationError,
    AuthorizationError,
    ExecutionError,
    SystemError,
    InvalidCertificateError,
    InvalidTokenError,
    InvalidDPoPError,
    TokenExpiredError,
    PolicyDeniedError,
    IntentMisalignedError,
    InvalidSignatureError,
    ZTATReplayError,
    ProviderAPIError,
    ActionNotAllowedError,
    ServiceUnavailableError,
    InternalError,
    AuditIntegrityError
)

from .middleware import error_handling_middleware, setup_error_handlers

from .retry import (
    exponential_backoff_retry,
    retry_on_network_error,
    RetryContext
)

__all__ = [
    "AuthenticationError",
    "AuthorizationError",
    "ExecutionError",
    "SystemError",
    "InvalidCertificateError",
    "InvalidTokenError",
    "InvalidDPoPError",
    "TokenExpiredError",
    "PolicyDeniedError",
    "IntentMisalignedError",
    "InvalidSignatureError",
    "ZTATReplayError",
    "ProviderAPIError",
    "ActionNotAllowedError",
    "ServiceUnavailableError",
    "InternalError",
    "AuditIntegrityError",
    "error_handling_middleware",
    "setup_error_handlers",
    "exponential_backoff_retry",
    "retry_on_network_error",
    "RetryContext"
]
