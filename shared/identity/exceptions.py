"""Exception hierarchy for Identity Abstraction Layer.

This module defines a consistent exception hierarchy for all identity provider
adapters, enabling uniform error handling across different providers.
"""


class VaultError(Exception):
    """Base exception for all Identity Abstraction Layer errors.
    
    All IAL-specific exceptions inherit from this base class, allowing
    callers to catch all IAL errors with a single except clause.
    """
    pass


class VaultProviderError(VaultError):
    """Exception raised for network or provider-side errors.
    
    This exception is raised when:
    - Network connectivity issues occur
    - The identity provider returns a 5xx server error
    - The provider API is temporarily unavailable
    - Other transient provider-side failures occur
    
    This error typically indicates a retryable condition.
    """
    pass


class VaultAuthenticationError(VaultError):
    """Exception raised for authentication failures.
    
    This exception is raised when:
    - Client credentials are invalid or expired
    - The identity provider returns a 401 Unauthorized response
    - Authentication tokens are rejected by the provider
    
    This error typically indicates a configuration issue that requires
    manual intervention.
    """
    pass


class VaultValidationError(VaultError):
    """Exception raised for validation errors.
    
    This exception is raised when:
    - Input parameters (RAR, scopes) are invalid or malformed
    - Provider responses are missing required fields
    - Response data types don't match expected schema
    - Configuration values fail validation
    
    This error typically indicates a programming error or data quality issue.
    """
    pass


class VaultTimeoutError(VaultError):
    """Exception raised when requests exceed configured timeout.
    
    This exception is raised when:
    - HTTP requests to the identity provider time out
    - The provider takes longer than the configured timeout to respond
    
    This error may indicate network issues or provider performance problems.
    """
    pass


class VaultConfigurationError(VaultError):
    """Exception raised for configuration errors.
    
    This exception is raised when:
    - Required configuration parameters are missing
    - Configuration values are invalid or malformed
    - The specified identity provider type is not recognized
    - Provider-specific configuration is incomplete
    
    This error typically indicates a deployment or configuration issue.
    """
    pass
