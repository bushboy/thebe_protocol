# Identity Abstraction Layer - Adapter Development Guide

## Overview

This guide explains how to implement custom adapters for the Identity Abstraction Layer. By following these guidelines, you can integrate any identity provider into the Zero-Trust Agentic Guardian system.

## Prerequisites

Before developing a custom adapter, ensure you understand:

- The IVaultProvider interface contract
- Rich Authorization Request (RAR) format
- Provider-specific authentication protocols
- Exception handling requirements
- Testing requirements

## IVaultProvider Interface

All adapters must implement the `IVaultProvider` abstract interface:

```python
from abc import ABC, abstractmethod
from typing import Dict, Any
from shared.schemas import RichAuthorizationRequest


class IVaultProvider(ABC):
    """Abstract interface for identity provider adapters."""
    
    @abstractmethod
    async def get_token(
        self,
        rar: RichAuthorizationRequest,
        provider: str
    ) -> Dict[str, Any]:
        """Request a provider-specific token."""
        pass
    
    @abstractmethod
    async def exchange_token(
        self,
        existing_token: str,
        new_scopes: list[str],
        provider: str
    ) -> Dict[str, Any]:
        """Exchange an existing token for a new token with different scopes."""
        pass
    
    @abstractmethod
    async def revoke_session(self, session_id: str) -> bool:
        """Revoke an active session."""
        pass
    
    @abstractmethod
    async def health_check(self) -> bool:
        """Check if the identity provider is accessible."""
        pass
    
    @abstractmethod
    def get_provider_name(self) -> str:
        """Get the identity provider type."""
        pass
```

## Step-by-Step Adapter Implementation

### Step 1: Create Adapter Class

Create a new file in `shared/identity/` for your adapter:

```python
# shared/identity/custom_adapter.py

import httpx
from typing import Dict, Any
from .ivault_provider import IVaultProvider
from .exceptions import (
    VaultProviderError,
    VaultAuthenticationError,
    VaultValidationError,
    VaultTimeoutError
)
from shared.schemas import RichAuthorizationRequest
from shared.logging import JSONLogger


logger = JSONLogger(__name__)


class CustomAdapter(IVaultProvider):
    """Custom identity provider adapter implementation."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize custom adapter.
        
        Args:
            config: Configuration dictionary with provider-specific keys
        """
        # Extract and validate configuration
        self.api_url = config["api_url"]
        self.client_id = config["client_id"]
        self.client_secret = config["client_secret"]
        self.timeout = config.get("timeout", 10.0)
        
        # Initialize HTTP client or SDK
        self.client = httpx.AsyncClient(timeout=self.timeout)
        
        logger.info(f"Initialized CustomAdapter for API: {self.api_url}")
```

### Step 2: Implement get_token Method

The `get_token` method is the core functionality - it requests a provider token:

```python
    async def get_token(
        self,
        rar: RichAuthorizationRequest,
        provider: str
    ) -> Dict[str, Any]:
        """Request provider token from custom identity provider.
        
        Args:
            rar: Rich Authorization Request with action details
            provider: Target provider (github, slack, etc.)
            
        Returns:
            Dictionary with token information:
            - access_token: Provider access token (required)
            - token_type: Token type, usually "Bearer" (required)
            - expires_in: Token expiration in seconds (required)
            - scope: Granted scopes (optional)
            
        Raises:
            VaultProviderError: Network or provider errors
            VaultAuthenticationError: Invalid credentials
            VaultValidationError: Invalid RAR or response
            VaultTimeoutError: Request timeout
        """
        logger.info(f"Requesting token for provider: {provider}")
        
        # Step 1: Construct provider-specific token request
        token_request = self._build_token_request(rar, provider)
        
        # Step 2: Make HTTP request to identity provider
        try:
            response = await self.client.post(
                f"{self.api_url}/token",
                json=token_request,
                headers={"Content-Type": "application/json"}
            )
            
            # Step 3: Handle error responses
            if response.status_code == 401:
                raise VaultAuthenticationError(
                    "Authentication failed - check credentials"
                )
            
            if response.status_code >= 400:
                error_detail = response.json() if response.text else {}
                raise VaultProviderError(
                    f"Provider returned {response.status_code}: "
                    f"{error_detail.get('error', 'Unknown error')}"
                )
            
            # Step 4: Parse and validate response
            token_data = response.json()
            
            # Step 5: Return normalized token structure
            return {
                "access_token": token_data["access_token"],
                "token_type": token_data.get("token_type", "Bearer"),
                "expires_in": token_data.get("expires_in", 3600),
                "scope": token_data.get("scope", " ".join(rar.actions))
            }
        
        except httpx.TimeoutException:
            raise VaultTimeoutError(f"Request timed out after {self.timeout}s")
        except httpx.RequestError as e:
            raise VaultProviderError(f"Request failed: {str(e)}")
    
    def _build_token_request(
        self,
        rar: RichAuthorizationRequest,
        provider: str
    ) -> Dict[str, Any]:
        """Build provider-specific token request.
        
        This method should translate the RAR into the format
        expected by your identity provider.
        """
        return {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "client_credentials",
            "scope": " ".join(rar.actions),
            "provider": provider
        }
```

### Step 3: Implement exchange_token Method

The `exchange_token` method exchanges an existing token for a new one:

```python
    async def exchange_token(
        self,
        existing_token: str,
        new_scopes: list[str],
        provider: str
    ) -> Dict[str, Any]:
        """Exchange token for different scopes.
        
        Args:
            existing_token: Current access token
            new_scopes: Requested scopes for new token
            provider: Target provider
            
        Returns:
            Dictionary with new token information
            
        Raises:
            VaultProviderError: Exchange failed
            VaultAuthenticationError: Invalid token
        """
        exchange_request = {
            "grant_type": "token_exchange",
            "subject_token": existing_token,
            "scope": " ".join(new_scopes)
        }
        
        try:
            response = await self.client.post(
                f"{self.api_url}/token/exchange",
                json=exchange_request
            )
            
            if response.status_code == 401:
                raise VaultAuthenticationError("Token exchange failed - invalid token")
            
            if response.status_code != 200:
                raise VaultProviderError(f"Token exchange failed: {response.status_code}")
            
            return response.json()
        
        except httpx.TimeoutException:
            raise VaultTimeoutError("Token exchange timed out")
```

### Step 4: Implement revoke_session Method

The `revoke_session` method revokes an active session:

```python
    async def revoke_session(self, session_id: str) -> bool:
        """Revoke an active session.
        
        Args:
            session_id: Unique session identifier
            
        Returns:
            True if revocation succeeded, False otherwise
        """
        try:
            response = await self.client.post(
                f"{self.api_url}/revoke",
                json={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "token": session_id
                }
            )
            
            return response.status_code == 200
        
        except Exception as e:
            logger.error(f"Session revocation failed: {str(e)}")
            return False
```

### Step 5: Implement health_check Method

The `health_check` method verifies provider availability:

```python
    async def health_check(self) -> bool:
        """Check if the identity provider is accessible.
        
        Returns:
            True if provider is healthy, False otherwise
        """
        try:
            response = await self.client.get(
                f"{self.api_url}/health",
                timeout=5.0
            )
            return response.status_code == 200
        except Exception:
            return False
```

### Step 6: Implement get_provider_name Method

The `get_provider_name` method returns the provider identifier:

```python
    def get_provider_name(self) -> str:
        """Get the identity provider type.
        
        Returns:
            Provider name (used in logs and metrics)
        """
        return "custom"
```

## Exception Handling Requirements

### Exception Hierarchy

All adapters must use the standard exception hierarchy:

```python
from shared.identity.exceptions import (
    VaultError,                    # Base exception
    VaultProviderError,            # Network/provider errors
    VaultAuthenticationError,      # Authentication failures
    VaultValidationError,          # Validation errors
    VaultTimeoutError,             # Timeout errors
    VaultConfigurationError        # Configuration errors
)
```

### When to Raise Each Exception

**VaultAuthenticationError:**
- 401 Unauthorized responses
- Invalid credentials
- Expired authentication tokens

**VaultProviderError:**
- Network errors
- 5xx server errors
- Provider-specific errors
- Unexpected response formats

**VaultValidationError:**
- Invalid RAR format
- Missing required fields
- Invalid parameter values
- 400 Bad Request responses

**VaultTimeoutError:**
- Request timeouts
- Connection timeouts
- Read timeouts

**VaultConfigurationError:**
- Missing required configuration
- Invalid configuration values
- Configuration validation failures

### Exception Handling Example

```python
try:
    response = await self.client.post(url, json=data)
    
    if response.status_code == 400:
        raise VaultValidationError("Invalid request parameters")
    elif response.status_code == 401:
        raise VaultAuthenticationError("Authentication failed")
    elif response.status_code >= 500:
        raise VaultProviderError(f"Provider error: {response.status_code}")
    
    return response.json()

except httpx.TimeoutException:
    raise VaultTimeoutError("Request timed out")
except httpx.RequestError as e:
    raise VaultProviderError(f"Network error: {str(e)}")
```

## Configuration Model

### Create Pydantic Configuration Model

Define a Pydantic model for your adapter's configuration:

```python
# shared/identity/config_models.py

from pydantic import BaseModel, Field, validator


class CustomConfig(BaseModel):
    """Configuration for Custom identity provider."""
    
    api_url: str = Field(..., description="Custom API URL")
    client_id: str = Field(..., description="Client ID")
    client_secret: str = Field(..., description="Client secret")
    timeout: float = Field(10.0, description="Request timeout in seconds")
    
    @validator('api_url')
    def validate_api_url(cls, v):
        if not v.startswith('https://'):
            raise ValueError('API URL must use HTTPS')
        return v.rstrip('/')
    
    @validator('timeout')
    def validate_timeout(cls, v):
        if v <= 0:
            raise ValueError('Timeout must be positive')
        return v
```

### Update Root Configuration Model

Add your configuration to the root IAL configuration:

```python
class IALConfig(BaseModel):
    """Root configuration for Identity Abstraction Layer."""
    
    identity_provider: str = Field(
        ...,
        description="Identity provider type"
    )
    auth0_config: Optional[Auth0Config] = None
    keycloak_config: Optional[KeycloakConfig] = None
    aws_secrets_config: Optional[AWSSecretsConfig] = None
    custom_config: Optional[CustomConfig] = None  # Add your config
    
    @validator('identity_provider')
    def validate_provider(cls, v):
        allowed = ['auth0', 'keycloak', 'aws_secrets', 'custom']
        if v not in allowed:
            raise ValueError(f'Invalid provider. Must be one of: {allowed}')
        return v
```

## Integrating with VaultFactory

### Update VaultFactory

Add your adapter to the VaultFactory:

```python
# shared/identity/vault_factory.py

from .custom_adapter import CustomAdapter


class VaultFactory:
    """Factory for creating identity provider adapters."""
    
    _instance = None
    
    @classmethod
    def create_provider(cls, config: IALConfig) -> IVaultProvider:
        """Create and return the configured identity provider adapter."""
        
        if cls._instance is not None:
            return cls._instance
        
        provider_type = config.identity_provider
        
        if provider_type == "auth0":
            cls._instance = cls._create_auth0_adapter(config.auth0_config)
        elif provider_type == "keycloak":
            cls._instance = cls._create_keycloak_adapter(config.keycloak_config)
        elif provider_type == "aws_secrets":
            cls._instance = cls._create_aws_secrets_adapter(config.aws_secrets_config)
        elif provider_type == "custom":
            cls._instance = cls._create_custom_adapter(config.custom_config)
        else:
            raise VaultConfigurationError(
                f"Unsupported identity provider: {provider_type}"
            )
        
        return cls._instance
    
    @staticmethod
    def _create_custom_adapter(config: CustomConfig) -> CustomAdapter:
        """Create Custom adapter instance."""
        if config is None:
            raise VaultConfigurationError(
                "custom_config is required when identity_provider is 'custom'"
            )
        
        return CustomAdapter(config.dict())
```

## Testing Requirements

### Unit Tests

Create unit tests for your adapter in `tests/unit/test_custom_adapter.py`:

```python
import pytest
from unittest.mock import AsyncMock, patch
from shared.identity.custom_adapter import CustomAdapter
from shared.identity.exceptions import (
    VaultAuthenticationError,
    VaultProviderError,
    VaultTimeoutError
)


@pytest.fixture
def custom_config():
    return {
        "api_url": "https://custom.example.com",
        "client_id": "test_client",
        "client_secret": "test_secret",
        "timeout": 10.0
    }


@pytest.fixture
def custom_adapter(custom_config):
    return CustomAdapter(custom_config)


@pytest.mark.asyncio
async def test_get_token_success(custom_adapter):
    """Test successful token retrieval."""
    # Mock HTTP response
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "access_token": "test_token",
        "token_type": "Bearer",
        "expires_in": 3600
    }
    
    with patch.object(custom_adapter.client, 'post', return_value=mock_response):
        rar = create_test_rar()
        result = await custom_adapter.get_token(rar, "github")
        
        assert result["access_token"] == "test_token"
        assert result["token_type"] == "Bearer"
        assert result["expires_in"] == 3600


@pytest.mark.asyncio
async def test_get_token_authentication_error(custom_adapter):
    """Test authentication error handling."""
    mock_response = AsyncMock()
    mock_response.status_code = 401
    
    with patch.object(custom_adapter.client, 'post', return_value=mock_response):
        rar = create_test_rar()
        
        with pytest.raises(VaultAuthenticationError):
            await custom_adapter.get_token(rar, "github")


@pytest.mark.asyncio
async def test_get_token_timeout(custom_adapter):
    """Test timeout handling."""
    with patch.object(
        custom_adapter.client,
        'post',
        side_effect=httpx.TimeoutException("Timeout")
    ):
        rar = create_test_rar()
        
        with pytest.raises(VaultTimeoutError):
            await custom_adapter.get_token(rar, "github")
```

### Property Tests

Create property tests in `tests/property/test_custom_adapter_properties.py`:

```python
from hypothesis import given, strategies as st
from shared.identity.custom_adapter import CustomAdapter


@given(
    actions=st.lists(st.text(min_size=1), min_size=1, max_size=5),
    provider=st.sampled_from(['github', 'slack', 'google_workspace'])
)
@pytest.mark.asyncio
async def test_get_token_returns_valid_structure(actions, provider):
    """Property: get_token always returns valid token structure."""
    adapter = CustomAdapter(test_config())
    rar = create_rar_with_actions(actions)
    
    # Mock successful response
    with patch_successful_response():
        result = await adapter.get_token(rar, provider)
        
        # Verify required fields
        assert "access_token" in result
        assert "token_type" in result
        assert "expires_in" in result
        
        # Verify types
        assert isinstance(result["access_token"], str)
        assert isinstance(result["token_type"], str)
        assert isinstance(result["expires_in"], int)
        assert result["expires_in"] > 0
```

### Integration Tests

Create integration tests in `tests/integration/test_custom_adapter.py`:

```python
import pytest
from shared.identity.custom_adapter import CustomAdapter


@pytest.mark.integration
@pytest.mark.asyncio
async def test_custom_adapter_real_provider():
    """Test adapter with real Custom provider."""
    config = {
        "api_url": "https://test.custom.example.com",
        "client_id": os.getenv("CUSTOM_CLIENT_ID"),
        "client_secret": os.getenv("CUSTOM_CLIENT_SECRET"),
        "timeout": 30.0
    }
    
    adapter = CustomAdapter(config)
    
    # Test health check
    is_healthy = await adapter.health_check()
    assert is_healthy, "Provider should be accessible"
    
    # Test token retrieval
    rar = create_test_rar()
    token = await adapter.get_token(rar, "github")
    
    assert token["access_token"]
    assert token["expires_in"] > 0
```

### Compliance Tests

Your adapter must pass the adapter compliance test suite:

```python
# tests/property/test_adapter_compliance.py

@pytest.mark.parametrize("adapter_class", [
    Auth0Adapter,
    KeycloakAdapter,
    AWSSecretsAdapter,
    CustomAdapter  # Add your adapter
])
def test_adapter_implements_interface(adapter_class):
    """Verify adapter implements all interface methods."""
    assert issubclass(adapter_class, IVaultProvider)
    
    required_methods = [
        'get_token',
        'exchange_token',
        'revoke_session',
        'health_check',
        'get_provider_name'
    ]
    
    for method in required_methods:
        assert hasattr(adapter_class, method)
```

## Best Practices

### 1. Structured Logging

Use JSONLogger for all log messages:

```python
from shared.logging import JSONLogger

logger = JSONLogger(__name__)

logger.info("Token request initiated", extra={
    "provider": provider,
    "actions": rar.actions
})

logger.error("Token request failed", extra={
    "provider": provider,
    "status_code": response.status_code,
    "error": error_message
})
```

### 2. Metrics Collection

Integrate Prometheus metrics:

```python
from shared.identity.metrics import (
    token_request_duration,
    token_request_counter
)

start_time = time.time()
try:
    result = await self._make_request()
    token_request_counter.labels(
        provider_type=self.get_provider_name(),
        operation="get_token",
        status="success"
    ).inc()
    return result
finally:
    duration = time.time() - start_time
    token_request_duration.labels(
        provider_type=self.get_provider_name(),
        operation="get_token"
    ).observe(duration)
```

### 3. Retry Logic

Apply retry decorator for transient failures:

```python
from shared.identity.retry import with_retry

class CustomAdapter(IVaultProvider):
    
    @with_retry(max_attempts=3, backoff_base=1.0)
    async def get_token(self, rar, provider):
        # Implementation
        pass
```

### 4. Configuration Validation

Validate configuration in `__init__`:

```python
def __init__(self, config: Dict[str, Any]):
    required_fields = ["api_url", "client_id", "client_secret"]
    
    for field in required_fields:
        if field not in config:
            raise VaultConfigurationError(
                f"Missing required field: {field}"
            )
    
    self.api_url = config["api_url"]
    # ... rest of initialization
```

### 5. Resource Cleanup

Implement proper cleanup:

```python
async def __aenter__(self):
    return self

async def __aexit__(self, exc_type, exc_val, exc_tb):
    await self.client.aclose()
```

## Complete Example

See `shared/identity/auth0_adapter.py` for a complete, production-ready adapter implementation.

## Checklist

Before submitting your adapter, ensure:

- [ ] Implements all IVaultProvider methods
- [ ] Raises appropriate exceptions
- [ ] Includes configuration model with validation
- [ ] Integrated into VaultFactory
- [ ] Has comprehensive unit tests
- [ ] Has property tests
- [ ] Has integration tests (if possible)
- [ ] Passes adapter compliance tests
- [ ] Uses structured logging
- [ ] Collects metrics
- [ ] Implements retry logic
- [ ] Validates configuration
- [ ] Handles resource cleanup
- [ ] Documentation updated

## Next Steps

- Review [Architecture Documentation](architecture.md) for design context
- See [Configuration Guide](configuration.md) for configuration format
- Check [API Reference](api-reference.md) for interface details
- Read [Troubleshooting Guide](troubleshooting.md) for debugging tips
