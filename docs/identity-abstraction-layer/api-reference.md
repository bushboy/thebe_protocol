# Identity Abstraction Layer - API Reference

## Overview

This document provides comprehensive API reference for the Identity Abstraction Layer components, including interfaces, adapters, exceptions, configuration models, and utility functions.

## Table of Contents

- [IVaultProvider Interface](#ivaultprovider-interface)
- [Adapters](#adapters)
  - [Auth0Adapter](#auth0adapter)
  - [KeycloakAdapter](#keycloakadapter)
  - [AWSSecretsAdapter](#awssecretsadapter)
- [VaultFactory](#vaultfactory)
- [Exception Hierarchy](#exception-hierarchy)
- [Configuration Models](#configuration-models)
- [Token Models](#token-models)
- [Utility Functions](#utility-functions)

---

## IVaultProvider Interface

Abstract base class defining the contract for all identity provider adapters.

### Module

```python
from shared.identity.ivault_provider import IVaultProvider
```

### Class Definition

```python
class IVaultProvider(ABC):
    """Abstract interface for identity provider adapters."""
```

### Methods

#### get_token

Request a provider-specific token.

```python
@abstractmethod
async def get_token(
    self,
    rar: RichAuthorizationRequest,
    provider: str
) -> Dict[str, Any]:
    """Request a provider-specific token.
    
    Args:
        rar: Rich Authorization Request containing action details
        provider: Target provider (github, slack, google_workspace)
        
    Returns:
        Dictionary with token information:
        - access_token (str): Provider access token
        - token_type (str): Token type (usually "Bearer")
        - expires_in (int): Token expiration in seconds
        - scope (str): Granted scopes (space-separated)
        
    Raises:
        VaultProviderError: Network or provider errors
        VaultAuthenticationError: Invalid credentials
        VaultValidationError: Invalid RAR or response
        VaultTimeoutError: Request timeout
    """
```

**Example:**
```python
rar = RichAuthorizationRequest(
    type="https://ztag.dev/rar",
    actions=["repo:read", "repo:write"],
    locations=["https://github.com/org/repo"],
    purpose="Read and write repository contents",
    context={}
)

token = await provider.get_token(rar, "github")
print(token["access_token"])  # "gho_..."
```

#### exchange_token

Exchange an existing token for a new token with different scopes.

```python
@abstractmethod
async def exchange_token(
    self,
    existing_token: str,
    new_scopes: list[str],
    provider: str
) -> Dict[str, Any]:
    """Exchange an existing token for a new token with different scopes.
    
    Args:
        existing_token: Current access token
        new_scopes: Requested scopes for new token
        provider: Target provider
        
    Returns:
        Dictionary with new token information (same structure as get_token)
        
    Raises:
        VaultProviderError: Exchange failed
        VaultAuthenticationError: Invalid token
    """
```

**Example:**
```python
new_token = await provider.exchange_token(
    existing_token="gho_existing_token",
    new_scopes=["repo:read"],
    provider="github"
)
```

#### revoke_session

Revoke an active session.

```python
@abstractmethod
async def revoke_session(self, session_id: str) -> bool:
    """Revoke an active session.
    
    Args:
        session_id: Unique session identifier
        
    Returns:
        True if revocation succeeded, False otherwise
        
    Raises:
        VaultProviderError: Revocation failed
    """
```

**Example:**
```python
success = await provider.revoke_session("session_abc123")
if success:
    print("Session revoked successfully")
```

#### health_check

Check if the identity provider is accessible.

```python
@abstractmethod
async def health_check(self) -> bool:
    """Check if the identity provider is accessible.
    
    Returns:
        True if provider is healthy, False otherwise
    """
```

**Example:**
```python
is_healthy = await provider.health_check()
if not is_healthy:
    logger.error("Provider is unavailable")
```

#### get_provider_name

Get the identity provider type.

```python
@abstractmethod
def get_provider_name(self) -> str:
    """Get the identity provider type.
    
    Returns:
        Provider name (auth0, keycloak, aws_secrets)
    """
```

**Example:**
```python
provider_name = provider.get_provider_name()
print(f"Using provider: {provider_name}")  # "auth0"
```

---

## Adapters

### Auth0Adapter

Auth0 Token Vault adapter implementation.

#### Module

```python
from shared.identity.auth0_adapter import Auth0Adapter
```

#### Constructor

```python
def __init__(self, config: Dict[str, Any]):
    """Initialize Auth0 adapter.
    
    Args:
        config: Configuration dictionary with keys:
            - domain (str): Auth0 tenant domain
            - client_id (str): M2M application client ID
            - client_secret (str): M2M application client secret
            - token_vault_url (str, optional): Custom Token Vault URL
            - timeout (float, optional): Request timeout in seconds (default: 10.0)
    """
```

**Example:**
```python
adapter = Auth0Adapter({
    "domain": "tenant.auth0.com",
    "client_id": "client_id",
    "client_secret": "client_secret",
    "timeout": 15.0
})
```

#### Methods

All methods from `IVaultProvider` interface, plus:

##### _get_provider_audience

Map provider name to OAuth audience.

```python
def _get_provider_audience(self, provider: str) -> str:
    """Map provider to OAuth audience.
    
    Args:
        provider: Provider name (github, slack, google_workspace)
        
    Returns:
        OAuth audience URL
    """
```

**Audience Mappings:**
- `github` → `https://api.github.com`
- `slack` → `https://slack.com/api`
- `google_workspace` → `https://www.googleapis.com`

---

### KeycloakAdapter

Keycloak identity provider adapter implementation.

#### Module

```python
from shared.identity.keycloak_adapter import KeycloakAdapter
```

#### Constructor

```python
def __init__(self, config: Dict[str, Any]):
    """Initialize Keycloak adapter.
    
    Args:
        config: Configuration dictionary with keys:
            - server_url (str): Keycloak server URL
            - realm (str): Keycloak realm name
            - client_id (str): Client ID
            - client_secret (str): Client secret
            - scope_mapping (dict, optional): Dict mapping RAR actions to Keycloak scopes
            - timeout (float, optional): Request timeout in seconds (default: 10.0)
    """
```

**Example:**
```python
adapter = KeycloakAdapter({
    "server_url": "https://keycloak.example.com",
    "realm": "production",
    "client_id": "permission-broker",
    "client_secret": "secret",
    "scope_mapping": {
        "repo:read": "github:repo:read",
        "repo:write": ["github:repo:write", "github:repo:admin"]
    }
})
```

#### Methods

All methods from `IVaultProvider` interface, plus:

##### _map_scopes

Map RAR actions to Keycloak scopes.

```python
def _map_scopes(self, rar_actions: list[str], provider: str) -> list[str]:
    """Map RAR actions to Keycloak scopes using configured mapping.
    
    Args:
        rar_actions: List of RAR action strings
        provider: Target provider name
        
    Returns:
        List of Keycloak scope strings
    """
```

**Example:**
```python
scopes = adapter._map_scopes(["repo:read", "repo:write"], "github")
# Returns: ["github:repo:read", "github:repo:write", "github:repo:admin"]
```

---

### AWSSecretsAdapter

AWS Secrets Manager adapter implementation.

#### Module

```python
from shared.identity.aws_secrets_adapter import AWSSecretsAdapter
```

#### Constructor

```python
def __init__(self, config: Dict[str, Any]):
    """Initialize AWS Secrets Manager adapter.
    
    Args:
        config: Configuration dictionary with keys:
            - region (str): AWS region
            - secret_name_prefix (str): Prefix for secret names
            - session_table_name (str): DynamoDB table for session tracking
            - timeout (float, optional): Request timeout in seconds (default: 10.0)
    """
```

**Example:**
```python
adapter = AWSSecretsAdapter({
    "region": "us-east-1",
    "secret_name_prefix": "ztag/providers",
    "session_table_name": "ztag-sessions"
})
```

#### Methods

All methods from `IVaultProvider` interface, plus:

##### _generate_token

Generate provider token from credentials.

```python
def _generate_token(
    self,
    credentials: Dict[str, Any],
    provider: str
) -> str:
    """Generate provider token using retrieved credentials.
    
    Args:
        credentials: Provider credentials from Secrets Manager
        provider: Target provider name
        
    Returns:
        Generated access token
    """
```

##### _generate_session_id

Generate unique session identifier.

```python
def _generate_session_id(self) -> str:
    """Generate unique session ID.
    
    Returns:
        UUID-based session identifier
    """
```

##### _store_session

Store session metadata in DynamoDB.

```python
async def _store_session(
    self,
    session_id: str,
    provider: str,
    token_metadata: Dict[str, Any]
) -> None:
    """Store session information in DynamoDB.
    
    Args:
        session_id: Unique session identifier
        provider: Provider name
        token_metadata: Token metadata to store
    """
```

---

## VaultFactory

Factory class for creating identity provider adapters.

### Module

```python
from shared.identity.vault_factory import VaultFactory
```

### Class Methods

#### create_provider

Create and return the configured identity provider adapter.

```python
@classmethod
def create_provider(cls, config: IALConfig) -> IVaultProvider:
    """Create and return the configured identity provider adapter.
    
    Args:
        config: IAL configuration object
        
    Returns:
        Configured adapter instance (singleton)
        
    Raises:
        VaultConfigurationError: Invalid configuration
    """
```

**Example:**
```python
from shared.identity.config_parser import load_config

config = load_config("config/ial_config.json")
provider = VaultFactory.create_provider(config)

# Subsequent calls return same instance
provider2 = VaultFactory.create_provider(config)
assert provider is provider2  # True
```

#### reset

Reset factory singleton (for testing).

```python
@classmethod
def reset(cls) -> None:
    """Reset factory singleton instance.
    
    Used in tests to ensure clean state between test cases.
    """
```

**Example:**
```python
# In test teardown
VaultFactory.reset()
```

---

## Exception Hierarchy

### Module

```python
from shared.identity.exceptions import (
    VaultError,
    VaultProviderError,
    VaultAuthenticationError,
    VaultValidationError,
    VaultTimeoutError,
    VaultConfigurationError
)
```

### VaultError

Base exception for all IAL errors.

```python
class VaultError(Exception):
    """Base exception for Identity Abstraction Layer errors."""
```

### VaultProviderError

Network or provider errors.

```python
class VaultProviderError(VaultError):
    """Exception raised for network or provider errors."""
```

**When raised:**
- Network errors
- 5xx server errors
- Provider-specific errors
- Unexpected response formats

**Example:**
```python
try:
    token = await provider.get_token(rar, "github")
except VaultProviderError as e:
    logger.error(f"Provider error: {e}")
    return HTTPException(status_code=502, detail="Provider unavailable")
```

### VaultAuthenticationError

Authentication failures.

```python
class VaultAuthenticationError(VaultError):
    """Exception raised for authentication failures."""
```

**When raised:**
- 401 Unauthorized responses
- Invalid credentials
- Expired authentication tokens

**Example:**
```python
try:
    token = await provider.get_token(rar, "github")
except VaultAuthenticationError as e:
    logger.error(f"Authentication failed: {e}")
    return HTTPException(status_code=401, detail="Authentication failed")
```

### VaultValidationError

Validation errors.

```python
class VaultValidationError(VaultError):
    """Exception raised for validation errors."""
```

**When raised:**
- Invalid RAR format
- Missing required fields
- Invalid parameter values
- 400 Bad Request responses

**Example:**
```python
try:
    token = await provider.get_token(rar, "github")
except VaultValidationError as e:
    logger.error(f"Validation error: {e}")
    return HTTPException(status_code=400, detail="Invalid request")
```

### VaultTimeoutError

Timeout errors.

```python
class VaultTimeoutError(VaultError):
    """Exception raised for timeout errors."""
```

**When raised:**
- Request timeouts
- Connection timeouts
- Read timeouts

**Example:**
```python
try:
    token = await provider.get_token(rar, "github")
except VaultTimeoutError as e:
    logger.error(f"Request timeout: {e}")
    return HTTPException(status_code=504, detail="Gateway timeout")
```

### VaultConfigurationError

Configuration errors.

```python
class VaultConfigurationError(VaultError):
    """Exception raised for configuration errors."""
```

**When raised:**
- Missing required configuration
- Invalid configuration values
- Configuration validation failures

**Example:**
```python
try:
    provider = VaultFactory.create_provider(config)
except VaultConfigurationError as e:
    logger.error(f"Configuration error: {e}")
    sys.exit(1)
```

---

## Configuration Models

### Module

```python
from shared.identity.config_models import (
    IALConfig,
    Auth0Config,
    KeycloakConfig,
    AWSSecretsConfig
)
```

### IALConfig

Root configuration model.

```python
class IALConfig(BaseModel):
    """Root configuration for Identity Abstraction Layer."""
    
    identity_provider: str
    auth0_config: Optional[Auth0Config] = None
    keycloak_config: Optional[KeycloakConfig] = None
    aws_secrets_config: Optional[AWSSecretsConfig] = None
```

**Fields:**
- `identity_provider` (str): Provider type ("auth0", "keycloak", "aws_secrets")
- `auth0_config` (Auth0Config, optional): Auth0 configuration
- `keycloak_config` (KeycloakConfig, optional): Keycloak configuration
- `aws_secrets_config` (AWSSecretsConfig, optional): AWS configuration

**Example:**
```python
config = IALConfig(
    identity_provider="auth0",
    auth0_config=Auth0Config(
        domain="tenant.auth0.com",
        client_id="client_id",
        client_secret="secret"
    )
)
```

### Auth0Config

Auth0-specific configuration.

```python
class Auth0Config(BaseModel):
    """Configuration for Auth0 identity provider."""
    
    domain: str
    client_id: str
    client_secret: str
    token_vault_url: Optional[str] = None
    timeout: float = 10.0
```

**Fields:**
- `domain` (str, required): Auth0 tenant domain
- `client_id` (str, required): M2M application client ID
- `client_secret` (str, required): M2M application client secret
- `token_vault_url` (str, optional): Custom Token Vault URL
- `timeout` (float, optional): Request timeout (default: 10.0)

### KeycloakConfig

Keycloak-specific configuration.

```python
class KeycloakConfig(BaseModel):
    """Configuration for Keycloak identity provider."""
    
    server_url: str
    realm: str
    client_id: str
    client_secret: str
    scope_mapping: Dict[str, Union[str, List[str]]] = {}
    timeout: float = 10.0
```

**Fields:**
- `server_url` (str, required): Keycloak server URL
- `realm` (str, required): Keycloak realm name
- `client_id` (str, required): Client ID
- `client_secret` (str, required): Client secret
- `scope_mapping` (dict, optional): RAR action to scope mapping
- `timeout` (float, optional): Request timeout (default: 10.0)

### AWSSecretsConfig

AWS Secrets Manager-specific configuration.

```python
class AWSSecretsConfig(BaseModel):
    """Configuration for AWS Secrets Manager identity provider."""
    
    region: str
    secret_name_prefix: str
    session_table_name: str
    timeout: float = 10.0
```

**Fields:**
- `region` (str, required): AWS region
- `secret_name_prefix` (str, required): Prefix for secret names
- `session_table_name` (str, required): DynamoDB table name
- `timeout` (float, optional): Request timeout (default: 10.0)

---

## Token Models

### Module

```python
from shared.identity.token_models import ProviderToken
```

### ProviderToken

Normalized token response model.

```python
class ProviderToken(BaseModel):
    """Provider token response model."""
    
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    scope: Optional[str] = None
```

**Fields:**
- `access_token` (str, required): Provider access token
- `token_type` (str, optional): Token type (default: "Bearer")
- `expires_in` (int, required): Token expiration in seconds
- `scope` (str, optional): Granted scopes (space-separated)

**Example:**
```python
token = ProviderToken(
    access_token="gho_abc123",
    token_type="Bearer",
    expires_in=3600,
    scope="repo:read repo:write"
)
```

---

## Utility Functions

### Configuration Parser

#### Module

```python
from shared.identity.config_parser import load_config
```

#### load_config

Load and parse IAL configuration from file.

```python
def load_config(config_path: str) -> IALConfig:
    """Load and parse IAL configuration from file.
    
    Args:
        config_path: Path to configuration file (JSON or YAML)
        
    Returns:
        Parsed and validated IALConfig object
        
    Raises:
        FileNotFoundError: Configuration file not found
        VaultConfigurationError: Invalid configuration
    """
```

**Example:**
```python
config = load_config("config/ial_config.json")
print(config.identity_provider)  # "auth0"
```

### Configuration Pretty Printer

#### Module

```python
from shared.identity.config_printer import pretty_print_config
```

#### pretty_print_config

Format configuration as human-readable string.

```python
def pretty_print_config(config: IALConfig) -> str:
    """Format configuration as human-readable string.
    
    Args:
        config: IAL configuration object
        
    Returns:
        Formatted configuration string with sensitive values redacted
    """
```

**Example:**
```python
config = load_config("config/ial_config.json")
print(pretty_print_config(config))
```

**Output:**
```
Identity Abstraction Layer Configuration
=========================================

Active Provider: auth0

Auth0 Configuration:
  Domain: tenant.auth0.com
  Client ID: client_id
  Client Secret: ********** (redacted)
  Timeout: 10.0 seconds
```

### Token Pretty Printer

#### Module

```python
from shared.identity.token_printer import pretty_print_token
```

#### pretty_print_token

Format token as human-readable string.

```python
def pretty_print_token(token: Dict[str, Any]) -> str:
    """Format token as human-readable string.
    
    Args:
        token: Token dictionary
        
    Returns:
        Formatted token string with access_token redacted
    """
```

**Example:**
```python
token = await provider.get_token(rar, "github")
print(pretty_print_token(token))
```

**Output:**
```
Provider Token
==============

Access Token: gho_abc1... (redacted)
Token Type: Bearer
Expires In: 3600 seconds (1 hour)
Scopes:
  - repo:read
  - repo:write
```

### Retry Decorator

#### Module

```python
from shared.identity.retry import with_retry
```

#### with_retry

Decorator for adding retry logic with exponential backoff.

```python
def with_retry(
    max_attempts: int = 3,
    backoff_base: float = 1.0
):
    """Decorator for adding retry logic with exponential backoff.
    
    Args:
        max_attempts: Maximum number of retry attempts
        backoff_base: Base delay for exponential backoff in seconds
        
    Returns:
        Decorated function with retry logic
    """
```

**Example:**
```python
@with_retry(max_attempts=3, backoff_base=1.0)
async def get_token(self, rar, provider):
    # Implementation
    pass
```

---

## Usage Examples

### Complete Example: Token Request Flow

```python
import asyncio
from shared.identity.vault_factory import VaultFactory
from shared.identity.config_parser import load_config
from shared.schemas import RichAuthorizationRequest

async def main():
    # Load configuration
    config = load_config("config/ial_config.json")
    
    # Create provider
    provider = VaultFactory.create_provider(config)
    
    # Check health
    if not await provider.health_check():
        print("Provider is unavailable")
        return
    
    # Create RAR
    rar = RichAuthorizationRequest(
        type="https://ztag.dev/rar",
        actions=["repo:read", "repo:write"],
        locations=["https://github.com/org/repo"],
        purpose="Read and write repository contents",
        context={}
    )
    
    # Request token
    try:
        token = await provider.get_token(rar, "github")
        print(f"Token: {token['access_token'][:20]}...")
        print(f"Expires in: {token['expires_in']} seconds")
    except VaultAuthenticationError:
        print("Authentication failed")
    except VaultTimeoutError:
        print("Request timed out")
    except VaultProviderError as e:
        print(f"Provider error: {e}")

asyncio.run(main())
```

### Complete Example: Error Handling

```python
from shared.identity.exceptions import (
    VaultProviderError,
    VaultAuthenticationError,
    VaultValidationError,
    VaultTimeoutError
)

async def request_token_with_error_handling(provider, rar, provider_name):
    try:
        token = await provider.get_token(rar, provider_name)
        return token
    
    except VaultAuthenticationError as e:
        logger.error(f"Authentication failed: {e}")
        raise HTTPException(status_code=401, detail="Authentication failed")
    
    except VaultValidationError as e:
        logger.error(f"Validation error: {e}")
        raise HTTPException(status_code=400, detail="Invalid request")
    
    except VaultTimeoutError as e:
        logger.error(f"Request timeout: {e}")
        raise HTTPException(status_code=504, detail="Gateway timeout")
    
    except VaultProviderError as e:
        logger.error(f"Provider error: {e}")
        raise HTTPException(status_code=502, detail="Provider unavailable")
```

---

## See Also

- [Architecture Documentation](architecture.md) - Design and architecture details
- [Configuration Guide](configuration.md) - Configuration examples and options
- [Adapter Development Guide](adapter-development.md) - Creating custom adapters
- [Migration Guide](migration.md) - Migrating from TokenVaultClient
- [Troubleshooting Guide](troubleshooting.md) - Common issues and solutions
