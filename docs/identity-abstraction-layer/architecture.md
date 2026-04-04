# Identity Abstraction Layer - Architecture

## Overview

The Identity Abstraction Layer (IAL) decouples the Zero-Trust Agentic Guardian system from specific Identity Provider (IdP) implementations. This architectural decision transforms the system into Identity-Agnostic Middleware, allowing organizations to choose their preferred identity provider without modifying core authorization logic.

## Design Principles

### 1. Interface Segregation
The `IVaultProvider` interface defines a single responsibility: token operations. Each method has a clear purpose and minimal dependencies.

### 2. Dependency Inversion
The Permission Broker depends on the `IVaultProvider` abstraction, not concrete implementations. This allows new adapters to be added without modifying the broker.

### 3. Open/Closed Principle
The system is open for extension (new adapters) but closed for modification (core logic remains unchanged).

### 4. Backward Compatibility
Existing Auth0 deployments continue working without changes. The Auth0Adapter preserves all TokenVaultClient functionality.

### 5. Configuration-Driven
Provider selection is a configuration decision, not a code change. The VaultFactory reads configuration and instantiates the appropriate adapter.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Zero-Trust Agentic Guardian                   │
│                                                                   │
│  ┌──────────┐    ┌────────────┐    ┌──────────────────────┐    │
│  │ Planner  │───▶│   Safety   │───▶│  Permission Broker   │    │
│  │ Service  │    │   Agent    │    │                      │    │
│  └──────────┘    └────────────┘    │  ┌────────────────┐  │    │
│                                     │  │ VaultFactory   │  │    │
│                                     │  └────────┬───────┘  │    │
│                                     │           │          │    │
│                                     │           ▼          │    │
│                                     │  ┌────────────────┐  │    │
│                                     │  │ IVaultProvider │  │    │
│                                     │  │   Interface    │  │    │
│                                     │  └────────┬───────┘  │    │
│                                     └───────────┼──────────┘    │
│                                                 │                │
└─────────────────────────────────────────────────┼────────────────┘
                                                  │
                    ┌─────────────────────────────┼─────────────────────────┐
                    │                             │                         │
                    ▼                             ▼                         ▼
          ┌──────────────────┐        ┌──────────────────┐      ┌──────────────────┐
          │  Auth0Adapter    │        │ KeycloakAdapter  │      │ AWSSecretsAdapter│
          │                  │        │                  │      │                  │
          │ - Token Vault    │        │ - Client Creds   │      │ - Secrets Mgr    │
          │ - RAR Support    │        │ - Token Exchange │      │ - DynamoDB       │
          └────────┬─────────┘        └────────┬─────────┘      └────────┬─────────┘
                   │                           │                         │
                   ▼                           ▼                         ▼
          ┌──────────────────┐        ┌──────────────────┐      ┌──────────────────┐
          │   Auth0 Cloud    │        │   Keycloak       │      │   AWS Services   │
          │   Token Vault    │        │   Server         │      │   Secrets Mgr    │
          └──────────────────┘        └──────────────────┘      └──────────────────┘
```

## Component Architecture

### Core Components

#### IVaultProvider Interface
Abstract base class defining the contract for all identity provider adapters.

**Responsibilities:**
- Define standard methods for token operations
- Ensure consistent error handling across adapters
- Provide type hints for IDE support

**Methods:**
- `get_token(rar, provider)` - Request provider-specific token
- `exchange_token(existing_token, new_scopes, provider)` - Exchange token for different scopes
- `revoke_session(session_id)` - Revoke active session
- `health_check()` - Check provider availability
- `get_provider_name()` - Return provider type identifier

#### VaultFactory
Factory class that instantiates the correct adapter based on configuration.

**Responsibilities:**
- Read and validate configuration
- Instantiate appropriate adapter
- Provide singleton pattern for adapter lifecycle
- Validate configuration completeness

**Design Pattern:** Factory Method + Singleton

**Configuration Flow:**
1. Read `identity_provider` field from configuration
2. Validate provider-specific configuration section exists
3. Validate required fields are present
4. Instantiate adapter with validated configuration
5. Return adapter instance (reuse existing if already created)

#### Auth0Adapter
Refactored implementation of TokenVaultClient implementing IVaultProvider.

**Responsibilities:**
- Integrate with Auth0 Token Vault API
- Construct RAR-compliant token requests
- Handle Auth0-specific error responses
- Map provider names to OAuth audiences

**Key Features:**
- Preserves all existing TokenVaultClient functionality
- Supports authorization_details parameter for RAR
- Handles timeout and retry logic
- Maps 401/4xx/5xx responses to appropriate exceptions

#### KeycloakAdapter
New implementation for Keycloak identity provider.

**Responsibilities:**
- Authenticate using client credentials flow
- Map RAR actions to Keycloak scopes
- Support realm-based multi-tenancy
- Handle Keycloak-specific protocols

**Key Features:**
- Configurable scope mapping dictionary
- Support for multiple scopes per action
- Realm URL construction
- Token exchange using Keycloak protocol

#### AWSSecretsAdapter
New implementation for AWS Secrets Manager credential storage.

**Responsibilities:**
- Retrieve credentials from Secrets Manager
- Generate provider tokens from credentials
- Track session revocation in DynamoDB
- Support IAM role authentication

**Key Features:**
- boto3 integration for AWS APIs
- Session tracking with unique session IDs
- DynamoDB-based revocation records
- Support for multiple AWS authentication methods

### Supporting Components

#### Exception Hierarchy
Unified exception hierarchy for consistent error handling.

```
VaultError (base)
├── VaultProviderError (network/provider errors)
├── VaultAuthenticationError (authentication failures)
├── VaultValidationError (validation errors)
├── VaultTimeoutError (timeout errors)
└── VaultConfigurationError (configuration errors)
```

#### Configuration Models
Pydantic models for configuration validation.

- `IALConfig` - Root configuration with provider selection
- `Auth0Config` - Auth0-specific configuration
- `KeycloakConfig` - Keycloak-specific configuration
- `AWSSecretsConfig` - AWS-specific configuration

#### Token Models
Pydantic models for token response parsing.

- `ProviderToken` - Normalized token response structure

## Integration with Permission Broker

### Before IAL
```python
# Direct coupling to Auth0
token_vault_client = TokenVaultClient(
    domain=config.auth0_domain,
    client_id=config.client_id,
    client_secret=config.client_secret
)

provider_token = await token_vault_client.request_provider_token(rar, provider)
```

### After IAL
```python
# Decoupled through abstraction
vault_provider = VaultFactory.create_provider(config)

provider_token = await vault_provider.get_token(rar, provider)
```

### Authorization Flow Integration

1. **Intent Validation**: Permission Broker validates Intent Signature from Planner
2. **Policy Validation**: Permission Broker validates Policy Approval from Safety Agent
3. **RAR Construction**: Permission Broker constructs Rich Authorization Request
4. **Adapter Selection**: VaultFactory provides configured adapter
5. **Token Request**: Adapter retrieves provider token using provider-specific protocol
6. **ZT-AT Construction**: Permission Broker constructs Zero-Trust Authorization Token
7. **Token Delivery**: Executor Agent receives ZT-AT + provider token

## Design Patterns

### Adapter Pattern
The IAL uses the Adapter pattern to convert provider-specific APIs into a uniform interface.

**Problem:** Different identity providers have incompatible APIs
**Solution:** Create adapter classes that implement a common interface

**Benefits:**
- Uniform interface for all providers
- Easy to add new providers
- Existing code doesn't need changes

### Factory Method Pattern
The VaultFactory uses the Factory Method pattern to instantiate adapters.

**Problem:** Client code shouldn't know which concrete class to instantiate
**Solution:** Factory method reads configuration and returns appropriate instance

**Benefits:**
- Configuration-driven instantiation
- Centralized validation logic
- Singleton pattern for lifecycle management

### Strategy Pattern
The IAL implements the Strategy pattern for provider selection.

**Problem:** Need to select algorithm (provider) at runtime
**Solution:** Define family of algorithms (adapters) with common interface

**Benefits:**
- Runtime provider selection
- Easy to switch providers
- No conditional logic in client code

## Error Handling Strategy

### Exception Mapping
Adapters raise specific exceptions that the Permission Broker maps to HTTP status codes:

| Exception | HTTP Status | Meaning |
|-----------|-------------|---------|
| VaultProviderError | 502 Bad Gateway | Network or provider error |
| VaultAuthenticationError | 401 Unauthorized | Invalid credentials |
| VaultValidationError | 400 Bad Request | Invalid request |
| VaultTimeoutError | 504 Gateway Timeout | Request timeout |
| VaultConfigurationError | 500 Internal Server Error | Configuration error |

### Retry Logic
Adapters implement exponential backoff with jitter for transient failures:

- Retry on network errors (up to 3 attempts)
- Retry on 5xx responses (up to 3 attempts)
- No retry on 4xx responses (client errors)
- Exponential backoff: 1s, 2s, 4s
- Jitter to prevent thundering herd

## Security Considerations

### Credential Storage
- Auth0: Client credentials in configuration
- Keycloak: Client credentials in configuration
- AWS: IAM roles or access keys, provider credentials in Secrets Manager

### Token Handling
- Tokens never logged in plaintext
- Token redaction in pretty printers (show first 8 chars only)
- Tokens transmitted over HTTPS only
- Token expiration enforced

### Configuration Security
- Sensitive values support environment variable substitution
- Configuration validation at startup
- Redaction of secrets in logs
- Support for external secret management

## Performance Considerations

### Singleton Pattern
VaultFactory uses singleton pattern to avoid repeated adapter instantiation.

### Connection Pooling
Adapters use httpx.AsyncClient with connection pooling for HTTP requests.

### Timeout Configuration
Each adapter supports configurable timeouts to tune performance.

### Metrics Collection
Adapters collect Prometheus metrics for monitoring:
- Operation duration histograms
- Success/failure counters
- Provider type labels

## Extensibility

### Adding New Adapters

1. Create new class implementing `IVaultProvider`
2. Implement all five interface methods
3. Add configuration model for new provider
4. Update VaultFactory to instantiate new adapter
5. Add integration tests
6. Update documentation

### Adapter Requirements

- Implement all `IVaultProvider` methods
- Raise appropriate exceptions from exception hierarchy
- Support configurable timeouts
- Log operations with structured logging
- Collect metrics for monitoring
- Pass adapter compliance tests

## Testing Strategy

### Unit Tests
Test individual adapter methods with mocked HTTP responses.

### Property Tests
Verify universal properties across all adapters using Hypothesis.

### Integration Tests
Test complete flows with real or containerized identity providers.

### Compliance Tests
Verify all adapters implement interface correctly and consistently.

### Backward Compatibility Tests
Ensure Auth0Adapter passes all existing TokenVaultClient tests.

## Deployment Considerations

### Configuration Migration
Use provided migration script to convert TokenVaultClient config to IAL format.

### Rollback Strategy
IAL maintains backward compatibility - rollback by reverting configuration.

### Health Monitoring
Monitor adapter health checks and metrics for provider availability.

### Logging
Structured JSON logging for all adapter operations with correlation IDs.

## Future Enhancements

### Potential Additions
- Azure AD adapter
- Okta adapter
- Custom OAuth2 adapter
- Token caching layer
- Circuit breaker pattern
- Rate limiting

### Architectural Evolution
- Plugin system for dynamic adapter loading
- Adapter marketplace
- Multi-provider failover
- Token refresh automation
