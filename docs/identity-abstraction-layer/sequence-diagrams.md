# Identity Abstraction Layer - Sequence Diagrams

## Overview

This document provides detailed sequence diagrams for the Identity Abstraction Layer, illustrating the flow of token requests, exchanges, and revocations across different identity providers.

## Table of Contents

- [Permission Broker Integration Flow](#permission-broker-integration-flow)
- [Auth0 Token Request Flow](#auth0-token-request-flow)
- [Keycloak Token Request Flow](#keycloak-token-request-flow)
- [AWS Secrets Manager Token Request Flow](#aws-secrets-manager-token-request-flow)
- [Token Exchange Flow](#token-exchange-flow)
- [Session Revocation Flow](#session-revocation-flow)
- [Health Check Flow](#health-check-flow)
- [Error Handling Flow](#error-handling-flow)

---

## Permission Broker Integration Flow

This diagram shows the complete authorization flow from the Permission Broker through the IAL to the identity provider.

```mermaid
sequenceDiagram
    participant Client as Client Application
    participant PB as Permission Broker
    participant VF as VaultFactory
    participant Adapter as IVaultProvider
    participant IdP as Identity Provider
    participant Executor as Executor Agent
    participant Provider as External Provider

    Client->>PB: POST /authorize (Intent + Policy)
    
    Note over PB: Validate Intent Signature
    PB->>PB: Verify Intent Signature
    
    Note over PB: Validate Policy Approval
    PB->>PB: Verify Policy Approval
    
    Note over PB: Construct RAR
    PB->>PB: Build Rich Authorization Request
    
    PB->>VF: create_provider()
    VF->>VF: Read configuration
    VF->>VF: Validate config
    VF->>Adapter: __init__(config)
    Adapter-->>VF: Adapter instance
    VF-->>PB: Return adapter
    
    PB->>Adapter: get_token(rar, provider)
    
    Note over Adapter: Map RAR to provider format
    Adapter->>Adapter: Transform RAR
    
    Adapter->>IdP: Request token (provider-specific)
    
    Note over IdP: Validate credentials
    IdP->>IdP: Authenticate client
    
    Note over IdP: Generate provider token
    IdP->>IdP: Create access token
    
    IdP-->>Adapter: Token response
    
    Note over Adapter: Parse and validate
    Adapter->>Adapter: Validate response
    
    Adapter-->>PB: Provider token
    
    Note over PB: Construct ZT-AT
    PB->>PB: Build Zero-Trust Authorization Token
    PB->>PB: Sign ZT-AT with broker key
    
    PB-->>Client: ZT-AT + Provider token
    
    Client->>Executor: Execute action with ZT-AT
    Executor->>Executor: Validate ZT-AT
    Executor->>Provider: API call with provider token
    Provider-->>Executor: API response
    Executor-->>Client: Execution result
```

---

## Auth0 Token Request Flow

Detailed flow for Auth0 Token Vault integration.

```mermaid
sequenceDiagram
    participant Adapter as Auth0Adapter
    participant Auth0 as Auth0 Token Vault
    participant GitHub as GitHub API

    Note over Adapter: Construct token request
    Adapter->>Adapter: Build request payload
    
    Note over Adapter: Request structure:<br/>{<br/>  grant_type: "client_credentials",<br/>  client_id: "...",<br/>  client_secret: "...",<br/>  audience: "https://api.github.com",<br/>  scope: "repo:write",<br/>  authorization_details: [RAR]<br/>}
    
    Adapter->>Auth0: POST /oauth/token
    
    Note over Auth0: Validate client credentials
    Auth0->>Auth0: Verify client_id and client_secret
    
    Note over Auth0: Check Token Vault connection
    Auth0->>Auth0: Verify GitHub connection exists
    
    Auth0->>GitHub: Request token with scopes
    Note over Auth0,GitHub: Auth0 uses stored GitHub<br/>OAuth app credentials
    
    GitHub->>GitHub: Validate Auth0 OAuth app
    GitHub->>GitHub: Generate access token
    
    GitHub-->>Auth0: GitHub access token
    
    Note over Auth0: Construct response
    Auth0->>Auth0: Build token response
    
    Auth0-->>Adapter: Token response
    Note over Auth0,Adapter: {<br/>  access_token: "gho_...",<br/>  token_type: "Bearer",<br/>  expires_in: 3600,<br/>  scope: "repo:write"<br/>}
    
    Note over Adapter: Validate response structure
    Adapter->>Adapter: Check required fields
    Adapter->>Adapter: Validate token format
    
    Note over Adapter: Extract token fields
    Adapter->>Adapter: Parse access_token, expires_in, scope
    
    Adapter-->>Adapter: Return normalized token
```

---

## Keycloak Token Request Flow

Detailed flow for Keycloak client credentials flow with scope mapping.

```mermaid
sequenceDiagram
    participant Adapter as KeycloakAdapter
    participant KC as Keycloak Server
    participant Provider as External Provider

    Note over Adapter: Map RAR actions to Keycloak scopes
    Adapter->>Adapter: Apply scope_mapping configuration
    Note over Adapter: Example:<br/>repo:read → github:repo:read<br/>repo:write → [github:repo:write, github:repo:admin]
    
    Note over Adapter: Construct token request
    Adapter->>Adapter: Build form-encoded request
    
    Adapter->>KC: POST /realms/{realm}/protocol/openid-connect/token
    Note over Adapter,KC: Content-Type: application/x-www-form-urlencoded<br/>{<br/>  grant_type: "client_credentials",<br/>  client_id: "...",<br/>  client_secret: "...",<br/>  scope: "github:repo:read github:repo:write"<br/>}
    
    Note over KC: Validate client credentials
    KC->>KC: Verify client_id and client_secret
    
    Note over KC: Check client permissions
    KC->>KC: Verify client has requested scopes
    KC->>KC: Check service account roles
    
    Note over KC: Generate access token
    KC->>KC: Create JWT with scopes
    KC->>KC: Sign token with realm key
    
    KC-->>Adapter: Token response
    Note over KC,Adapter: {<br/>  access_token: "eyJhbG...",<br/>  token_type: "Bearer",<br/>  expires_in: 300,<br/>  scope: "github:repo:read github:repo:write"<br/>}
    
    Note over Adapter: Extract provider credentials
    Adapter->>Adapter: Parse token claims
    Adapter->>Adapter: Extract provider-specific credentials
    
    Note over Adapter: Use credentials for provider token
    Adapter->>Provider: Request token with credentials
    Note over Adapter,Provider: Provider-specific OAuth flow<br/>using credentials from Keycloak token
    
    Provider->>Provider: Validate credentials
    Provider->>Provider: Generate access token
    
    Provider-->>Adapter: Provider token
    
    Adapter-->>Adapter: Return normalized token
```

---

## AWS Secrets Manager Token Request Flow

Detailed flow for AWS Secrets Manager credential retrieval and session tracking.

```mermaid
sequenceDiagram
    participant Adapter as AWSSecretsAdapter
    participant SM as AWS Secrets Manager
    participant DDB as DynamoDB
    participant Provider as External Provider

    Note over Adapter: Construct secret name
    Adapter->>Adapter: Build secret path
    Note over Adapter: Format: {prefix}/{provider}/credentials<br/>Example: ztag/providers/github/credentials
    
    Adapter->>SM: GetSecretValue(secret_name)
    
    Note over SM: Validate IAM permissions
    SM->>SM: Check caller has secretsmanager:GetSecretValue
    SM->>SM: Verify secret exists
    
    SM-->>Adapter: Secret value
    Note over SM,Adapter: {<br/>  "client_id": "...",<br/>  "client_secret": "...",<br/>  "api_key": "..."<br/>}
    
    Note over Adapter: Parse credentials JSON
    Adapter->>Adapter: Extract credential fields
    Adapter->>Adapter: Validate credential structure
    
    Note over Adapter: Request token from provider
    Adapter->>Provider: OAuth request with credentials
    Note over Adapter,Provider: Provider-specific OAuth flow<br/>using credentials from Secrets Manager
    
    Provider->>Provider: Validate credentials
    Provider->>Provider: Generate access token
    
    Provider-->>Adapter: Provider token
    
    Note over Adapter: Generate session ID
    Adapter->>Adapter: Create UUID-based session ID
    
    Note over Adapter: Prepare session metadata
    Adapter->>Adapter: Build session record
    Note over Adapter: {<br/>  session_id: "uuid",<br/>  provider: "github",<br/>  created_at: "2024-01-01T00:00:00Z",<br/>  token_metadata: {...}<br/>}
    
    Adapter->>DDB: PutItem(session_record)
    
    Note over DDB: Store session
    DDB->>DDB: Write to session table
    
    DDB-->>Adapter: Write confirmation
    
    Adapter-->>Adapter: Return normalized token
```

---

## Token Exchange Flow

Flow for exchanging an existing token for a new token with different scopes.

```mermaid
sequenceDiagram
    participant Client as Client Application
    participant PB as Permission Broker
    participant Adapter as IVaultProvider
    participant IdP as Identity Provider

    Client->>PB: Request token exchange
    Note over Client,PB: Existing token + new scopes
    
    PB->>Adapter: exchange_token(existing_token, new_scopes, provider)
    
    Note over Adapter: Construct exchange request
    Adapter->>Adapter: Build token exchange payload
    Note over Adapter: {<br/>  grant_type: "token_exchange",<br/>  subject_token: "existing_token",<br/>  requested_scopes: ["new:scope"]<br/>}
    
    Adapter->>IdP: POST /token/exchange
    
    Note over IdP: Validate existing token
    IdP->>IdP: Verify token signature
    IdP->>IdP: Check token expiration
    
    Note over IdP: Validate new scopes
    IdP->>IdP: Check scope permissions
    IdP->>IdP: Verify client authorization
    
    Note over IdP: Generate new token
    IdP->>IdP: Create new access token
    IdP->>IdP: Apply new scopes
    
    IdP-->>Adapter: New token response
    
    Adapter->>Adapter: Validate response
    Adapter-->>PB: New token
    
    PB-->>Client: New ZT-AT with exchanged token
```

---

## Session Revocation Flow

Flow for revoking an active session.

```mermaid
sequenceDiagram
    participant Client as Client Application
    participant PB as Permission Broker
    participant Adapter as IVaultProvider
    participant IdP as Identity Provider
    participant DDB as DynamoDB (AWS only)

    Client->>PB: POST /revoke (session_id)
    
    PB->>Adapter: revoke_session(session_id)
    
    alt Auth0 or Keycloak
        Note over Adapter: Construct revocation request
        Adapter->>Adapter: Build revoke payload
        
        Adapter->>IdP: POST /revoke
        Note over Adapter,IdP: {<br/>  client_id: "...",<br/>  client_secret: "...",<br/>  token: "session_id"<br/>}
        
        Note over IdP: Validate credentials
        IdP->>IdP: Verify client credentials
        
        Note over IdP: Revoke token
        IdP->>IdP: Invalidate token
        IdP->>IdP: Clear session
        
        IdP-->>Adapter: 200 OK
        Adapter-->>PB: True (success)
    
    else AWS Secrets Manager
        Note over Adapter: Mark session as revoked
        Adapter->>DDB: UpdateItem(session_id)
        Note over Adapter,DDB: Set revoked_at timestamp
        
        DDB->>DDB: Update session record
        DDB-->>Adapter: Update confirmation
        Adapter-->>PB: True (success)
    end
    
    PB->>PB: Log revocation event
    PB-->>Client: 200 OK
```

---

## Health Check Flow

Flow for checking identity provider availability.

```mermaid
sequenceDiagram
    participant Monitor as Monitoring System
    participant PB as Permission Broker
    participant Adapter as IVaultProvider
    participant IdP as Identity Provider

    Monitor->>PB: GET /health
    
    PB->>Adapter: health_check()
    
    alt Auth0
        Adapter->>IdP: GET /.well-known/openid-configuration
        
        alt Provider Healthy
            IdP-->>Adapter: 200 OK + OIDC config
            Adapter-->>PB: True
        else Provider Unhealthy
            IdP-->>Adapter: Timeout or error
            Adapter-->>PB: False
        end
    
    else Keycloak
        Adapter->>IdP: GET /realms/{realm}
        
        alt Provider Healthy
            IdP-->>Adapter: 200 OK + realm info
            Adapter-->>PB: True
        else Provider Unhealthy
            IdP-->>Adapter: Timeout or error
            Adapter-->>PB: False
        end
    
    else AWS Secrets Manager
        Adapter->>IdP: ListSecrets (max 1 item)
        
        alt Provider Healthy
            IdP-->>Adapter: 200 OK + secret list
            Adapter-->>PB: True
        else Provider Unhealthy
            IdP-->>Adapter: Timeout or error
            Adapter-->>PB: False
        end
    end
    
    Note over PB: Build health response
    PB->>PB: Include provider name and status
    
    PB-->>Monitor: Health status
    Note over PB,Monitor: {<br/>  "status": "healthy",<br/>  "identity_provider": "auth0",<br/>  "provider_accessible": true<br/>}
```

---

## Error Handling Flow

Flow showing error handling and retry logic.

```mermaid
sequenceDiagram
    participant PB as Permission Broker
    participant Adapter as IVaultProvider
    participant Retry as Retry Decorator
    participant IdP as Identity Provider

    PB->>Adapter: get_token(rar, provider)
    
    Note over Adapter: Retry decorator wraps method
    Adapter->>Retry: Execute with retry logic
    
    loop Retry attempts (max 3)
        Retry->>IdP: POST /token
        
        alt Success (200 OK)
            IdP-->>Retry: Token response
            Retry-->>Adapter: Token data
            Note over Retry: Exit retry loop
        
        else 4xx Client Error
            IdP-->>Retry: 400/401/403/404
            Note over Retry: No retry for client errors
            Retry->>Retry: Raise VaultAuthenticationError or VaultValidationError
            Retry-->>Adapter: Exception
            Note over Retry: Exit retry loop
        
        else 5xx Server Error
            IdP-->>Retry: 500/502/503
            Note over Retry: Retry on server errors
            
            alt Not last attempt
                Retry->>Retry: Calculate backoff delay
                Note over Retry: delay = base * (2 ^ attempt) + jitter<br/>Example: 1s, 2s, 4s
                Retry->>Retry: Sleep(delay)
                Retry->>Retry: Log retry attempt
                Note over Retry: Continue to next attempt
            else Last attempt
                Retry->>Retry: Raise VaultProviderError
                Note over Retry: Include all attempt details
                Retry-->>Adapter: Exception
                Note over Retry: Exit retry loop
            end
        
        else Network Error
            IdP-->>Retry: Connection error / Timeout
            Note over Retry: Retry on network errors
            
            alt Not last attempt
                Retry->>Retry: Calculate backoff delay
                Retry->>Retry: Sleep(delay)
                Retry->>Retry: Log retry attempt
                Note over Retry: Continue to next attempt
            else Last attempt
                Retry->>Retry: Raise VaultProviderError or VaultTimeoutError
                Retry-->>Adapter: Exception
                Note over Retry: Exit retry loop
            end
        end
    end
    
    alt Success
        Adapter-->>PB: Token
        PB->>PB: Construct ZT-AT
        PB-->>PB: Return success
    
    else VaultAuthenticationError
        Adapter-->>PB: VaultAuthenticationError
        PB->>PB: Log error
        PB-->>PB: Return HTTP 401
    
    else VaultValidationError
        Adapter-->>PB: VaultValidationError
        PB->>PB: Log error
        PB-->>PB: Return HTTP 400
    
    else VaultTimeoutError
        Adapter-->>PB: VaultTimeoutError
        PB->>PB: Log error
        PB-->>PB: Return HTTP 504
    
    else VaultProviderError
        Adapter-->>PB: VaultProviderError
        PB->>PB: Log error
        PB-->>PB: Return HTTP 502
    end
```

---

## Factory Instantiation Flow

Flow showing how VaultFactory creates and caches adapter instances.

```mermaid
sequenceDiagram
    participant PB as Permission Broker
    participant VF as VaultFactory
    participant Config as Configuration
    participant Adapter as IVaultProvider

    Note over PB: Application startup
    PB->>Config: load_config("ial_config.json")
    Config->>Config: Read file
    Config->>Config: Parse JSON/YAML
    Config->>Config: Substitute environment variables
    Config->>Config: Validate with Pydantic
    Config-->>PB: IALConfig object
    
    PB->>VF: create_provider(config)
    
    Note over VF: Check singleton instance
    VF->>VF: if _instance is not None
    
    alt Instance exists
        VF-->>PB: Return cached instance
    
    else Instance doesn't exist
        Note over VF: Read provider type
        VF->>VF: provider_type = config.identity_provider
        
        alt provider_type == "auth0"
            VF->>VF: Validate auth0_config exists
            VF->>VF: Validate required fields
            VF->>Adapter: Auth0Adapter(config.auth0_config)
            Adapter->>Adapter: Initialize HTTP client
            Adapter->>Adapter: Set up logging
            Adapter-->>VF: Adapter instance
        
        else provider_type == "keycloak"
            VF->>VF: Validate keycloak_config exists
            VF->>VF: Validate required fields
            VF->>Adapter: KeycloakAdapter(config.keycloak_config)
            Adapter->>Adapter: Initialize HTTP client
            Adapter->>Adapter: Build token URL
            Adapter-->>VF: Adapter instance
        
        else provider_type == "aws_secrets"
            VF->>VF: Validate aws_secrets_config exists
            VF->>VF: Validate required fields
            VF->>Adapter: AWSSecretsAdapter(config.aws_secrets_config)
            Adapter->>Adapter: Initialize boto3 clients
            Adapter->>Adapter: Set up DynamoDB table
            Adapter-->>VF: Adapter instance
        
        else Invalid provider
            VF->>VF: Raise VaultConfigurationError
            VF-->>PB: Exception
        end
        
        Note over VF: Cache instance
        VF->>VF: _instance = adapter
        
        VF->>VF: Log adapter creation
        VF-->>PB: Return adapter instance
    end
    
    Note over PB: Use adapter for token requests
    PB->>Adapter: get_token(rar, provider)
```

---

## Metrics Collection Flow

Flow showing how metrics are collected during token operations.

```mermaid
sequenceDiagram
    participant Adapter as IVaultProvider
    participant Metrics as Prometheus Metrics
    participant IdP as Identity Provider

    Note over Adapter: Start token request
    Adapter->>Adapter: start_time = time.time()
    
    Adapter->>IdP: Request token
    
    alt Success
        IdP-->>Adapter: Token response
        
        Note over Adapter: Record success
        Adapter->>Metrics: token_request_counter.labels(<br/>  provider_type="auth0",<br/>  operation="get_token",<br/>  status="success"<br/>).inc()
        
        Note over Adapter: Record duration
        Adapter->>Adapter: duration = time.time() - start_time
        Adapter->>Metrics: token_request_duration.labels(<br/>  provider_type="auth0",<br/>  operation="get_token"<br/>).observe(duration)
    
    else Failure
        IdP-->>Adapter: Error response
        
        Note over Adapter: Record failure
        Adapter->>Metrics: token_request_counter.labels(<br/>  provider_type="auth0",<br/>  operation="get_token",<br/>  status="failure"<br/>).inc()
        
        Note over Adapter: Record duration
        Adapter->>Adapter: duration = time.time() - start_time
        Adapter->>Metrics: token_request_duration.labels(<br/>  provider_type="auth0",<br/>  operation="get_token"<br/>).observe(duration)
        
        Adapter->>Adapter: Raise exception
    end
```

---

## See Also

- [Architecture Documentation](architecture.md) - Design and architecture details
- [Configuration Guide](configuration.md) - Configuration examples
- [API Reference](api-reference.md) - Detailed API documentation
- [Troubleshooting Guide](troubleshooting.md) - Common issues and solutions
