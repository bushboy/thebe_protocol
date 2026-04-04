# Implementation Plan: Identity Abstraction Layer

## Overview

This implementation plan breaks down the Identity Abstraction Layer (IAL) feature into discrete coding tasks. The IAL decouples the Zero-Trust Agentic Guardian system from specific Identity Provider implementations by introducing a provider-agnostic interface with concrete adapters for Auth0, Keycloak, and AWS Secrets Manager.

The implementation follows a bottom-up approach: shared library components first, then adapter implementations, factory pattern, configuration handling, Permission Broker integration, and finally testing and documentation.

## Tasks

- [x] 1. Create shared library structure for Identity Abstraction Layer
  - Create `shared/identity/` directory for IAL components
  - Create `shared/identity/__init__.py` with module exports
  - Create `shared/identity/exceptions.py` for exception hierarchy
  - _Requirements: 14.1, 14.2, 14.3, 14.4_

- [x] 2. Implement IVaultProvider interface and exception hierarchy
  - [x] 2.1 Define exception hierarchy in `shared/identity/exceptions.py`
    - Implement `VaultError` base exception
    - Implement `VaultProviderError` for network/provider errors
    - Implement `VaultAuthenticationError` for authentication failures
    - Implement `VaultValidationError` for validation errors
    - Implement `VaultTimeoutError` for timeout errors
    - Implement `VaultConfigurationError` for configuration errors
    - _Requirements: 14.1, 14.2, 14.3, 14.4_
  
  - [x] 2.2 Define IVaultProvider abstract interface in `shared/identity/ivault_provider.py`
    - Define abstract `get_token` method accepting RAR and provider name
    - Define abstract `exchange_token` method for token exchange
    - Define abstract `revoke_session` method for session revocation
    - Define abstract `health_check` method for provider availability
    - Define abstract `get_provider_name` method returning provider type
    - Add comprehensive docstrings with parameter and return type documentation
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_
  
  - [x] 2.3 Write property test for exception hierarchy
    - **Property 22, 23, 24, 25: Adapter Error Handling**
    - **Validates: Requirements 14.1, 14.2, 14.3, 14.4**


- [x] 3. Implement configuration data models
  - [x] 3.1 Create configuration models in `shared/identity/config_models.py`
    - Implement `Auth0Config` Pydantic model with validation
    - Implement `KeycloakConfig` Pydantic model with validation
    - Implement `AWSSecretsConfig` Pydantic model with validation
    - Implement `IALConfig` root configuration model with provider selection
    - Add field validators for required fields, timeouts, and URLs
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.7, 15.1, 15.2, 15.3, 19.6_
  
  - [x] 3.2 Write property test for configuration validation
    - **Property 13, 15, 26, 27, 36: Configuration Validation**
    - **Validates: Requirements 6.5, 6.7, 15.1, 15.2, 15.3, 15.4, 15.5, 19.6**
  
  - [x] 3.3 Create token response model in `shared/identity/token_models.py`
    - Implement `ProviderToken` Pydantic model
    - Add validators for access_token, expires_in, token_type
    - Normalize token_type to "Bearer"
    - _Requirements: 17.1, 17.4, 17.5, 17.6_
  
  - [x] 3.4 Write property test for token response parsing
    - **Property 1, 32: Token Retrieval and Round-Trip Consistency**
    - **Validates: Requirements 17.1, 17.2, 17.3, 17.4, 17.5, 17.6, 18.5**

- [x] 4. Implement Auth0Adapter
  - [x] 4.1 Create Auth0Adapter in `shared/identity/auth0_adapter.py`
    - Implement `__init__` method with configuration parsing and validation
    - Implement `get_token` method with Auth0 Token Vault integration
    - Construct token request with RAR authorization_details
    - Parse and validate token response
    - Handle Auth0-specific error responses (401, 4xx, 5xx)
    - Map provider names to OAuth audiences
    - _Requirements: 2.1, 2.2, 2.6, 2.7_
  
  - [x] 4.2 Implement remaining Auth0Adapter methods
    - Implement `exchange_token` using Auth0 token exchange endpoint
    - Implement `revoke_session` using Auth0 revocation endpoint
    - Implement `health_check` using OpenID configuration endpoint
    - Implement `get_provider_name` returning "auth0"
    - Add structured logging with JSONLogger
    - _Requirements: 2.3, 2.4, 2.5_
  
  - [x] 4.3 Write property test for Auth0Adapter backward compatibility
    - **Property 7: Auth0 Backward Compatibility**
    - **Validates: Requirements 2.6, 8.1**
  
  - [x] 4.4 Write unit tests for Auth0Adapter
    - Test token request construction with RAR
    - Test error handling for 401, 4xx, 5xx responses
    - Test timeout handling
    - Test audience mapping for different providers
    - _Requirements: 2.2, 2.6_

- [x] 5. Implement KeycloakAdapter
  - [x] 5.1 Create KeycloakAdapter in `shared/identity/keycloak_adapter.py`
    - Implement `__init__` method with Keycloak configuration parsing
    - Implement `get_token` method with client credentials flow
    - Implement `_map_scopes` method for RAR action to Keycloak scope translation
    - Support configurable scope_mapping dictionary
    - Handle Keycloak-specific error responses
    - Construct token URL from server_url and realm
    - _Requirements: 3.1, 3.2, 3.7, 21.3, 21.4, 21.7_
  
  - [x] 5.2 Implement remaining KeycloakAdapter methods
    - Implement `exchange_token` using Keycloak token exchange protocol
    - Implement `revoke_session` using Keycloak logout endpoint
    - Implement `health_check` using realm endpoint
    - Implement `get_provider_name` returning "keycloak"
    - Add structured logging with JSONLogger
    - _Requirements: 3.3, 3.4, 3.5, 3.6_
  
  - [x] 5.3 Write property test for Keycloak scope mapping
    - **Property 8, 9: Keycloak Scope Mapping Translation and Multi-Scope Support**
    - **Validates: Requirements 3.7, 21.3, 21.4, 21.7**
  
  - [x] 5.4 Write unit tests for KeycloakAdapter
    - Test scope mapping with configured mappings
    - Test scope mapping fallback to action names
    - Test multi-scope support for single action
    - Test realm URL construction
    - _Requirements: 3.7, 21.7_

- [x] 6. Implement AWSSecretsAdapter
  - [x] 6.1 Create AWSSecretsAdapter in `shared/identity/aws_secrets_adapter.py`
    - Implement `__init__` method with AWS configuration and boto3 client initialization
    - Implement `get_token` method retrieving credentials from Secrets Manager
    - Implement `_generate_token` helper for provider token generation
    - Implement `_generate_session_id` helper for unique session IDs
    - Implement `_store_session` method for DynamoDB session tracking
    - Handle AWS-specific exceptions (ResourceNotFoundException, InvalidRequestException)
    - _Requirements: 4.1, 4.2, 4.6, 4.7_
  
  - [x] 6.2 Implement remaining AWSSecretsAdapter methods
    - Implement `exchange_token` retrieving updated credentials from Secrets Manager
    - Implement `revoke_session` marking session as revoked in DynamoDB
    - Implement `health_check` using Secrets Manager list_secrets API
    - Implement `get_provider_name` returning "aws_secrets"
    - Add structured logging with JSONLogger
    - _Requirements: 4.3, 4.4, 4.5_
  
  - [x] 6.3 Write unit tests for AWSSecretsAdapter
    - Test credential retrieval from Secrets Manager
    - Test session storage in DynamoDB
    - Test session revocation in DynamoDB
    - Test IAM role authentication
    - Mock boto3 clients for testing
    - _Requirements: 4.2, 4.4, 4.6_

- [x] 7. Implement VaultFactory
  - [x] 7.1 Create VaultFactory in `shared/identity/vault_factory.py`
    - Implement `create_provider` class method with configuration parsing
    - Implement singleton pattern to return existing instance
    - Implement `_create_auth0_adapter` with Auth0 config validation
    - Implement `_create_keycloak_adapter` with Keycloak config validation
    - Implement `_create_aws_secrets_adapter` with AWS config validation
    - Validate identity_provider field and raise VaultConfigurationError for invalid values
    - Validate required configuration fields before instantiation
    - Add structured logging for adapter creation
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7_
  
  - [x] 7.2 Implement factory reset method for testing
    - Implement `reset` class method to clear singleton instance
    - _Requirements: 5.1_
  
  - [x] 7.3 Write property test for factory provider instantiation
    - **Property 10, 11, 12: Factory Provider Instantiation and Validation**
    - **Validates: Requirements 5.2, 5.3, 5.4, 5.5, 5.6, 5.7**
  
  - [x] 7.4 Write unit tests for VaultFactory
    - Test Auth0 adapter instantiation with valid config
    - Test Keycloak adapter instantiation with valid config
    - Test AWS adapter instantiation with valid config
    - Test error for unrecognized provider type
    - Test error for missing configuration section
    - Test error for missing required fields
    - Test singleton pattern behavior
    - _Requirements: 5.2, 5.3, 5.4, 5.5, 5.7_

- [x] 8. Checkpoint - Ensure all adapter and factory tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 9. Implement retry logic and timeout handling
  - [x] 9.1 Create retry decorator in `shared/identity/retry.py`
    - Implement `with_retry` decorator for adapter methods
    - Implement exponential backoff with jitter calculation
    - Retry on network errors and 5xx responses (up to 3 retries)
    - Do not retry on 4xx responses
    - Log each retry attempt with attempt number and delay
    - Raise VaultProviderError with all attempt details after exhaustion
    - _Requirements: 20.1, 20.2, 20.3, 20.4, 20.5, 20.6, 20.7_
  
  - [x] 9.2 Apply retry decorator to adapter methods
    - Apply `with_retry` to `get_token` methods in all adapters
    - Apply `with_retry` to `exchange_token` methods in all adapters
    - Ensure timeout configuration is respected in all HTTP requests
    - _Requirements: 19.2, 19.3, 20.1_
  
  - [x] 9.3 Write property test for retry behavior
    - **Property 37, 38, 39, 40: Adapter Retry Logic**
    - **Validates: Requirements 20.1, 20.2, 20.3, 20.5, 20.6, 20.7**
  
  - [x] 9.4 Write unit tests for retry logic
    - Test retry on network errors
    - Test retry on 5xx responses
    - Test no retry on 4xx responses
    - Test exponential backoff timing
    - Test jitter application
    - Test error message after retry exhaustion
    - _Requirements: 20.1, 20.2, 20.3, 20.5, 20.6, 20.7_

- [x] 10. Implement configuration utilities
  - [x] 10.1 Create configuration parser in `shared/identity/config_parser.py`
    - Implement environment variable substitution for ${VAR_NAME} syntax
    - Implement configuration validation using Pydantic models
    - Implement default value application for optional parameters
    - Load configuration from JSON or YAML files
    - _Requirements: 6.6, 6.7, 15.4_
  
  - [x] 10.2 Create configuration pretty printer in `shared/identity/config_printer.py`
    - Implement `pretty_print_config` function for human-readable output
    - Format configuration as indented JSON
    - Redact sensitive fields (client_secret, access keys)
    - Display active identity provider type
    - Display all configuration parameters for active provider
    - _Requirements: 16.1, 16.2, 16.3, 16.4_
  
  - [x] 10.3 Write property test for configuration round-trip consistency
    - **Property 14, 29, 30, 31: Configuration Parsing and Pretty Printing**
    - **Validates: Requirements 6.6, 16.1, 16.2, 16.3, 16.4, 16.5**
  
  - [x] 10.4 Write unit tests for configuration utilities
    - Test environment variable substitution
    - Test default value application
    - Test configuration validation
    - Test pretty printer redaction
    - Test round-trip consistency
    - _Requirements: 6.6, 6.7, 16.4, 16.5_

- [x] 11. Implement token utilities
  - [x] 11.1 Create token pretty printer in `shared/identity/token_printer.py`
    - Implement `pretty_print_token` function for human-readable output
    - Format token with clear field labels
    - Display token_type and expires_in in human-readable format
    - Display granted scopes as formatted list
    - Redact access_token showing only first 8 characters
    - _Requirements: 18.1, 18.2, 18.3, 18.4_
  
  - [x] 11.2 Write property test for token pretty printing
    - **Property 33, 34: Token Pretty Printer Redaction and Formatting**
    - **Validates: Requirements 18.1, 18.2, 18.3, 18.4**
  
  - [x] 11.3 Write unit tests for token utilities
    - Test token pretty printing format
    - Test access_token redaction
    - Test expires_in human-readable format
    - Test scope list formatting
    - _Requirements: 18.1, 18.2, 18.3, 18.4_

- [x] 12. Implement adapter metrics collection
  - [x] 12.1 Create metrics module in `shared/identity/metrics.py`
    - Implement Prometheus metrics for adapter operations
    - Create duration histogram for get_token operations
    - Create duration histogram for exchange_token operations
    - Create duration histogram for revoke_session operations
    - Create counter for operation success/failure
    - Include provider_type as label in all metrics
    - _Requirements: 22.1, 22.2, 22.3, 22.4, 22.5, 22.7_
  
  - [x] 12.2 Integrate metrics into adapter methods
    - Add metrics recording to Auth0Adapter methods
    - Add metrics recording to KeycloakAdapter methods
    - Add metrics recording to AWSSecretsAdapter methods
    - Record operation duration and success/failure status
    - _Requirements: 22.1, 22.2, 22.3, 22.4_
  
  - [x] 12.3 Write property test for metrics recording
    - **Property 41: Adapter Metrics Recording**
    - **Validates: Requirements 22.1, 22.2, 22.3, 22.4**

- [x] 13. Checkpoint - Ensure all utility and metrics tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 14. Integrate IAL into Permission Broker
  - [x] 14.1 Update Permission Broker configuration in `services/permission_broker/config.py`
    - Add IAL configuration loading from environment or config file
    - Support both old TokenVaultClient config and new IAL config
    - Add configuration validation at startup
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 7.6_
  
  - [x] 14.2 Refactor Permission Broker to use VaultFactory in `services/permission_broker/main.py`
    - Replace TokenVaultClient instantiation with VaultFactory.create_provider()
    - Update authorize endpoint to use IVaultProvider interface
    - Call adapter.get_token() instead of token_vault_client.request_provider_token()
    - Maintain same ZT-AT construction logic
    - _Requirements: 7.1, 7.2, 7.3_
  
  - [x] 14.3 Implement adapter error mapping in Permission Broker
    - Map VaultProviderError to HTTP 502 Bad Gateway
    - Map VaultAuthenticationError to HTTP 401 Unauthorized
    - Map VaultValidationError to HTTP 400 Bad Request
    - Map VaultTimeoutError to HTTP 504 Gateway Timeout
    - Preserve existing error logging to Audit Service
    - _Requirements: 7.4, 14.5, 14.6, 14.7_
  
  - [x] 14.4 Update Permission Broker health endpoint
    - Call adapter.health_check() in /health endpoint
    - Include adapter provider name in health response
    - Log which identity provider adapter is being used at startup
    - _Requirements: 7.6, 7.7_
  
  - [x] 14.5 Write property test for Permission Broker integration
    - **Property 16, 17, 18: Permission Broker Adapter Integration and Error Mapping**
    - **Validates: Requirements 7.2, 7.3, 7.4, 7.5, 14.5, 14.6, 14.7**
  
  - [x] 14.6 Write integration tests for Permission Broker with IAL
    - Test authorization flow with Auth0Adapter
    - Test authorization flow with KeycloakAdapter (mocked)
    - Test authorization flow with AWSSecretsAdapter (mocked)
    - Test error handling and HTTP status code mapping
    - Test health endpoint with adapter health check
    - _Requirements: 7.2, 7.3, 7.4, 7.7_

- [x] 15. Implement backward compatibility verification
  - [x] 15.1 Create backward compatibility test suite in `tests/integration/test_backward_compatibility.py`
    - Test that Auth0Adapter produces same token response structure as TokenVaultClient
    - Test that ZT-AT structure is preserved with IAL-enabled broker
    - Test that Executor Agent accepts ZT-ATs from IAL-enabled broker
    - Test that Audit Service logs events with same format
    - Run all existing TokenVaultClient tests against Auth0Adapter
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5_
  
  - [x] 15.2 Write property test for ZT-AT structure preservation
    - **Property 19, 20, 21: ZT-AT Structure and Audit Log Preservation**
    - **Validates: Requirements 8.3, 8.4, 8.5**
  
  - [x] 15.3 Write unit tests for backward compatibility
    - Test Auth0Adapter with existing TokenVaultClient test cases
    - Test ZT-AT field preservation
    - Test audit log format preservation
    - _Requirements: 8.1, 8.2, 8.3, 8.5_

- [x] 16. Implement adapter compliance test suite
  - [x] 16.1 Create adapter compliance tests in `tests/property/test_adapter_compliance.py`
    - Generate random RAR objects and verify all adapters return valid ProviderToken
    - Verify all adapters raise appropriate exceptions for invalid inputs
    - Verify all adapters implement all IVaultProvider methods
    - Verify token expiration times are positive integers
    - Verify health_check returns boolean value
    - Verify get_provider_name returns non-empty string
    - Verify calling get_token twice returns different access_token values
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.7_
  
  - [x] 16.2 Write property tests for adapter compliance
    - **Property 1, 2, 3, 4, 5, 6: Adapter Interface Compliance**
    - **Validates: Requirements 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.7**

- [x] 17. Checkpoint - Ensure all integration and compliance tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 18. Create configuration migration script
  - [x] 18.1 Create migration script in `scripts/migrate_ial_config.py`
    - Read existing Permission Broker configuration file
    - Detect TokenVaultClient configuration parameters
    - Generate new IALConfig with identity_provider set to "auth0"
    - Copy Auth0 configuration to auth0_config section
    - Validate generated configuration using Pydantic models
    - Create backup of original configuration file
    - Write new configuration file
    - Output summary of migration changes
    - _Requirements: 24.1, 24.2, 24.3, 24.4, 24.5, 24.6, 24.7_
  
  - [x] 18.2 Write unit tests for migration script
    - Test detection of TokenVaultClient configuration
    - Test generation of new IALConfig
    - Test configuration validation
    - Test backup file creation
    - Test migration summary output
    - _Requirements: 24.1, 24.2, 24.3, 24.4, 24.5, 24.6, 24.7_

- [x] 19. Create adapter integration test infrastructure
  - [x] 19.1 Create Auth0 integration tests in `tests/integration/test_auth0_adapter.py`
    - Configure test Auth0 tenant with Token Vault enabled
    - Test get_token successfully retrieves GitHub token from Auth0
    - Test returned token can be used for authenticated GitHub API calls
    - Test exchange_token successfully exchanges token for different scope
    - Test revoke_session successfully revokes Auth0 session
    - Test health_check returns true when Auth0 is accessible
    - Test appropriate errors when Auth0 is unreachable
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7_
  
  - [x] 19.2 Create Keycloak integration tests in `tests/integration/test_keycloak_adapter.py`
    - Configure test Keycloak realm with client credentials
    - Test get_token successfully retrieves token from Keycloak
    - Test returned token contains requested scopes
    - Test exchange_token successfully exchanges token using Keycloak protocol
    - Test revoke_session successfully revokes Keycloak session
    - Test health_check returns true when Keycloak is accessible
    - Test scope mapping correctly translates RAR actions to Keycloak scopes
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6, 11.7_
  
  - [x] 19.3 Create AWS Secrets Manager integration tests in `tests/integration/test_aws_secrets_adapter.py`
    - Configure test AWS account with Secrets Manager and DynamoDB (or use LocalStack)
    - Test get_token successfully retrieves credentials from Secrets Manager
    - Test returned token can be used to authenticate with target provider
    - Test exchange_token retrieves updated credentials from Secrets Manager
    - Test revoke_session writes revocation record to DynamoDB
    - Test health_check returns true when AWS Secrets Manager is accessible
    - Test IAM role authentication works correctly
    - _Requirements: 12.1, 12.2, 12.3, 12.4, 12.5, 12.6, 12.7_

- [x] 20. Create documentation
  - [x] 20.1 Create architecture documentation in `docs/identity-abstraction-layer/architecture.md`
    - Document IAL architecture and design decisions
    - Include component diagrams and sequence diagrams
    - Explain adapter pattern and factory pattern usage
    - Document integration with Permission Broker
    - _Requirements: 23.1_
  
  - [x] 20.2 Create configuration guide in `docs/identity-abstraction-layer/configuration.md`
    - Provide configuration examples for Auth0
    - Provide configuration examples for Keycloak
    - Provide configuration examples for AWS Secrets Manager
    - Document environment variable substitution
    - Document default values for optional parameters
    - _Requirements: 23.2_
  
  - [x] 20.3 Create adapter development guide in `docs/identity-abstraction-layer/adapter-development.md`
    - Provide code examples for implementing new adapters
    - Document IVaultProvider interface requirements
    - Document exception handling requirements
    - Document testing requirements for new adapters
    - _Requirements: 23.3_
  
  - [x] 20.4 Create migration guide in `docs/identity-abstraction-layer/migration.md`
    - Document migration process from TokenVaultClient to IAL
    - Provide step-by-step migration instructions
    - Document configuration migration script usage
    - Document backward compatibility guarantees
    - _Requirements: 23.4_
  
  - [x] 20.5 Create troubleshooting guide in `docs/identity-abstraction-layer/troubleshooting.md`
    - Document common configuration errors and solutions
    - Document adapter-specific error scenarios
    - Document debugging techniques for IAL issues
    - Document health check interpretation
    - _Requirements: 23.5_
  
  - [x] 20.6 Create API reference documentation in `docs/identity-abstraction-layer/api-reference.md`
    - Document IVaultProvider interface methods
    - Document exception hierarchy
    - Document configuration models
    - Document VaultFactory usage
    - _Requirements: 23.6_
  
  - [x] 20.7 Add sequence diagrams to documentation
    - Create sequence diagram for Auth0 token request flow
    - Create sequence diagram for Keycloak token request flow
    - Create sequence diagram for AWS Secrets Manager token request flow
    - Create sequence diagram for Permission Broker integration
    - _Requirements: 23.7_

- [ ] 21. Final checkpoint - Ensure all tests pass and documentation is complete
  - Run full test suite (unit, property, integration)
  - Verify all documentation is complete and accurate
  - Verify backward compatibility with existing Auth0 integration
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation at key milestones
- Property tests validate universal correctness properties across all adapters
- Unit tests validate specific examples and edge cases
- Integration tests verify complete flows with real or containerized identity providers
- The implementation maintains complete backward compatibility with existing Auth0 integration
- All adapters follow consistent error handling and retry patterns
- Configuration supports environment variable substitution for sensitive values
- Metrics collection enables monitoring of identity provider performance
