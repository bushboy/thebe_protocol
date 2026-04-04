# Implementation Plan: Zero-Trust Agentic Guardian Architecture

## Overview

This implementation plan breaks down the Zero-Trust Agentic Guardian Architecture into discrete coding tasks. The system will be built incrementally, starting with shared libraries and infrastructure setup, then implementing each service in dependency order. All code will be written in Python 3.14.2+ using FastAPI for services, with comprehensive property-based testing using Hypothesis.

The implementation follows this sequence:
1. Project structure and shared libraries
2. Infrastructure setup (Auth0, certificates, OPA)
3. Core services (Intent Engine, Safety Agent)
4. Authorization services (Planner, Permission Broker)
5. Execution and audit services
6. Integration and testing

## Tasks

- [x] 1. Set up project structure and shared libraries
  - Create directory structure matching the folder layout
  - Set up Python virtual environment and dependencies (FastAPI, Hypothesis, PyJWT, cryptography, sentence-transformers, httpx, pydantic)
  - Create shared library modules: jwt, dpop, mtls, schemas, logging
  - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7_

- [x] 2. Implement shared data models (schemas)
  - [x] 2.1 Create Pydantic models for IntentSignature, PolicyDecision, RAR, ZT-AT, AuditLogEntry, DPoPProof
    - Define all fields with proper types and validation
    - Add JSON schema examples
    - _Requirements: 4.6_

  - [x] 2.2 Write property test for data model validation
    - **Property 31: IntentSignature Validation**
    - **Validates: Requirements 20.1, 20.3, 20.4, 20.5**

- [x] 3. Implement JWT utilities (shared/jwt/)
  - [x] 3.1 Create JWT validation module
    - Implement signature verification using PyJWT
    - Validate issuer, audience, expiration
    - Implement nonce tracking for replay prevention
    - Validate timestamp freshness
    - _Requirements: 4.1, 4.2_

  - [x] 3.2 Write property test for JWT validation
    - **Property 14: JWT Validation Completeness**
    - **Validates: Requirements 4.1, 4.2**

- [x] 4. Implement DPoP utilities (shared/dpop/)
  - [x] 4.1 Create DPoP proof generation module
    - Generate DPoP proof JWTs bound to HTTP requests
    - Include jti, htm, htu, iat, ath fields
    - Sign with service private key
    - _Requirements: 4.3_

  - [x] 4.2 Create DPoP proof verification module
    - Verify DPoP signature
    - Validate token binding (ath matches access token hash)
    - Validate request matching (htm and htu match actual request)
    - _Requirements: 4.4_

  - [x] 4.3 Write property test for DPoP proof binding
    - **Property 15: DPoP Proof Binding**
    - **Validates: Requirements 4.3, 4.4**

- [x] 5. Implement mTLS utilities (shared/mtls/)
  - [x] 5.1 Create certificate loading module
    - Load PEM certificates using cryptography library
    - Extract client identity from certificate subject
    - Validate certificate chain against root CA
    - _Requirements: 4.5_

  - [x] 5.2 Write property test for certificate identity extraction
    - **Property 16: Certificate Identity Extraction**
    - **Validates: Requirements 4.5**

- [x] 6. Implement structured logging (shared/logging/)
  - [x] 6.1 Create JSON logging module
    - Configure Python logging to output JSON
    - Add correlation ID to all log entries
    - Add audit hooks for security events
    - _Requirements: 4.7_

  - [x] 6.2 Write property test for structured logging format
    - **Property 17: Structured Logging Format**
    - **Validates: Requirements 4.7**

- [x] 7. Create Auth0 configuration script (infra/auth0/)
  - [x] 7.1 Implement M2M application creation
    - Use Auth0 Management API to create 5 M2M applications
    - Enable client_credentials grant for each
    - Generate DPoP keypairs and register as JWKs
    - Output manifest JSON with credentials
    - _Requirements: 1.1, 1.2, 1.3, 1.4_

  - [x] 7.2 Configure Token Vault and connected accounts
    - Enable Auth0 Token Vault
    - Configure GitHub, Slack, Google Workspace connections
    - Set up read-only and write-action scopes
    - _Requirements: 1.5, 1.6, 1.7_

  - [x] 7.3 Write property test for M2M application uniqueness
    - **Property 9: M2M Application Uniqueness**
    - **Validates: Requirements 1.2, 1.3, 1.4**

- [x] 8. Create certificate generation script (infra/certificates/)
  - [x] 8.1 Implement root CA creation
    - Generate root CA private key and self-signed certificate
    - Store in PEM format
    - _Requirements: 2.1_

  - [x] 8.2 Implement service certificate generation
    - Generate client and server certificates for all 6 services
    - Sign with root CA
    - Store in service-specific folders
    - Create generate_all_certs.sh automation script
    - _Requirements: 2.2, 2.3, 2.4_

  - [x] 8.3 Write property test for certificate chain validation
    - **Property 10: Certificate Chain Validation**
    - **Validates: Requirements 2.2, 2.3, 2.5**

  - [x] 8.4 Write property test for certificate PEM format
    - **Property 35: Certificate PEM Format**
    - **Validates: Requirements 2.3**

- [x] 9. Create OPA policies (infra/opa/)
  - [x] 9.1 Write OPA policies in Rego
    - Policy for destructive GitHub actions (admin-only)
    - Policy for spending limits
    - Policy for allowed action categories
    - Policy for intent alignment thresholds
    - _Requirements: 3.1, 3.2, 3.3, 3.4_

  - [x] 9.2 Create Python OPA client wrapper
    - Implement policy evaluation interface
    - Handle OPA HTTP API communication
    - _Requirements: 3.5_

  - [x] 9.3 Write property test for OPA policy enforcement
    - **Property 8: OPA Policy Enforcement**
    - **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5**

- [x] 10. Checkpoint - Verify infrastructure and shared libraries
  - Ensure all tests pass, ask the user if questions arise.

- [x] 11. Implement Intent Engine service (services/intent-engine/)
  - [x] 11.1 Create FastAPI application with endpoints
    - POST /sign-intent endpoint
    - POST /verify-intent endpoint
    - GET /health endpoint
    - _Requirements: 6.4, 6.5_

  - [x] 11.2 Implement intent signature generation
    - Load sentence-transformer model (all-MiniLM-L6-v2)
    - Generate embeddings from user goals
    - Create IntentSignature objects with hash and allowed actions
    - Sign with private key
    - _Requirements: 6.1, 6.2_

  - [x] 11.3 Implement intent verification
    - Compute cosine similarity between embeddings
    - Compare against threshold (0.7)
    - Return alignment decision
    - _Requirements: 6.3_

  - [x] 11.4 Add authentication middleware
    - Validate JWT + DPoP + mTLS for all requests
    - _Requirements: 11.1, 11.2, 11.3, 11.4_

  - [x] 11.5 Write property test for intent embedding dimensionality
    - **Property 19: Intent Embedding Dimensionality**
    - **Validates: Requirements 6.1, 6.2, 20.2**

  - [x] 11.6 Write property test for intent similarity computation
    - **Property 20: Intent Similarity Computation**
    - **Validates: Requirements 6.3**

  - [x] 11.7 Write property test for IntentSignature round-trip
    - **Property 3: IntentSignature Round-Trip Consistency**
    - **Validates: Requirements 21.5**

- [x] 12. Implement Safety Agent service (services/safety-agent/)
  - [x] 12.1 Create FastAPI application with endpoints
    - POST /evaluate endpoint
    - GET /health endpoint
    - _Requirements: 7.4_

  - [x] 12.2 Implement policy evaluation logic
    - Validate requester identity (Planner + Intent Engine)
    - Query OPA for each task in graph
    - Collect policy decisions
    - _Requirements: 7.1, 7.2_

  - [x] 12.3 Implement policy approval signing
    - Generate cryptographic signature for ALLOW decisions
    - Include denial reason for DENY decisions
    - _Requirements: 7.3, 7.5_

  - [x] 12.4 Add authentication middleware
    - Validate JWT + DPoP + mTLS for all requests
    - _Requirements: 11.1, 11.2, 11.3, 11.4_

  - [x] 12.5 Write property test for policy approval signature validity
    - **Property 21: Policy Approval Signature Validity**
    - **Validates: Requirements 7.3, 7.4**

  - [x] 12.6 Write property test for policy denial reason inclusion
    - **Property 22: Policy Denial Reason Inclusion**
    - **Validates: Requirements 7.5**

- [x] 13. Implement Planner Service (services/planner/)
  - [x] 13.1 Create FastAPI application with endpoints
    - POST /plan endpoint
    - GET /health endpoint
    - _Requirements: 5.1, 5.6_

  - [x] 13.2 Implement task graph generation
    - Parse user goal and context
    - Generate task execution graph
    - _Requirements: 5.3_

  - [x] 13.3 Integrate with Intent Engine
    - Call Intent Engine to obtain IntentSignature
    - Attach signature to response
    - _Requirements: 5.4, 5.5_

  - [x] 13.4 Add authentication middleware
    - Validate JWT + DPoP + mTLS for all requests
    - _Requirements: 5.2, 11.1, 11.2, 11.3, 11.4_

  - [x] 13.5 Write property test for task graph generation
    - **Property 18: Task Graph Generation**
    - **Validates: Requirements 5.3, 5.4, 5.5**

  - [x] 13.6 Write property test for service authentication
    - **Property 1: Service Authentication Triple Validation**
    - **Validates: Requirements 5.2, 7.1, 8.1, 11.1, 11.2, 11.3, 11.4, 11.5**

- [x] 14. Checkpoint - Verify core services
  - Ensure all tests pass, ask the user if questions arise.

- [x] 15. Implement Permission Broker service (services/permission-broker/)
  - [x] 15.1 Create FastAPI application with endpoints
    - POST /authorize endpoint
    - GET /health endpoint
    - _Requirements: 8.7_

  - [x] 15.2 Implement authorization chain validation
    - Validate JWT + DPoP + mTLS
    - Verify Safety Agent signature
    - Verify IntentSignature alignment
    - _Requirements: 8.1, 8.2, 8.3_

  - [x] 15.3 Implement RAR construction
    - Build Rich Authorization Request with action type, scopes, locations, purpose, context
    - _Requirements: 8.4_

  - [x] 15.4 Integrate with Auth0 Token Vault
    - Request provider-specific tokens using RAR
    - _Requirements: 8.5_

  - [x] 15.5 Implement ZT-AT construction
    - Build Zero-Trust Authorization Token with full chain
    - Sign with broker private key
    - Set expiration timestamp
    - _Requirements: 8.6_

  - [x] 15.6 Implement failure logging
    - Log all validation failures to Audit Service
    - _Requirements: 8.8_

  - [x] 15.7 Write property test for authorization chain completeness
    - **Property 12: Authorization Chain Completeness**
    - **Validates: Requirements 8.2, 8.3, 8.6, 9.2**

  - [x] 15.8 Write property test for RAR construction
    - **Property 23: Rich Authorization Request Construction**
    - **Validates: Requirements 8.4**

  - [x] 15.9 Write property test for provider token retrieval
    - **Property 24: Provider Token Retrieval**
    - **Validates: Requirements 8.5, 8.7**

  - [x] 15.10 Write property test for authorization failure logging
    - **Property 25: Authorization Failure Logging**
    - **Validates: Requirements 8.8**

- [x] 16. Implement Executor Agent service (services/executor/)
  - [x] 16.1 Create FastAPI application with endpoints
    - POST /execute endpoint
    - GET /health endpoint
    - _Requirements: 9.5_

  - [x] 16.2 Implement ZT-AT validation
    - Validate ZT-AT structure and signatures
    - Check expiration timestamp
    - _Requirements: 9.2, 9.6_

  - [x] 16.3 Implement replay prevention
    - Use Redis to track used ZT-ATs
    - Reject duplicate ZT-ATs
    - _Requirements: 9.1, 9.4_

  - [x] 16.4 Implement provider action execution
    - Extract provider and action from ZT-AT
    - Generate DPoP proof for provider API call
    - Execute action using provider SDK (PyGithub, slack-sdk, google-api-python-client)
    - _Requirements: 9.3_

  - [x] 16.5 Integrate with Audit Service
    - Log all executions with full context
    - _Requirements: 10.2_

  - [x] 16.6 Write property test for ZT-AT replay prevention
    - **Property 11: ZT-AT Replay Prevention**
    - **Validates: Requirements 9.1, 9.4**

  - [x] 16.7 Write property test for DPoP-bound API calls
    - **Property 26: DPoP-Bound API Calls**
    - **Validates: Requirements 9.3**

  - [x] 16.8 Write property test for expired token rejection
    - **Property 27: Expired Token Rejection**
    - **Validates: Requirements 9.6**

- [x] 17. Implement Audit Service (services/audit/)
  - [x] 17.1 Create FastAPI application with endpoints
    - POST /log endpoint
    - GET /verify endpoint
    - GET /logs endpoint with query parameters
    - _Requirements: 10.4_

  - [x] 17.2 Implement hash chain storage
    - Set up PostgreSQL database
    - Create schema for audit log entries
    - Implement append-only insertion
    - _Requirements: 10.1_

  - [x] 17.3 Implement hash chain computation
    - Compute SHA256(previous_hash || entry_data) for each entry
    - Link entries cryptographically
    - _Requirements: 10.3_

  - [x] 17.4 Implement log entry storage
    - Store component identity, action metadata, ZT-AT, DPoP fingerprint
    - _Requirements: 10.2_

  - [x] 17.5 Implement chain verification
    - Verify hash chain integrity
    - Detect tampering
    - _Requirements: 10.5_

  - [x] 17.6 Write property test for hash chain integrity
    - **Property 5: Hash Chain Integrity**
    - **Validates: Requirements 10.1, 10.3, 22.2**

  - [x] 17.7 Write property test for audit log completeness
    - **Property 13: Audit Log Completeness**
    - **Validates: Requirements 10.2, 13.5**

  - [x] 17.8 Write property test for audit log timestamp monotonicity
    - **Property 32: Audit Log Timestamp Monotonicity**
    - **Validates: Requirements 22.3, 22.4, 22.5**

  - [x] 17.9 Write property test for audit log round-trip
    - **Property 4: Audit Log Round-Trip Consistency**
    - **Validates: Requirements 23.5**

- [x] 18. Checkpoint - Verify all services
  - Ensure all tests pass, ask the user if questions arise.

- [x] 19. Implement configuration parser and pretty printer
  - [x] 19.1 Create configuration parser module
    - Parse Auth0 manifest JSON
    - Validate required fields
    - Load DPoP private keys
    - Provide typed interface
    - _Requirements: 18.1, 18.2, 18.3, 18.4, 18.5_

  - [x] 19.2 Create configuration pretty printer module
    - Format Auth0 manifest as readable JSON
    - Format certificate information
    - Format OPA policies with syntax highlighting
    - Redact sensitive information
    - _Requirements: 19.1, 19.2, 19.3, 19.4_

  - [x] 19.3 Write property test for configuration parser validation
    - **Property 28: Configuration Parser Validation**
    - **Validates: Requirements 18.1, 18.3, 18.4**

  - [x] 19.4 Write property test for DPoP key format validation
    - **Property 29: DPoP Key Format Validation**
    - **Validates: Requirements 18.2**

  - [x] 19.5 Write property test for configuration round-trip
    - **Property 2: Configuration Round-Trip Consistency**
    - **Validates: Requirements 19.5**

  - [x] 19.6 Write property test for pretty printer redaction
    - **Property 30: Pretty Printer Redaction**
    - **Validates: Requirements 19.4**

- [x] 20. Implement IntentSignature parser and pretty printer
  - [x] 20.1 Create IntentSignature parser module
    - Deserialize from JSON
    - Validate embedding dimensionality
    - Validate hash format
    - Validate allowed actions list
    - _Requirements: 20.1, 20.2, 20.3, 20.4, 20.5_

  - [x] 20.2 Create IntentSignature pretty printer module
    - Format embedding vectors compactly
    - Display hashes in hexadecimal
    - List allowed actions clearly
    - Include similarity scores
    - _Requirements: 21.1, 21.2, 21.3, 21.4_

  - [x] 20.3 Write property test for IntentSignature validation (already covered in task 2.2)

- [x] 21. Implement Audit Log parser and pretty printer
  - [x] 21.1 Create Audit Log parser module
    - Deserialize from JSON
    - Validate hash chain
    - Validate required fields
    - Validate timestamp monotonicity
    - _Requirements: 22.1, 22.2, 22.3, 22.4, 22.5_

  - [x] 21.2 Create Audit Log pretty printer module
    - Format timestamps in ISO 8601
    - Display component identities with labels
    - Format ZT-AT contents with indentation
    - Display hash chain links with visual indicators
    - _Requirements: 23.1, 23.2, 23.3, 23.4_

  - [x] 21.3 Write property test for audit log parsing (already covered in task 17.8)

- [x] 22. Implement error handling across all services
  - [x] 22.1 Add error handling middleware to all services
    - Handle authentication errors (401)
    - Handle authorization errors (403)
    - Handle execution errors (409, 502)
    - Handle system errors (500, 503)
    - _Requirements: 24.1, 24.2, 24.3, 24.4, 24.5_

  - [x] 22.2 Implement retry logic with exponential backoff
    - Retry network errors up to 3 times
    - Use exponential backoff (1s, 2s, 4s)
    - _Requirements: 24.1_

  - [x] 22.3 Write property test for error handling consistency
    - **Property 33: Error Handling Consistency**
    - **Validates: Requirements 24.1, 24.2, 24.3, 24.4, 24.5**

- [x] 23. Implement token lifetime enforcement
  - [x] 23.1 Configure Auth0 token lifetimes
    - Set JWT lifetime to 5 minutes
    - _Requirements: 12.1_

  - [x] 23.2 Implement token expiration validation in all services
    - Validate JWT expiration
    - Validate ZT-AT expiration
    - Validate DPoP timestamp freshness (60 seconds)
    - Reject expired tokens
    - _Requirements: 12.2, 12.3, 12.4, 12.5_

  - [x] 23.3 Write property test for token lifetime enforcement
    - **Property 6: Token Lifetime Enforcement**
    - **Validates: Requirements 12.3, 12.4, 12.5**

- [x] 24. Implement prompt injection defense
  - [x] 24.1 Integrate intent alignment checks across services
    - Intent Engine computes similarity for all actions
    - Safety Agent rejects misaligned actions
    - Permission Broker refuses tokens for invalid signatures
    - Audit Service logs all rejections
    - _Requirements: 13.1, 13.2, 13.3, 13.4, 13.5_

  - [x] 24.2 Write property test for intent alignment detection
    - **Property 7: Intent Alignment Detection**
    - **Validates: Requirements 13.1, 13.2, 13.3, 13.4**

- [x] 25. Implement provider scope categorization
  - [x] 25.1 Add scope categorization to Auth0 configuration
    - Define read-only scopes per provider
    - Define write-action scopes per provider
    - _Requirements: 1.7_

  - [x] 25.2 Enforce scope distinctions in Permission Broker
    - Validate requested scopes against categories
    - Include appropriate scopes in RAR
    - _Requirements: 1.7_

  - [x] 25.3 Write property test for provider scope categorization
    - **Property 34: Provider Scope Categorization**
    - **Validates: Requirements 1.7**

- [x] 26. Checkpoint - Verify complete system
  - Ensure all tests pass, ask the user if questions arise.

- [x] 27. Create Docker Compose configuration (infra/docker/)
  - [x] 27.1 Write docker-compose.yml
    - Define services for all 6 components
    - Mount certificate directories
    - Inject Auth0 credentials as environment variables
    - Configure internal mTLS-only communication
    - Expose only Permission Broker externally
    - Add health checks
    - _Requirements: 16.1, 16.2, 16.3, 16.4, 16.5, 16.6_

  - [x] 27.2 Create Dockerfiles for each service
    - Use Python 3.14.2+ base image
    - Install dependencies
    - Copy service code
    - Set up entry points

- [x] 28. Create operational scripts (scripts/)
  - [x] 28.1 Create setup_all.sh script
    - Execute Auth0 setup
    - Generate certificates
    - Initialize services
    - Validate prerequisites
    - Output resource summary
    - _Requirements: 17.1, 17.4, 17.5_

  - [x] 28.2 Create run_integration_tests.sh script
    - Run all integration tests
    - Report results
    - _Requirements: 17.2_

  - [x] 28.3 Create rotate_certificates.sh script
    - Regenerate all certificates
    - Update service configurations
    - Perform zero-downtime rotation
    - _Requirements: 17.3_

- [ ] 29. Write integration tests (tests/integration/)
  - [ ] 29.1 Create happy path integration test
    - Test full pipeline: user goal → execution → audit log
    - Verify each component validates previous output
    - Verify audit log completeness
    - Verify provider token retrieval and usage
    - _Requirements: 14.1, 14.2, 14.3, 14.4, 14.5_

  - [ ] 29.2 Write additional integration tests
    - Test token expiration flow
    - Test policy denial flow
    - Test certificate validation flow

- [ ] 30. Write attack scenario tests (tests/attack-scenarios/)
  - [ ] 30.1 Create prompt injection attack test
    - Inject "delete main branch" into benign goal
    - Verify Intent Engine detects mismatch
    - Verify Safety Agent denies evaluation
    - Verify Permission Broker refuses token
    - Verify Executor receives no token
    - Verify Audit Service logs rejection
    - _Requirements: 15.1, 15.2, 15.3, 15.4, 15.5, 15.6_

  - [ ] 30.2 Write additional attack scenario tests
    - Test token theft (JWT without DPoP)
    - Test replay attack (reused ZT-AT)
    - Test certificate spoofing
    - Test policy bypass attempt
    - Test audit tampering detection

- [ ] 31. Final checkpoint - Complete system verification
  - Run all unit tests (>80% coverage)
  - Run all property tests (100 iterations each, 35 properties)
  - Run all integration tests (6 scenarios)
  - Run all attack scenario tests (6 attack vectors)
  - Verify Docker Compose deployment
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional property-based tests that can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation at key milestones
- Property tests validate universal correctness properties using Hypothesis
- Unit tests validate specific examples and edge cases
- Integration tests verify end-to-end flows
- Attack scenario tests validate security controls
- All services use Python 3.14.2+ with FastAPI
- All inter-service communication uses mTLS + JWT + DPoP
- All tokens are short-lived and purpose-bound
- All logs are cryptographically chained
