# Requirements Document: Zero-Trust Agentic Guardian Architecture

## Introduction

The Zero-Trust Agentic Guardian Architecture is a comprehensive multi-agent system designed to execute user-requested tasks through a cryptographically verified authorization chain. The system implements zero-trust security principles where every request is authenticated, authorized, and audited. The architecture protects against prompt injection attacks, enforces policy-based access control, and maintains tamper-evident audit logs. All service-to-service communication uses mutual TLS (mTLS), and all tokens are bound to specific identities and purposes using JWT with DPoP (Demonstrating Proof-of-Possession).

## Glossary

- **Planner_Service**: The service that accepts user goals and generates task execution plans
- **Intent_Engine**: The service that generates cryptographic intent signatures using semantic embeddings
- **Safety_Agent**: The service that evaluates proposed actions against OPA policies and signs approvals
- **Permission_Broker**: The Zero-Trust Policy Enforcement Point that validates the authorization chain and issues tokens
- **Executor_Agent**: The service that performs individual actions using provider-specific tokens
- **Audit_Service**: The service that maintains cryptographically chained, append-only audit logs
- **Auth0_Token_Vault**: Auth0's secure token storage for third-party provider credentials
- **M2M_Application**: Machine-to-Machine application registered in Auth0 for service authentication
- **mTLS**: Mutual Transport Layer Security - bidirectional certificate-based authentication
- **DPoP**: Demonstrating Proof-of-Possession - cryptographic binding of tokens to clients
- **OPA**: Open Policy Agent - policy-based authorization engine
- **IntentSignature**: A cryptographic signature containing semantic embeddings and allowed actions
- **ZT-AT**: Zero-Trust Authorization Token - a composite token containing the full authorization chain
- **RAR**: Rich Authorization Request - detailed authorization request format
- **Provider**: External service (GitHub, Slack, Google Workspace) that the system integrates with
- **JWK**: JSON Web Key - public key representation for cryptographic operations
- **CA**: Certificate Authority - entity that issues digital certificates

## Requirements

### Requirement 1: Auth0 Infrastructure Setup

**User Story:** As a system administrator, I want to configure Auth0 with M2M applications and Token Vault, so that services can authenticate and access provider credentials securely.

#### Acceptance Criteria

1. THE Auth0_Configuration_Script SHALL create exactly five M2M applications with names: planner, safety-agent, permission-broker, executor, intent-engine
2. WHEN creating each M2M application, THE Auth0_Configuration_Script SHALL enable the client_credentials grant type
3. WHEN creating each M2M application, THE Auth0_Configuration_Script SHALL generate a unique DPoP keypair and register the public key as a JWK
4. WHEN all M2M applications are created, THE Auth0_Configuration_Script SHALL output a manifest JSON file containing client_id, jwks_uri, and dpop_private_key_path for each service
5. THE Auth0_Configuration_Script SHALL enable the Auth0 Token Vault feature
6. THE Auth0_Configuration_Script SHALL configure connected accounts for GitHub, Slack, and Google Workspace
7. WHEN configuring provider scopes, THE Auth0_Configuration_Script SHALL distinguish between read-only scopes and write-action scopes for each provider

### Requirement 2: Certificate Infrastructure

**User Story:** As a security engineer, I want to establish a certificate authority and generate mTLS certificates, so that all service-to-service communication is mutually authenticated.

#### Acceptance Criteria

1. THE Certificate_Generation_Script SHALL create a root Certificate Authority with a self-signed certificate
2. WHEN the root CA exists, THE Certificate_Generation_Script SHALL generate both client and server certificates for each of the six services
3. THE Certificate_Generation_Script SHALL store certificates in PEM format within service-specific folders under infra/certificates/
4. THE Certificate_Generation_Script SHALL create an automation script named generate_all_certs.sh that regenerates all certificates
5. WHEN any service establishes a connection, THE Service SHALL enforce mTLS by validating the peer certificate against the root CA

### Requirement 3: Policy Definition and Enforcement

**User Story:** As a compliance officer, I want to define authorization policies in OPA, so that the system enforces business rules and security constraints.

#### Acceptance Criteria

1. THE OPA_Policy_Repository SHALL contain a policy that denies destructive GitHub actions unless the requester role equals admin
2. THE OPA_Policy_Repository SHALL contain a policy that enforces spending limits for cloud resource actions
3. THE OPA_Policy_Repository SHALL contain a policy that restricts actions to allowed categories defined per service
4. THE OPA_Policy_Repository SHALL contain a policy that requires intent alignment scores to exceed a minimum threshold
5. THE Safety_Agent SHALL use a Python OPA client to evaluate policies against proposed actions

### Requirement 4: Shared Library Components

**User Story:** As a developer, I want reusable libraries for authentication and authorization, so that all services implement security consistently.

#### Acceptance Criteria

1. THE JWT_Library SHALL validate JWT tokens by verifying signature, issuer, audience, and expiration
2. THE JWT_Library SHALL validate nonce uniqueness and timestamp freshness to prevent replay attacks
3. THE DPoP_Library SHALL generate DPoP proof tokens bound to specific HTTP requests
4. THE DPoP_Library SHALL verify DPoP proofs by validating signature, token binding, and request matching
5. THE mTLS_Library SHALL load certificates from PEM files and extract client identity from certificate subject
6. THE Schema_Library SHALL define Pydantic models for IntentSignature, PolicyDecision, ZT-AT, and RAR
7. THE Logging_Library SHALL output structured JSON logs with correlation IDs and audit hooks

### Requirement 5: Task Planning Service

**User Story:** As a user, I want to submit goals to the Planner, so that the system generates an execution plan for my request.

#### Acceptance Criteria

1. THE Planner_Service SHALL expose a FastAPI endpoint at POST /plan that accepts user goals
2. WHEN receiving a request, THE Planner_Service SHALL validate the JWT, DPoP proof, and mTLS client certificate
3. WHEN a valid request is received, THE Planner_Service SHALL generate a task graph representing the execution plan
4. WHEN the task graph is generated, THE Planner_Service SHALL call the Intent_Engine to obtain an IntentSignature
5. WHEN the IntentSignature is received, THE Planner_Service SHALL return the proposed actions with the signature to the caller
6. THE Planner_Service SHALL expose a GET /health endpoint for service health checks

### Requirement 6: Intent Signature Generation

**User Story:** As a security architect, I want to generate semantic intent signatures, so that the system can detect prompt injection and intent drift.

#### Acceptance Criteria

1. THE Intent_Engine SHALL use sentence-transformer models to generate embeddings from user goals
2. THE Intent_Engine SHALL create IntentSignature objects containing the embedding vector, cryptographic hash, and allowed action list
3. WHEN verifying intent, THE Intent_Engine SHALL compute similarity scores between the original intent and proposed actions
4. THE Intent_Engine SHALL expose a POST /sign-intent endpoint that generates intent signatures
5. THE Intent_Engine SHALL expose a POST /verify-intent endpoint that validates intent alignment

### Requirement 7: Policy Evaluation and Approval

**User Story:** As a security officer, I want the Safety Agent to evaluate all actions against policies, so that unauthorized or dangerous actions are blocked.

#### Acceptance Criteria

1. THE Safety_Agent SHALL validate the identity of the Planner_Service and Intent_Engine using JWT and mTLS
2. WHEN receiving an evaluation request, THE Safety_Agent SHALL query OPA with the proposed actions and context
3. WHEN OPA returns a policy decision, THE Safety_Agent SHALL generate a cryptographic signature using its private key
4. THE Safety_Agent SHALL expose a POST /evaluate endpoint that returns ALLOW or DENY decisions with signed approvals
5. IF the policy decision is DENY, THEN THE Safety_Agent SHALL include the denial reason in the response

### Requirement 8: Zero-Trust Authorization

**User Story:** As a security architect, I want the Permission Broker to validate the complete authorization chain, so that only verified requests receive provider tokens.

#### Acceptance Criteria

1. THE Permission_Broker SHALL validate JWT, DPoP proof, and mTLS certificate for all incoming requests
2. WHEN receiving an authorization request, THE Permission_Broker SHALL verify the Safety_Agent signature on the policy approval
3. WHEN the policy approval is valid, THE Permission_Broker SHALL verify the IntentSignature alignment
4. WHEN all validations pass, THE Permission_Broker SHALL construct a Rich Authorization Request for the specific provider action
5. WHEN the RAR is constructed, THE Permission_Broker SHALL request a provider-specific token from Auth0_Token_Vault
6. WHEN the provider token is received, THE Permission_Broker SHALL construct a Zero-Trust Authorization Token containing the full authorization chain
7. THE Permission_Broker SHALL expose a POST /authorize endpoint that returns ZT-AT and short-lived provider tokens
8. IF any validation fails, THEN THE Permission_Broker SHALL deny the request and log the failure reason

### Requirement 9: Action Execution

**User Story:** As a system operator, I want the Executor to perform individual actions safely, so that only authorized operations are executed against providers.

#### Acceptance Criteria

1. THE Executor_Agent SHALL implement a single-action execution model where each action requires a separate authorization
2. WHEN receiving an execution request, THE Executor_Agent SHALL validate the ZT-AT structure and signatures
3. WHEN the ZT-AT is valid, THE Executor_Agent SHALL extract the provider-specific token and perform the action using DPoP-bound API calls
4. THE Executor_Agent SHALL reject any action that has already been executed using the same ZT-AT
5. THE Executor_Agent SHALL expose a POST /execute endpoint that accepts ZT-AT and action parameters
6. IF the ZT-AT is invalid or expired, THEN THE Executor_Agent SHALL reject the request without performing the action

### Requirement 10: Audit Logging

**User Story:** As a compliance auditor, I want cryptographically chained audit logs, so that I can verify the integrity of all system actions.

#### Acceptance Criteria

1. THE Audit_Service SHALL maintain an append-only log structure where each entry is cryptographically linked to the previous entry
2. WHEN logging an action, THE Audit_Service SHALL store the component identity, action metadata, ZT-AT contents, and DPoP fingerprint
3. THE Audit_Service SHALL compute a hash chain where each log entry includes the hash of the previous entry
4. THE Audit_Service SHALL expose a POST /log endpoint that accepts audit entries
5. WHEN querying logs, THE Audit_Service SHALL provide verification that the hash chain is intact and unmodified

### Requirement 11: Service Communication Security

**User Story:** As a security engineer, I want all service-to-service communication to use mTLS, JWT, and DPoP, so that every request is authenticated and bound to the caller.

#### Acceptance Criteria

1. WHEN any service makes a request to another service, THE Service SHALL establish an mTLS connection using its client certificate
2. WHEN making a request, THE Service SHALL obtain a JWT access token from Auth0 using the client_credentials grant
3. WHEN making a request, THE Service SHALL generate a DPoP proof token bound to the specific HTTP request and JWT
4. WHEN receiving a request, THE Service SHALL validate the mTLS certificate, JWT token, and DPoP proof before processing
5. IF any validation fails, THEN THE Service SHALL reject the request and return an authentication error

### Requirement 12: Token Lifecycle Management

**User Story:** As a security architect, I want all tokens to be short-lived and purpose-bound, so that compromised tokens have limited impact.

#### Acceptance Criteria

1. THE Auth0_Configuration SHALL set JWT access token lifetime to a maximum of 5 minutes
2. THE Permission_Broker SHALL issue provider tokens with the minimum lifetime required for the specific action
3. THE ZT-AT SHALL include an expiration timestamp that is validated by the Executor_Agent
4. THE DPoP_Proof SHALL include a timestamp that is validated to be within 60 seconds of the current time
5. WHEN a token expires, THE Service SHALL reject any request using that token

### Requirement 13: Prompt Injection Defense

**User Story:** As a security researcher, I want the system to detect and block prompt injection attacks, so that malicious instructions cannot override the original user intent.

#### Acceptance Criteria

1. WHEN the Intent_Engine receives a verification request, THE Intent_Engine SHALL compute semantic similarity between the original intent and each proposed action
2. IF the similarity score falls below the configured threshold, THEN THE Intent_Engine SHALL flag the action as misaligned
3. WHEN the Safety_Agent evaluates actions, THE Safety_Agent SHALL reject any action flagged as misaligned by the Intent_Engine
4. THE Permission_Broker SHALL refuse to issue tokens for actions that lack valid IntentSignature verification
5. THE Audit_Service SHALL log all rejected actions with the reason for rejection

### Requirement 14: Integration Testing

**User Story:** As a QA engineer, I want comprehensive integration tests, so that I can verify the complete authorization flow works correctly.

#### Acceptance Criteria

1. THE Integration_Test_Suite SHALL include a test that executes the full pipeline from user goal to action execution
2. THE Integration_Test SHALL verify that a valid user goal results in successful action execution and audit log entry
3. THE Integration_Test SHALL verify that each component in the chain validates the previous component's output
4. THE Integration_Test SHALL verify that the Audit_Service contains a complete record of the authorization chain
5. THE Integration_Test SHALL verify that provider tokens are successfully retrieved from Auth0_Token_Vault and used for API calls

### Requirement 15: Attack Scenario Testing

**User Story:** As a security tester, I want to verify the system blocks malicious inputs, so that I can confirm the security controls are effective.

#### Acceptance Criteria

1. THE Attack_Scenario_Test SHALL inject a prompt containing "delete main branch" into a benign user goal
2. THE Attack_Scenario_Test SHALL verify that the Intent_Engine detects the intent mismatch
3. THE Attack_Scenario_Test SHALL verify that the Safety_Agent denies the policy evaluation
4. THE Attack_Scenario_Test SHALL verify that the Permission_Broker refuses the token request
5. THE Attack_Scenario_Test SHALL verify that the Executor_Agent receives no token and performs no action
6. THE Attack_Scenario_Test SHALL verify that the Audit_Service logs the rejection with full context

### Requirement 16: Deployment Infrastructure

**User Story:** As a DevOps engineer, I want Docker Compose configuration for all services, so that I can deploy the complete system consistently.

#### Acceptance Criteria

1. THE Docker_Compose_Configuration SHALL define services for all six components: Planner, Intent Engine, Safety Agent, Permission Broker, Executor, and Audit
2. THE Docker_Compose_Configuration SHALL mount certificate directories into each service container
3. THE Docker_Compose_Configuration SHALL inject Auth0 credentials as environment variables
4. THE Docker_Compose_Configuration SHALL configure internal services to communicate only over mTLS
5. THE Docker_Compose_Configuration SHALL expose only the Permission_Broker endpoint to external clients
6. THE Docker_Compose_Configuration SHALL include health checks for all services

### Requirement 17: Operational Scripts

**User Story:** As a system administrator, I want automation scripts for setup and maintenance, so that I can manage the system efficiently.

#### Acceptance Criteria

1. THE Setup_Script SHALL execute all configuration steps including Auth0 setup, certificate generation, and service initialization
2. THE Integration_Test_Script SHALL run all integration tests and report results
3. THE Certificate_Rotation_Script SHALL regenerate all certificates and update service configurations without downtime
4. THE Setup_Script SHALL validate that all prerequisites are met before proceeding with configuration
5. THE Setup_Script SHALL output a summary of all created resources and their locations

### Requirement 18: Configuration Parsing and Validation

**User Story:** As a developer, I want to parse and validate the Auth0 manifest, so that services can load their credentials correctly.

#### Acceptance Criteria

1. THE Configuration_Parser SHALL read the Auth0 manifest JSON file and extract service-specific credentials
2. WHEN loading DPoP private keys, THE Configuration_Parser SHALL validate the key format and cryptographic parameters
3. THE Configuration_Parser SHALL validate that all required fields are present in the manifest
4. IF the manifest is invalid or incomplete, THEN THE Configuration_Parser SHALL raise a descriptive error
5. THE Configuration_Parser SHALL provide a typed interface for accessing configuration values

### Requirement 19: Pretty Printing for Configuration

**User Story:** As a system administrator, I want human-readable output of configuration, so that I can verify settings and troubleshoot issues.

#### Acceptance Criteria

1. THE Configuration_Pretty_Printer SHALL format the Auth0 manifest as readable JSON with proper indentation
2. THE Configuration_Pretty_Printer SHALL format certificate information including subject, issuer, and expiration dates
3. THE Configuration_Pretty_Printer SHALL format OPA policies with syntax highlighting
4. WHEN printing sensitive information, THE Configuration_Pretty_Printer SHALL redact private keys and secrets
5. FOR ALL valid configuration objects, parsing then pretty printing then parsing SHALL produce an equivalent object

### Requirement 20: Intent Signature Parsing and Validation

**User Story:** As a developer, I want to parse and validate IntentSignature objects, so that services can verify intent alignment correctly.

#### Acceptance Criteria

1. THE IntentSignature_Parser SHALL deserialize IntentSignature objects from JSON format
2. THE IntentSignature_Parser SHALL validate that embedding vectors have the correct dimensionality
3. THE IntentSignature_Parser SHALL validate that cryptographic hashes match the expected format
4. THE IntentSignature_Parser SHALL validate that allowed action lists are non-empty
5. IF the IntentSignature is malformed, THEN THE IntentSignature_Parser SHALL raise a validation error

### Requirement 21: Pretty Printing for Intent Signatures

**User Story:** As a security analyst, I want readable output of IntentSignature objects, so that I can audit intent verification decisions.

#### Acceptance Criteria

1. THE IntentSignature_Pretty_Printer SHALL format embedding vectors in a compact, readable format
2. THE IntentSignature_Pretty_Printer SHALL display cryptographic hashes in hexadecimal format
3. THE IntentSignature_Pretty_Printer SHALL list allowed actions with clear formatting
4. THE IntentSignature_Pretty_Printer SHALL include similarity scores when displaying verification results
5. FOR ALL valid IntentSignature objects, parsing then pretty printing then parsing SHALL produce an equivalent object

### Requirement 22: Audit Log Parsing and Validation

**User Story:** As a compliance auditor, I want to parse and validate audit logs, so that I can verify the integrity of the audit trail.

#### Acceptance Criteria

1. THE Audit_Log_Parser SHALL deserialize audit log entries from JSON format
2. THE Audit_Log_Parser SHALL validate the hash chain by recomputing hashes and comparing with stored values
3. THE Audit_Log_Parser SHALL validate that all required fields are present in each log entry
4. THE Audit_Log_Parser SHALL validate that timestamps are monotonically increasing
5. IF the hash chain is broken or invalid, THEN THE Audit_Log_Parser SHALL raise an integrity error

### Requirement 23: Pretty Printing for Audit Logs

**User Story:** As a compliance auditor, I want human-readable audit logs, so that I can review system activity efficiently.

#### Acceptance Criteria

1. THE Audit_Log_Pretty_Printer SHALL format audit entries with timestamps in ISO 8601 format
2. THE Audit_Log_Pretty_Printer SHALL display component identities with clear labels
3. THE Audit_Log_Pretty_Printer SHALL format ZT-AT contents with proper indentation
4. THE Audit_Log_Pretty_Printer SHALL display hash chain links with visual indicators
5. FOR ALL valid audit log sequences, parsing then pretty printing then parsing SHALL produce an equivalent sequence

### Requirement 24: Error Handling and Recovery

**User Story:** As a system operator, I want graceful error handling, so that transient failures don't cause system-wide outages.

#### Acceptance Criteria

1. WHEN a service encounters a network error, THE Service SHALL retry the request with exponential backoff up to 3 attempts
2. WHEN a service receives an invalid token, THE Service SHALL return a 401 Unauthorized response with a descriptive error message
3. WHEN a service encounters an internal error, THE Service SHALL log the error with full context and return a 500 Internal Server Error response
4. WHEN Auth0 is unavailable, THE Service SHALL return a 503 Service Unavailable response and log the outage
5. WHEN certificate validation fails, THE Service SHALL reject the connection and log the certificate details for debugging
