# Design Document: Zero-Trust Agentic Guardian Architecture

## Overview

The Zero-Trust Agentic Guardian Architecture implements a multi-agent system where every request flows through a cryptographically verified authorization chain. The system consists of six microservices that communicate using mutual TLS (mTLS), JWT tokens, and DPoP (Demonstrating Proof-of-Possession) token binding. The architecture prevents prompt injection attacks through semantic intent verification, enforces policy-based access control using Open Policy Agent (OPA), and maintains tamper-evident audit logs using cryptographic hash chains.

The authorization flow follows this sequence:
1. User submits a goal to the Planner Service
2. Planner generates a task graph and requests an Intent Signature from the Intent Engine
3. Safety Agent evaluates the plan against OPA policies and signs the approval
4. Permission Broker validates the complete chain and requests provider tokens from Auth0 Token Vault
5. Executor Agent performs individual actions using the provider tokens
6. Audit Service logs every step with cryptographic verification

All services authenticate using Auth0 M2M (Machine-to-Machine) applications with client credentials flow. Provider credentials (GitHub, Slack, Google Workspace) are stored in Auth0 Token Vault and accessed through Rich Authorization Requests (RAR).

## Architecture

### System Components

**Planner Service** (`services/planner/`)
- Accepts user goals via REST API
- Generates task execution graphs
- Coordinates with Intent Engine for semantic verification
- Returns proposed action plans

**Intent Engine** (`services/intent-engine/`)
- Generates semantic embeddings using sentence-transformers
- Creates cryptographic Intent Signatures
- Verifies intent alignment between original goals and proposed actions
- Detects prompt injection through similarity scoring

**Safety Agent** (`services/safety-agent/`)
- Evaluates actions against OPA policies
- Validates identity of requesting services
- Signs policy approvals with private key
- Enforces business rules and security constraints

**Permission Broker** (`services/permission-broker/`)
- Acts as Zero-Trust Policy Enforcement Point (PEP)
- Validates complete authorization chain
- Constructs Rich Authorization Requests (RAR)
- Issues Zero-Trust Authorization Tokens (ZT-AT)
- Interfaces with Auth0 Token Vault

**Executor Agent** (`services/executor/`)
- Executes individual actions against providers
- Validates ZT-AT before execution
- Prevents token reuse
- Makes DPoP-bound API calls

**Audit Service** (`services/audit/`)
- Maintains append-only, hash-chained logs
- Stores complete authorization context
- Provides tamper-evident audit trail
- Enables compliance verification

### Communication Security

All service-to-service communication uses a triple authentication mechanism:

1. **mTLS (Mutual TLS)**: Both client and server present X.509 certificates signed by the internal CA. This provides transport-layer authentication and encryption.

2. **JWT (JSON Web Token)**: Services obtain access tokens from Auth0 using client_credentials grant. Tokens include issuer, audience, expiration, and service identity claims.

3. **DPoP (Demonstrating Proof-of-Possession)**: Each request includes a DPoP proof token that cryptographically binds the JWT to the client's private key and the specific HTTP request. This prevents token theft and replay attacks.

### Infrastructure Components

**Auth0 Configuration** (`infra/auth0/`)
- Five M2M applications (one per service)
- DPoP keypairs registered as JWKs
- Token Vault enabled with connected accounts
- Provider-specific scopes configured

**Certificate Infrastructure** (`infra/certificates/`)
- Root CA for internal PKI
- Client and server certificates per service
- Automated certificate generation and rotation
- PEM format storage

**OPA Policies** (`infra/opa/`)
- Policy definitions in Rego language
- Role-based access control rules
- Spending limit enforcement
- Intent alignment thresholds

**Shared Libraries** (`shared/`)
- JWT validation and generation
- DPoP proof creation and verification
- mTLS certificate handling
- Pydantic data models
- Structured logging with correlation IDs

## Components and Interfaces

### Planner Service

**Technology Stack:**
- FastAPI for REST API
- Python 3.14.2+
- Pydantic for data validation
- httpx for async HTTP client

**Endpoints:**

```
POST /plan
Request:
{
  "user_goal": "string",
  "user_id": "string",
  "context": {
    "role": "string",
    "allowed_providers": ["string"]
  }
}

Response:
{
  "plan_id": "string",
  "task_graph": [
    {
      "task_id": "string",
      "action": "string",
      "provider": "string",
      "dependencies": ["string"]
    }
  ],
  "intent_signature": {
    "embedding": [float],
    "hash": "string",
    "allowed_actions": ["string"],
    "timestamp": "string"
  }
}

GET /health
Response:
{
  "status": "healthy",
  "version": "string"
}
```

**Internal Logic:**
1. Validate incoming JWT + DPoP + mTLS
2. Parse user goal and context
3. Generate task graph using planning algorithm
4. Call Intent Engine with user goal
5. Attach Intent Signature to response
6. Log request to Audit Service

**Configuration:**
- Auth0 client credentials
- DPoP private key path
- mTLS certificate paths
- Intent Engine service URL
- Audit Service URL

### Intent Engine

**Technology Stack:**
- FastAPI for REST API
- sentence-transformers library (all-MiniLM-L6-v2 model)
- numpy for vector operations
- cryptography library for hashing

**Endpoints:**

```
POST /sign-intent
Request:
{
  "user_goal": "string",
  "allowed_actions": ["string"]
}

Response:
{
  "intent_signature": {
    "embedding": [float],
    "hash": "string",
    "allowed_actions": ["string"],
    "timestamp": "string",
    "signature": "string"
  }
}

POST /verify-intent
Request:
{
  "intent_signature": {
    "embedding": [float],
    "hash": "string",
    "allowed_actions": ["string"],
    "timestamp": "string",
    "signature": "string"
  },
  "proposed_action": "string"
}

Response:
{
  "aligned": boolean,
  "similarity_score": float,
  "threshold": float
}
```

**Internal Logic:**
1. Load sentence-transformer model on startup
2. For sign-intent: Generate embedding from user goal, compute hash, create signature
3. For verify-intent: Generate embedding from proposed action, compute cosine similarity
4. Compare similarity against threshold (default: 0.7)
5. Return alignment decision

**Configuration:**
- Model name: all-MiniLM-L6-v2
- Similarity threshold: 0.7
- Private key for signing
- Auth0 credentials

### Safety Agent

**Technology Stack:**
- FastAPI for REST API
- OPA Python client library
- cryptography library for signing
- PyJWT for token validation

**Endpoints:**

```
POST /evaluate
Request:
{
  "plan_id": "string",
  "task_graph": [
    {
      "task_id": "string",
      "action": "string",
      "provider": "string"
    }
  ],
  "intent_signature": {...},
  "requester_identity": {
    "service": "string",
    "certificate_subject": "string"
  },
  "context": {
    "user_id": "string",
    "role": "string"
  }
}

Response:
{
  "decision": "ALLOW" | "DENY",
  "policy_approval": {
    "decision": "string",
    "reason": "string",
    "evaluated_policies": ["string"],
    "signature": "string",
    "timestamp": "string"
  }
}
```

**Internal Logic:**
1. Validate requester identity (Planner + Intent Engine)
2. For each task in graph:
   - Construct OPA input document
   - Query OPA policy engine
   - Collect policy decisions
3. If all policies allow, sign approval with private key
4. Return decision with signature

**OPA Policy Structure:**
```rego
package agentic_guardian

# Deny destructive GitHub actions unless admin
deny[msg] {
  input.action == "delete_branch"
  input.provider == "github"
  input.context.role != "admin"
  msg := "Destructive GitHub actions require admin role"
}

# Enforce spending limits
deny[msg] {
  input.action == "create_instance"
  input.provider == "aws"
  input.estimated_cost > input.context.spending_limit
  msg := "Action exceeds spending limit"
}

# Require intent alignment
deny[msg] {
  input.intent_alignment_score < 0.7
  msg := "Intent alignment score below threshold"
}
```

**Configuration:**
- OPA server URL
- Policy bundle path
- Private key for signing
- Auth0 credentials

### Permission Broker

**Technology Stack:**
- FastAPI for REST API
- Auth0 Management API client
- cryptography library for verification
- PyJWT for token handling

**Endpoints:**

```
POST /authorize
Request:
{
  "plan_id": "string",
  "task_id": "string",
  "action": "string",
  "provider": "string",
  "policy_approval": {
    "decision": "string",
    "signature": "string",
    "timestamp": "string"
  },
  "intent_signature": {...}
}

Response:
{
  "zt_at": {
    "plan_id": "string",
    "task_id": "string",
    "action": "string",
    "provider": "string",
    "policy_approval": {...},
    "intent_signature": {...},
    "broker_signature": "string",
    "issued_at": "string",
    "expires_at": "string"
  },
  "provider_token": {
    "access_token": "string",
    "token_type": "Bearer",
    "expires_in": int,
    "scope": "string"
  }
}
```

**Internal Logic:**
1. Validate JWT + DPoP + mTLS from requester
2. Verify Safety Agent signature on policy approval
3. Verify Intent Signature alignment
4. Construct Rich Authorization Request (RAR):
   ```json
   {
     "type": "github_action",
     "actions": ["repo:write"],
     "locations": ["https://github.com/org/repo"],
     "purpose": "task_execution",
     "context": {
       "plan_id": "...",
       "task_id": "...",
       "intent_hash": "..."
     }
   }
   ```
5. Request provider token from Auth0 Token Vault
6. Construct Zero-Trust Authorization Token (ZT-AT)
7. Sign ZT-AT with broker private key
8. Return ZT-AT and provider token

**Configuration:**
- Auth0 domain and credentials
- Token Vault API endpoint
- Private key for signing
- Public keys for verification (Safety Agent, Intent Engine)

### Executor Agent

**Technology Stack:**
- FastAPI for REST API
- httpx for async HTTP with DPoP
- Provider-specific SDK clients (PyGithub, slack-sdk, google-api-python-client)
- Redis for token deduplication

**Endpoints:**

```
POST /execute
Request:
{
  "zt_at": {...},
  "provider_token": {
    "access_token": "string",
    "token_type": "Bearer"
  },
  "action_params": {
    "repository": "string",
    "branch": "string",
    ...
  }
}

Response:
{
  "execution_id": "string",
  "status": "success" | "failure",
  "result": {...},
  "timestamp": "string"
}
```

**Internal Logic:**
1. Validate ZT-AT structure and signatures
2. Check ZT-AT expiration
3. Verify ZT-AT has not been used before (check Redis)
4. Store ZT-AT hash in Redis with TTL
5. Extract provider and action from ZT-AT
6. Generate DPoP proof for provider API call
7. Execute action using provider SDK
8. Log execution to Audit Service
9. Return result

**Provider Action Mapping:**
```python
PROVIDER_ACTIONS = {
    "github": {
        "create_branch": github_client.create_branch,
        "create_pr": github_client.create_pull_request,
        "list_repos": github_client.list_repositories,
    },
    "slack": {
        "send_message": slack_client.chat_postMessage,
        "list_channels": slack_client.conversations_list,
    },
    "google_workspace": {
        "send_email": gmail_client.send_message,
        "create_doc": docs_client.create_document,
    }
}
```

**Configuration:**
- Provider API endpoints
- DPoP private key
- Redis connection string
- Public keys for ZT-AT verification

### Audit Service

**Technology Stack:**
- FastAPI for REST API
- PostgreSQL for log storage
- cryptography library for hashing
- Pydantic for log entry validation

**Endpoints:**

```
POST /log
Request:
{
  "component": "string",
  "event_type": "string",
  "action_metadata": {...},
  "zt_at": {...},
  "dpop_fingerprint": "string",
  "timestamp": "string"
}

Response:
{
  "log_id": "string",
  "hash": "string",
  "previous_hash": "string"
}

GET /verify
Response:
{
  "chain_valid": boolean,
  "total_entries": int,
  "first_hash": "string",
  "last_hash": "string"
}

GET /logs?plan_id={plan_id}
Response:
{
  "logs": [
    {
      "log_id": "string",
      "component": "string",
      "event_type": "string",
      "timestamp": "string",
      "hash": "string",
      "previous_hash": "string"
    }
  ]
}
```

**Internal Logic:**
1. Receive log entry
2. Retrieve previous log entry hash
3. Compute current entry hash: `SHA256(previous_hash || entry_data)`
4. Store entry with hash chain link
5. Return log ID and hash

**Hash Chain Structure:**
```
Entry 0: hash = SHA256("genesis" || data_0)
Entry 1: hash = SHA256(hash_0 || data_1)
Entry 2: hash = SHA256(hash_1 || data_2)
...
```

**Configuration:**
- Database connection string
- Genesis hash value
- Auth0 credentials

## Data Models

### IntentSignature

```python
from pydantic import BaseModel, Field
from typing import List
from datetime import datetime

class IntentSignature(BaseModel):
    embedding: List[float] = Field(..., description="Semantic embedding vector")
    hash: str = Field(..., description="SHA256 hash of user goal")
    allowed_actions: List[str] = Field(..., description="List of permitted action types")
    timestamp: datetime = Field(..., description="Signature creation time")
    signature: str = Field(..., description="Cryptographic signature")

    class Config:
        json_schema_extra = {
            "example": {
                "embedding": [0.123, -0.456, ...],
                "hash": "a1b2c3d4...",
                "allowed_actions": ["github:create_branch", "github:create_pr"],
                "timestamp": "2024-01-15T10:30:00Z",
                "signature": "e5f6g7h8..."
            }
        }
```

### PolicyDecision

```python
class PolicyDecision(BaseModel):
    decision: str = Field(..., pattern="^(ALLOW|DENY)$")
    reason: str = Field(..., description="Human-readable explanation")
    evaluated_policies: List[str] = Field(..., description="List of policy names evaluated")
    signature: str = Field(..., description="Safety Agent signature")
    timestamp: datetime = Field(..., description="Decision time")
    signer_identity: str = Field(..., description="Certificate subject of signer")
```

### RichAuthorizationRequest

```python
class RichAuthorizationRequest(BaseModel):
    type: str = Field(..., description="Action type identifier")
    actions: List[str] = Field(..., description="Required OAuth scopes")
    locations: List[str] = Field(..., description="Resource URLs")
    purpose: str = Field(..., description="Purpose of access")
    context: dict = Field(..., description="Additional context")

    class Config:
        json_schema_extra = {
            "example": {
                "type": "github_action",
                "actions": ["repo:write"],
                "locations": ["https://github.com/org/repo"],
                "purpose": "task_execution",
                "context": {
                    "plan_id": "plan_123",
                    "task_id": "task_456",
                    "intent_hash": "a1b2c3..."
                }
            }
        }
```

### ZeroTrustAuthorizationToken

```python
class ZeroTrustAuthorizationToken(BaseModel):
    plan_id: str = Field(..., description="Unique plan identifier")
    task_id: str = Field(..., description="Unique task identifier")
    action: str = Field(..., description="Action to be performed")
    provider: str = Field(..., description="Target provider")
    policy_approval: PolicyDecision = Field(..., description="Safety Agent approval")
    intent_signature: IntentSignature = Field(..., description="Intent verification")
    broker_signature: str = Field(..., description="Permission Broker signature")
    issued_at: datetime = Field(..., description="Token issuance time")
    expires_at: datetime = Field(..., description="Token expiration time")
    nonce: str = Field(..., description="Unique nonce for replay prevention")
```

### AuditLogEntry

```python
class AuditLogEntry(BaseModel):
    log_id: str = Field(..., description="Unique log entry ID")
    component: str = Field(..., description="Service that generated the log")
    event_type: str = Field(..., description="Type of event")
    action_metadata: dict = Field(..., description="Action-specific data")
    zt_at: Optional[ZeroTrustAuthorizationToken] = Field(None, description="Associated ZT-AT")
    dpop_fingerprint: str = Field(..., description="DPoP key fingerprint")
    timestamp: datetime = Field(..., description="Event timestamp")
    hash: str = Field(..., description="Current entry hash")
    previous_hash: str = Field(..., description="Previous entry hash")
```

### DPoPProof

```python
class DPoPProof(BaseModel):
    jti: str = Field(..., description="Unique token identifier")
    htm: str = Field(..., description="HTTP method")
    htu: str = Field(..., description="HTTP URI")
    iat: int = Field(..., description="Issued at timestamp")
    ath: str = Field(..., description="Access token hash")

    def generate_proof(self, private_key, access_token: str, method: str, url: str) -> str:
        """Generate DPoP proof JWT"""
        import jwt
        import hashlib
        import time
        import uuid

        # Compute access token hash
        token_hash = hashlib.sha256(access_token.encode()).hexdigest()

        # Create proof payload
        payload = {
            "jti": str(uuid.uuid4()),
            "htm": method,
            "htu": url,
            "iat": int(time.time()),
            "ath": token_hash
        }

        # Sign with private key
        proof = jwt.encode(payload, private_key, algorithm="RS256", headers={"typ": "dpop+jwt"})
        return proof
```

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system—essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*


### Property 1: Service Authentication Triple Validation

*For any* inter-service request, the receiving service should validate all three authentication mechanisms (mTLS certificate, JWT token, and DPoP proof) and reject the request if any validation fails.

**Validates: Requirements 5.2, 7.1, 8.1, 11.1, 11.2, 11.3, 11.4, 11.5**

### Property 2: Configuration Round-Trip Consistency

*For any* valid configuration object (Auth0 manifest), parsing then pretty printing then parsing should produce an equivalent object with all fields preserved.

**Validates: Requirements 19.5**

### Property 3: IntentSignature Round-Trip Consistency

*For any* valid IntentSignature object, parsing then pretty printing then parsing should produce an equivalent object with embedding vectors, hashes, and allowed actions preserved.

**Validates: Requirements 21.5**

### Property 4: Audit Log Round-Trip Consistency

*For any* valid audit log sequence, parsing then pretty printing then parsing should produce an equivalent sequence with all entries and hash chain links preserved.

**Validates: Requirements 23.5**

### Property 5: Hash Chain Integrity

*For any* sequence of audit log entries, each entry's hash should equal SHA256(previous_hash || entry_data), and any modification to an entry should break the chain and be detectable during verification.

**Validates: Requirements 10.1, 10.3, 22.2**

### Property 6: Token Lifetime Enforcement

*For any* token (JWT, ZT-AT, DPoP proof, or provider token), if the current time exceeds the token's expiration timestamp, then all services should reject requests using that token.

**Validates: Requirements 12.3, 12.4, 12.5**

### Property 7: Intent Alignment Detection

*For any* user goal and proposed action, if the semantic similarity score between them falls below the configured threshold (0.7), then the Intent Engine should flag the action as misaligned, the Safety Agent should reject it, and the Permission Broker should refuse to issue tokens for it.

**Validates: Requirements 13.1, 13.2, 13.3, 13.4**

### Property 8: OPA Policy Enforcement

*For any* proposed action and policy context, the Safety Agent should query OPA with the action details, and if any policy returns a deny decision, the Safety Agent should return DENY with the policy reason.

**Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5**

### Property 9: M2M Application Uniqueness

*For any* two M2M applications in the Auth0 manifest, their client_id values should be distinct and their DPoP keypairs should be cryptographically unique.

**Validates: Requirements 1.2, 1.3, 1.4**

### Property 10: Certificate Chain Validation

*For any* service certificate (client or server), the certificate should be signed by the root CA, and mTLS connections should reject certificates not signed by the trusted root CA.

**Validates: Requirements 2.2, 2.3, 2.5**

### Property 11: ZT-AT Replay Prevention

*For any* ZT-AT, if the Executor Agent has already executed an action using that ZT-AT, then subsequent execution requests with the same ZT-AT should be rejected.

**Validates: Requirements 9.1, 9.4**

### Property 12: Authorization Chain Completeness

*For any* ZT-AT issued by the Permission Broker, the token should contain a valid PolicyDecision from the Safety Agent, a valid IntentSignature from the Intent Engine, and a valid broker signature, and the Executor Agent should validate all three before execution.

**Validates: Requirements 8.2, 8.3, 8.6, 9.2**

### Property 13: Audit Log Completeness

*For any* action executed by the Executor Agent, the Audit Service should contain a log entry with the component identity, action metadata, ZT-AT contents, and DPoP fingerprint.

**Validates: Requirements 10.2, 13.5**

### Property 14: JWT Validation Completeness

*For any* JWT token, the JWT library should validate the signature, issuer, audience, expiration, nonce uniqueness, and timestamp freshness, and reject tokens that fail any validation.

**Validates: Requirements 4.1, 4.2**

### Property 15: DPoP Proof Binding

*For any* DPoP proof token, the proof should be cryptographically bound to the specific HTTP method, URL, and JWT access token, and verification should fail if any of these elements are modified.

**Validates: Requirements 4.3, 4.4**

### Property 16: Certificate Identity Extraction

*For any* valid PEM certificate, the mTLS library should successfully load the certificate and extract the client identity from the certificate subject field.

**Validates: Requirements 4.5**

### Property 17: Structured Logging Format

*For any* log entry produced by the logging library, the output should be valid JSON containing a correlation ID and all required audit fields.

**Validates: Requirements 4.7**

### Property 18: Task Graph Generation

*For any* valid user goal received by the Planner Service, the service should generate a task graph, obtain an IntentSignature from the Intent Engine, and return both in the response.

**Validates: Requirements 5.3, 5.4, 5.5**

### Property 19: Intent Embedding Dimensionality

*For any* user goal processed by the Intent Engine, the generated embedding vector should have the dimensionality expected by the sentence-transformer model (384 for all-MiniLM-L6-v2).

**Validates: Requirements 6.1, 6.2, 20.2**

### Property 20: Intent Similarity Computation

*For any* original intent and proposed action, the Intent Engine should compute a cosine similarity score between their embeddings, and the score should be in the range [0, 1].

**Validates: Requirements 6.3**

### Property 21: Policy Approval Signature Validity

*For any* policy approval from the Safety Agent, the approval should contain a cryptographic signature that can be verified using the Safety Agent's public key.

**Validates: Requirements 7.3, 7.4**

### Property 22: Policy Denial Reason Inclusion

*For any* DENY decision from the Safety Agent, the response should include a human-readable reason explaining which policy caused the denial.

**Validates: Requirements 7.5**

### Property 23: Rich Authorization Request Construction

*For any* validated authorization request, the Permission Broker should construct a RAR containing the action type, required scopes, resource locations, purpose, and context including plan_id, task_id, and intent_hash.

**Validates: Requirements 8.4**

### Property 24: Provider Token Retrieval

*For any* valid RAR, the Permission Broker should successfully request a provider-specific token from Auth0 Token Vault and include it in the response.

**Validates: Requirements 8.5, 8.7**

### Property 25: Authorization Failure Logging

*For any* validation failure in the Permission Broker, the broker should deny the request and log the failure reason to the Audit Service.

**Validates: Requirements 8.8**

### Property 26: DPoP-Bound API Calls

*For any* action executed by the Executor Agent, the API call to the provider should include a DPoP proof token bound to the provider access token and the specific HTTP request.

**Validates: Requirements 9.3**

### Property 27: Expired Token Rejection

*For any* ZT-AT with an expiration timestamp in the past, the Executor Agent should reject the execution request without performing the action.

**Validates: Requirements 9.6**

### Property 28: Configuration Parser Validation

*For any* Auth0 manifest JSON, the configuration parser should validate that all required fields (client_id, jwks_uri, dpop_private_key_path) are present for each service, and raise a descriptive error if any are missing.

**Validates: Requirements 18.1, 18.3, 18.4**

### Property 29: DPoP Key Format Validation

*For any* DPoP private key loaded by the configuration parser, the parser should validate the key format and cryptographic parameters (RSA 2048-bit or higher), and reject invalid keys.

**Validates: Requirements 18.2**

### Property 30: Pretty Printer Redaction

*For any* configuration object containing sensitive information (private keys, secrets), the pretty printer should redact these values in the output while preserving all non-sensitive fields.

**Validates: Requirements 19.4**

### Property 31: IntentSignature Validation

*For any* IntentSignature JSON, the parser should validate that the embedding vector has correct dimensionality, the hash matches the expected format (64 hex characters for SHA256), and the allowed action list is non-empty, raising validation errors for malformed signatures.

**Validates: Requirements 20.1, 20.3, 20.4, 20.5**

### Property 32: Audit Log Timestamp Monotonicity

*For any* sequence of audit log entries, the timestamps should be monotonically increasing, and the parser should raise an integrity error if timestamps are out of order.

**Validates: Requirements 22.3, 22.4, 22.5**

### Property 33: Error Handling Consistency

*For any* service encountering an error (network failure, invalid token, internal error, Auth0 unavailable, certificate validation failure), the service should log the error with full context, return an appropriate HTTP status code (401, 500, 503), and include a descriptive error message.

**Validates: Requirements 24.1, 24.2, 24.3, 24.4, 24.5**

### Property 34: Provider Scope Categorization

*For any* provider configured in Auth0, the configuration should distinguish between read-only scopes (e.g., repo:read, channels:read) and write-action scopes (e.g., repo:write, chat:write), and the Permission Broker should enforce these distinctions when constructing RARs.

**Validates: Requirements 1.7**

### Property 35: Certificate PEM Format

*For any* certificate generated by the certificate generation script, the certificate should be stored in valid PEM format and be loadable by standard cryptography libraries.

**Validates: Requirements 2.3**

## Error Handling

### Authentication Errors

**Invalid mTLS Certificate:**
- HTTP Status: 401 Unauthorized
- Response: `{"error": "invalid_certificate", "message": "Client certificate not signed by trusted CA"}`
- Logging: Certificate subject, issuer, and validation failure reason

**Invalid JWT Token:**
- HTTP Status: 401 Unauthorized
- Response: `{"error": "invalid_token", "message": "JWT signature verification failed"}`
- Logging: Token issuer, audience, and validation failure reason

**Invalid DPoP Proof:**
- HTTP Status: 401 Unauthorized
- Response: `{"error": "invalid_dpop", "message": "DPoP proof does not match request"}`
- Logging: DPoP fingerprint, expected vs actual request parameters

**Expired Token:**
- HTTP Status: 401 Unauthorized
- Response: `{"error": "token_expired", "message": "Token expired at {timestamp}"}`
- Logging: Token type, expiration time, current time

### Authorization Errors

**Policy Denial:**
- HTTP Status: 403 Forbidden
- Response: `{"error": "policy_denied", "message": "{policy_reason}", "policy": "{policy_name}"}`
- Logging: Full policy evaluation context, denied action details

**Intent Misalignment:**
- HTTP Status: 403 Forbidden
- Response: `{"error": "intent_misaligned", "message": "Action does not match original intent", "similarity_score": 0.45}`
- Logging: Original intent hash, proposed action, similarity score

**Invalid Signature:**
- HTTP Status: 403 Forbidden
- Response: `{"error": "invalid_signature", "message": "Safety Agent signature verification failed"}`
- Logging: Expected signer identity, signature value, verification failure reason

### Execution Errors

**ZT-AT Replay:**
- HTTP Status: 409 Conflict
- Response: `{"error": "token_reused", "message": "ZT-AT has already been used for execution"}`
- Logging: ZT-AT hash, original execution timestamp, attempted reuse timestamp

**Provider API Failure:**
- HTTP Status: 502 Bad Gateway
- Response: `{"error": "provider_error", "message": "GitHub API returned error: {error_message}"}`
- Logging: Provider name, API endpoint, request parameters, provider error response

**Action Not Allowed:**
- HTTP Status: 403 Forbidden
- Response: `{"error": "action_not_allowed", "message": "Action not in ZT-AT allowed actions list"}`
- Logging: Requested action, allowed actions from ZT-AT

### System Errors

**Service Unavailable:**
- HTTP Status: 503 Service Unavailable
- Response: `{"error": "service_unavailable", "message": "Auth0 is currently unavailable"}`
- Logging: Downstream service name, error details, retry attempts
- Retry: Exponential backoff up to 3 attempts (1s, 2s, 4s)

**Internal Error:**
- HTTP Status: 500 Internal Server Error
- Response: `{"error": "internal_error", "message": "An unexpected error occurred", "correlation_id": "{id}"}`
- Logging: Full stack trace, request context, correlation ID

**Audit Log Integrity Error:**
- HTTP Status: 500 Internal Server Error
- Response: `{"error": "audit_integrity_error", "message": "Hash chain verification failed"}`
- Logging: Expected hash, actual hash, entry index where chain breaks
- Action: Alert security team, halt system operations

## Testing Strategy

The testing strategy employs a dual approach combining unit tests for specific examples and edge cases with property-based tests for universal correctness properties.

### Unit Testing

Unit tests focus on:
- Specific examples demonstrating correct behavior
- Edge cases (empty inputs, boundary values, special characters)
- Error conditions and exception handling
- Integration points between components
- Mock external dependencies (Auth0, provider APIs)

**Example Unit Tests:**
```python
def test_planner_rejects_request_without_jwt():
    """Test that Planner returns 401 when JWT is missing"""
    response = client.post("/plan", json={"user_goal": "test"})
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_token"

def test_intent_engine_handles_empty_goal():
    """Test that Intent Engine rejects empty user goals"""
    response = client.post("/sign-intent", json={"user_goal": "", "allowed_actions": []})
    assert response.status_code == 400

def test_audit_service_genesis_entry():
    """Test that first audit entry uses genesis hash"""
    entry = audit_service.log_entry({"component": "test", "event": "init"})
    assert entry.previous_hash == "genesis"
```

### Property-Based Testing

Property-based tests verify universal properties across randomized inputs using a PBT library (Hypothesis for Python). Each test runs a minimum of 100 iterations.

**PBT Library:** Hypothesis (Python)

**Test Configuration:**
- Minimum iterations: 100 per property
- Shrinking: Enabled (find minimal failing examples)
- Seed: Randomized (reproducible with seed logging)

**Property Test Structure:**
```python
from hypothesis import given, strategies as st

@given(st.text(min_size=1), st.lists(st.text(), min_size=1))
def test_intent_signature_round_trip(user_goal, allowed_actions):
    """Feature: zero-trust-agentic-guardian, Property 3: IntentSignature Round-Trip Consistency"""
    # Generate intent signature
    signature = intent_engine.sign_intent(user_goal, allowed_actions)

    # Serialize to JSON
    json_str = signature.model_dump_json()

    # Parse back
    parsed = IntentSignature.model_validate_json(json_str)

    # Pretty print
    pretty_str = pretty_print_intent_signature(parsed)

    # Parse again
    final = IntentSignature.model_validate_json(pretty_str)

    # Verify equivalence
    assert final.embedding == signature.embedding
    assert final.hash == signature.hash
    assert final.allowed_actions == signature.allowed_actions
```

**Generator Strategies:**

```python
# Generate valid JWT tokens
@st.composite
def jwt_token_strategy(draw):
    payload = {
        "iss": draw(st.sampled_from(["planner", "safety-agent", "permission-broker"])),
        "aud": draw(st.sampled_from(["intent-engine", "safety-agent", "permission-broker"])),
        "exp": draw(st.integers(min_value=int(time.time()), max_value=int(time.time()) + 300)),
        "iat": int(time.time()),
        "jti": str(uuid.uuid4())
    }
    return jwt.encode(payload, private_key, algorithm="RS256")

# Generate valid IntentSignatures
@st.composite
def intent_signature_strategy(draw):
    embedding = draw(st.lists(st.floats(min_value=-1, max_value=1), min_size=384, max_size=384))
    user_goal = draw(st.text(min_size=1, max_size=500))
    hash_value = hashlib.sha256(user_goal.encode()).hexdigest()
    allowed_actions = draw(st.lists(st.text(min_size=1), min_size=1, max_size=10))

    return IntentSignature(
        embedding=embedding,
        hash=hash_value,
        allowed_actions=allowed_actions,
        timestamp=datetime.now(),
        signature="mock_signature"
    )

# Generate valid ZT-ATs
@st.composite
def zt_at_strategy(draw):
    return ZeroTrustAuthorizationToken(
        plan_id=str(uuid.uuid4()),
        task_id=str(uuid.uuid4()),
        action=draw(st.sampled_from(["create_branch", "create_pr", "send_message"])),
        provider=draw(st.sampled_from(["github", "slack", "google_workspace"])),
        policy_approval=draw(policy_decision_strategy()),
        intent_signature=draw(intent_signature_strategy()),
        broker_signature="mock_broker_signature",
        issued_at=datetime.now(),
        expires_at=datetime.now() + timedelta(minutes=5),
        nonce=str(uuid.uuid4())
    )
```

**Example Property Tests:**

```python
@given(zt_at_strategy())
def test_zt_at_replay_prevention(zt_at):
    """Feature: zero-trust-agentic-guardian, Property 11: ZT-AT Replay Prevention"""
    # First execution should succeed
    result1 = executor.execute(zt_at, {"param": "value"})
    assert result1.status == "success"

    # Second execution with same ZT-AT should fail
    result2 = executor.execute(zt_at, {"param": "value"})
    assert result2.status == "failure"
    assert "token_reused" in result2.error

@given(st.lists(audit_log_entry_strategy(), min_size=2, max_size=20))
def test_hash_chain_integrity(log_entries):
    """Feature: zero-trust-agentic-guardian, Property 5: Hash Chain Integrity"""
    # Build hash chain
    chain = audit_service.build_chain(log_entries)

    # Verify chain is valid
    assert audit_service.verify_chain(chain) == True

    # Tamper with middle entry
    if len(chain) > 2:
        chain[len(chain) // 2].action_metadata["tampered"] = True

        # Verification should fail
        assert audit_service.verify_chain(chain) == False

@given(st.text(min_size=10), st.text(min_size=10))
def test_intent_alignment_detection(original_goal, injected_action):
    """Feature: zero-trust-agentic-guardian, Property 7: Intent Alignment Detection"""
    # Assume injected_action is semantically different from original_goal
    # (Hypothesis will generate diverse pairs)

    # Sign original intent
    signature = intent_engine.sign_intent(original_goal, ["benign_action"])

    # Verify alignment with injected action
    result = intent_engine.verify_intent(signature, injected_action)

    # If similarity is below threshold, should be flagged
    if result.similarity_score < 0.7:
        assert result.aligned == False

        # Safety Agent should reject
        policy_decision = safety_agent.evaluate(
            task_graph=[{"action": injected_action}],
            intent_signature=signature
        )
        assert policy_decision.decision == "DENY"

        # Permission Broker should refuse token
        with pytest.raises(AuthorizationError):
            permission_broker.authorize(
                action=injected_action,
                policy_approval=policy_decision,
                intent_signature=signature
            )
```

### Integration Testing

Integration tests verify the complete authorization flow:

1. **Happy Path Test:** Valid user goal → successful execution → audit log entry
2. **Prompt Injection Test:** Malicious goal → intent mismatch → denial → audit log
3. **Token Expiration Test:** Expired ZT-AT → execution rejection
4. **Policy Denial Test:** Destructive action without admin role → policy denial
5. **Certificate Validation Test:** Invalid mTLS certificate → connection rejection
6. **Token Vault Test:** Valid RAR → provider token retrieval → API call success

### Attack Scenario Testing

Specific attack scenarios to validate security controls:

1. **Prompt Injection:** Inject "delete main branch" into benign goal
2. **Token Theft:** Attempt to use stolen JWT without DPoP proof
3. **Replay Attack:** Reuse ZT-AT for multiple executions
4. **Certificate Spoofing:** Present certificate not signed by root CA
5. **Policy Bypass:** Attempt destructive action without admin role
6. **Audit Tampering:** Modify audit log entry and verify detection

### Test Coverage Goals

- Unit test coverage: >80% line coverage
- Property test coverage: All 35 correctness properties implemented
- Integration test coverage: All 6 services in complete flow
- Attack scenario coverage: All 6 attack vectors tested

### Continuous Testing

- Run unit tests on every commit
- Run property tests (100 iterations) on every PR
- Run integration tests before deployment
- Run attack scenarios weekly in staging environment
- Monitor property test failures for regression detection
