# Zero-Trust Agentic Guardian Architecture

A comprehensive multi-agent system implementing zero-trust security principles for executing user-requested tasks through a cryptographically verified authorization chain.

## Overview

The Zero-Trust Agentic Guardian Architecture is a production-grade security framework that protects against prompt injection attacks, enforces policy-based access control, and maintains tamper-evident audit logs. Every request flows through a cryptographically verified authorization chain with mutual TLS (mTLS), JWT tokens, and DPoP (Demonstrating Proof-of-Possession) token binding.

### Key Features

- **Zero-Trust Security**: Every request is authenticated, authorized, and audited
- **Prompt Injection Defense**: Semantic intent verification using sentence-transformers
- **Policy Enforcement**: Open Policy Agent (OPA) for business rules and security constraints
- **Cryptographic Audit Trail**: Hash-chained, append-only audit logs
- **Multi-Provider Support**: GitHub, Slack, Google Workspace integrations via Auth0 Token Vault
- **Triple Authentication**: mTLS + JWT + DPoP for all service-to-service communication

## Architecture

The system consists of six microservices:

1. **Planner Service** - Accepts user goals and generates task execution plans
2. **Intent Engine** - Generates semantic embeddings and cryptographic intent signatures
3. **Safety Agent** - Evaluates actions against OPA policies and signs approvals
4. **Permission Broker** - Zero-Trust Policy Enforcement Point (PEP) that validates authorization chains
5. **Executor Agent** - Performs individual actions using provider-specific tokens
6. **Audit Service** - Maintains cryptographically chained, append-only audit logs

### Authorization Flow

```text
User Goal → Planner → Intent Engine → Safety Agent → Permission Broker → Executor → Audit
                ↓           ↓              ↓                ↓              ↓         ↓
           Task Graph  Intent Sig    Policy Approval    ZT-AT Token    Execution  Log Entry
```

## Client API Surface

The intended external client contract is intentionally small.

### Public Endpoints (Client-Facing)

1. `POST /plan` on Planner (`http://localhost:8002/plan`)
2. `POST /authorize` on Permission Broker (`http://localhost:8004/authorize`)
3. `GET /health` on Planner (`http://localhost:8002/health`)
4. `GET /health` on Permission Broker (`http://localhost:8004/health`)

### Internal Endpoints (Service-to-Service Only)

The following endpoints are designed for internal service communication and should not be called directly by external clients:

- Intent Engine: `/sign-intent`, `/verify-intent`
- Safety Agent: `/evaluate`
- Executor: `/execute`
- Audit: `/log`, `/verify`, `/logs`

### Expected External Call Sequence

1. Client submits goal to Planner via `POST /plan`
2. Client submits task authorization requests to Permission Broker via `POST /authorize`

### Client Request Guidance

For `POST /authorize`, clients should send:

- `plan_id`
- `task_id`
- `action`
- `provider`
- `intent_signature`
- `action_params` (optional)

Example request payload:

```json
{
   "plan_id": "3a4a68a7-cc3b-4efd-9a8c-e9f53f9e9f18",
   "task_id": "task_001",
   "action": "create_branch",
   "provider": "github",
   "intent_signature": {
      "embedding": [0.0, 0.0, 0.0],
      "hash": "6f1f0d4a44b9d9758fa9dcaa0f95e31f35ed4cf5d1b7bcb49a37a3e8c4f6f4be",
      "allowed_actions": ["github:create_branch", "github:create_pr"],
      "timestamp": "2026-03-26T12:00:00Z",
      "signature": "intent_sig_base64"
   },
   "action_params": {
      "repository": "org/repo",
      "branch": "feature/zero-trust"
   }
}
```

Note: `intent_signature.embedding` must be a 384-dimensional vector in real requests. The short vector above is illustrative only.

Clients should not construct or send `policy_approval` in normal usage. Permission Broker performs policy evaluation internally for client requests.

Compatibility note: `policy_approval` is still accepted for legacy callers during migration.

Deprecation timeline for `policy_approval` in client requests:

1. Current: accepted but optional (preferred: omit)
2. Next minor release: accepted with deprecation warning in logs
3. Next major release: removed from external client contract

This preserves the zero-trust flow while keeping the external API surface minimal and predictable.

## Project Structure

```text
agentic-guardian/
├── docs/                    # Documentation
├── infra/
│   ├── auth0/              # Auth0 M2M setup scripts
│   ├── certificates/       # mTLS certificate infrastructure
│   ├── docker/             # Docker Compose configuration
│   └── opa/                # OPA policy definitions
├── services/
│   ├── planner/            # Task planning service
│   ├── intent-engine/      # Intent signature generation
│   ├── safety-agent/       # Policy enforcement
│   ├── permission-broker/  # Zero-Trust PEP
│   ├── executor/           # Action execution
│   └── audit/              # Audit logging
├── shared/
│   ├── jwt/                # JWT utilities
│   ├── dpop/               # DPoP utilities
│   ├── mtls/               # mTLS utilities
│   ├── schemas/            # Pydantic data models
│   └── logging/            # Structured logging
├── tests/
│   ├── integration/        # Integration tests
│   ├── e2e/                # End-to-end tests
│   └── attack-scenarios/   # Security tests
└── scripts/                # Setup and deployment scripts
```

## Technology Stack

- **Language**: Python 3.14.2
- **Web Framework**: FastAPI
- **Testing**: Hypothesis (property-based testing)
- **Authentication**: Auth0 with Token Vault
- **Policy Engine**: Open Policy Agent (OPA)
- **ML/Embeddings**: sentence-transformers (all-MiniLM-L6-v2)
- **Cryptography**: PyJWT, cryptography library
- **Database**: PostgreSQL (audit logs)
- **Cache**: Redis (replay prevention)

## Getting Started

### Prerequisites

- Python 3.14.2
- Auth0 account with Token Vault enabled
- Docker and Docker Compose
- OpenSSL (for certificate generation)

### Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd agentic-guardian
   ```

2. **Run the setup script**
   ```bash
   ./scripts/setup_all.sh
   ```

   This will:
   - Configure Auth0 M2M applications
   - Generate mTLS certificates
   - Initialize OPA policies
   - Set up service configurations

3. **Start the services**
   ```bash
   docker compose -f infra/docker/docker-compose.yml up -d
   ```

4. **Run integration tests**
   ```bash
   ./scripts/run_integration_tests.sh
   ```

## Development

### Implementation Plan

The project follows a spec-driven development methodology. See `.kiro/specs/zero-trust-agentic-guardian/` for:

- **requirements.md**: 24 requirements with 120 acceptance criteria
- **design.md**: Complete architecture with 35 correctness properties
- **tasks.md**: 31 implementation tasks with property-based tests

To start implementing, open `tasks.md` and follow the tasks sequentially.

### Running Tests

```bash
# Run all tests
pytest

# Run property-based tests
pytest tests/ -k "property"

# Run integration tests
pytest tests/integration/

# Run attack scenario tests
pytest tests/attack-scenarios/
```

### Certificate Rotation

```bash
./scripts/rotate_certificates.sh
```

## Security

### Authentication Mechanisms

All service-to-service communication uses triple authentication:

1. **mTLS**: X.509 certificates signed by internal CA
2. **JWT**: Access tokens from Auth0 with 5-minute lifetime
3. **DPoP**: Proof-of-possession tokens bound to specific requests

### Token Lifecycle

- JWT tokens: 5 minutes maximum
- Provider tokens: Minimum lifetime for specific action
- ZT-AT tokens: Include expiration timestamp
- DPoP proofs: 60-second freshness window

### Prompt Injection Defense

The system detects prompt injection through:
- Semantic similarity scoring (threshold: 0.7)
- Intent signature verification
- Policy-based rejection of misaligned actions
- Complete audit trail of all rejections

## Documentation

- [Requirements Document](.kiro/specs/zero-trust-agentic-guardian/requirements.md)
- [Design Document](.kiro/specs/zero-trust-agentic-guardian/design.md)
- [Implementation Tasks](.kiro/specs/zero-trust-agentic-guardian/tasks.md)

## Contributing

1. Follow the implementation tasks in `tasks.md`
2. Write property-based tests using Hypothesis
3. Ensure all services implement triple authentication
4. Maintain cryptographic audit trail
5. Run integration and attack scenario tests

## License

[Specify your license here]

## Contact

[Specify contact information here]
