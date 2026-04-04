# Zero-Trust Agentic Guardian - Project Structure

## Overview

This document describes the project structure created for the Zero-Trust Agentic Guardian Architecture.

## Directory Structure

```
agentic-guardian/
├── .kiro/                          # Kiro spec files
│   └── specs/
│       └── zero-trust-agentic-guardian/
│           ├── requirements.md     # 24 requirements with 120 acceptance criteria
│           ├── design.md           # Complete architecture with 35 correctness properties
│           └── tasks.md            # 31 implementation tasks
│
├── infra/                          # Infrastructure configuration
│   ├── auth0/                      # Auth0 M2M setup scripts (Task 7)
│   ├── certificates/               # mTLS certificate infrastructure (Task 8)
│   ├── docker/                     # Docker Compose configuration (Task 27)
│   └── opa/                        # OPA policy definitions (Task 9)
│
├── services/                       # Microservices
│   ├── planner/                    # Task planning service (Task 13)
│   ├── intent-engine/              # Intent signature generation (Task 11)
│   ├── safety-agent/               # Policy enforcement (Task 12)
│   ├── permission-broker/          # Zero-Trust PEP (Task 15)
│   ├── executor/                   # Action execution (Task 16)
│   └── audit/                      # Audit logging (Task 17)
│
├── shared/                         # Shared libraries (Task 1)
│   ├── jwt/                        # JWT validation utilities (Task 3)
│   │   ├── __init__.py
│   │   └── validator.py            # JWT validation with replay prevention
│   │
│   ├── dpop/                       # DPoP utilities (Task 4)
│   │   ├── __init__.py
│   │   └── proof.py                # DPoP proof generation and verification
│   │
│   ├── mtls/                       # mTLS utilities (Task 5)
│   │   ├── __init__.py
│   │   └── certificates.py         # Certificate loading and validation
│   │
│   ├── schemas/                    # Pydantic data models (Task 2)
│   │   ├── __init__.py
│   │   └── models.py               # All shared data structures
│   │
│   ├── logging/                    # Structured logging (Task 6)
│   │   ├── __init__.py
│   │   └── json_logger.py          # JSON logging with correlation IDs
│   │
│   └── README.md                   # Shared libraries documentation
│
├── tests/                          # Test suite
│   ├── integration/                # Integration tests (Task 29)
│   ├── attack-scenarios/           # Attack scenario tests (Task 30)
│   └── test_shared_imports.py      # Basic import tests
│
├── scripts/                        # Setup and deployment scripts
│   └── (Task 28)
│
├── .env.example                    # Environment variables template
├── .gitignore                      # Git ignore rules
├── pytest.ini                      # Pytest configuration
├── README.md                       # Project README
├── requirements.txt                # Python dependencies
├── setup.py                        # Package setup configuration
└── setup_venv.bat                  # Windows virtual environment setup script
```

## Completed Components

### Task 1: Set up project structure and shared libraries ✓

#### Created Directory Structure
- All service directories (planner, intent-engine, safety-agent, permission-broker, executor, audit)
- All infrastructure directories (auth0, certificates, docker, opa)
- All shared library modules (jwt, dpop, mtls, schemas, logging)
- Test directories (integration, attack-scenarios)
- Scripts directory

#### Shared Libraries Implemented

1. **JWT Library** (`shared/jwt/`)
   - `validator.py`: JWT validation with replay prevention
   - Validates signature, issuer, audience, expiration
   - Tracks nonces to prevent replay attacks
   - Validates timestamp freshness
   - Requirements: 4.1, 4.2

2. **DPoP Library** (`shared/dpop/`)
   - `proof.py`: DPoP proof generation and verification
   - Generates DPoP proof JWTs bound to HTTP requests
   - Verifies token binding (ath matches access token hash)
   - Validates request matching (htm and htu match actual request)
   - Requirements: 4.3, 4.4

3. **mTLS Library** (`shared/mtls/`)
   - `certificates.py`: Certificate loading and validation
   - Loads PEM certificates
   - Extracts client identity from certificate subject
   - Validates certificate chain against root CA
   - Requirements: 4.5

4. **Schemas Library** (`shared/schemas/`)
   - `models.py`: Pydantic data models
   - IntentSignature: Semantic embeddings and cryptographic signatures
   - PolicyDecision: OPA policy evaluation results
   - RichAuthorizationRequest: Detailed authorization requests
   - ZeroTrustAuthorizationToken: Complete authorization chain tokens
   - AuditLogEntry: Cryptographically chained audit log entries
   - DPoPProof: Proof-of-possession token structure
   - Requirements: 4.6

5. **Logging Library** (`shared/logging/`)
   - `json_logger.py`: JSON logging with correlation IDs
   - Outputs structured JSON logs
   - Adds correlation ID to all log entries
   - Provides audit hooks for security events
   - Requirements: 4.7

#### Python Virtual Environment
- Created virtual environment in `venv/`
- Installed all dependencies from `requirements.txt`
- Installed package in development mode (`pip install -e .`)

#### Dependencies Installed
- FastAPI 0.135.1 (web framework)
- uvicorn 0.41.0 (ASGI server)
- httpx 0.28.1 (HTTP client)
- hypothesis 6.151.9 (property-based testing)
- pytest 9.0.2 (testing framework)
- pytest-asyncio 1.3.0 (async testing)
- PyJWT 2.11.0 (JWT handling)
- cryptography 46.0.5 (cryptographic operations)
- sentence-transformers 5.2.3 (semantic embeddings)
- pydantic 2.12.5 (data validation)
- pydantic-settings 2.13.1 (settings management)
- psycopg2-binary 2.9.11 (PostgreSQL driver)
- redis 7.3.0 (Redis client)
- requests 2.32.5 (HTTP library)
- PyGithub 2.8.1 (GitHub API)
- slack-sdk 3.40.1 (Slack API)
- google-api-python-client 2.192.0 (Google APIs)
- python-dotenv 1.2.2 (environment variables)

#### Configuration Files
- `pytest.ini`: Pytest configuration with markers for unit, integration, property, and attack tests
- `.env.example`: Template for environment variables
- `setup.py`: Package setup configuration
- `setup_venv.bat`: Windows setup script for virtual environment

#### Tests
- Created `tests/test_shared_imports.py` to verify all shared libraries can be imported
- All 5 import tests passing

## Next Steps

The project structure is now complete and ready for implementation of the remaining tasks:

1. **Task 2**: Implement shared data models (schemas) - Property tests
2. **Task 3**: Implement JWT utilities - Property tests
3. **Task 4**: Implement DPoP utilities - Property tests
4. **Task 5**: Implement mTLS utilities - Property tests
5. **Task 6**: Implement structured logging - Property tests
6. **Task 7**: Create Auth0 configuration script
7. **Task 8**: Create certificate generation script
8. **Task 9**: Create OPA policies
9. **Task 10**: Checkpoint - Verify infrastructure and shared libraries
10. Continue with service implementation (Tasks 11-31)

## Usage

### Activate Virtual Environment

Windows:
```cmd
venv\Scripts\activate.bat
```

### Run Tests

```cmd
pytest                              # Run all tests
pytest tests/test_shared_imports.py # Run specific test file
pytest -v                           # Verbose output
pytest -k "property"                # Run only property tests
```

### Import Shared Libraries

```python
from shared.jwt import JWTValidator
from shared.dpop import DPoPProofGenerator, DPoPProofVerifier
from shared.mtls import CertificateLoader
from shared.schemas import IntentSignature, ZeroTrustAuthorizationToken
from shared.logging import JSONLogger, setup_logging
```

## Requirements Mapping

This task addresses the following requirements:

- **Requirement 4.1**: JWT validation with signature, issuer, audience, expiration checks
- **Requirement 4.2**: Nonce tracking and timestamp freshness validation
- **Requirement 4.3**: DPoP proof generation bound to HTTP requests
- **Requirement 4.4**: DPoP proof verification with token binding and request matching
- **Requirement 4.5**: Certificate loading and identity extraction
- **Requirement 4.6**: Pydantic models for all data structures
- **Requirement 4.7**: Structured JSON logging with correlation IDs
