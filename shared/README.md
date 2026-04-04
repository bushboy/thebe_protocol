# Shared Libraries

This directory contains shared libraries used across all services in the Zero-Trust Agentic Guardian Architecture.

## Modules

### jwt/
JWT token validation and generation utilities.

- **validator.py**: JWT validation with replay prevention and freshness checks
- Validates signature, issuer, audience, expiration
- Tracks nonces to prevent replay attacks
- Validates timestamp freshness

### dpop/
DPoP (Demonstrating Proof-of-Possession) utilities.

- **proof.py**: DPoP proof generation and verification
- Generates DPoP proof JWTs bound to HTTP requests
- Verifies token binding (ath matches access token hash)
- Validates request matching (htm and htu match actual request)

### mtls/
mTLS (Mutual TLS) certificate handling utilities.

- **certificates.py**: Certificate loading and validation
- Loads PEM certificates
- Extracts client identity from certificate subject
- Validates certificate chain against root CA

### schemas/
Pydantic data models for all shared data structures.

- **models.py**: Data models including:
  - IntentSignature: Semantic embeddings and cryptographic signatures
  - PolicyDecision: OPA policy evaluation results
  - RichAuthorizationRequest: Detailed authorization requests
  - ZeroTrustAuthorizationToken: Complete authorization chain tokens
  - AuditLogEntry: Cryptographically chained audit log entries
  - DPoPProof: Proof-of-possession token structure

### logging/
Structured JSON logging utilities.

- **json_logger.py**: JSON logging with correlation IDs
- Outputs structured JSON logs
- Adds correlation ID to all log entries
- Provides audit hooks for security events

## Usage

Import shared libraries in your service code:

```python
from shared.jwt import JWTValidator
from shared.dpop import DPoPProofGenerator, DPoPProofVerifier
from shared.mtls import CertificateLoader
from shared.schemas import IntentSignature, ZeroTrustAuthorizationToken
from shared.logging import JSONLogger, setup_logging

# Setup logging
setup_logging(level="INFO")
logger = JSONLogger(__name__)

# Use libraries
jwt_validator = JWTValidator(public_key_pem, issuer, audience)
payload = jwt_validator.validate(token)

dpop_generator = DPoPProofGenerator(private_key_pem)
proof = dpop_generator.generate_proof(access_token, "POST", "https://api.example.com/resource")

cert_loader = CertificateLoader(root_ca_cert_pem)
cert, identity = cert_loader.load_and_validate(cert_pem)

logger.info("Request processed", user_id="user123", action="create_branch")
```

## Requirements

All shared libraries follow these requirements:

- **Requirement 4.1**: JWT validation with signature, issuer, audience, expiration checks
- **Requirement 4.2**: Nonce tracking and timestamp freshness validation
- **Requirement 4.3**: DPoP proof generation bound to HTTP requests
- **Requirement 4.4**: DPoP proof verification with token binding and request matching
- **Requirement 4.5**: Certificate loading and identity extraction
- **Requirement 4.6**: Pydantic models for all data structures
- **Requirement 4.7**: Structured JSON logging with correlation IDs
