# Token Lifetime Enforcement

This module provides comprehensive token expiration validation for the Zero-Trust Agentic Guardian Architecture.

## Overview

The token lifetime enforcement module validates expiration for three types of tokens:

1. **JWT Tokens**: Validates the `exp` (expiration) claim
2. **ZT-AT Tokens**: Validates the `expires_at` field
3. **DPoP Proofs**: Validates timestamp freshness (60 seconds)

## Requirements

- **Requirement 12.1**: JWT lifetime set to 5 minutes
- **Requirement 12.2**: Provider tokens have minimum lifetime
- **Requirement 12.3**: JWT expiration validated
- **Requirement 12.4**: ZT-AT expiration validated
- **Requirement 12.5**: DPoP timestamp freshness validated (60 seconds)

## Usage

### Validate JWT Expiration

```python
from shared.token_lifetime import TokenLifetimeValidator, TokenExpiredError

jwt_payload = {
    "exp": 1705320900,
    "iat": 1705320600,
    "iss": "planner",
    "aud": "intent-engine"
}

try:
    TokenLifetimeValidator.validate_jwt_expiration(jwt_payload)
    print("JWT is valid")
except TokenExpiredError as e:
    print(f"JWT expired: {e}")
```

### Validate ZT-AT Expiration

```python
from datetime import datetime, timezone
from shared.schemas.models import ZeroTrustAuthorizationToken
from shared.token_lifetime import TokenLifetimeValidator, TokenExpiredError

zt_at = ZeroTrustAuthorizationToken(
    plan_id="plan_123",
    task_id="task_456",
    action="create_branch",
    provider="github",
    # ... other fields ...
    expires_at=datetime.now(timezone.utc) + timedelta(minutes=5)
)

try:
    TokenLifetimeValidator.validate_zt_at_expiration(zt_at)
    print("ZT-AT is valid")
except TokenExpiredError as e:
    print(f"ZT-AT expired: {e}")
```

### Validate DPoP Timestamp Freshness

```python
import time
from shared.token_lifetime import TokenLifetimeValidator, TokenExpiredError

dpop_payload = {
    "jti": "550e8400-e29b-41d4-a716-446655440000",
    "htm": "POST",
    "htu": "https://api.example.com/resource",
    "iat": int(time.time()),
    "ath": "a1b2c3d4..."
}

try:
    TokenLifetimeValidator.validate_dpop_timestamp_freshness(dpop_payload)
    print("DPoP proof is fresh")
except TokenExpiredError as e:
    print(f"DPoP proof expired: {e}")
```

### Validate All Tokens at Once

```python
from shared.token_lifetime import TokenLifetimeValidator, TokenExpiredError

try:
    TokenLifetimeValidator.validate_all_tokens(
        jwt_payload=jwt_payload,
        zt_at=zt_at,
        dpop_payload=dpop_payload
    )
    print("All tokens are valid")
except TokenExpiredError as e:
    print(f"Token validation failed: {e}")
```

## Integration with Services

All services should validate token expiration before processing requests:

```python
from fastapi import HTTPException
from shared.token_lifetime import TokenLifetimeValidator, TokenExpiredError

@app.post("/execute")
async def execute_action(request: ExecuteRequest):
    try:
        # Validate all tokens
        TokenLifetimeValidator.validate_all_tokens(
            jwt_payload=request.jwt_payload,
            zt_at=request.zt_at,
            dpop_payload=request.dpop_payload
        )
    except TokenExpiredError as e:
        raise HTTPException(
            status_code=401,
            detail={"error": "token_expired", "message": str(e)}
        )
    
    # Process request...
```

## Token Lifetime Configuration

- **JWT Tokens**: 5 minutes (configured in Auth0)
- **ZT-AT Tokens**: 5 minutes (set by Permission Broker)
- **DPoP Proofs**: 60 seconds freshness window

## Error Handling

The module raises `TokenExpiredError` with descriptive messages:

- JWT expired: Includes expiration timestamp and current time
- ZT-AT expired: Includes expiration timestamp and current time
- DPoP too old: Includes proof age and maximum allowed age
- DPoP in future: Indicates clock skew issue

## Testing

See `tests/test_token_lifetime_properties.py` for property-based tests validating token lifetime enforcement.
