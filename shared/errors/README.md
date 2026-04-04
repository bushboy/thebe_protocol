# Error Handling Module

This module provides standardized error handling for all services in the Zero-Trust Agentic Guardian Architecture.

## Features

- **Custom Exception Classes**: Organized by error category (Authentication, Authorization, Execution, System)
- **Error Handling Middleware**: Automatic error catching, logging, and response formatting
- **Correlation ID Tracking**: Every request gets a unique correlation ID for tracing
- **Structured Logging**: All errors logged with full context in JSON format
- **Standardized Responses**: Consistent error response format across all services
- **Retry Logic**: Exponential backoff for network and service availability errors

## Usage

### In Service Main File

```python
from fastapi import FastAPI
from shared.errors import setup_error_handlers

app = FastAPI(title="My Service")

# Set up error handlers (includes middleware)
setup_error_handlers(app)
```

### Raising Custom Exceptions

```python
from shared.errors import (
    InvalidTokenError,
    PolicyDeniedError,
    ServiceUnavailableError
)

# Authentication error
if not valid_token:
    raise InvalidTokenError(
        message="JWT signature verification failed",
        details={"issuer": token_issuer}
    )

# Authorization error
if policy_result.decision == "DENY":
    raise PolicyDeniedError(
        message=policy_result.reason,
        policy_name="destructive_actions",
        details={"action": requested_action}
    )

# System error
if not auth0_available:
    raise ServiceUnavailableError(
        service_name="Auth0",
        details={"retry_attempts": 3}
    )
```

### Retry Logic with Exponential Backoff

The module provides retry decorators and context managers for handling transient failures:

#### Using Decorator

```python
from shared.errors import retry_on_network_error, exponential_backoff_retry

# Retry on common network errors (3 retries: 1s, 2s, 4s)
@retry_on_network_error
async def call_external_service():
    response = await httpx.get("https://api.example.com")
    return response.json()

# Custom retry configuration
@exponential_backoff_retry(
    max_retries=5,
    base_delay=2.0,
    exceptions=(ConnectionError, TimeoutError)
)
def make_database_call():
    return db.query("SELECT * FROM table")
```

#### Using Context Manager

```python
from shared.errors import RetryContext

retry_ctx = RetryContext(max_retries=3, base_delay=1.0)
for attempt in retry_ctx:
    try:
        result = make_network_call()
        break
    except ConnectionError as e:
        retry_ctx.handle_exception(e)
```

## Exception Hierarchy

### Authentication Errors (401)
- `InvalidCertificateError`: mTLS certificate validation failed
- `InvalidTokenError`: JWT token validation failed
- `InvalidDPoPError`: DPoP proof validation failed
- `TokenExpiredError`: Token has expired

### Authorization Errors (403)
- `PolicyDeniedError`: OPA policy denied the action
- `IntentMisalignedError`: Action doesn't match original intent
- `InvalidSignatureError`: Signature verification failed
- `ActionNotAllowedError`: Action not in ZT-AT allowed list

### Execution Errors (409, 502)
- `ZTATReplayError`: ZT-AT already used (409)
- `ProviderAPIError`: Provider API call failed (502)

### System Errors (500, 503)
- `ServiceUnavailableError`: Downstream service unavailable (503)
- `InternalError`: Unexpected internal error (500)
- `AuditIntegrityError`: Audit log hash chain broken (500)

## Error Response Format

All errors return JSON responses with this structure:

```json
{
  "error": "error_code",
  "message": "Human-readable error message",
  "additional_field": "value",
  "correlation_id": "uuid"
}
```

Response headers include:
- `X-Correlation-ID`: Unique identifier for request tracing

## Retry Behavior

Network errors are automatically retried with exponential backoff:
- **Attempt 1**: Immediate execution
- **Attempt 2**: Wait 1 second, retry
- **Attempt 3**: Wait 2 seconds, retry
- **Attempt 4**: Wait 4 seconds, retry
- **After 3 retries**: Raise the last exception

Retryable errors include:
- `ConnectionError`
- `TimeoutError`
- `ServiceUnavailableError`

## Requirements

Validates Requirements: 24.1, 24.2, 24.3, 24.4, 24.5
