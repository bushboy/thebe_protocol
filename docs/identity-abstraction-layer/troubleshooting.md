# Identity Abstraction Layer - Troubleshooting Guide

## Overview

This guide provides solutions to common issues encountered when using the Identity Abstraction Layer. Each section includes symptoms, root causes, diagnostic steps, and solutions.

## Quick Diagnostic Commands

```bash
# Check adapter health
python -c "
import asyncio
from shared.identity.vault_factory import VaultFactory
from shared.identity.config_parser import load_config

async def check():
    config = load_config('config/ial_config.json')
    provider = VaultFactory.create_provider(config)
    healthy = await provider.health_check()
    print(f'Provider: {provider.get_provider_name()}')
    print(f'Health: {\"OK\" if healthy else \"FAILED\"}')

asyncio.run(check())
"

# Validate configuration
python -c "
from shared.identity.config_parser import load_config
from shared.identity.config_printer import pretty_print_config

config = load_config('config/ial_config.json')
print(pretty_print_config(config))
"

# Check logs
tail -f logs/permission_broker.log | grep -i "vault\|identity\|adapter"

# Check metrics
curl http://localhost:8080/metrics | grep vault_
```

## Configuration Issues

### Issue: Configuration File Not Found

**Symptoms:**
```
FileNotFoundError: [Errno 2] No such file or directory: 'config/ial_config.json'
```

**Root Cause:**
- Configuration file doesn't exist at expected location
- Incorrect file path
- Missing IAL_CONFIG_PATH environment variable

**Diagnostic Steps:**
```bash
# Check if file exists
ls -la config/ial_config.json

# Check environment variable
echo $IAL_CONFIG_PATH

# Check current directory
pwd
```

**Solutions:**

1. **Create configuration file:**
```bash
# Copy example configuration
cp config/ial_config.example.json config/ial_config.json

# Edit with your values
nano config/ial_config.json
```

2. **Set correct path:**
```bash
export IAL_CONFIG_PATH=/path/to/ial_config.json
```

3. **Use absolute path:**
```python
config = load_config("/etc/ztag/ial_config.json")
```

### Issue: Invalid JSON/YAML Syntax

**Symptoms:**
```
json.decoder.JSONDecodeError: Expecting ',' delimiter: line 5 column 3
```

**Root Cause:**
- Syntax error in configuration file
- Missing comma, bracket, or quote
- Invalid YAML indentation

**Diagnostic Steps:**
```bash
# Validate JSON
python -m json.tool config/ial_config.json

# Validate YAML
python -c "import yaml; yaml.safe_load(open('config/ial_config.yaml'))"
```

**Solutions:**

1. **Fix JSON syntax:**
```json
{
  "identity_provider": "auth0",
  "auth0_config": {
    "domain": "tenant.auth0.com",
    "client_id": "client_id",
    "client_secret": "secret"  // Remove trailing comma if last item
  }
}
```

2. **Use JSON validator:**
```bash
# Online: https://jsonlint.com/
# Or use jq
jq . config/ial_config.json
```

### Issue: Missing Required Configuration Field

**Symptoms:**
```
VaultConfigurationError: Missing required field 'client_secret' in auth0_config
```

**Root Cause:**
- Required configuration field not provided
- Typo in field name
- Wrong configuration section

**Diagnostic Steps:**
```bash
# Check configuration structure
cat config/ial_config.json | jq '.auth0_config'

# List all fields
cat config/ial_config.json | jq 'keys'
```

**Solutions:**

1. **Add missing field:**
```json
{
  "auth0_config": {
    "domain": "tenant.auth0.com",
    "client_id": "client_id",
    "client_secret": "${AUTH0_CLIENT_SECRET}"  // Add this
  }
}
```

2. **Check required fields by provider:**

**Auth0:**
- `domain` (required)
- `client_id` (required)
- `client_secret` (required)
- `token_vault_url` (optional)
- `timeout` (optional)

**Keycloak:**
- `server_url` (required)
- `realm` (required)
- `client_id` (required)
- `client_secret` (required)
- `scope_mapping` (optional)
- `timeout` (optional)

**AWS Secrets Manager:**
- `region` (required)
- `secret_name_prefix` (required)
- `session_table_name` (required)
- `timeout` (optional)

### Issue: Environment Variable Not Substituted

**Symptoms:**
```
VaultAuthenticationError: Authentication failed
# Configuration shows: "${AUTH0_CLIENT_SECRET}" instead of actual value
```

**Root Cause:**
- Environment variable not set
- Variable name mismatch
- Incorrect substitution syntax

**Diagnostic Steps:**
```bash
# Check if variable is set
echo $AUTH0_CLIENT_SECRET

# List all environment variables
env | grep AUTH0

# Check configuration parsing
python -c "
from shared.identity.config_parser import load_config
config = load_config('config/ial_config.json')
print(config.auth0_config.client_secret)
"
```

**Solutions:**

1. **Set environment variable:**
```bash
# Linux/macOS
export AUTH0_CLIENT_SECRET="your_secret_here"

# Windows PowerShell
$env:AUTH0_CLIENT_SECRET="your_secret_here"

# Add to .env file
echo "AUTH0_CLIENT_SECRET=your_secret_here" >> .env
```

2. **Verify substitution syntax:**
```json
{
  "client_secret": "${AUTH0_CLIENT_SECRET}"  // Correct
  // NOT: "$AUTH0_CLIENT_SECRET" or "{AUTH0_CLIENT_SECRET}"
}
```

3. **Load .env file:**
```python
from dotenv import load_dotenv
load_dotenv()
```

### Issue: Invalid Provider Type

**Symptoms:**
```
VaultConfigurationError: Invalid identity_provider 'oauth2'. Must be one of: auth0, keycloak, aws_secrets
```

**Root Cause:**
- Unsupported provider type
- Typo in provider name
- Case sensitivity issue

**Diagnostic Steps:**
```bash
# Check provider value
cat config/ial_config.json | jq '.identity_provider'
```

**Solutions:**

1. **Use valid provider:**
```json
{
  "identity_provider": "auth0"  // Valid: auth0, keycloak, aws_secrets
}
```

2. **Check case sensitivity:**
```json
{
  "identity_provider": "auth0"  // Correct
  // NOT: "Auth0" or "AUTH0"
}
```

## Authentication Issues

### Issue: Auth0 Authentication Failed

**Symptoms:**
```
VaultAuthenticationError: Auth0 authentication failed
HTTP 401 Unauthorized
```

**Root Cause:**
- Invalid client credentials
- Expired client secret
- Wrong Auth0 domain
- M2M application not configured

**Diagnostic Steps:**
```bash
# Test Auth0 credentials manually
curl -X POST https://YOUR_DOMAIN.auth0.com/oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "client_credentials",
    "client_id": "YOUR_CLIENT_ID",
    "client_secret": "YOUR_CLIENT_SECRET",
    "audience": "https://api.github.com"
  }'

# Check adapter health
python -c "
import asyncio
from shared.identity.auth0_adapter import Auth0Adapter

async def test():
    adapter = Auth0Adapter({
        'domain': 'YOUR_DOMAIN.auth0.com',
        'client_id': 'YOUR_CLIENT_ID',
        'client_secret': 'YOUR_CLIENT_SECRET'
    })
    print(await adapter.health_check())

asyncio.run(test())
"
```

**Solutions:**

1. **Verify credentials in Auth0 dashboard:**
   - Go to Applications → Your M2M App
   - Copy Client ID and Client Secret
   - Update configuration

2. **Check M2M application settings:**
   - Ensure "Client Credentials" grant is enabled
   - Verify Token Vault is enabled
   - Check authorized APIs

3. **Rotate client secret:**
   - Generate new secret in Auth0 dashboard
   - Update configuration
   - Restart Permission Broker

### Issue: Keycloak Authentication Failed

**Symptoms:**
```
VaultAuthenticationError: Keycloak authentication failed
HTTP 401 Unauthorized
```

**Root Cause:**
- Invalid client credentials
- Wrong realm name
- Client not configured for service accounts
- Missing client roles

**Diagnostic Steps:**
```bash
# Test Keycloak credentials
curl -X POST https://KEYCLOAK_URL/realms/REALM/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET"

# Check realm accessibility
curl https://KEYCLOAK_URL/realms/REALM
```

**Solutions:**

1. **Verify Keycloak client configuration:**
   - Go to Clients → Your Client
   - Enable "Service Accounts Enabled"
   - Set "Access Type" to "confidential"
   - Save and regenerate secret

2. **Check realm name:**
```json
{
  "keycloak_config": {
    "realm": "production"  // Must match exactly (case-sensitive)
  }
}
```

3. **Verify client roles:**
   - Go to Clients → Your Client → Service Account Roles
   - Assign necessary roles

### Issue: AWS Secrets Manager Access Denied

**Symptoms:**
```
VaultProviderError: Access denied to secret
botocore.exceptions.ClientError: An error occurred (AccessDeniedException)
```

**Root Cause:**
- Insufficient IAM permissions
- Wrong AWS region
- Secret doesn't exist
- IAM role not attached

**Diagnostic Steps:**
```bash
# Test AWS credentials
aws sts get-caller-identity

# List secrets
aws secretsmanager list-secrets --region us-east-1

# Try to get secret
aws secretsmanager get-secret-value \
  --secret-id ztag/providers/github/credentials \
  --region us-east-1

# Check IAM permissions
aws iam get-role-policy \
  --role-name permission-broker-role \
  --policy-name secrets-access
```

**Solutions:**

1. **Add IAM permissions:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:ListSecrets"
      ],
      "Resource": "arn:aws:secretsmanager:REGION:ACCOUNT:secret:ztag/providers/*"
    }
  ]
}
```

2. **Verify region:**
```json
{
  "aws_secrets_config": {
    "region": "us-east-1"  // Must match secret location
  }
}
```

3. **Create missing secret:**
```bash
aws secretsmanager create-secret \
  --name ztag/providers/github/credentials \
  --secret-string '{"client_id":"...","client_secret":"..."}' \
  --region us-east-1
```

## Network and Connectivity Issues

### Issue: Connection Timeout

**Symptoms:**
```
VaultTimeoutError: Request timed out after 10.0s
httpx.TimeoutException
```

**Root Cause:**
- Network latency
- Provider unavailable
- Firewall blocking requests
- Timeout too short

**Diagnostic Steps:**
```bash
# Test network connectivity
ping tenant.auth0.com

# Test HTTPS connectivity
curl -v https://tenant.auth0.com/.well-known/openid-configuration

# Check DNS resolution
nslookup tenant.auth0.com

# Test with longer timeout
curl --max-time 30 https://tenant.auth0.com/oauth/token
```

**Solutions:**

1. **Increase timeout:**
```json
{
  "auth0_config": {
    "timeout": 30.0  // Increase from default 10.0
  }
}
```

2. **Check firewall rules:**
```bash
# Allow outbound HTTPS
sudo ufw allow out 443/tcp

# Check iptables
sudo iptables -L OUTPUT
```

3. **Verify proxy settings:**
```bash
# Set proxy if needed
export HTTPS_PROXY=http://proxy.example.com:8080
```

4. **Test provider availability:**
```bash
# Check Auth0 status
curl https://status.auth0.com/api/v2/status.json

# Check Keycloak health
curl https://keycloak.example.com/health
```

### Issue: SSL Certificate Verification Failed

**Symptoms:**
```
ssl.SSLError: [SSL: CERTIFICATE_VERIFY_FAILED]
```

**Root Cause:**
- Self-signed certificate
- Expired certificate
- Missing CA certificates
- Corporate proxy with SSL inspection

**Diagnostic Steps:**
```bash
# Check certificate
openssl s_client -connect tenant.auth0.com:443 -showcerts

# Check CA certificates
ls /etc/ssl/certs/

# Test without verification (diagnostic only)
curl -k https://tenant.auth0.com/oauth/token
```

**Solutions:**

1. **Update CA certificates:**
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install ca-certificates

# CentOS/RHEL
sudo yum update ca-certificates
```

2. **Add custom CA certificate:**
```bash
# Copy certificate
sudo cp custom-ca.crt /usr/local/share/ca-certificates/

# Update certificates
sudo update-ca-certificates
```

3. **For development only (not recommended for production):**
```python
import httpx

# Disable SSL verification (INSECURE)
client = httpx.AsyncClient(verify=False)
```

## Token Request Issues

### Issue: Invalid RAR Format

**Symptoms:**
```
VaultValidationError: Invalid RAR format
KeyError: 'actions'
```

**Root Cause:**
- Missing required RAR fields
- Invalid RAR structure
- Wrong data types

**Diagnostic Steps:**
```python
# Validate RAR structure
from shared.schemas import RichAuthorizationRequest

rar = RichAuthorizationRequest(
    type="https://ztag.dev/rar",
    actions=["repo:read"],
    locations=["https://github.com/org/repo"],
    purpose="Read repository",
    context={}
)
print(rar.dict())
```

**Solutions:**

1. **Ensure all required fields:**
```python
rar = RichAuthorizationRequest(
    type="https://ztag.dev/rar",      # Required
    actions=["repo:read"],             # Required (list)
    locations=["https://..."],         # Required (list)
    purpose="Description",             # Required (string)
    context={}                         # Required (dict)
)
```

2. **Check data types:**
```python
# Correct
actions=["repo:read", "repo:write"]  # List of strings

# Incorrect
actions="repo:read"  # String instead of list
```

### Issue: Token Response Missing Fields

**Symptoms:**
```
VaultValidationError: Missing required field 'access_token' in token response
KeyError: 'access_token'
```

**Root Cause:**
- Provider returned unexpected response format
- Provider error not caught
- Parsing logic error

**Diagnostic Steps:**
```bash
# Check raw provider response
curl -X POST https://tenant.auth0.com/oauth/token \
  -H "Content-Type: application/json" \
  -d '{"grant_type":"client_credentials",...}' \
  | jq .
```

**Solutions:**

1. **Check provider response format:**
```json
// Expected format
{
  "access_token": "...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "..."
}
```

2. **Add response validation:**
```python
token_data = response.json()

required_fields = ["access_token", "token_type", "expires_in"]
for field in required_fields:
    if field not in token_data:
        raise VaultValidationError(f"Missing field: {field}")
```

### Issue: Scope Mapping Not Working (Keycloak)

**Symptoms:**
- Keycloak returns token without expected scopes
- Actions not translated to scopes

**Root Cause:**
- Incorrect scope_mapping configuration
- Missing scope definitions in Keycloak
- Client doesn't have scope permissions

**Diagnostic Steps:**
```bash
# Check scope mapping configuration
cat config/ial_config.json | jq '.keycloak_config.scope_mapping'

# Test scope translation
python -c "
from shared.identity.keycloak_adapter import KeycloakAdapter

adapter = KeycloakAdapter({
    'server_url': '...',
    'realm': '...',
    'client_id': '...',
    'client_secret': '...',
    'scope_mapping': {'repo:read': 'github:repo:read'}
})

scopes = adapter._map_scopes(['repo:read'], 'github')
print(scopes)
"
```

**Solutions:**

1. **Configure scope mapping:**
```json
{
  "keycloak_config": {
    "scope_mapping": {
      "repo:read": "github:repo:read",
      "repo:write": ["github:repo:write", "github:repo:admin"]
    }
  }
}
```

2. **Define scopes in Keycloak:**
   - Go to Client Scopes
   - Create new scope (e.g., "github:repo:read")
   - Add to client's assigned scopes

3. **Check client scope permissions:**
   - Go to Clients → Your Client → Client Scopes
   - Ensure required scopes are assigned

## Health Check Issues

### Issue: Health Check Always Returns False

**Symptoms:**
```python
healthy = await provider.health_check()
# healthy is always False
```

**Root Cause:**
- Provider endpoint unreachable
- Wrong health check URL
- Timeout too short
- Network issues

**Diagnostic Steps:**
```bash
# Test health endpoints manually

# Auth0
curl https://tenant.auth0.com/.well-known/openid-configuration

# Keycloak
curl https://keycloak.example.com/realms/your-realm

# AWS
aws secretsmanager list-secrets --region us-east-1 --max-items 1
```

**Solutions:**

1. **Verify endpoint accessibility:**
```bash
# Check if endpoint responds
curl -I https://tenant.auth0.com/.well-known/openid-configuration
```

2. **Increase health check timeout:**
```python
async def health_check(self) -> bool:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:  # Increase timeout
            response = await client.get(self.health_url)
            return response.status_code == 200
    except Exception:
        return False
```

3. **Check network connectivity:**
```bash
# Test DNS
nslookup tenant.auth0.com

# Test connectivity
telnet tenant.auth0.com 443
```

## Performance Issues

### Issue: Slow Token Requests

**Symptoms:**
- Token requests take >5 seconds
- High latency in metrics
- Timeout warnings in logs

**Root Cause:**
- Network latency
- Provider performance issues
- No connection pooling
- Retry logic causing delays

**Diagnostic Steps:**
```bash
# Measure request time
time curl -X POST https://tenant.auth0.com/oauth/token \
  -H "Content-Type: application/json" \
  -d '{"grant_type":"client_credentials",...}'

# Check metrics
curl http://localhost:8080/metrics | grep vault_token_request_duration

# Check logs for retry attempts
grep "retry attempt" logs/permission_broker.log
```

**Solutions:**

1. **Enable connection pooling:**
```python
# httpx.AsyncClient already uses connection pooling
# Ensure client is reused, not recreated per request
```

2. **Optimize timeout:**
```json
{
  "auth0_config": {
    "timeout": 15.0  // Balance between responsiveness and reliability
  }
}
```

3. **Check provider performance:**
```bash
# Monitor provider latency
for i in {1..10}; do
  time curl -X POST https://tenant.auth0.com/oauth/token ...
done
```

4. **Review retry configuration:**
```python
# Adjust retry settings if needed
@with_retry(max_attempts=2, backoff_base=0.5)  # Reduce retries
```

### Issue: High Memory Usage

**Symptoms:**
- Permission Broker memory usage increasing
- Out of memory errors
- Slow performance over time

**Root Cause:**
- HTTP clients not closed
- Singleton pattern memory leak
- Large token cache

**Diagnostic Steps:**
```bash
# Monitor memory usage
ps aux | grep permission_broker

# Check for resource leaks
python -m memory_profiler services/permission_broker/main.py
```

**Solutions:**

1. **Ensure proper cleanup:**
```python
async def __aenter__(self):
    return self

async def __aexit__(self, exc_type, exc_val, exc_tb):
    await self.client.aclose()
```

2. **Use context managers:**
```python
async with httpx.AsyncClient() as client:
    response = await client.post(...)
```

3. **Reset factory for testing:**
```python
# In tests
VaultFactory.reset()
```

## Logging and Debugging

### Enable Debug Logging

```python
import logging

# Enable debug logging for IAL
logging.getLogger('shared.identity').setLevel(logging.DEBUG)

# Enable httpx debug logging
logging.getLogger('httpx').setLevel(logging.DEBUG)
```

### Structured Logging

```python
from shared.logging import JSONLogger

logger = JSONLogger(__name__)

logger.info("Token request", extra={
    "provider": provider,
    "actions": rar.actions,
    "correlation_id": correlation_id
})
```

### Log Analysis

```bash
# Filter IAL logs
grep "identity\|vault\|adapter" logs/permission_broker.log

# Find errors
grep "ERROR" logs/permission_broker.log | grep -i vault

# Track specific request
grep "correlation_id=abc123" logs/permission_broker.log
```

## Getting Help

If you're still experiencing issues:

1. **Collect diagnostic information:**
```bash
# Configuration (redact secrets)
python -c "from shared.identity.config_printer import pretty_print_config; ..."

# Health check results
python -c "import asyncio; ..."

# Recent logs
tail -n 100 logs/permission_broker.log

# Metrics
curl http://localhost:8080/metrics | grep vault_
```

2. **Check documentation:**
   - [Architecture](architecture.md)
   - [Configuration Guide](configuration.md)
   - [API Reference](api-reference.md)
   - [Migration Guide](migration.md)

3. **Run diagnostic tests:**
```bash
pytest tests/integration/ -v
```

4. **Contact support** with:
   - IAL version
   - Provider type (Auth0/Keycloak/AWS)
   - Configuration (redacted)
   - Error messages
   - Logs
   - Steps to reproduce
