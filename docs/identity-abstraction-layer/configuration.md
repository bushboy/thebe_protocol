# Identity Abstraction Layer - Configuration Guide

## Overview

The Identity Abstraction Layer uses a unified configuration format that supports multiple identity providers. This guide provides configuration examples and explains all available options.

## Configuration File Format

The IAL supports both JSON and YAML configuration formats. The configuration file should be placed in the Permission Broker's configuration directory.

### Configuration Structure

```json
{
  "identity_provider": "auth0|keycloak|aws_secrets",
  "auth0_config": { ... },
  "keycloak_config": { ... },
  "aws_secrets_config": { ... }
}
```

The `identity_provider` field determines which adapter is used. Only the configuration section matching the selected provider needs to be complete.

## Auth0 Configuration

### Basic Configuration

```json
{
  "identity_provider": "auth0",
  "auth0_config": {
    "domain": "your-tenant.auth0.com",
    "client_id": "your_m2m_client_id",
    "client_secret": "your_m2m_client_secret"
  }
}
```

### Complete Configuration with Optional Parameters

```json
{
  "identity_provider": "auth0",
  "auth0_config": {
    "domain": "your-tenant.auth0.com",
    "client_id": "your_m2m_client_id",
    "client_secret": "${AUTH0_CLIENT_SECRET}",
    "token_vault_url": "https://your-tenant.auth0.com/oauth/token",
    "timeout": 10.0
  }
}
```

### Auth0 Configuration Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `domain` | Yes | - | Auth0 tenant domain (e.g., "your-tenant.auth0.com") |
| `client_id` | Yes | - | M2M application client ID |
| `client_secret` | Yes | - | M2M application client secret |
| `token_vault_url` | No | `https://{domain}/oauth/token` | Custom Token Vault URL |
| `timeout` | No | 10.0 | Request timeout in seconds |

### Auth0 Setup Requirements

1. Create M2M application in Auth0 dashboard
2. Enable Token Vault for the application
3. Configure Token Vault connections (GitHub, Slack, etc.)
4. Grant necessary permissions to the M2M application
5. Copy client ID and client secret to configuration

### Auth0 YAML Example

```yaml
identity_provider: auth0
auth0_config:
  domain: your-tenant.auth0.com
  client_id: your_m2m_client_id
  client_secret: ${AUTH0_CLIENT_SECRET}
  timeout: 15.0
```

## Keycloak Configuration

### Basic Configuration

```json
{
  "identity_provider": "keycloak",
  "keycloak_config": {
    "server_url": "https://keycloak.example.com",
    "realm": "your-realm",
    "client_id": "permission-broker",
    "client_secret": "your_client_secret"
  }
}
```

### Complete Configuration with Scope Mapping

```json
{
  "identity_provider": "keycloak",
  "keycloak_config": {
    "server_url": "https://keycloak.example.com",
    "realm": "your-realm",
    "client_id": "permission-broker",
    "client_secret": "${KEYCLOAK_CLIENT_SECRET}",
    "scope_mapping": {
      "repo:read": "github:repo:read",
      "repo:write": ["github:repo:write", "github:repo:admin"],
      "channels:read": "slack:channels:read",
      "channels:write": "slack:channels:write"
    },
    "timeout": 10.0
  }
}
```

### Keycloak Configuration Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `server_url` | Yes | - | Keycloak server URL (e.g., "https://keycloak.example.com") |
| `realm` | Yes | - | Keycloak realm name |
| `client_id` | Yes | - | Client ID for the Permission Broker |
| `client_secret` | Yes | - | Client secret |
| `scope_mapping` | No | {} | Dictionary mapping RAR actions to Keycloak scopes |
| `timeout` | No | 10.0 | Request timeout in seconds |

### Keycloak Scope Mapping

The `scope_mapping` dictionary translates RAR actions to Keycloak-specific scopes:

**Single Scope Mapping:**
```json
{
  "repo:read": "github:repo:read"
}
```

**Multiple Scopes per Action:**
```json
{
  "repo:write": ["github:repo:write", "github:repo:admin"]
}
```

**Default Behavior (no mapping):**
If an action has no mapping, the adapter uses `{provider}:{action}` format.
Example: `repo:read` → `github:repo:read`

### Keycloak Setup Requirements

1. Create realm in Keycloak
2. Create client with "Client Credentials" flow enabled
3. Configure client scopes for provider access
4. Set up service account roles
5. Copy client ID and client secret to configuration

### Keycloak YAML Example

```yaml
identity_provider: keycloak
keycloak_config:
  server_url: https://keycloak.example.com
  realm: production
  client_id: permission-broker
  client_secret: ${KEYCLOAK_CLIENT_SECRET}
  scope_mapping:
    repo:read: github:repo:read
    repo:write:
      - github:repo:write
      - github:repo:admin
  timeout: 12.0
```

## AWS Secrets Manager Configuration

### Basic Configuration

```json
{
  "identity_provider": "aws_secrets",
  "aws_secrets_config": {
    "region": "us-east-1",
    "secret_name_prefix": "ztag/providers",
    "session_table_name": "ztag-sessions"
  }
}
```

### Complete Configuration with Optional Parameters

```json
{
  "identity_provider": "aws_secrets",
  "aws_secrets_config": {
    "region": "us-east-1",
    "secret_name_prefix": "ztag/providers",
    "session_table_name": "ztag-sessions",
    "timeout": 10.0
  }
}
```

### AWS Configuration Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `region` | Yes | - | AWS region (e.g., "us-east-1") |
| `secret_name_prefix` | Yes | - | Prefix for secret names in Secrets Manager |
| `session_table_name` | Yes | - | DynamoDB table name for session tracking |
| `timeout` | No | 10.0 | Request timeout in seconds |

### AWS Secret Structure

Secrets in AWS Secrets Manager should follow this naming convention:
```
{secret_name_prefix}/{provider}/credentials
```

Example secret names:
- `ztag/providers/github/credentials`
- `ztag/providers/slack/credentials`
- `ztag/providers/google_workspace/credentials`

Secret value format (JSON):
```json
{
  "client_id": "provider_client_id",
  "client_secret": "provider_client_secret",
  "access_token": "optional_long_lived_token",
  "api_key": "optional_api_key"
}
```

### DynamoDB Table Schema

Create a DynamoDB table with the following schema:

**Table Name:** As specified in `session_table_name`

**Primary Key:**
- Partition Key: `session_id` (String)

**Attributes:**
- `session_id` (String) - Unique session identifier
- `provider` (String) - Provider name (github, slack, etc.)
- `created_at` (String) - ISO 8601 timestamp
- `revoked_at` (String) - ISO 8601 timestamp (optional)
- `token_metadata` (Map) - Token metadata

### AWS Setup Requirements

1. Create Secrets Manager secrets for each provider
2. Create DynamoDB table for session tracking
3. Configure IAM role or access keys for Permission Broker
4. Grant permissions:
   - `secretsmanager:GetSecretValue` on secrets
   - `dynamodb:PutItem` on session table
   - `dynamodb:UpdateItem` on session table
   - `secretsmanager:ListSecrets` for health checks

### AWS IAM Policy Example

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
      "Resource": "arn:aws:secretsmanager:us-east-1:123456789012:secret:ztag/providers/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "dynamodb:GetItem"
      ],
      "Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/ztag-sessions"
    }
  ]
}
```

### AWS YAML Example

```yaml
identity_provider: aws_secrets
aws_secrets_config:
  region: us-east-1
  secret_name_prefix: ztag/providers
  session_table_name: ztag-sessions
  timeout: 15.0
```

## Environment Variable Substitution

All configuration values support environment variable substitution using the `${VAR_NAME}` syntax.

### Example with Environment Variables

```json
{
  "identity_provider": "auth0",
  "auth0_config": {
    "domain": "${AUTH0_DOMAIN}",
    "client_id": "${AUTH0_CLIENT_ID}",
    "client_secret": "${AUTH0_CLIENT_SECRET}",
    "timeout": 10.0
  }
}
```

### Setting Environment Variables

**Linux/macOS:**
```bash
export AUTH0_DOMAIN="your-tenant.auth0.com"
export AUTH0_CLIENT_ID="your_client_id"
export AUTH0_CLIENT_SECRET="your_client_secret"
```

**Windows (PowerShell):**
```powershell
$env:AUTH0_DOMAIN="your-tenant.auth0.com"
$env:AUTH0_CLIENT_ID="your_client_id"
$env:AUTH0_CLIENT_SECRET="your_client_secret"
```

**Docker:**
```yaml
environment:
  - AUTH0_DOMAIN=your-tenant.auth0.com
  - AUTH0_CLIENT_ID=your_client_id
  - AUTH0_CLIENT_SECRET=your_client_secret
```

### Best Practices for Environment Variables

1. Never commit secrets to version control
2. Use environment variables for all sensitive values
3. Document required environment variables in README
4. Use `.env.example` file to show required variables
5. Validate environment variables at startup

## Default Values

### Timeout Defaults

All adapters use a default timeout of 10.0 seconds if not specified.

```json
{
  "identity_provider": "auth0",
  "auth0_config": {
    "domain": "your-tenant.auth0.com",
    "client_id": "your_client_id",
    "client_secret": "your_client_secret"
    // timeout defaults to 10.0
  }
}
```

### Auth0 Token Vault URL Default

If `token_vault_url` is not specified, it defaults to:
```
https://{domain}/oauth/token
```

### Keycloak Scope Mapping Default

If `scope_mapping` is not specified or an action has no mapping, the adapter uses:
```
{provider}:{action}
```

Example: `repo:read` with provider `github` → `github:repo:read`

## Configuration Validation

The IAL validates configuration at startup and raises descriptive errors for invalid configurations.

### Common Validation Errors

**Missing Required Field:**
```
VaultConfigurationError: Missing required field 'client_secret' in auth0_config
```

**Invalid Provider Type:**
```
VaultConfigurationError: Invalid identity_provider 'invalid'. Must be one of: auth0, keycloak, aws_secrets
```

**Missing Provider Configuration:**
```
VaultConfigurationError: Configuration section 'keycloak_config' is required when identity_provider is 'keycloak'
```

**Invalid Timeout Value:**
```
VaultConfigurationError: Timeout must be a positive number, got: -5.0
```

## Configuration Examples by Use Case

### Development Environment (Auth0)

```json
{
  "identity_provider": "auth0",
  "auth0_config": {
    "domain": "dev-tenant.auth0.com",
    "client_id": "dev_client_id",
    "client_secret": "dev_client_secret",
    "timeout": 30.0
  }
}
```

### Production Environment (Keycloak)

```json
{
  "identity_provider": "keycloak",
  "keycloak_config": {
    "server_url": "https://keycloak.prod.example.com",
    "realm": "production",
    "client_id": "${KEYCLOAK_CLIENT_ID}",
    "client_secret": "${KEYCLOAK_CLIENT_SECRET}",
    "scope_mapping": {
      "repo:read": "github:repo:read",
      "repo:write": ["github:repo:write", "github:repo:admin"]
    },
    "timeout": 15.0
  }
}
```

### Cloud Deployment (AWS Secrets Manager)

```json
{
  "identity_provider": "aws_secrets",
  "aws_secrets_config": {
    "region": "${AWS_REGION}",
    "secret_name_prefix": "ztag/providers",
    "session_table_name": "ztag-sessions-prod",
    "timeout": 20.0
  }
}
```

## Configuration File Location

The Permission Broker looks for configuration in the following locations (in order):

1. Path specified by `IAL_CONFIG_PATH` environment variable
2. `./config/ial_config.json`
3. `./config/ial_config.yaml`
4. `/etc/ztag/ial_config.json`
5. `/etc/ztag/ial_config.yaml`

### Specifying Custom Configuration Path

```bash
export IAL_CONFIG_PATH=/path/to/custom/config.json
```

## Configuration Pretty Printing

Use the configuration pretty printer to verify your configuration:

```python
from shared.identity.config_parser import load_config
from shared.identity.config_printer import pretty_print_config

config = load_config("config/ial_config.json")
print(pretty_print_config(config))
```

Output example:
```
Identity Abstraction Layer Configuration
=========================================

Active Provider: auth0

Auth0 Configuration:
  Domain: your-tenant.auth0.com
  Client ID: your_client_id
  Client Secret: ********** (redacted)
  Token Vault URL: https://your-tenant.auth0.com/oauth/token
  Timeout: 10.0 seconds
```

## Troubleshooting Configuration Issues

### Configuration Not Loading

1. Check file path and permissions
2. Verify JSON/YAML syntax
3. Check environment variables are set
4. Review Permission Broker logs for validation errors

### Provider Not Working

1. Verify provider-specific configuration is complete
2. Test provider connectivity manually
3. Check credentials are valid
4. Review adapter logs for detailed errors

### Environment Variables Not Substituting

1. Verify environment variables are exported
2. Check variable names match exactly (case-sensitive)
3. Ensure `${VAR_NAME}` syntax is used correctly
4. Restart Permission Broker after setting variables

## Next Steps

- Review [Architecture Documentation](architecture.md) for design details
- See [Migration Guide](migration.md) for upgrading from TokenVaultClient
- Check [Troubleshooting Guide](troubleshooting.md) for common issues
- Read [API Reference](api-reference.md) for programmatic usage
