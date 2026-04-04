# Auth0 Configuration for Zero-Trust Agentic Guardian

This directory contains scripts and configuration for setting up Auth0 infrastructure for the Zero-Trust Agentic Guardian system.

## Overview

The Auth0 configuration script (`setup_auth0.py`) automates the creation of:
- 5 M2M (Machine-to-Machine) applications for service authentication
- DPoP keypairs for token binding
- Provider connection templates for GitHub, Slack, and Google Workspace
- Configuration manifest with all credentials

## Prerequisites

1. **Auth0 Account**: You need an Auth0 account with appropriate permissions
2. **Management API Token**: Create a Management API token with the following scopes:
   - `create:clients`
   - `update:clients`
   - `read:clients`
   - `create:connections`
   - `update:connections`
   - `read:connections`

3. **Python Dependencies**: Install required packages:
   ```bash
   pip install cryptography requests
   ```

4. **Auth0 Enterprise Plan** (for Token Vault): Token Vault requires an Enterprise plan

## Usage

### Step 1: Set Environment Variables

```bash
export AUTH0_DOMAIN='your-tenant.auth0.com'
export AUTH0_MANAGEMENT_TOKEN='your-management-api-token'
```

### Step 2: Run Configuration Script

```bash
python infra/auth0/setup_auth0.py
```

The script will:
1. Create 5 M2M applications (planner, safety-agent, permission-broker, executor, intent-engine)
2. Generate DPoP keypairs for each service
3. Register DPoP public keys as JWKs
4. Generate configuration manifest at `infra/auth0/auth0_manifest.json`

### Step 3: Manual Configuration Steps

After running the script, complete these manual steps in the Auth0 Dashboard:

#### Enable Token Vault
1. Contact Auth0 support to enable Token Vault (Enterprise feature)
2. Navigate to Dashboard → Extensions → Token Vault
3. Enable Token Vault for your tenant

#### Configure Provider Connections
1. Navigate to Dashboard → Authentication → Social
2. Add GitHub connection:
   - Enable connection
   - Configure OAuth App credentials
   - Set scopes: `repo:read`, `repo:write`, `user:read`, `org:read`, `admin:org`, `delete_repo`
3. Add Slack connection:
   - Enable connection
   - Configure OAuth App credentials
   - Set scopes: `channels:read`, `chat:write`, `channels:manage`, `users:read`, `groups:read`, `groups:write`
4. Add Google Workspace connection:
   - Enable connection
   - Configure OAuth App credentials
   - Set scopes: Gmail and Drive read/write permissions

#### Link Applications to Connections
1. For each provider connection, enable it for the M2M applications
2. Update the manifest file with the connection IDs

## Output Files

### `auth0_manifest.json`
Complete configuration manifest containing:
- Service credentials (client_id, client_secret)
- DPoP key paths
- Provider connection templates
- Configuration notes

**Example structure:**
```json
{
  "version": "1.0",
  "auth0_domain": "your-tenant.auth0.com",
  "services": {
    "planner": {
      "client_id": "...",
      "client_secret": "...",
      "jwks_uri": "...",
      "dpop_private_key_path": "...",
      "dpop_key_id": "..."
    },
    ...
  },
  "provider_connections": {
    "github": {
      "name": "github",
      "strategy": "github",
      "scope_categories": {
        "read_only": ["repo:read", "user:read", "org:read"],
        "write_action": ["repo:write", "admin:org", "delete_repo"]
      }
    },
    ...
  }
}
```

### `keys/` Directory
Contains DPoP private keys for each service:
- `planner_dpop_private.pem`
- `safety-agent_dpop_private.pem`
- `permission-broker_dpop_private.pem`
- `executor_dpop_private.pem`
- `intent-engine_dpop_private.pem`

**⚠️ Security Warning**: These private keys must be protected and distributed securely to services.

## Security Considerations

1. **Protect the Manifest**: The `auth0_manifest.json` file contains sensitive credentials
2. **Secure Key Distribution**: DPoP private keys should be distributed using secure channels
3. **Rotate Credentials**: Implement regular credential rotation
4. **Limit Token Lifetime**: Configure short-lived tokens (5 minutes recommended)
5. **Monitor Access**: Enable Auth0 logging and monitoring

## Troubleshooting

### "Management API token expired"
- Generate a new Management API token in Auth0 Dashboard
- Update the `AUTH0_MANAGEMENT_TOKEN` environment variable

### "Insufficient permissions"
- Verify your Management API token has the required scopes
- Check that your Auth0 account has appropriate permissions

### "Token Vault not available"
- Token Vault requires an Auth0 Enterprise plan
- Contact Auth0 support to enable this feature

## Requirements Mapping

This configuration script implements the following requirements:
- **Requirement 1.1**: Creates exactly five M2M applications
- **Requirement 1.2**: Enables client_credentials grant for each
- **Requirement 1.3**: Generates DPoP keypairs and registers as JWKs
- **Requirement 1.4**: Outputs manifest JSON with credentials
- **Requirement 1.5**: Enables Auth0 Token Vault
- **Requirement 1.6**: Configures GitHub, Slack, Google Workspace connections
- **Requirement 1.7**: Distinguishes read-only and write-action scopes
