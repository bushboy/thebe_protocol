# Configuration Utilities for Identity Abstraction Layer

## Overview

The configuration utilities provide parsing and pretty printing capabilities for IAL configuration. These utilities enable loading configuration from JSON/YAML files with environment variable substitution, validation, and human-readable output formatting.

## Components

### ConfigurationParser

The `ConfigurationParser` class loads and parses IAL configuration from files or dictionaries.

**Features:**
- Load from JSON or YAML files
- Environment variable substitution using `${VAR_NAME}` syntax
- Automatic validation using Pydantic models
- Default value application for optional parameters

**Usage:**

```python
from shared.identity import ConfigurationParser

# Load from file
parser = ConfigurationParser()
config = parser.load("config.json")

# Load from dictionary
config_dict = {
    "identity_provider": "auth0",
    "auth0_config": {
        "domain": "myapp.auth0.com",
        "client_id": "abc123",
        "client_secret": "${AUTH0_SECRET}",
        "timeout": 15.0
    }
}
config = parser.load_from_dict(config_dict)
```

### Configuration Pretty Printer

The `pretty_print_config` function formats IAL configuration as human-readable indented JSON.

**Features:**
- Format as indented JSON with proper structure
- Redact sensitive fields (client_secret, access keys)
- Display active identity provider type
- Display all configuration parameters for active provider
- Support round-trip consistency

**Usage:**

```python
from shared.identity import pretty_print_config, IALConfig, Auth0Config

config = IALConfig(
    identity_provider="auth0",
    auth0_config=Auth0Config(
        domain="myapp.auth0.com",
        client_id="abc123",
        client_secret="secret123",
        timeout=10.0
    )
)

# Pretty print with redaction (safe for logs)
print(pretty_print_config(config, redact_sensitive=True))

# Pretty print without redaction (for config files)
print(pretty_print_config(config, redact_sensitive=False))
```

## Environment Variable Substitution

Configuration files can reference environment variables using the `${VAR_NAME}` syntax:

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

The parser will automatically substitute these references with the actual environment variable values.

## Default Values

Optional configuration parameters have default values:

| Parameter | Default Value | Description |
|-----------|---------------|-------------|
| `timeout` | 10.0 | Request timeout in seconds |
| `token_vault_url` | None | Custom Token Vault URL (Auth0 only) |
| `scope_mapping` | {} | Scope mapping dictionary (Keycloak only) |

## Sensitive Field Redaction

When `redact_sensitive=True`, the pretty printer redacts the following fields:

- `client_secret`
- `access_key`
- `secret_key`
- `access_token`
- `refresh_token`
- `api_key`
- `private_key`
- `password`

Redacted values show the first 4 characters followed by `***`:

```
"client_secret": "supe***"
```

## Round-Trip Consistency

The configuration utilities guarantee round-trip consistency:

```
config → pretty_print → parse → pretty_print → parse
```

All fields are preserved through multiple round-trips without data loss or corruption.

## Configuration Examples

### Auth0 Configuration

```json
{
  "identity_provider": "auth0",
  "auth0_config": {
    "domain": "myapp.auth0.com",
    "client_id": "abc123xyz",
    "client_secret": "${AUTH0_CLIENT_SECRET}",
    "token_vault_url": "https://myapp.auth0.com/oauth/token",
    "timeout": 15.0
  }
}
```

### Keycloak Configuration

```json
{
  "identity_provider": "keycloak",
  "keycloak_config": {
    "server_url": "https://keycloak.example.com",
    "realm": "my-realm",
    "client_id": "my-client",
    "client_secret": "${KEYCLOAK_CLIENT_SECRET}",
    "scope_mapping": {
      "repo:write": "github:repo:write",
      "repo:read": "github:repo:read"
    },
    "timeout": 20.0
  }
}
```

### AWS Secrets Manager Configuration

```json
{
  "identity_provider": "aws_secrets",
  "aws_secrets_config": {
    "region": "us-east-1",
    "secret_name_prefix": "myapp/providers",
    "session_table_name": "myapp-sessions",
    "timeout": 12.0
  }
}
```

## Error Handling

The configuration utilities raise `VaultConfigurationError` for:

- Missing configuration files
- Invalid JSON/YAML syntax
- Missing required fields
- Invalid field values
- Missing environment variables
- Validation failures

Example:

```python
from shared.identity import ConfigurationParser
from shared.identity.exceptions import VaultConfigurationError

try:
    parser = ConfigurationParser()
    config = parser.load("config.json")
except VaultConfigurationError as e:
    print(f"Configuration error: {e}")
```

## Testing

The configuration utilities are thoroughly tested with:

- **Unit tests**: Test specific functionality (environment variable substitution, default values, validation, redaction)
- **Property tests**: Test universal properties (round-trip consistency, JSON validity, field preservation)

Run tests:

```bash
# Unit tests
pytest tests/test_config_utilities_unit.py -v

# Property tests
pytest tests/test_config_utilities_properties.py -v

# All tests
pytest tests/test_config_utilities_*.py -v
```

## Examples

See `examples/config_utilities_example.py` for complete working examples demonstrating:

1. Loading configuration from JSON files
2. Environment variable substitution
3. Pretty printing with redaction
4. Round-trip consistency verification
5. Default value application

Run the examples:

```bash
python examples/config_utilities_example.py
```

## API Reference

### ConfigurationParser

```python
class ConfigurationParser:
    def load(self, config_path: Union[str, Path]) -> IALConfig:
        """Load and parse configuration from a file."""
        
    def load_from_dict(self, config_dict: Dict[str, Any]) -> IALConfig:
        """Load and parse configuration from a dictionary."""
```

### pretty_print_config

```python
def pretty_print_config(config: IALConfig, redact_sensitive: bool = True) -> str:
    """Format IAL configuration as human-readable indented JSON.
    
    Args:
        config: IALConfig object to format
        redact_sensitive: Whether to redact sensitive fields (default: True)
        
    Returns:
        Formatted JSON string with proper indentation
    """
```

## Requirements Validated

The configuration utilities validate the following requirements:

- **Requirement 6.6**: Environment variable substitution for ${VAR_NAME} syntax
- **Requirement 6.7**: Default value application for optional parameters
- **Requirement 15.4**: Configuration validation using Pydantic models
- **Requirement 16.1**: Format configuration as readable JSON with proper indentation
- **Requirement 16.2**: Display active identity provider type
- **Requirement 16.3**: Display all configuration parameters for active provider
- **Requirement 16.4**: Redact sensitive fields (client_secret, access keys)
- **Requirement 16.5**: Round-trip consistency (parse → pretty print → parse preserves values)
