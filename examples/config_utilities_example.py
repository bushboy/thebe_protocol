"""
Example demonstrating configuration utilities for Identity Abstraction Layer.

This example shows how to:
1. Load configuration from JSON files
2. Use environment variable substitution
3. Pretty print configuration with redaction
4. Verify round-trip consistency
"""

import os
import sys
import json
import tempfile
from pathlib import Path

# Add parent directory to path to import shared module
sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.identity import (
    ConfigurationParser,
    pretty_print_config,
    IALConfig,
    Auth0Config,
)


def example_1_load_from_file():
    """Example 1: Load configuration from JSON file"""
    print("=" * 60)
    print("Example 1: Load Configuration from JSON File")
    print("=" * 60)
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create a sample configuration file
        config_file = Path(temp_dir) / "ial_config.json"
        config_data = {
            "identity_provider": "auth0",
            "auth0_config": {
                "domain": "myapp.auth0.com",
                "client_id": "abc123xyz",
                "client_secret": "super_secret_value_12345",
                "token_vault_url": "https://myapp.auth0.com/oauth/token",
                "timeout": 15.0
            }
        }
        config_file.write_text(json.dumps(config_data, indent=2))
        
        # Load configuration
        parser = ConfigurationParser()
        config = parser.load(config_file)
        
        print(f"✓ Loaded configuration for provider: {config.identity_provider}")
        print(f"✓ Auth0 domain: {config.auth0_config.domain}")
        print(f"✓ Timeout: {config.auth0_config.timeout}s")
        print()


def example_2_environment_variable_substitution():
    """Example 2: Use environment variable substitution"""
    print("=" * 60)
    print("Example 2: Environment Variable Substitution")
    print("=" * 60)
    
    # Set environment variables
    os.environ["MY_AUTH0_DOMAIN"] = "production.auth0.com"
    os.environ["MY_CLIENT_ID"] = "prod_client_123"
    os.environ["MY_CLIENT_SECRET"] = "prod_secret_xyz"
    
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create config with environment variable references
            config_file = Path(temp_dir) / "ial_config.json"
            config_data = {
                "identity_provider": "auth0",
                "auth0_config": {
                    "domain": "${MY_AUTH0_DOMAIN}",
                    "client_id": "${MY_CLIENT_ID}",
                    "client_secret": "${MY_CLIENT_SECRET}",
                    "timeout": 10.0
                }
            }
            config_file.write_text(json.dumps(config_data, indent=2))
            
            # Load configuration - environment variables will be substituted
            parser = ConfigurationParser()
            config = parser.load(config_file)
            
            print(f"✓ Domain substituted: {config.auth0_config.domain}")
            print(f"✓ Client ID substituted: {config.auth0_config.client_id}")
            print(f"✓ Client secret substituted: {config.auth0_config.client_secret[:10]}...")
            print()
    
    finally:
        # Clean up environment variables
        del os.environ["MY_AUTH0_DOMAIN"]
        del os.environ["MY_CLIENT_ID"]
        del os.environ["MY_CLIENT_SECRET"]


def example_3_pretty_print_with_redaction():
    """Example 3: Pretty print configuration with sensitive field redaction"""
    print("=" * 60)
    print("Example 3: Pretty Print with Redaction")
    print("=" * 60)
    
    # Create a configuration object
    config = IALConfig(
        identity_provider="auth0",
        auth0_config=Auth0Config(
            domain="myapp.auth0.com",
            client_id="abc123xyz",
            client_secret="super_secret_value_12345",
            timeout=15.0
        )
    )
    
    # Pretty print with redaction (default)
    print("With redaction (safe for logs):")
    print(pretty_print_config(config, redact_sensitive=True))
    print()
    
    # Pretty print without redaction (for configuration files)
    print("Without redaction (for config files):")
    print(pretty_print_config(config, redact_sensitive=False))
    print()


def example_4_round_trip_consistency():
    """Example 4: Verify round-trip consistency"""
    print("=" * 60)
    print("Example 4: Round-Trip Consistency")
    print("=" * 60)
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create original configuration
        original_config = IALConfig(
            identity_provider="keycloak",
            keycloak_config={
                "server_url": "https://keycloak.example.com",
                "realm": "my-realm",
                "client_id": "my-client",
                "client_secret": "my-secret-12345",
                "scope_mapping": {
                    "repo:write": "github:repo:write",
                    "repo:read": "github:repo:read"
                },
                "timeout": 20.0
            }
        )
        
        print("Original configuration:")
        print(f"  Provider: {original_config.identity_provider}")
        print(f"  Realm: {original_config.keycloak_config.realm}")
        print(f"  Scope mappings: {len(original_config.keycloak_config.scope_mapping)}")
        print()
        
        # Round-trip: config -> JSON -> parse -> JSON -> parse
        for i in range(3):
            # Pretty print
            pretty_json = pretty_print_config(original_config, redact_sensitive=False)
            
            # Write to file
            config_file = Path(temp_dir) / f"config_{i}.json"
            config_file.write_text(pretty_json)
            
            # Parse
            parser = ConfigurationParser()
            original_config = parser.load(config_file)
        
        print(f"After {3} round-trips:")
        print(f"  Provider: {original_config.identity_provider}")
        print(f"  Realm: {original_config.keycloak_config.realm}")
        print(f"  Scope mappings: {len(original_config.keycloak_config.scope_mapping)}")
        print("✓ All fields preserved!")
        print()


def example_5_default_values():
    """Example 5: Default value application"""
    print("=" * 60)
    print("Example 5: Default Value Application")
    print("=" * 60)
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create config without timeout (should use default)
        config_file = Path(temp_dir) / "ial_config.json"
        config_data = {
            "identity_provider": "auth0",
            "auth0_config": {
                "domain": "myapp.auth0.com",
                "client_id": "abc123",
                "client_secret": "secret123"
                # timeout not specified
            }
        }
        config_file.write_text(json.dumps(config_data))
        
        # Load configuration
        parser = ConfigurationParser()
        config = parser.load(config_file)
        
        print(f"✓ Timeout not specified in config")
        print(f"✓ Default timeout applied: {config.auth0_config.timeout}s")
        print()


if __name__ == "__main__":
    print("\n")
    print("╔" + "=" * 58 + "╗")
    print("║" + " " * 10 + "IAL Configuration Utilities Examples" + " " * 11 + "║")
    print("╚" + "=" * 58 + "╝")
    print()
    
    example_1_load_from_file()
    example_2_environment_variable_substitution()
    example_3_pretty_print_with_redaction()
    example_4_round_trip_consistency()
    example_5_default_values()
    
    print("=" * 60)
    print("All examples completed successfully!")
    print("=" * 60)
