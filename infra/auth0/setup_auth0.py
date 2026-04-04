#!/usr/bin/env python3
"""
Auth0 Configuration Script for Zero-Trust Agentic Guardian Architecture

This script creates M2M applications, configures Token Vault, and sets up
provider connections for the Zero-Trust Agentic Guardian system.

Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7
"""

import os
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import requests
import base64
import hashlib


class Auth0ConfigurationError(Exception):
    """Raised when Auth0 configuration fails"""
    pass


class Auth0Configurator:
    """Manages Auth0 configuration for the Zero-Trust Agentic Guardian system"""
    
    # Service names as per Requirement 1.1
    SERVICE_NAMES = ["planner", "safety-agent", "permission-broker", "executor", "intent-engine"]
    
    # Provider scope categorization as per Requirement 1.7
    # read_only: Scopes that only allow reading/viewing data
    # write_action: Scopes that allow creating, updating, or deleting data
    PROVIDER_SCOPES = {
        "github": {
            "read_only": ["repo:read", "user:read", "org:read"],
            "write_action": ["repo:write", "admin:org", "delete_repo"]
        },
        "slack": {
            "read_only": ["channels:read", "users:read", "groups:read"],
            "write_action": ["chat:write", "channels:manage", "groups:write"]
        },
        "google_workspace": {
            "read_only": ["https://www.googleapis.com/auth/gmail.readonly", 
                         "https://www.googleapis.com/auth/drive.readonly"],
            "write_action": ["https://www.googleapis.com/auth/gmail.send",
                           "https://www.googleapis.com/auth/drive"]
        }
    }
    
    def __init__(self, domain: str, management_token: str, output_dir: str = "infra/auth0"):
        """
        Initialize Auth0 configurator
        
        Args:
            domain: Auth0 domain (e.g., 'your-tenant.auth0.com')
            management_token: Auth0 Management API token
            output_dir: Directory to store output files
        """
        self.domain = domain
        self.management_token = management_token
        self.output_dir = Path(output_dir)
        self.base_url = f"https://{domain}/api/v2"
        self.headers = {
            "Authorization": f"Bearer {management_token}",
            "Content-Type": "application/json"
        }
        
        # Create output directory if it doesn't exist
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Directory for DPoP keys
        self.keys_dir = self.output_dir / "keys"
        self.keys_dir.mkdir(exist_ok=True)
    
    def generate_dpop_keypair(self, service_name: str) -> Dict[str, str]:
        """
        Generate DPoP keypair for a service (Requirement 1.3)
        
        Args:
            service_name: Name of the service
            
        Returns:
            Dictionary with private_key_path, public_key_jwk, and key_id
        """
        # Generate RSA 2048-bit keypair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Serialize private key to PEM
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Save private key
        private_key_path = self.keys_dir / f"{service_name}_dpop_private.pem"
        private_key_path.write_bytes(private_pem)
        
        # Get public key
        public_key = private_key.public_key()
        
        # Extract public key numbers for JWK
        public_numbers = public_key.public_numbers()
        
        # Convert to base64url encoding
        def int_to_base64url(num: int) -> str:
            """Convert integer to base64url encoded string"""
            byte_length = (num.bit_length() + 7) // 8
            num_bytes = num.to_bytes(byte_length, byteorder='big')
            return base64.urlsafe_b64encode(num_bytes).rstrip(b'=').decode('utf-8')
        
        # Generate key ID (thumbprint)
        key_id = hashlib.sha256(f"{service_name}-dpop".encode()).hexdigest()[:16]
        
        # Create JWK representation
        jwk = {
            "kty": "RSA",
            "use": "sig",
            "kid": key_id,
            "n": int_to_base64url(public_numbers.n),
            "e": int_to_base64url(public_numbers.e),
            "alg": "RS256"
        }
        
        return {
            "private_key_path": str(private_key_path.absolute()),
            "public_key_jwk": jwk,
            "key_id": key_id
        }
    
    def create_m2m_application(self, service_name: str, dpop_jwk: Dict) -> Dict[str, str]:
        """
        Create M2M application in Auth0 (Requirements 1.2, 1.3, 12.1)
        
        Args:
            service_name: Name of the service
            dpop_jwk: DPoP public key in JWK format
            
        Returns:
            Dictionary with client_id, client_secret, and jwks_uri
        """
        # Create application
        app_data = {
            "name": f"ztag-{service_name}",
            "description": f"Zero-Trust Agentic Guardian - {service_name} service",
            "app_type": "non_interactive",  # M2M application
            "grant_types": ["client_credentials"],  # Requirement 1.2
            "token_endpoint_auth_method": "client_secret_post",
            "jwt_configuration": {
                "alg": "RS256",
                "lifetime_in_seconds": 300  # 5 minutes as per Requirement 12.1
            }
        }
        
        try:
            response = requests.post(
                f"{self.base_url}/clients",
                headers=self.headers,
                json=app_data
            )
            response.raise_for_status()
            app = response.json()
            
            client_id = app["client_id"]
            client_secret = app["client_secret"]
            
            # Register DPoP public key as JWK (Requirement 1.3)
            # Note: Auth0 doesn't have direct DPoP support, so we store the JWK
            # in the client metadata for retrieval by services
            update_data = {
                "client_metadata": {
                    "dpop_jwk": json.dumps(dpop_jwk)
                }
            }
            
            update_response = requests.patch(
                f"{self.base_url}/clients/{client_id}",
                headers=self.headers,
                json=update_data
            )
            update_response.raise_for_status()
            
            return {
                "client_id": client_id,
                "client_secret": client_secret,
                "jwks_uri": f"https://{self.domain}/.well-known/jwks.json"
            }
            
        except requests.exceptions.RequestException as e:
            raise Auth0ConfigurationError(f"Failed to create M2M application for {service_name}: {e}")
    def configure_token_lifetime(self, client_id: str) -> bool:
        """
        Configure JWT token lifetime to 5 minutes (Requirement 12.1)

        Args:
            client_id: Client ID of the M2M application

        Returns:
            True if successful
        """
        try:
            # Set token lifetime to 300 seconds (5 minutes)
            update_data = {
                "jwt_configuration": {
                    "lifetime_in_seconds": 300,  # 5 minutes as per Requirement 12.1
                    "alg": "RS256"
                }
            }

            response = requests.patch(
                f"{self.base_url}/clients/{client_id}",
                headers=self.headers,
                json=update_data
            )
            response.raise_for_status()

            return True

        except requests.exceptions.RequestException as e:
            raise Auth0ConfigurationError(f"Failed to configure token lifetime for {client_id}: {e}")

    
    def setup_m2m_applications(self) -> Dict[str, Dict]:
        """
        Create all M2M applications with DPoP keypairs (Requirements 1.1, 1.2, 1.3, 1.4)
        
        Returns:
            Dictionary mapping service names to their credentials
        """
        manifest = {}
        
        print(f"Creating {len(self.SERVICE_NAMES)} M2M applications...")
        
        for service_name in self.SERVICE_NAMES:
            print(f"  - Creating application for {service_name}...")
            
            # Generate DPoP keypair
            dpop_keys = self.generate_dpop_keypair(service_name)
            
            # Create M2M application
            app_credentials = self.create_m2m_application(
                service_name,
                dpop_keys["public_key_jwk"]
            )
            
            # Build manifest entry
            manifest[service_name] = {
                "client_id": app_credentials["client_id"],
                "client_secret": app_credentials["client_secret"],
                "jwks_uri": app_credentials["jwks_uri"],
                "dpop_private_key_path": dpop_keys["private_key_path"],
                "dpop_key_id": dpop_keys["key_id"]
            }
            
            print(f"    ✓ Created {service_name} (client_id: {app_credentials['client_id']})")
        
        return manifest
    
    def enable_token_vault(self) -> bool:
        """
        Enable Auth0 Token Vault (Requirement 1.5)
        
        Note: Token Vault enablement typically requires Auth0 support or
        enterprise plan configuration. This method provides a placeholder
        for the configuration step.
        
        Returns:
            True if successful
        """
        print("Enabling Auth0 Token Vault...")
        print("  ⚠ Note: Token Vault requires Auth0 Enterprise plan")
        print("  ⚠ Contact Auth0 support to enable Token Vault for your tenant")
        print("  ⚠ This script assumes Token Vault is already enabled")
        
        # In a real implementation, this would call Auth0 Management API
        # to enable Token Vault if the API supports it
        
        return True
    
    def configure_provider_connections(self) -> Dict[str, Dict]:
        """
        Configure connected accounts for providers (Requirements 1.6, 1.7)
        
        Note: Provider connections are typically configured through Auth0 Dashboard.
        This method provides configuration templates.
        
        Returns:
            Dictionary with provider connection configurations
        """
        print("Configuring provider connections...")
        
        connections = {}
        
        for provider, scopes in self.PROVIDER_SCOPES.items():
            print(f"  - Configuring {provider}...")
            
            connections[provider] = {
                "name": provider,
                "strategy": self._get_provider_strategy(provider),
                "enabled_clients": [],  # Will be populated with client IDs
                "options": {
                    "scope": scopes["read_only"] + scopes["write_action"]
                },
                "scope_categories": scopes  # Requirement 1.7
            }
            
            print(f"    ✓ Configured {provider} with {len(scopes['read_only'])} read-only and {len(scopes['write_action'])} write-action scopes")
        
        print("  ⚠ Note: Provider connections must be configured in Auth0 Dashboard")
        print("  ⚠ Use the connection templates in the manifest file")
        
        return connections
    
    def _get_provider_strategy(self, provider: str) -> str:
        """Get Auth0 connection strategy for provider"""
        strategy_map = {
            "github": "github",
            "slack": "slack",
            "google_workspace": "google-oauth2"
        }
        return strategy_map.get(provider, "oauth2")
    
    def generate_manifest(self, m2m_apps: Dict, connections: Dict) -> Dict:
        """
        Generate complete configuration manifest (Requirement 1.4)
        
        Args:
            m2m_apps: M2M application credentials
            connections: Provider connection configurations
            
        Returns:
            Complete manifest dictionary
        """
        manifest = {
            "version": "1.0",
            "auth0_domain": self.domain,
            "services": m2m_apps,
            "provider_connections": connections,
            "token_vault_enabled": True,
            "configuration_notes": {
                "token_vault": "Requires Auth0 Enterprise plan - contact Auth0 support",
                "provider_connections": "Configure in Auth0 Dashboard using the templates provided",
                "dpop_keys": "Private keys stored in infra/auth0/keys/ directory"
            }
        }
        
        return manifest
    
    def save_manifest(self, manifest: Dict, filename: str = "auth0_manifest.json") -> Path:
        """
        Save manifest to JSON file (Requirement 1.4)
        
        Args:
            manifest: Manifest dictionary
            filename: Output filename
            
        Returns:
            Path to saved manifest file
        """
        manifest_path = self.output_dir / filename
        
        with open(manifest_path, 'w') as f:
            json.dump(manifest, f, indent=2)
        
        print(f"\n✓ Manifest saved to: {manifest_path.absolute()}")
        
        return manifest_path
    
    def run_full_setup(self) -> Path:
        """
        Run complete Auth0 setup process
        
        Returns:
            Path to generated manifest file
        """
        print("=" * 60)
        print("Zero-Trust Agentic Guardian - Auth0 Configuration")
        print("=" * 60)
        print()
        
        try:
            # Step 1: Create M2M applications
            m2m_apps = self.setup_m2m_applications()
            print()
            
            # Step 2: Enable Token Vault
            self.enable_token_vault()
            print()
            
            # Step 3: Configure provider connections
            connections = self.configure_provider_connections()
            print()
            
            # Step 4: Generate and save manifest
            manifest = self.generate_manifest(m2m_apps, connections)
            manifest_path = self.save_manifest(manifest)
            
            print()
            print("=" * 60)
            print("Configuration Complete!")
            print("=" * 60)
            print(f"Services configured: {len(m2m_apps)}")
            print(f"Providers configured: {len(connections)}")
            print(f"DPoP keys generated: {len(m2m_apps)}")
            print()
            print("Next steps:")
            print("1. Enable Token Vault in Auth0 Dashboard (Enterprise plan required)")
            print("2. Configure provider connections in Auth0 Dashboard")
            print("3. Update provider connection client IDs in manifest")
            print("4. Distribute credentials to services securely")
            print()
            
            return manifest_path
            
        except Exception as e:
            print(f"\n✗ Configuration failed: {e}", file=sys.stderr)
            raise


def main():
    """Main entry point for Auth0 configuration script"""
    # Check for required environment variables
    domain = os.getenv("AUTH0_DOMAIN")
    management_token = os.getenv("AUTH0_MANAGEMENT_TOKEN")
    
    if not domain or not management_token:
        print("Error: Required environment variables not set", file=sys.stderr)
        print("", file=sys.stderr)
        print("Please set the following environment variables:", file=sys.stderr)
        print("  AUTH0_DOMAIN: Your Auth0 domain (e.g., 'your-tenant.auth0.com')", file=sys.stderr)
        print("  AUTH0_MANAGEMENT_TOKEN: Auth0 Management API token", file=sys.stderr)
        print("", file=sys.stderr)
        print("Example:", file=sys.stderr)
        print("  export AUTH0_DOMAIN='your-tenant.auth0.com'", file=sys.stderr)
        print("  export AUTH0_MANAGEMENT_TOKEN='your-token-here'", file=sys.stderr)
        sys.exit(1)
    
    # Run configuration
    configurator = Auth0Configurator(domain, management_token)
    configurator.run_full_setup()


if __name__ == "__main__":
    main()
