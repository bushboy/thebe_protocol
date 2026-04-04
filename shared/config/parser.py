"""
Configuration Parser for Zero-Trust Agentic Guardian Architecture

This module parses and validates Auth0 manifest JSON files, loads DPoP private keys,
and provides a typed interface for accessing configuration values.

Requirements: 18.1, 18.2, 18.3, 18.4, 18.5
"""

import json
from pathlib import Path
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field, field_validator
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa


class ConfigurationError(Exception):
    """Raised when configuration parsing or validation fails"""
    pass


class ServiceConfig(BaseModel):
    """Configuration for a single service (Requirement 18.5)"""
    
    client_id: str = Field(..., description="Auth0 client ID")
    client_secret: str = Field(..., description="Auth0 client secret")
    jwks_uri: str = Field(..., description="JWKS URI for public keys")
    dpop_private_key_path: str = Field(..., description="Path to DPoP private key")
    dpop_key_id: str = Field(..., description="DPoP key identifier")
    
    @field_validator('client_id', 'client_secret', 'jwks_uri', 'dpop_private_key_path', 'dpop_key_id')
    @classmethod
    def validate_non_empty(cls, v):
        """Validate that required fields are non-empty (Requirement 18.3)"""
        if not v or (isinstance(v, str) and not v.strip()):
            raise ValueError("Field cannot be empty")
        return v


class ProviderConnectionConfig(BaseModel):
    """Configuration for a provider connection"""
    
    name: str = Field(..., description="Provider name")
    strategy: str = Field(..., description="Auth0 connection strategy")
    enabled_clients: list = Field(default_factory=list, description="Enabled client IDs")
    options: Dict[str, Any] = Field(default_factory=dict, description="Connection options")
    scope_categories: Dict[str, list] = Field(default_factory=dict, description="Scope categorization")


class Auth0Config(BaseModel):
    """Complete Auth0 configuration (Requirement 18.5)"""
    
    version: str = Field(..., description="Configuration version")
    auth0_domain: str = Field(..., description="Auth0 domain")
    services: Dict[str, ServiceConfig] = Field(..., description="Service configurations")
    provider_connections: Dict[str, ProviderConnectionConfig] = Field(
        default_factory=dict,
        description="Provider connection configurations"
    )
    token_vault_enabled: bool = Field(default=False, description="Token Vault status")
    configuration_notes: Dict[str, str] = Field(
        default_factory=dict,
        description="Configuration notes"
    )
    
    @field_validator('services')
    @classmethod
    def validate_services_non_empty(cls, v):
        """Validate that services dictionary is non-empty (Requirement 18.1)"""
        if not v:
            raise ValueError("Services configuration cannot be empty")
        return v


class ConfigurationParser:
    """
    Parser for Auth0 manifest JSON files
    
    Provides validation and typed access to configuration values.
    Requirements: 18.1, 18.2, 18.3, 18.4, 18.5
    """
    
    REQUIRED_SERVICE_FIELDS = ["client_id", "jwks_uri", "dpop_private_key_path"]
    
    def __init__(self, manifest_path: Optional[str] = None):
        """
        Initialize configuration parser
        
        Args:
            manifest_path: Path to Auth0 manifest JSON file (optional)
        """
        self.manifest_path = manifest_path
        self.config: Optional[Auth0Config] = None
        self._dpop_keys_cache: Dict[str, Any] = {}
        
        if manifest_path:
            self.load(manifest_path)
    
    def load(self, manifest_path: str) -> Auth0Config:
        """
        Load and parse Auth0 manifest JSON (Requirement 18.1)
        
        Args:
            manifest_path: Path to manifest JSON file
            
        Returns:
            Parsed Auth0Config object
            
        Raises:
            ConfigurationError: If manifest is invalid or missing required fields
        """
        try:
            manifest_file = Path(manifest_path)
            
            if not manifest_file.exists():
                raise ConfigurationError(f"Manifest file not found: {manifest_path}")
            
            with open(manifest_file, 'r') as f:
                data = json.load(f)
            
            # Validate required top-level fields (Requirement 18.3)
            self._validate_required_fields(data)
            
            # Parse into typed model (Requirement 18.5)
            self.config = Auth0Config(**data)
            self.manifest_path = manifest_path
            
            # Validate DPoP keys for all services (Requirement 18.2)
            self._validate_all_dpop_keys()
            
            return self.config
            
        except json.JSONDecodeError as e:
            raise ConfigurationError(f"Invalid JSON in manifest file: {e}")
        except Exception as e:
            raise ConfigurationError(f"Failed to load configuration: {e}")
    
    def _validate_required_fields(self, data: Dict[str, Any]) -> None:
        """
        Validate that all required fields are present (Requirement 18.3, 18.4)
        
        Args:
            data: Parsed JSON data
            
        Raises:
            ConfigurationError: If required fields are missing
        """
        # Check top-level required fields
        required_top_level = ["version", "auth0_domain", "services"]
        for field in required_top_level:
            if field not in data:
                raise ConfigurationError(
                    f"Missing required field in manifest: {field}"
                )
        
        # Check services configuration
        services = data.get("services", {})
        if not services:
            raise ConfigurationError("Services configuration is empty")
        
        # Check each service has required fields (Requirement 18.4)
        for service_name, service_config in services.items():
            for field in self.REQUIRED_SERVICE_FIELDS:
                if field not in service_config:
                    raise ConfigurationError(
                        f"Service '{service_name}' missing required field: {field}"
                    )
    
    def _validate_all_dpop_keys(self) -> None:
        """
        Validate DPoP private keys for all services (Requirement 18.2)
        
        Raises:
            ConfigurationError: If any DPoP key is invalid
        """
        if not self.config:
            return
        
        for service_name, service_config in self.config.services.items():
            try:
                self.load_dpop_private_key(service_name)
            except Exception as e:
                raise ConfigurationError(
                    f"Invalid DPoP key for service '{service_name}': {e}"
                )
    
    def load_dpop_private_key(self, service_name: str):
        """
        Load and validate DPoP private key for a service (Requirement 18.2)
        
        Args:
            service_name: Name of the service
            
        Returns:
            Loaded private key object
            
        Raises:
            ConfigurationError: If key file not found or invalid format
        """
        if not self.config:
            raise ConfigurationError("Configuration not loaded")
        
        # Check cache first
        if service_name in self._dpop_keys_cache:
            return self._dpop_keys_cache[service_name]
        
        service_config = self.config.services.get(service_name)
        if not service_config:
            raise ConfigurationError(f"Service not found: {service_name}")
        
        key_path = Path(service_config.dpop_private_key_path)
        
        if not key_path.exists():
            raise ConfigurationError(
                f"DPoP private key file not found: {key_path}"
            )
        
        try:
            # Load private key from PEM file
            with open(key_path, 'rb') as f:
                key_data = f.read()
            
            private_key = serialization.load_pem_private_key(
                key_data,
                password=None,
                backend=default_backend()
            )
            
            # Validate key type and parameters (Requirement 18.2)
            if not isinstance(private_key, rsa.RSAPrivateKey):
                raise ConfigurationError(
                    f"DPoP key must be RSA, got {type(private_key).__name__}"
                )
            
            # Validate key size (minimum 2048 bits)
            key_size = private_key.key_size
            if key_size < 2048:
                raise ConfigurationError(
                    f"DPoP key size must be at least 2048 bits, got {key_size}"
                )
            
            # Cache the key
            self._dpop_keys_cache[service_name] = private_key
            
            return private_key
            
        except Exception as e:
            if isinstance(e, ConfigurationError):
                raise
            raise ConfigurationError(
                f"Failed to load DPoP private key for {service_name}: {e}"
            )
    
    def get_service_config(self, service_name: str) -> ServiceConfig:
        """
        Get configuration for a specific service (Requirement 18.5)
        
        Args:
            service_name: Name of the service
            
        Returns:
            ServiceConfig object
            
        Raises:
            ConfigurationError: If service not found
        """
        if not self.config:
            raise ConfigurationError("Configuration not loaded")
        
        service_config = self.config.services.get(service_name)
        if not service_config:
            raise ConfigurationError(f"Service not found: {service_name}")
        
        return service_config
    
    def get_provider_config(self, provider_name: str) -> ProviderConnectionConfig:
        """
        Get configuration for a specific provider
        
        Args:
            provider_name: Name of the provider
            
        Returns:
            ProviderConnectionConfig object
            
        Raises:
            ConfigurationError: If provider not found
        """
        if not self.config:
            raise ConfigurationError("Configuration not loaded")
        
        provider_config = self.config.provider_connections.get(provider_name)
        if not provider_config:
            raise ConfigurationError(f"Provider not found: {provider_name}")
        
        return provider_config
    
    def list_services(self) -> list:
        """
        List all configured services
        
        Returns:
            List of service names
        """
        if not self.config:
            return []
        
        return list(self.config.services.keys())
    
    def list_providers(self) -> list:
        """
        List all configured providers
        
        Returns:
            List of provider names
        """
        if not self.config:
            return []
        
        return list(self.config.provider_connections.keys())
    
    def validate(self) -> bool:
        """
        Validate the complete configuration
        
        Returns:
            True if configuration is valid
            
        Raises:
            ConfigurationError: If validation fails
        """
        if not self.config:
            raise ConfigurationError("Configuration not loaded")
        
        # Validate all DPoP keys
        self._validate_all_dpop_keys()
        
        # Additional validation checks can be added here
        
        return True
