"""
Configuration Pretty Printer for Zero-Trust Agentic Guardian Architecture

This module formats Auth0 manifests, certificate information, and OPA policies
in human-readable formats with proper redaction of sensitive information.

Requirements: 19.1, 19.2, 19.3, 19.4
"""

import json
import re
from typing import Dict, Any, Optional
from datetime import datetime
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from .parser import Auth0Config, ServiceConfig, ProviderConnectionConfig


class ConfigurationPrettyPrinter:
    """
    Pretty printer for configuration objects
    
    Formats configuration data in human-readable format with sensitive
    information redacted.
    
    Requirements: 19.1, 19.2, 19.3, 19.4
    """
    
    # Fields to redact (Requirement 19.4)
    # Use exact matches or specific patterns to avoid false positives
    SENSITIVE_FIELDS = [
        "client_secret",
        "dpop_private_key_path",
        "private_key",
        "api_key"
    ]
    
    # Additional patterns that should trigger redaction when they appear
    # at the end of a field name (to avoid false positives like "token_vault_enabled")
    SENSITIVE_SUFFIXES = [
        "_secret",
        "_password",
        "_token",
        "_key"
    ]
    
    # Exact field names that should be redacted
    SENSITIVE_EXACT = [
        "secret",
        "password",
        "token"
    ]
    
    def __init__(self, redact_sensitive: bool = True):
        """
        Initialize pretty printer
        
        Args:
            redact_sensitive: Whether to redact sensitive information
        """
        self.redact_sensitive = redact_sensitive
    
    def format_auth0_manifest(self, config: Auth0Config) -> str:
        """
        Format Auth0 manifest as readable JSON (Requirement 19.1)
        
        Args:
            config: Auth0Config object
            
        Returns:
            Formatted JSON string
        """
        # Convert to dictionary
        data = config.model_dump()
        
        # Redact sensitive information if enabled (Requirement 19.4)
        if self.redact_sensitive:
            data = self._redact_sensitive_data(data)
        
        # Format as JSON with indentation
        formatted = json.dumps(data, indent=2, default=str)
        
        return formatted
    
    def format_service_config(self, service_config: ServiceConfig, service_name: str) -> str:
        """
        Format a single service configuration
        
        Args:
            service_config: ServiceConfig object
            service_name: Name of the service
            
        Returns:
            Formatted string
        """
        lines = [
            f"Service: {service_name}",
            "=" * 60,
            f"Client ID: {service_config.client_id}",
        ]
        
        # Redact client secret if enabled
        if self.redact_sensitive:
            lines.append(f"Client Secret: [REDACTED]")
        else:
            lines.append(f"Client Secret: {service_config.client_secret}")
        
        lines.extend([
            f"JWKS URI: {service_config.jwks_uri}",
            f"DPoP Key ID: {service_config.dpop_key_id}",
        ])
        
        # Redact key path if enabled
        if self.redact_sensitive:
            lines.append(f"DPoP Private Key: [REDACTED]")
        else:
            lines.append(f"DPoP Private Key: {service_config.dpop_private_key_path}")
        
        return "\n".join(lines)
    
    def format_provider_config(self, provider_config: ProviderConnectionConfig) -> str:
        """
        Format a provider connection configuration
        
        Args:
            provider_config: ProviderConnectionConfig object
            
        Returns:
            Formatted string
        """
        lines = [
            f"Provider: {provider_config.name}",
            "=" * 60,
            f"Strategy: {provider_config.strategy}",
            f"Enabled Clients: {len(provider_config.enabled_clients)}",
        ]
        
        # Format scope categories
        if provider_config.scope_categories:
            lines.append("\nScope Categories:")
            for category, scopes in provider_config.scope_categories.items():
                lines.append(f"  {category}:")
                for scope in scopes:
                    lines.append(f"    - {scope}")
        
        return "\n".join(lines)
    
    def _redact_sensitive_data(self, data: Any) -> Any:
        """
        Recursively redact sensitive information (Requirement 19.4)
        
        Args:
            data: Data structure to redact
            
        Returns:
            Data with sensitive fields redacted
        """
        if isinstance(data, dict):
            redacted = {}
            for key, value in data.items():
                key_lower = key.lower()
                
                # Check if key is in the sensitive fields list
                if key_lower in [f.lower() for f in self.SENSITIVE_FIELDS]:
                    redacted[key] = "[REDACTED]"
                # Check if key is an exact match for sensitive exact names
                elif key_lower in self.SENSITIVE_EXACT:
                    redacted[key] = "[REDACTED]"
                # Check if key ends with a sensitive suffix
                elif any(key_lower.endswith(suffix) for suffix in self.SENSITIVE_SUFFIXES):
                    redacted[key] = "[REDACTED]"
                else:
                    redacted[key] = self._redact_sensitive_data(value)
            return redacted
        elif isinstance(data, list):
            return [self._redact_sensitive_data(item) for item in data]
        else:
            return data


def format_auth0_manifest(config: Auth0Config, redact_sensitive: bool = True) -> str:
    """
    Format Auth0 manifest as readable JSON (Requirement 19.1)
    
    Args:
        config: Auth0Config object
        redact_sensitive: Whether to redact sensitive information
        
    Returns:
        Formatted JSON string
    """
    printer = ConfigurationPrettyPrinter(redact_sensitive=redact_sensitive)
    return printer.format_auth0_manifest(config)


def format_certificate_info(cert_path: str) -> str:
    """
    Format certificate information (Requirement 19.2)
    
    Args:
        cert_path: Path to certificate file
        
    Returns:
        Formatted certificate information
    """
    try:
        cert_file = Path(cert_path)
        
        if not cert_file.exists():
            return f"Certificate file not found: {cert_path}"
        
        # Load certificate
        with open(cert_file, 'rb') as f:
            cert_data = f.read()
        
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        
        # Extract certificate information
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        serial = cert.serial_number
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        
        # Format output
        lines = [
            f"Certificate: {cert_path}",
            "=" * 60,
            f"Subject: {subject}",
            f"Issuer: {issuer}",
            f"Serial Number: {serial}",
            f"Valid From: {not_before.isoformat()}",
            f"Valid Until: {not_after.isoformat()}",
        ]
        
        # Check if expired
        now = datetime.now(not_after.tzinfo)
        if now > not_after:
            lines.append("Status: EXPIRED")
        elif now < not_before:
            lines.append("Status: NOT YET VALID")
        else:
            days_remaining = (not_after - now).days
            lines.append(f"Status: VALID ({days_remaining} days remaining)")
        
        # Add subject alternative names if present
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san_names = [name.value for name in san_ext.value]
            if san_names:
                lines.append("\nSubject Alternative Names:")
                for name in san_names:
                    lines.append(f"  - {name}")
        except x509.ExtensionNotFound:
            pass
        
        return "\n".join(lines)
        
    except Exception as e:
        return f"Error reading certificate: {e}"


def format_opa_policy(policy_path: str, syntax_highlighting: bool = True) -> str:
    """
    Format OPA policy with optional syntax highlighting (Requirement 19.3)
    
    Args:
        policy_path: Path to OPA policy file (.rego)
        syntax_highlighting: Whether to apply basic syntax highlighting
        
    Returns:
        Formatted policy string
    """
    try:
        policy_file = Path(policy_path)
        
        if not policy_file.exists():
            return f"Policy file not found: {policy_path}"
        
        with open(policy_file, 'r') as f:
            policy_content = f.read()
        
        # Basic syntax highlighting using ANSI color codes
        if syntax_highlighting:
            policy_content = _apply_rego_syntax_highlighting(policy_content)
        
        # Add header
        lines = [
            f"OPA Policy: {policy_path}",
            "=" * 60,
            "",
            policy_content
        ]
        
        return "\n".join(lines)
        
    except Exception as e:
        return f"Error reading policy: {e}"


def _apply_rego_syntax_highlighting(content: str) -> str:
    """
    Apply basic syntax highlighting to Rego policy content
    
    Args:
        content: Rego policy content
        
    Returns:
        Content with ANSI color codes (for terminal display)
    """
    # ANSI color codes
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    RESET = "\033[0m"
    
    # Highlight keywords
    keywords = [
        "package", "import", "default", "rule", "deny", "allow",
        "input", "data", "with", "as", "some", "not", "else"
    ]
    
    for keyword in keywords:
        # Use word boundaries to avoid partial matches
        pattern = r'\b' + keyword + r'\b'
        content = re.sub(pattern, f"{BLUE}{keyword}{RESET}", content)
    
    # Highlight strings
    content = re.sub(r'"([^"]*)"', f'{GREEN}"\\1"{RESET}', content)
    
    # Highlight comments
    content = re.sub(r'#(.*)$', f'{CYAN}#\\1{RESET}', content, flags=re.MULTILINE)
    
    # Highlight operators
    operators = ["==", "!=", ">=", "<=", ">", "<", ":=", "="]
    for op in operators:
        escaped_op = re.escape(op)
        content = re.sub(escaped_op, f"{YELLOW}{op}{RESET}", content)
    
    return content


def format_configuration_summary(config: Auth0Config) -> str:
    """
    Format a summary of the configuration
    
    Args:
        config: Auth0Config object
        
    Returns:
        Formatted summary string
    """
    lines = [
        "Zero-Trust Agentic Guardian Configuration Summary",
        "=" * 60,
        f"Version: {config.version}",
        f"Auth0 Domain: {config.auth0_domain}",
        f"Token Vault Enabled: {config.token_vault_enabled}",
        "",
        f"Services Configured: {len(config.services)}",
    ]
    
    for service_name in config.services.keys():
        lines.append(f"  - {service_name}")
    
    lines.append("")
    lines.append(f"Provider Connections: {len(config.provider_connections)}")
    
    for provider_name, provider_config in config.provider_connections.items():
        read_only = len(provider_config.scope_categories.get("read_only", []))
        write_action = len(provider_config.scope_categories.get("write_action", []))
        lines.append(f"  - {provider_name}: {read_only} read-only, {write_action} write-action scopes")
    
    if config.configuration_notes:
        lines.append("")
        lines.append("Configuration Notes:")
        for key, note in config.configuration_notes.items():
            lines.append(f"  {key}: {note}")
    
    return "\n".join(lines)
