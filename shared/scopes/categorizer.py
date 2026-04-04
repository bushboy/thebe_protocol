"""Provider scope categorization and validation.

This module provides utilities for categorizing provider scopes as read-only
or write-action scopes, and validating requested scopes against categories.

Requirements: 1.7
"""

from enum import Enum
from typing import List, Dict, Set
from shared.logging import JSONLogger


logger = JSONLogger(__name__)


class ScopeCategory(str, Enum):
    """Scope category enumeration."""
    READ_ONLY = "read_only"
    WRITE_ACTION = "write_action"


class ScopeCategorizer:
    """Categorizes and validates provider scopes.
    
    Provider scopes are categorized as:
    - read_only: Scopes that only allow reading/viewing data
    - write_action: Scopes that allow creating, updating, or deleting data
    
    Requirements: 1.7
    """
    
    # Provider scope categorization (matches Auth0 configuration)
    PROVIDER_SCOPES: Dict[str, Dict[str, List[str]]] = {
        "github": {
            "read_only": ["repo:read", "user:read", "org:read"],
            "write_action": ["repo:write", "admin:org", "delete_repo"]
        },
        "slack": {
            "read_only": ["channels:read", "users:read", "groups:read"],
            "write_action": ["chat:write", "channels:manage", "groups:write"]
        },
        "google_workspace": {
            "read_only": [
                "https://www.googleapis.com/auth/gmail.readonly",
                "https://www.googleapis.com/auth/drive.readonly"
            ],
            "write_action": [
                "https://www.googleapis.com/auth/gmail.send",
                "https://www.googleapis.com/auth/drive"
            ]
        }
    }
    
    @classmethod
    def get_scopes_for_category(
        cls,
        provider: str,
        category: ScopeCategory
    ) -> List[str]:
        """Get scopes for a specific provider and category.
        
        Args:
            provider: Provider name (github, slack, google_workspace)
            category: Scope category (read_only or write_action)
            
        Returns:
            List of scopes for the category
            
        Raises:
            ValueError: If provider is not supported
        """
        if provider not in cls.PROVIDER_SCOPES:
            raise ValueError(f"Unsupported provider: {provider}")
        
        scopes = cls.PROVIDER_SCOPES[provider].get(category.value, [])
        logger.debug(f"Retrieved {len(scopes)} {category.value} scopes for {provider}")
        
        return scopes
    
    @classmethod
    def get_all_scopes(cls, provider: str) -> List[str]:
        """Get all scopes for a provider (read-only + write-action).
        
        Args:
            provider: Provider name
            
        Returns:
            List of all scopes for the provider
            
        Raises:
            ValueError: If provider is not supported
        """
        if provider not in cls.PROVIDER_SCOPES:
            raise ValueError(f"Unsupported provider: {provider}")
        
        read_only = cls.PROVIDER_SCOPES[provider].get("read_only", [])
        write_action = cls.PROVIDER_SCOPES[provider].get("write_action", [])
        
        return read_only + write_action
    
    @classmethod
    def categorize_scope(cls, provider: str, scope: str) -> ScopeCategory:
        """Categorize a single scope as read-only or write-action.
        
        Args:
            provider: Provider name
            scope: Scope to categorize
            
        Returns:
            ScopeCategory (READ_ONLY or WRITE_ACTION)
            
        Raises:
            ValueError: If provider is not supported or scope is not recognized
        """
        if provider not in cls.PROVIDER_SCOPES:
            raise ValueError(f"Unsupported provider: {provider}")
        
        provider_scopes = cls.PROVIDER_SCOPES[provider]
        
        if scope in provider_scopes.get("read_only", []):
            return ScopeCategory.READ_ONLY
        elif scope in provider_scopes.get("write_action", []):
            return ScopeCategory.WRITE_ACTION
        else:
            raise ValueError(f"Unrecognized scope for {provider}: {scope}")
    
    @classmethod
    def validate_scopes(
        cls,
        provider: str,
        requested_scopes: List[str]
    ) -> Dict[str, List[str]]:
        """Validate requested scopes and categorize them.
        
        Args:
            provider: Provider name
            requested_scopes: List of requested scopes
            
        Returns:
            Dictionary with categorized scopes:
            {
                "read_only": [...],
                "write_action": [...],
                "invalid": [...]
            }
        """
        if provider not in cls.PROVIDER_SCOPES:
            logger.error(f"Unsupported provider: {provider}")
            return {
                "read_only": [],
                "write_action": [],
                "invalid": requested_scopes
            }
        
        categorized = {
            "read_only": [],
            "write_action": [],
            "invalid": []
        }
        
        provider_scopes = cls.PROVIDER_SCOPES[provider]
        read_only_set = set(provider_scopes.get("read_only", []))
        write_action_set = set(provider_scopes.get("write_action", []))
        
        for scope in requested_scopes:
            if scope in read_only_set:
                categorized["read_only"].append(scope)
            elif scope in write_action_set:
                categorized["write_action"].append(scope)
            else:
                categorized["invalid"].append(scope)
                logger.warning(f"Invalid scope for {provider}: {scope}")
        
        logger.info(
            f"Validated {len(requested_scopes)} scopes for {provider}: "
            f"{len(categorized['read_only'])} read-only, "
            f"{len(categorized['write_action'])} write-action, "
            f"{len(categorized['invalid'])} invalid"
        )
        
        return categorized
    
    @classmethod
    def is_read_only_scope(cls, provider: str, scope: str) -> bool:
        """Check if a scope is read-only.
        
        Args:
            provider: Provider name
            scope: Scope to check
            
        Returns:
            True if scope is read-only, False otherwise
        """
        try:
            category = cls.categorize_scope(provider, scope)
            return category == ScopeCategory.READ_ONLY
        except ValueError:
            return False
    
    @classmethod
    def is_write_action_scope(cls, provider: str, scope: str) -> bool:
        """Check if a scope is write-action.
        
        Args:
            provider: Provider name
            scope: Scope to check
            
        Returns:
            True if scope is write-action, False otherwise
        """
        try:
            category = cls.categorize_scope(provider, scope)
            return category == ScopeCategory.WRITE_ACTION
        except ValueError:
            return False
    
    @classmethod
    def get_supported_providers(cls) -> List[str]:
        """Get list of supported providers.
        
        Returns:
            List of provider names
        """
        return list(cls.PROVIDER_SCOPES.keys())
