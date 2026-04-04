"""Token response models for Identity Abstraction Layer.

This module defines Pydantic models for provider token responses.
All adapters return tokens in a standardized format.
"""

from typing import Optional
from pydantic import BaseModel, Field, field_validator


class ProviderToken(BaseModel):
    """Standardized provider token response.
    
    This model represents a token returned by any identity provider adapter.
    All adapters normalize their provider-specific responses to this format.
    
    Attributes:
        access_token: The provider access token
        token_type: Token type (normalized to "Bearer")
        expires_in: Token expiration time in seconds
        scope: Granted scopes as space-separated string
        refresh_token: Optional refresh token
    """
    access_token: str = Field(..., min_length=1, description="Provider access token")
    token_type: str = Field(default="Bearer", description="Token type")
    expires_in: int = Field(..., gt=0, description="Token expiration in seconds")
    scope: Optional[str] = Field(None, description="Granted scopes")
    refresh_token: Optional[str] = Field(None, description="Optional refresh token")
    
    @field_validator('access_token')
    @classmethod
    def validate_access_token(cls, v: str) -> str:
        """Validate access_token is non-empty.
        
        Args:
            v: The access token value
            
        Returns:
            The validated access token
            
        Raises:
            ValueError: If access_token is empty or whitespace
        """
        if not v or v.isspace():
            raise ValueError("access_token must be a non-empty string")
        return v.strip()
    
    @field_validator('token_type')
    @classmethod
    def normalize_token_type(cls, v: str) -> str:
        """Normalize token_type to "Bearer".
        
        Different providers may use different conventions (bearer, Bearer, BEARER).
        This validator normalizes all variations to the standard "Bearer" format.
        
        Args:
            v: The token type value
            
        Returns:
            Normalized token type ("Bearer")
        """
        if not v:
            return "Bearer"
        
        # Normalize to "Bearer" regardless of case
        normalized = v.strip()
        if normalized.lower() == "bearer":
            return "Bearer"
        
        # For non-bearer token types, preserve the original value
        return normalized
    
    @field_validator('expires_in')
    @classmethod
    def validate_expires_in(cls, v: int) -> int:
        """Validate expires_in is a positive integer.
        
        Args:
            v: The expiration time in seconds
            
        Returns:
            The validated expiration time
            
        Raises:
            ValueError: If expires_in is not positive
        """
        if v <= 0:
            raise ValueError("expires_in must be a positive integer")
        return v
    
    @field_validator('scope')
    @classmethod
    def validate_scope(cls, v: Optional[str]) -> Optional[str]:
        """Validate and normalize scope string.
        
        Args:
            v: The scope string (space-separated)
            
        Returns:
            The validated scope string or None
        """
        if v is None:
            return None
        
        # Strip whitespace and return None if empty
        stripped = v.strip()
        if not stripped:
            return None
        
        return stripped
    
    @field_validator('refresh_token')
    @classmethod
    def validate_refresh_token(cls, v: Optional[str]) -> Optional[str]:
        """Validate refresh_token if provided.
        
        Args:
            v: The refresh token value
            
        Returns:
            The validated refresh token or None
        """
        if v is None:
            return None
        
        # Strip whitespace and return None if empty
        stripped = v.strip()
        if not stripped:
            return None
        
        return stripped
    
    def to_dict(self) -> dict:
        """Convert token to dictionary format.
        
        Returns:
            Dictionary representation of the token, excluding None values.
        """
        result = {
            "access_token": self.access_token,
            "token_type": self.token_type,
            "expires_in": self.expires_in
        }
        
        if self.scope is not None:
            result["scope"] = self.scope
        
        if self.refresh_token is not None:
            result["refresh_token"] = self.refresh_token
        
        return result
    
    @classmethod
    def from_dict(cls, data: dict) -> "ProviderToken":
        """Create ProviderToken from dictionary.
        
        Args:
            data: Dictionary containing token data
            
        Returns:
            ProviderToken instance
            
        Raises:
            ValueError: If required fields are missing or invalid
        """
        return cls(
            access_token=data["access_token"],
            token_type=data.get("token_type", "Bearer"),
            expires_in=data["expires_in"],
            scope=data.get("scope"),
            refresh_token=data.get("refresh_token")
        )
