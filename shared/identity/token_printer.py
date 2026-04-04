"""Token pretty printing utilities for Identity Abstraction Layer.

This module provides human-readable formatting for provider tokens,
with appropriate redaction of sensitive information.
"""

from typing import Union, Dict, Any
from .token_models import ProviderToken


def pretty_print_token(token: Union[ProviderToken, Dict[str, Any]]) -> str:
    """Format provider token for human-readable output.
    
    This function formats a provider token with clear field labels and
    appropriate redaction of sensitive information. The access_token is
    redacted to show only the first 8 characters, and other fields are
    formatted in a human-readable manner.
    
    Args:
        token: ProviderToken instance or dictionary containing token data
        
    Returns:
        Formatted string representation of the token
        
    Examples:
        >>> token = ProviderToken(
        ...     access_token="gho_1234567890abcdefghijklmnop",
        ...     token_type="Bearer",
        ...     expires_in=3600,
        ...     scope="repo:read repo:write"
        ... )
        >>> print(pretty_print_token(token))
        Provider Token:
          Token Type: Bearer
          Expires In: 3600 seconds (1 hour)
          Access Token: gho_1234******** (redacted)
          Scopes:
            - repo:read
            - repo:write
    """
    # Convert dict to ProviderToken if needed
    if isinstance(token, dict):
        token = ProviderToken.from_dict(token)
    
    # Build formatted output
    lines = ["Provider Token:"]
    
    # Token type
    lines.append(f"  Token Type: {token.token_type}")
    
    # Expires in with human-readable format
    expires_str = _format_expiration(token.expires_in)
    lines.append(f"  Expires In: {token.expires_in} seconds ({expires_str})")
    
    # Redacted access token (show only first 8 characters)
    redacted_token = _redact_token(token.access_token)
    lines.append(f"  Access Token: {redacted_token} (redacted)")
    
    # Scopes as formatted list
    if token.scope:
        lines.append("  Scopes:")
        scopes = token.scope.split()
        for scope in scopes:
            lines.append(f"    - {scope}")
    else:
        lines.append("  Scopes: (none)")
    
    # Refresh token if present
    if token.refresh_token:
        redacted_refresh = _redact_token(token.refresh_token)
        lines.append(f"  Refresh Token: {redacted_refresh} (redacted)")
    
    return "\n".join(lines)


def _redact_token(token: str) -> str:
    """Redact token showing only first 8 characters.
    
    Args:
        token: The token string to redact
        
    Returns:
        Redacted token string (first 8 chars + asterisks)
        
    Examples:
        >>> _redact_token("gho_1234567890abcdefghijklmnop")
        'gho_1234********'
        >>> _redact_token("short")
        'short***'
    """
    if len(token) <= 8:
        # For short tokens, show all characters but add asterisks
        return token + "***"
    
    # Show first 8 characters and replace rest with asterisks
    return token[:8] + "********"


def _format_expiration(seconds: int) -> str:
    """Format expiration time in human-readable format.
    
    Converts seconds to the most appropriate time unit (seconds, minutes, hours, days).
    
    Args:
        seconds: Expiration time in seconds
        
    Returns:
        Human-readable expiration string
        
    Examples:
        >>> _format_expiration(30)
        '30 seconds'
        >>> _format_expiration(60)
        '1 minute'
        >>> _format_expiration(3600)
        '1 hour'
        >>> _format_expiration(7200)
        '2 hours'
        >>> _format_expiration(86400)
        '1 day'
    """
    if seconds < 60:
        return f"{seconds} second{'s' if seconds != 1 else ''}"
    
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    
    hours = minutes // 60
    if hours < 24:
        return f"{hours} hour{'s' if hours != 1 else ''}"
    
    days = hours // 24
    return f"{days} day{'s' if days != 1 else ''}"
