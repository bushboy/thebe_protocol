"""Provider scope categorization utilities.

This module provides utilities for categorizing and validating provider scopes
as read-only or write-action scopes.

Requirements: 1.7
"""

from .categorizer import ScopeCategorizer, ScopeCategory

__all__ = ["ScopeCategorizer", "ScopeCategory"]
