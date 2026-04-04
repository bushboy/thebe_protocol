"""Intent Engine service for semantic intent verification.

This service generates and verifies intent signatures using sentence transformers
to detect prompt injection and intent drift.
"""

from .main import app
from .intent_signer import IntentSigner
from .config import config

__all__ = ["app", "IntentSigner", "config"]
