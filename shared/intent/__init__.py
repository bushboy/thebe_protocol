"""
Intent signature parsing and formatting utilities.

This module provides tools for parsing, validating, and pretty-printing
IntentSignature objects used in the Zero-Trust Agentic Guardian Architecture.
"""

from .parser import (
    IntentSignatureParser,
    IntentSignatureError,
    parse_intent_signature,
    parse_intent_signature_file,
    validate_intent_signature
)

from .pretty_printer import (
    IntentSignaturePrettyPrinter,
    format_intent_signature,
    format_intent_signature_json,
    format_intent_comparison
)

__all__ = [
    "IntentSignatureParser",
    "IntentSignatureError",
    "parse_intent_signature",
    "parse_intent_signature_file",
    "validate_intent_signature",
    "IntentSignaturePrettyPrinter",
    "format_intent_signature",
    "format_intent_signature_json",
    "format_intent_comparison"
]
