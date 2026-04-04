"""Audit log parsing and pretty printing utilities.

This module provides tools for parsing, validating, and formatting
audit log entries with hash chain verification.
"""

from .parser import (
    AuditLogParser,
    AuditLogError,
    parse_audit_log,
    parse_audit_log_file,
    parse_audit_log_sequence,
    validate_audit_log
)

from .pretty_printer import (
    AuditLogPrettyPrinter,
    format_audit_log,
    format_audit_log_sequence,
    format_audit_log_json
)

__all__ = [
    # Parser
    "AuditLogParser",
    "AuditLogError",
    "parse_audit_log",
    "parse_audit_log_file",
    "parse_audit_log_sequence",
    "validate_audit_log",
    # Pretty Printer
    "AuditLogPrettyPrinter",
    "format_audit_log",
    "format_audit_log_sequence",
    "format_audit_log_json",
]
