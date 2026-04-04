"""
Audit Log Parser for Zero-Trust Agentic Guardian Architecture

This module parses and validates audit log entries from JSON format,
validates hash chains, required fields, and timestamp monotonicity.

Requirements: 22.1, 22.2, 22.3, 22.4, 22.5
"""

import json
import hashlib
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime
from pydantic import ValidationError

from shared.schemas.models import AuditLogEntry


class AuditLogError(Exception):
    """Raised when audit log parsing or validation fails"""
    pass


class AuditLogParser:
    """
    Parser for audit log entries
    
    Provides deserialization from JSON with validation of hash chain,
    required fields, and timestamp monotonicity.
    
    Requirements: 22.1, 22.2, 22.3, 22.4, 22.5
    """
    
    GENESIS_HASH = "genesis"
    
    def __init__(self):
        """Initialize audit log parser"""
        pass
    
    def parse_json(self, json_str: str) -> AuditLogEntry:
        """
        Parse single audit log entry from JSON string (Requirement 22.1)
        
        Args:
            json_str: JSON string containing AuditLogEntry data
            
        Returns:
            Parsed AuditLogEntry object
            
        Raises:
            AuditLogError: If JSON is invalid or validation fails
        """
        try:
            # Parse JSON string
            data = json.loads(json_str)
            
            # Validate and create AuditLogEntry
            # Pydantic validators will check required fields (Requirement 22.3)
            audit_entry = AuditLogEntry(**data)
            
            return audit_entry
            
        except json.JSONDecodeError as e:
            raise AuditLogError(f"Invalid JSON: {e}")
        except ValidationError as e:
            raise AuditLogError(f"Validation failed: {e}")
        except Exception as e:
            raise AuditLogError(f"Failed to parse audit log entry: {e}")
    
    def parse_dict(self, data: Dict[str, Any]) -> AuditLogEntry:
        """
        Parse audit log entry from dictionary (Requirement 22.1)
        
        Args:
            data: Dictionary containing AuditLogEntry data
            
        Returns:
            Parsed AuditLogEntry object
            
        Raises:
            AuditLogError: If validation fails
        """
        try:
            # Validate and create AuditLogEntry
            audit_entry = AuditLogEntry(**data)
            return audit_entry
            
        except ValidationError as e:
            raise AuditLogError(f"Validation failed: {e}")
        except Exception as e:
            raise AuditLogError(f"Failed to parse audit log entry: {e}")
    
    def parse_file(self, file_path: str) -> AuditLogEntry:
        """
        Parse single audit log entry from JSON file (Requirement 22.1)
        
        Args:
            file_path: Path to JSON file containing AuditLogEntry
            
        Returns:
            Parsed AuditLogEntry object
            
        Raises:
            AuditLogError: If file not found or validation fails
        """
        try:
            path = Path(file_path)
            
            if not path.exists():
                raise AuditLogError(f"File not found: {file_path}")
            
            with open(path, 'r') as f:
                json_str = f.read()
            
            return self.parse_json(json_str)
            
        except AuditLogError:
            raise
        except Exception as e:
            raise AuditLogError(f"Failed to read file: {e}")
    
    def parse_sequence(self, json_str: str) -> List[AuditLogEntry]:
        """
        Parse sequence of audit log entries from JSON array (Requirement 22.1)
        
        Args:
            json_str: JSON string containing array of AuditLogEntry data
            
        Returns:
            List of parsed AuditLogEntry objects
            
        Raises:
            AuditLogError: If JSON is invalid or validation fails
        """
        try:
            # Parse JSON array
            data_list = json.loads(json_str)
            
            if not isinstance(data_list, list):
                raise AuditLogError("Expected JSON array of audit log entries")
            
            # Parse each entry
            entries = []
            for i, data in enumerate(data_list):
                try:
                    entry = self.parse_dict(data)
                    entries.append(entry)
                except AuditLogError as e:
                    raise AuditLogError(f"Failed to parse entry at index {i}: {e}")
            
            return entries
            
        except json.JSONDecodeError as e:
            raise AuditLogError(f"Invalid JSON: {e}")
        except AuditLogError:
            raise
        except Exception as e:
            raise AuditLogError(f"Failed to parse audit log sequence: {e}")
    
    def parse_sequence_file(self, file_path: str) -> List[AuditLogEntry]:
        """
        Parse sequence of audit log entries from JSON file (Requirement 22.1)
        
        Args:
            file_path: Path to JSON file containing array of entries
            
        Returns:
            List of parsed AuditLogEntry objects
            
        Raises:
            AuditLogError: If file not found or validation fails
        """
        try:
            path = Path(file_path)
            
            if not path.exists():
                raise AuditLogError(f"File not found: {file_path}")
            
            with open(path, 'r') as f:
                json_str = f.read()
            
            return self.parse_sequence(json_str)
            
        except AuditLogError:
            raise
        except Exception as e:
            raise AuditLogError(f"Failed to read file: {e}")
    
    def validate_hash_chain(self, entries: List[AuditLogEntry]) -> Tuple[bool, Optional[int]]:
        """
        Validate hash chain integrity (Requirement 22.2)
        
        Computes hash for each entry and verifies it matches the stored hash.
        Each entry's hash should equal SHA256(previous_hash || entry_data).
        
        Args:
            entries: List of audit log entries in order
            
        Returns:
            Tuple of (is_valid, broken_index)
            - is_valid: True if chain is valid, False otherwise
            - broken_index: Index where chain breaks, or None if valid
            
        Raises:
            AuditLogError: If entries list is empty
        """
        if not entries:
            raise AuditLogError("Cannot validate empty entry list")
        
        for i, entry in enumerate(entries):
            # Compute expected hash
            expected_hash = self._compute_entry_hash(entry)
            
            # Compare with stored hash
            if entry.hash != expected_hash:
                return False, i
            
            # Verify previous_hash linkage
            if i == 0:
                # First entry should have genesis hash
                if entry.previous_hash != self.GENESIS_HASH:
                    return False, i
            else:
                # Subsequent entries should link to previous entry's hash
                if entry.previous_hash != entries[i - 1].hash:
                    return False, i
        
        return True, None
    
    def _compute_entry_hash(self, entry: AuditLogEntry) -> str:
        """
        Compute hash for an audit log entry (Requirement 22.2)
        
        Hash = SHA256(previous_hash || entry_data)
        
        Args:
            entry: AuditLogEntry object
            
        Returns:
            Computed hash as hexadecimal string
        """
        # Serialize entry data (excluding hash field itself)
        entry_data = {
            "log_id": entry.log_id,
            "component": entry.component,
            "event_type": entry.event_type,
            "action_metadata": entry.action_metadata,
            "zt_at": entry.zt_at.model_dump() if entry.zt_at else None,
            "dpop_fingerprint": entry.dpop_fingerprint,
            "timestamp": entry.timestamp.isoformat(),
            "previous_hash": entry.previous_hash
        }
        
        # Create deterministic JSON string
        entry_json = json.dumps(entry_data, sort_keys=True, separators=(',', ':'))
        
        # Compute hash: SHA256(previous_hash || entry_data)
        hash_input = entry.previous_hash + entry_json
        computed_hash = hashlib.sha256(hash_input.encode()).hexdigest()
        
        return computed_hash
    
    def validate_required_fields(self, entry: AuditLogEntry) -> bool:
        """
        Validate that all required fields are present (Requirement 22.3)
        
        Args:
            entry: AuditLogEntry object
            
        Returns:
            True if all required fields are present
            
        Raises:
            AuditLogError: If any required field is missing or invalid
        """
        required_fields = [
            "log_id", "component", "event_type", "action_metadata",
            "dpop_fingerprint", "timestamp", "hash", "previous_hash"
        ]
        
        for field in required_fields:
            value = getattr(entry, field, None)
            if value is None:
                raise AuditLogError(f"Required field missing: {field}")
            
            # Additional validation for string fields
            if field in ["log_id", "component", "event_type", "dpop_fingerprint", "hash", "previous_hash"]:
                if not isinstance(value, str) or not value.strip():
                    raise AuditLogError(f"Required field '{field}' must be non-empty string")
        
        return True
    
    def validate_timestamp_monotonicity(self, entries: List[AuditLogEntry]) -> Tuple[bool, List[int]]:
        """
        Validate timestamp monotonicity (Requirement 22.4, 22.5)
        
        Timestamps should be monotonically increasing (or equal).
        
        Args:
            entries: List of audit log entries in order
            
        Returns:
            Tuple of (is_monotonic, out_of_order_indices)
            - is_monotonic: True if timestamps are monotonic, False otherwise
            - out_of_order_indices: List of indices where timestamps are out of order
            
        Raises:
            AuditLogError: If entries list is empty
        """
        if not entries:
            raise AuditLogError("Cannot validate empty entry list")
        
        out_of_order_indices = []
        
        for i in range(1, len(entries)):
            prev_timestamp = entries[i - 1].timestamp
            curr_timestamp = entries[i].timestamp
            
            # Timestamps should be monotonically increasing (or equal)
            if curr_timestamp < prev_timestamp:
                out_of_order_indices.append(i)
        
        is_monotonic = len(out_of_order_indices) == 0
        
        return is_monotonic, out_of_order_indices
    
    def validate(self, entries: List[AuditLogEntry]) -> bool:
        """
        Validate complete audit log sequence (Requirements 22.1, 22.2, 22.3, 22.4, 22.5)
        
        Performs all validation checks:
        - Required fields present
        - Hash chain integrity
        - Timestamp monotonicity
        
        Args:
            entries: List of audit log entries
            
        Returns:
            True if all validations pass
            
        Raises:
            AuditLogError: If any validation fails
        """
        if not entries:
            raise AuditLogError("Cannot validate empty entry list")
        
        # Validate required fields for each entry (Requirement 22.3)
        for i, entry in enumerate(entries):
            try:
                self.validate_required_fields(entry)
            except AuditLogError as e:
                raise AuditLogError(f"Entry {i} validation failed: {e}")
        
        # Validate hash chain (Requirement 22.2)
        is_valid, broken_index = self.validate_hash_chain(entries)
        if not is_valid:
            raise AuditLogError(
                f"Hash chain integrity error: chain broken at index {broken_index}"
            )
        
        # Validate timestamp monotonicity (Requirement 22.4, 22.5)
        is_monotonic, out_of_order_indices = self.validate_timestamp_monotonicity(entries)
        if not is_monotonic:
            raise AuditLogError(
                f"Timestamp monotonicity error: timestamps out of order at indices {out_of_order_indices}"
            )
        
        return True


def parse_audit_log(json_str: str) -> AuditLogEntry:
    """
    Parse single audit log entry from JSON string (convenience function)
    
    Args:
        json_str: JSON string containing AuditLogEntry data
        
    Returns:
        Parsed AuditLogEntry object
        
    Raises:
        AuditLogError: If parsing or validation fails
    """
    parser = AuditLogParser()
    return parser.parse_json(json_str)


def parse_audit_log_file(file_path: str) -> AuditLogEntry:
    """
    Parse single audit log entry from JSON file (convenience function)
    
    Args:
        file_path: Path to JSON file
        
    Returns:
        Parsed AuditLogEntry object
        
    Raises:
        AuditLogError: If parsing or validation fails
    """
    parser = AuditLogParser()
    return parser.parse_file(file_path)


def parse_audit_log_sequence(json_str: str) -> List[AuditLogEntry]:
    """
    Parse sequence of audit log entries from JSON array (convenience function)
    
    Args:
        json_str: JSON string containing array of entries
        
    Returns:
        List of parsed AuditLogEntry objects
        
    Raises:
        AuditLogError: If parsing or validation fails
    """
    parser = AuditLogParser()
    return parser.parse_sequence(json_str)


def validate_audit_log(entries: List[AuditLogEntry]) -> bool:
    """
    Validate audit log sequence (convenience function)
    
    Args:
        entries: List of audit log entries
        
    Returns:
        True if all validations pass
        
    Raises:
        AuditLogError: If validation fails
    """
    parser = AuditLogParser()
    return parser.validate(entries)
