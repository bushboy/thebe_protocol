"""
IntentSignature Parser for Zero-Trust Agentic Guardian Architecture

This module parses and validates IntentSignature objects from JSON format,
ensuring embedding dimensionality, hash format, and allowed actions list
are correct.

Requirements: 20.1, 20.2, 20.3, 20.4, 20.5
"""

import json
from pathlib import Path
from typing import Optional, Union, Dict, Any
from pydantic import ValidationError

from shared.schemas.models import IntentSignature


class IntentSignatureError(Exception):
    """Raised when IntentSignature parsing or validation fails"""
    pass


class IntentSignatureParser:
    """
    Parser for IntentSignature objects
    
    Provides deserialization from JSON with validation of embedding
    dimensionality, hash format, and allowed actions list.
    
    Requirements: 20.1, 20.2, 20.3, 20.4, 20.5
    """
    
    def __init__(self):
        """Initialize IntentSignature parser"""
        pass
    
    def parse_json(self, json_str: str) -> IntentSignature:
        """
        Parse IntentSignature from JSON string (Requirement 20.1)
        
        Args:
            json_str: JSON string containing IntentSignature data
            
        Returns:
            Parsed IntentSignature object
            
        Raises:
            IntentSignatureError: If JSON is invalid or validation fails
        """
        try:
            # Parse JSON string
            data = json.loads(json_str)
            
            # Validate and create IntentSignature
            # Pydantic validators will check:
            # - Embedding dimensionality (Requirement 20.2)
            # - Hash format (Requirement 20.3)
            # - Allowed actions non-empty (Requirement 20.4, 20.5)
            intent_signature = IntentSignature(**data)
            
            return intent_signature
            
        except json.JSONDecodeError as e:
            raise IntentSignatureError(f"Invalid JSON: {e}")
        except ValidationError as e:
            raise IntentSignatureError(f"Validation failed: {e}")
        except Exception as e:
            raise IntentSignatureError(f"Failed to parse IntentSignature: {e}")
    
    def parse_dict(self, data: Dict[str, Any]) -> IntentSignature:
        """
        Parse IntentSignature from dictionary (Requirement 20.1)
        
        Args:
            data: Dictionary containing IntentSignature data
            
        Returns:
            Parsed IntentSignature object
            
        Raises:
            IntentSignatureError: If validation fails
        """
        try:
            # Validate and create IntentSignature
            intent_signature = IntentSignature(**data)
            return intent_signature
            
        except ValidationError as e:
            raise IntentSignatureError(f"Validation failed: {e}")
        except Exception as e:
            raise IntentSignatureError(f"Failed to parse IntentSignature: {e}")
    
    def parse_file(self, file_path: str) -> IntentSignature:
        """
        Parse IntentSignature from JSON file (Requirement 20.1)
        
        Args:
            file_path: Path to JSON file containing IntentSignature
            
        Returns:
            Parsed IntentSignature object
            
        Raises:
            IntentSignatureError: If file not found or validation fails
        """
        try:
            path = Path(file_path)
            
            if not path.exists():
                raise IntentSignatureError(f"File not found: {file_path}")
            
            with open(path, 'r') as f:
                json_str = f.read()
            
            return self.parse_json(json_str)
            
        except IntentSignatureError:
            raise
        except Exception as e:
            raise IntentSignatureError(f"Failed to read file: {e}")
    
    def validate(self, intent_signature: IntentSignature) -> bool:
        """
        Validate an IntentSignature object
        
        Args:
            intent_signature: IntentSignature to validate
            
        Returns:
            True if valid
            
        Raises:
            IntentSignatureError: If validation fails
        """
        try:
            # Validate embedding dimensionality (Requirement 20.2)
            if len(intent_signature.embedding) != 384:
                raise IntentSignatureError(
                    f"Embedding must have 384 dimensions, got {len(intent_signature.embedding)}"
                )
            
            # Validate hash format (Requirement 20.3)
            hash_value = intent_signature.hash
            if len(hash_value) != 64:
                raise IntentSignatureError(
                    f"Hash must be 64 characters (SHA256), got {len(hash_value)}"
                )
            
            if not all(c in '0123456789abcdef' for c in hash_value.lower()):
                raise IntentSignatureError(
                    "Hash must contain only hexadecimal characters"
                )
            
            # Validate allowed actions list (Requirement 20.4, 20.5)
            if not intent_signature.allowed_actions:
                raise IntentSignatureError(
                    "Allowed actions list cannot be empty"
                )
            
            return True
            
        except IntentSignatureError:
            raise
        except Exception as e:
            raise IntentSignatureError(f"Validation failed: {e}")


def parse_intent_signature(json_str: str) -> IntentSignature:
    """
    Parse IntentSignature from JSON string (convenience function)
    
    Args:
        json_str: JSON string containing IntentSignature data
        
    Returns:
        Parsed IntentSignature object
        
    Raises:
        IntentSignatureError: If parsing or validation fails
    """
    parser = IntentSignatureParser()
    return parser.parse_json(json_str)


def parse_intent_signature_file(file_path: str) -> IntentSignature:
    """
    Parse IntentSignature from JSON file (convenience function)
    
    Args:
        file_path: Path to JSON file
        
    Returns:
        Parsed IntentSignature object
        
    Raises:
        IntentSignatureError: If parsing or validation fails
    """
    parser = IntentSignatureParser()
    return parser.parse_file(file_path)


def validate_intent_signature(intent_signature: IntentSignature) -> bool:
    """
    Validate an IntentSignature object (convenience function)
    
    Args:
        intent_signature: IntentSignature to validate
        
    Returns:
        True if valid
        
    Raises:
        IntentSignatureError: If validation fails
    """
    parser = IntentSignatureParser()
    return parser.validate(intent_signature)
