"""
IntentSignature Pretty Printer for Zero-Trust Agentic Guardian Architecture

This module formats IntentSignature objects in human-readable format with
compact embedding vectors, hexadecimal hashes, clear action lists, and
similarity scores.

Requirements: 21.1, 21.2, 21.3, 21.4
"""

import json
from typing import Optional, List
from datetime import datetime

from shared.schemas.models import IntentSignature


class IntentSignaturePrettyPrinter:
    """
    Pretty printer for IntentSignature objects
    
    Formats IntentSignature data in human-readable format with compact
    embedding representation, hexadecimal hashes, and clear action lists.
    
    Requirements: 21.1, 21.2, 21.3, 21.4
    """
    
    def __init__(self, compact_embeddings: bool = True):
        """
        Initialize pretty printer
        
        Args:
            compact_embeddings: Whether to format embeddings compactly
        """
        self.compact_embeddings = compact_embeddings
    
    def format(
        self,
        intent_signature: IntentSignature,
        similarity_score: Optional[float] = None,
        include_json: bool = False
    ) -> str:
        """
        Format IntentSignature as readable text
        
        Args:
            intent_signature: IntentSignature object to format
            similarity_score: Optional similarity score to include (Requirement 21.4)
            include_json: Whether to include JSON representation
            
        Returns:
            Formatted string
        """
        lines = [
            "Intent Signature",
            "=" * 60,
        ]
        
        # Format timestamp
        timestamp_str = intent_signature.timestamp.isoformat()
        lines.append(f"Timestamp: {timestamp_str}")
        
        # Format hash in hexadecimal (Requirement 21.2)
        lines.append(f"Hash: {self._format_hash(intent_signature.hash)}")
        
        # Format allowed actions clearly (Requirement 21.3)
        lines.append(f"\nAllowed Actions ({len(intent_signature.allowed_actions)}):")
        for action in intent_signature.allowed_actions:
            lines.append(f"  - {action}")
        
        # Format embedding vector compactly (Requirement 21.1)
        lines.append(f"\nEmbedding Vector:")
        lines.append(self._format_embedding(intent_signature.embedding))
        
        # Format signature
        lines.append(f"\nSignature: {intent_signature.signature[:32]}...")
        
        # Include similarity score if provided (Requirement 21.4)
        if similarity_score is not None:
            lines.append(f"\nSimilarity Score: {similarity_score:.4f}")
            
            # Add alignment status
            threshold = 0.7
            aligned = similarity_score >= threshold
            status = "ALIGNED" if aligned else "MISALIGNED"
            lines.append(f"Alignment Status: {status} (threshold: {threshold})")
        
        # Include JSON representation if requested
        if include_json:
            lines.append("\nJSON Representation:")
            lines.append("-" * 60)
            json_str = intent_signature.model_dump_json(indent=2)
            lines.append(json_str)
        
        return "\n".join(lines)
    
    def _format_hash(self, hash_value: str) -> str:
        """
        Format hash in hexadecimal (Requirement 21.2)
        
        Args:
            hash_value: Hash string
            
        Returns:
            Formatted hash string
        """
        # Display hash in groups of 8 characters for readability
        groups = [hash_value[i:i+8] for i in range(0, len(hash_value), 8)]
        return " ".join(groups)
    
    def _format_embedding(self, embedding: List[float]) -> str:
        """
        Format embedding vector compactly (Requirement 21.1)
        
        Args:
            embedding: Embedding vector
            
        Returns:
            Formatted embedding string
        """
        if self.compact_embeddings:
            # Show first 5 and last 5 values with statistics
            first_5 = embedding[:5]
            last_5 = embedding[-5:]
            
            # Calculate statistics
            min_val = min(embedding)
            max_val = max(embedding)
            mean_val = sum(embedding) / len(embedding)
            
            lines = [
                f"  Dimensions: {len(embedding)}",
                f"  Range: [{min_val:.4f}, {max_val:.4f}]",
                f"  Mean: {mean_val:.4f}",
                f"  First 5: [{', '.join(f'{v:.4f}' for v in first_5)}]",
                f"  Last 5:  [{', '.join(f'{v:.4f}' for v in last_5)}]"
            ]
            return "\n".join(lines)
        else:
            # Show full embedding in rows of 8 values
            rows = []
            for i in range(0, len(embedding), 8):
                row = embedding[i:i+8]
                row_str = ", ".join(f"{v:.4f}" for v in row)
                rows.append(f"  [{row_str}]")
            return "\n".join(rows)
    
    def format_json(self, intent_signature: IntentSignature, indent: int = 2) -> str:
        """
        Format IntentSignature as JSON
        
        Args:
            intent_signature: IntentSignature object
            indent: JSON indentation level
            
        Returns:
            JSON string
        """
        return intent_signature.model_dump_json(indent=indent)
    
    def format_compact(self, intent_signature: IntentSignature) -> str:
        """
        Format IntentSignature in compact single-line format
        
        Args:
            intent_signature: IntentSignature object
            
        Returns:
            Compact formatted string
        """
        timestamp_str = intent_signature.timestamp.isoformat()
        hash_short = intent_signature.hash[:16]
        actions_str = ", ".join(intent_signature.allowed_actions[:3])
        if len(intent_signature.allowed_actions) > 3:
            actions_str += f" (+{len(intent_signature.allowed_actions) - 3} more)"
        
        return (
            f"IntentSignature(hash={hash_short}..., "
            f"actions=[{actions_str}], "
            f"timestamp={timestamp_str})"
        )
    
    def format_comparison(
        self,
        original: IntentSignature,
        proposed_action: str,
        similarity_score: float
    ) -> str:
        """
        Format a comparison between original intent and proposed action
        
        Args:
            original: Original IntentSignature
            proposed_action: Proposed action to compare
            similarity_score: Computed similarity score (Requirement 21.4)
            
        Returns:
            Formatted comparison string
        """
        lines = [
            "Intent Alignment Verification",
            "=" * 60,
            "",
            "Original Intent:",
            f"  Hash: {self._format_hash(original.hash)}",
            f"  Timestamp: {original.timestamp.isoformat()}",
            f"  Allowed Actions: {', '.join(original.allowed_actions)}",
            "",
            "Proposed Action:",
            f"  {proposed_action}",
            "",
            "Similarity Analysis:",
            f"  Score: {similarity_score:.4f}",
            f"  Threshold: 0.7",
        ]
        
        # Determine alignment status
        aligned = similarity_score >= 0.7
        if aligned:
            lines.append(f"  Status: ✓ ALIGNED")
            lines.append(f"  Decision: Action is consistent with original intent")
        else:
            lines.append(f"  Status: ✗ MISALIGNED")
            lines.append(f"  Decision: Action deviates from original intent")
            lines.append(f"  Warning: Possible prompt injection detected")
        
        return "\n".join(lines)


def format_intent_signature(
    intent_signature: IntentSignature,
    similarity_score: Optional[float] = None,
    compact_embeddings: bool = True
) -> str:
    """
    Format IntentSignature as readable text (convenience function)
    
    Args:
        intent_signature: IntentSignature object
        similarity_score: Optional similarity score to include
        compact_embeddings: Whether to format embeddings compactly
        
    Returns:
        Formatted string
    """
    printer = IntentSignaturePrettyPrinter(compact_embeddings=compact_embeddings)
    return printer.format(intent_signature, similarity_score=similarity_score)


def format_intent_signature_json(intent_signature: IntentSignature, indent: int = 2) -> str:
    """
    Format IntentSignature as JSON (convenience function)
    
    Args:
        intent_signature: IntentSignature object
        indent: JSON indentation level
        
    Returns:
        JSON string
    """
    printer = IntentSignaturePrettyPrinter()
    return printer.format_json(intent_signature, indent=indent)


def format_intent_comparison(
    original: IntentSignature,
    proposed_action: str,
    similarity_score: float
) -> str:
    """
    Format intent alignment comparison (convenience function)
    
    Args:
        original: Original IntentSignature
        proposed_action: Proposed action
        similarity_score: Similarity score
        
    Returns:
        Formatted comparison string
    """
    printer = IntentSignaturePrettyPrinter()
    return printer.format_comparison(original, proposed_action, similarity_score)
