"""
Demonstration of IntentSignature parser and pretty printer functionality.

This script shows how to:
1. Create an IntentSignature
2. Serialize it to JSON
3. Parse it back from JSON
4. Pretty print it in various formats
5. Compare intents with similarity scores
"""

from datetime import datetime
from shared.schemas.models import IntentSignature
from shared.intent.parser import IntentSignatureParser, parse_intent_signature
from shared.intent.pretty_printer import (
    IntentSignaturePrettyPrinter,
    format_intent_signature,
    format_intent_comparison
)


def main():
    print("=" * 80)
    print("IntentSignature Parser and Pretty Printer Demo")
    print("=" * 80)
    print()
    
    # 1. Create an IntentSignature
    print("1. Creating an IntentSignature...")
    intent_sig = IntentSignature(
        embedding=[0.123, -0.456, 0.789, 0.321] + [0.1] * 380,
        hash="a1b2c3d4e5f67890123456789012345678901234567890123456789012345678",
        allowed_actions=[
            "github:create_branch",
            "github:create_pr",
            "github:list_repos"
        ],
        timestamp=datetime(2024, 1, 15, 10, 30, 0),
        signature="example_signature_xyz123"
    )
    print("✓ IntentSignature created")
    print()
    
    # 2. Serialize to JSON
    print("2. Serializing to JSON...")
    json_str = intent_sig.model_dump_json(indent=2)
    print("✓ Serialized to JSON")
    print(f"   JSON length: {len(json_str)} characters")
    print()
    
    # 3. Parse from JSON
    print("3. Parsing from JSON...")
    parser = IntentSignatureParser()
    parsed_sig = parser.parse_json(json_str)
    print("✓ Parsed successfully")
    print(f"   Embedding dimensions: {len(parsed_sig.embedding)}")
    print(f"   Hash: {parsed_sig.hash[:16]}...")
    print(f"   Allowed actions: {len(parsed_sig.allowed_actions)}")
    print()
    
    # 4. Pretty print in compact format
    print("4. Pretty printing (compact format)...")
    print("-" * 80)
    printer = IntentSignaturePrettyPrinter(compact_embeddings=True)
    formatted = printer.format(intent_sig)
    print(formatted)
    print("-" * 80)
    print()
    
    # 5. Pretty print with similarity score
    print("5. Pretty printing with similarity score (aligned)...")
    print("-" * 80)
    formatted_with_score = printer.format(intent_sig, similarity_score=0.85)
    print(formatted_with_score)
    print("-" * 80)
    print()
    
    # 6. Pretty print with low similarity score (misaligned)
    print("6. Pretty printing with low similarity score (misaligned)...")
    print("-" * 80)
    formatted_misaligned = printer.format(intent_sig, similarity_score=0.45)
    print(formatted_misaligned)
    print("-" * 80)
    print()
    
    # 7. Format comparison (aligned)
    print("7. Formatting intent comparison (aligned action)...")
    print("-" * 80)
    comparison_aligned = format_intent_comparison(
        intent_sig,
        "github:create_pull_request",
        0.88
    )
    print(comparison_aligned)
    print("-" * 80)
    print()
    
    # 8. Format comparison (misaligned - potential prompt injection)
    print("8. Formatting intent comparison (misaligned - potential prompt injection)...")
    print("-" * 80)
    comparison_misaligned = format_intent_comparison(
        intent_sig,
        "github:delete_repository",
        0.32
    )
    print(comparison_misaligned)
    print("-" * 80)
    print()
    
    # 9. Compact single-line format
    print("9. Compact single-line format...")
    compact = printer.format_compact(intent_sig)
    print(compact)
    print()
    
    # 10. Round-trip verification
    print("10. Verifying round-trip consistency...")
    json_str_1 = printer.format_json(intent_sig)
    parsed_1 = parser.parse_json(json_str_1)
    json_str_2 = printer.format_json(parsed_1)
    parsed_2 = parser.parse_json(json_str_2)
    
    # Verify equivalence
    assert parsed_2.embedding == intent_sig.embedding
    assert parsed_2.hash == intent_sig.hash
    assert parsed_2.allowed_actions == intent_sig.allowed_actions
    print("✓ Round-trip consistency verified")
    print()
    
    print("=" * 80)
    print("Demo completed successfully!")
    print("=" * 80)


if __name__ == "__main__":
    main()
