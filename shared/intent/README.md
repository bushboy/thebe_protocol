# IntentSignature Parser and Pretty Printer

This module provides parsing, validation, and pretty-printing functionality for `IntentSignature` objects used in the Zero-Trust Agentic Guardian Architecture.

## Overview

The IntentSignature module consists of two main components:

1. **Parser** (`parser.py`): Deserializes and validates IntentSignature objects from JSON
2. **Pretty Printer** (`pretty_printer.py`): Formats IntentSignature objects in human-readable formats

## Requirements Satisfied

- **Requirement 20.1**: Deserialize from JSON
- **Requirement 20.2**: Validate embedding dimensionality (384 dimensions)
- **Requirement 20.3**: Validate hash format (64 hexadecimal characters)
- **Requirement 20.4**: Validate allowed actions list (non-empty)
- **Requirement 20.5**: Raise validation errors for malformed signatures
- **Requirement 21.1**: Format embedding vectors compactly
- **Requirement 21.2**: Display hashes in hexadecimal
- **Requirement 21.3**: List allowed actions clearly
- **Requirement 21.4**: Include similarity scores

## Usage

### Parsing IntentSignatures

```python
from shared.intent.parser import IntentSignatureParser, parse_intent_signature

# Parse from JSON string
parser = IntentSignatureParser()
intent_sig = parser.parse_json(json_string)

# Or use convenience function
intent_sig = parse_intent_signature(json_string)

# Parse from file
intent_sig = parser.parse_file("intent_signature.json")

# Parse from dictionary
intent_sig = parser.parse_dict(data_dict)

# Validate an existing IntentSignature
is_valid = parser.validate(intent_sig)
```

### Pretty Printing IntentSignatures

```python
from shared.intent.pretty_printer import (
    IntentSignaturePrettyPrinter,
    format_intent_signature,
    format_intent_comparison
)

# Create printer
printer = IntentSignaturePrettyPrinter(compact_embeddings=True)

# Format with similarity score
output = printer.format(intent_sig, similarity_score=0.85)
print(output)

# Format comparison between original intent and proposed action
comparison = format_intent_comparison(
    original_intent,
    "github:create_pr",
    similarity_score=0.88
)
print(comparison)

# Compact single-line format
compact = printer.format_compact(intent_sig)
print(compact)

# JSON format
json_output = printer.format_json(intent_sig, indent=2)
```

### Validation

The parser automatically validates:

1. **Embedding Dimensionality**: Must be exactly 384 dimensions (for all-MiniLM-L6-v2 model)
2. **Hash Format**: Must be 64 hexadecimal characters (SHA256)
3. **Allowed Actions**: Must be a non-empty list

Invalid data will raise `IntentSignatureError` with descriptive error messages.

### Round-Trip Consistency

The module ensures round-trip consistency:

```python
# Original → JSON → Parsed → JSON → Parsed
original = IntentSignature(...)
json_str = printer.format_json(original)
parsed = parser.parse_json(json_str)

# All fields are preserved
assert parsed.embedding == original.embedding
assert parsed.hash == original.hash
assert parsed.allowed_actions == original.allowed_actions
```

## Output Formats

### Standard Format

```
Intent Signature
============================================================
Timestamp: 2024-01-15T10:30:00
Hash: a1b2c3d4 e5f67890 12345678 90123456 78901234 56789012 34567890 12345678

Allowed Actions (3):
  - github:create_branch
  - github:create_pr
  - github:list_repos

Embedding Vector:
  Dimensions: 384
  Range: [-0.4560, 0.7890]
  Mean: 0.1010
  First 5: [0.1230, -0.4560, 0.7890, 0.3210, 0.1000]
  Last 5:  [0.1000, 0.1000, 0.1000, 0.1000, 0.1000]

Signature: example_signature_xyz123...

Similarity Score: 0.8500
Alignment Status: ALIGNED (threshold: 0.7)
```

### Comparison Format

```
Intent Alignment Verification
============================================================

Original Intent:
  Hash: a1b2c3d4 e5f67890 12345678 90123456 78901234 56789012 34567890 12345678
  Timestamp: 2024-01-15T10:30:00
  Allowed Actions: github:create_branch, github:create_pr, github:list_repos

Proposed Action:
  github:create_pull_request

Similarity Analysis:
  Score: 0.8800
  Threshold: 0.7
  Status: ✓ ALIGNED
  Decision: Action is consistent with original intent
```

### Compact Format

```
IntentSignature(hash=a1b2c3d4e5f67890..., actions=[github:create_branch, github:create_pr, github:list_repos], timestamp=2024-01-15T10:30:00)
```

## Error Handling

The module provides clear error messages for validation failures:

```python
try:
    intent_sig = parser.parse_json(invalid_json)
except IntentSignatureError as e:
    print(f"Validation failed: {e}")
    # Example: "Embedding must have 384 dimensions, got 100"
```

## Testing

The module includes comprehensive tests:

- **Unit tests**: `tests/test_intent_signature_parser.py`, `tests/test_intent_signature_pretty_printer.py`
- **Integration tests**: `tests/test_intent_signature_roundtrip.py`
- **Property-based tests**: `tests/test_intent_signature_validation.py`

Run tests:
```bash
pytest tests/test_intent_signature*.py -v
```

## Example

See `examples/intent_signature_demo.py` for a complete demonstration of all features.

## Related Modules

- `shared/schemas/models.py`: IntentSignature Pydantic model definition
- `services/intent-engine/`: Service that generates IntentSignatures
- `services/safety-agent/`: Service that validates intent alignment
