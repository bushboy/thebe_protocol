# Audit Log Parser and Pretty Printer

This module provides tools for parsing, validating, and formatting audit log entries with hash chain verification.

## Features

### Parser (`parser.py`)

The `AuditLogParser` class provides:

- **JSON Deserialization**: Parse audit log entries from JSON strings, dictionaries, or files
- **Hash Chain Validation**: Verify cryptographic hash chain integrity (SHA256)
- **Required Fields Validation**: Ensure all required fields are present
- **Timestamp Monotonicity**: Verify timestamps are monotonically increasing
- **Complete Validation**: Perform all validation checks in one call

**Requirements**: 22.1, 22.2, 22.3, 22.4, 22.5

### Pretty Printer (`pretty_printer.py`)

The `AuditLogPrettyPrinter` class provides:

- **ISO 8601 Timestamps**: Format timestamps in standard ISO 8601 format
- **Component Labels**: Display component identities with descriptive labels
- **ZT-AT Formatting**: Format Zero-Trust Authorization Token contents with indentation
- **Hash Chain Visualization**: Display hash chain links with visual indicators
- **Sequence Formatting**: Format multiple entries with chain visualization
- **Summary Statistics**: Generate summary of audit log sequences

**Requirements**: 23.1, 23.2, 23.3, 23.4

## Usage Examples

### Parsing Audit Logs

```python
from shared.audit import parse_audit_log, parse_audit_log_sequence, validate_audit_log

# Parse single entry from JSON string
entry = parse_audit_log(json_string)

# Parse sequence from JSON array
entries = parse_audit_log_sequence(json_array_string)

# Validate complete sequence
try:
    validate_audit_log(entries)
    print("Audit log is valid!")
except AuditLogError as e:
    print(f"Validation failed: {e}")
```

### Pretty Printing Audit Logs

```python
from shared.audit import format_audit_log, format_audit_log_sequence

# Format single entry
formatted = format_audit_log(entry, show_zt_at=True)
print(formatted)

# Format sequence with chain visualization
formatted_sequence = format_audit_log_sequence(
    entries,
    show_zt_at=False,
    show_chain_visualization=True
)
print(formatted_sequence)
```

### Advanced Usage

```python
from shared.audit import AuditLogParser, AuditLogPrettyPrinter

# Create parser
parser = AuditLogParser()

# Parse and validate
entries = parser.parse_sequence(json_string)

# Validate hash chain
is_valid, broken_index = parser.validate_hash_chain(entries)
if not is_valid:
    print(f"Hash chain broken at index {broken_index}")

# Validate timestamp monotonicity
is_monotonic, out_of_order = parser.validate_timestamp_monotonicity(entries)
if not is_monotonic:
    print(f"Timestamps out of order at indices: {out_of_order}")

# Create pretty printer
printer = AuditLogPrettyPrinter(show_full_hashes=True)

# Format with custom options
formatted = printer.format(entries[0], show_zt_at=True)
print(formatted)

# Generate summary
summary = printer.format_summary(entries)
print(summary)
```

## Hash Chain Validation

The parser validates that each entry's hash equals `SHA256(previous_hash || entry_data)`:

1. First entry has `previous_hash = "genesis"`
2. Each subsequent entry's `previous_hash` equals the previous entry's `hash`
3. Each entry's `hash` is computed from its data and previous hash

Any modification to an entry will break the chain and be detected during validation.

## Timestamp Monotonicity

The parser ensures timestamps are monotonically increasing (or equal):

- Timestamps must not decrease
- Equal timestamps are allowed (for entries created in the same millisecond)
- Out-of-order timestamps indicate tampering or system clock issues

## Error Handling

All functions raise `AuditLogError` with descriptive messages when:

- JSON parsing fails
- Required fields are missing
- Hash chain is broken
- Timestamps are out of order
- Validation fails for any reason

## Testing

Property-based tests verify correctness properties:

- **Property 4**: Round-trip consistency (parse → pretty print → parse)
- **Property 5**: Hash chain integrity
- **Property 13**: Audit log completeness
- **Property 32**: Timestamp monotonicity

See `tests/test_audit_properties.py` for complete test suite.
