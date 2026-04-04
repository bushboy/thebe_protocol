"""
Demo script for Audit Log Parser and Pretty Printer

This script demonstrates the usage of the audit log parsing and pretty
printing functionality, including hash chain validation and formatting.
"""

import json
from datetime import datetime, timedelta

from shared.audit import (
    AuditLogParser,
    AuditLogPrettyPrinter,
    parse_audit_log,
    parse_audit_log_sequence,
    validate_audit_log,
    format_audit_log,
    format_audit_log_sequence
)
from shared.schemas.models import (
    AuditLogEntry,
    ZeroTrustAuthorizationToken,
    PolicyDecision,
    IntentSignature
)


def create_sample_entries():
    """Create sample audit log entries with valid hash chain."""
    parser = AuditLogParser()
    entries = []
    
    # Entry 1: Planner creates plan
    entry1_data = {
        "log_id": "log_001",
        "component": "planner",
        "event_type": "plan_created",
        "action_metadata": {
            "plan_id": "plan_123",
            "user_goal": "Create a new feature branch",
            "tasks": 3
        },
        "zt_at": None,
        "dpop_fingerprint": "fp_planner_abc123",
        "timestamp": datetime.utcnow(),
        "previous_hash": "genesis"
    }
    
    # Compute hash for entry 1
    temp_entry1 = AuditLogEntry(**entry1_data, hash="temp")
    entry1_data["hash"] = parser._compute_entry_hash(temp_entry1)
    entry1 = AuditLogEntry(**entry1_data)
    entries.append(entry1)
    
    # Entry 2: Intent Engine signs intent
    entry2_data = {
        "log_id": "log_002",
        "component": "intent-engine",
        "event_type": "intent_signed",
        "action_metadata": {
            "plan_id": "plan_123",
            "intent_hash": "a1b2c3d4e5f6...",
            "allowed_actions": ["github:create_branch", "github:create_pr"]
        },
        "zt_at": None,
        "dpop_fingerprint": "fp_intent_def456",
        "timestamp": datetime.utcnow() + timedelta(seconds=1),
        "previous_hash": entry1.hash
    }
    
    temp_entry2 = AuditLogEntry(**entry2_data, hash="temp")
    entry2_data["hash"] = parser._compute_entry_hash(temp_entry2)
    entry2 = AuditLogEntry(**entry2_data)
    entries.append(entry2)
    
    # Entry 3: Safety Agent evaluates policy
    entry3_data = {
        "log_id": "log_003",
        "component": "safety-agent",
        "event_type": "policy_evaluated",
        "action_metadata": {
            "plan_id": "plan_123",
            "decision": "ALLOW",
            "policies_evaluated": ["destructive_actions", "spending_limits"]
        },
        "zt_at": None,
        "dpop_fingerprint": "fp_safety_ghi789",
        "timestamp": datetime.utcnow() + timedelta(seconds=2),
        "previous_hash": entry2.hash
    }
    
    temp_entry3 = AuditLogEntry(**entry3_data, hash="temp")
    entry3_data["hash"] = parser._compute_entry_hash(temp_entry3)
    entry3 = AuditLogEntry(**entry3_data)
    entries.append(entry3)
    
    # Entry 4: Executor executes action
    entry4_data = {
        "log_id": "log_004",
        "component": "executor",
        "event_type": "action_executed",
        "action_metadata": {
            "plan_id": "plan_123",
            "task_id": "task_001",
            "action": "create_branch",
            "provider": "github",
            "result": "success",
            "branch_name": "feature/new-feature"
        },
        "zt_at": None,
        "dpop_fingerprint": "fp_executor_jkl012",
        "timestamp": datetime.utcnow() + timedelta(seconds=3),
        "previous_hash": entry3.hash
    }
    
    temp_entry4 = AuditLogEntry(**entry4_data, hash="temp")
    entry4_data["hash"] = parser._compute_entry_hash(temp_entry4)
    entry4 = AuditLogEntry(**entry4_data)
    entries.append(entry4)
    
    return entries


def demo_parsing():
    """Demonstrate audit log parsing."""
    print("=" * 70)
    print("AUDIT LOG PARSING DEMO")
    print("=" * 70)
    print()
    
    # Create sample entries
    entries = create_sample_entries()
    
    # Serialize to JSON
    json_str = json.dumps([entry.model_dump() for entry in entries], default=str, indent=2)
    
    print("1. Parsing audit log sequence from JSON")
    print("-" * 70)
    
    # Parse back
    parser = AuditLogParser()
    parsed_entries = parser.parse_sequence(json_str)
    
    print(f"✓ Successfully parsed {len(parsed_entries)} entries")
    print()
    
    # Validate hash chain
    print("2. Validating hash chain integrity")
    print("-" * 70)
    
    is_valid, broken_index = parser.validate_hash_chain(parsed_entries)
    
    if is_valid:
        print("✓ Hash chain is valid and intact")
    else:
        print(f"✗ Hash chain broken at index {broken_index}")
    print()
    
    # Validate timestamp monotonicity
    print("3. Validating timestamp monotonicity")
    print("-" * 70)
    
    is_monotonic, out_of_order = parser.validate_timestamp_monotonicity(parsed_entries)
    
    if is_monotonic:
        print("✓ Timestamps are monotonically increasing")
    else:
        print(f"✗ Timestamps out of order at indices: {out_of_order}")
    print()
    
    # Complete validation
    print("4. Complete validation")
    print("-" * 70)
    
    try:
        parser.validate(parsed_entries)
        print("✓ All validations passed!")
    except Exception as e:
        print(f"✗ Validation failed: {e}")
    print()


def demo_pretty_printing():
    """Demonstrate audit log pretty printing."""
    print("=" * 70)
    print("AUDIT LOG PRETTY PRINTING DEMO")
    print("=" * 70)
    print()
    
    # Create sample entries
    entries = create_sample_entries()
    
    # Format single entry
    print("1. Formatting single audit log entry")
    print("-" * 70)
    
    printer = AuditLogPrettyPrinter(show_full_hashes=False)
    formatted_single = printer.format(entries[0])
    print(formatted_single)
    print()
    
    # Format compact
    print("2. Compact formatting")
    print("-" * 70)
    
    for entry in entries:
        compact = printer.format_compact(entry)
        print(compact)
    print()
    
    # Format sequence with chain visualization
    print("3. Formatting sequence with chain visualization")
    print("-" * 70)
    
    formatted_sequence = printer.format_sequence(
        entries,
        show_zt_at=False,
        show_chain_visualization=True
    )
    print(formatted_sequence)
    print()
    
    # Format summary
    print("4. Audit log summary")
    print("-" * 70)
    
    summary = printer.format_summary(entries)
    print(summary)
    print()


def demo_tampering_detection():
    """Demonstrate tampering detection."""
    print("=" * 70)
    print("TAMPERING DETECTION DEMO")
    print("=" * 70)
    print()
    
    # Create sample entries
    entries = create_sample_entries()
    
    print("1. Original hash chain (valid)")
    print("-" * 70)
    
    parser = AuditLogParser()
    is_valid, broken_index = parser.validate_hash_chain(entries)
    print(f"Hash chain valid: {is_valid}")
    print()
    
    # Tamper with middle entry
    print("2. Tampering with entry 2 (modifying action_metadata)")
    print("-" * 70)
    
    tampered_entries = entries.copy()
    entry2_dict = tampered_entries[1].model_dump()
    entry2_dict["action_metadata"]["tampered"] = True
    entry2_dict["action_metadata"]["malicious_field"] = "injected_data"
    tampered_entries[1] = AuditLogEntry(**entry2_dict)
    
    print("Modified entry 2 action_metadata:")
    print(f"  Added: tampered=True")
    print(f"  Added: malicious_field='injected_data'")
    print()
    
    # Validate tampered chain
    print("3. Validating tampered chain")
    print("-" * 70)
    
    is_valid, broken_index = parser.validate_hash_chain(tampered_entries)
    
    if is_valid:
        print("✗ Tampering NOT detected (this should not happen!)")
    else:
        print(f"✓ Tampering detected at entry {broken_index}")
        print(f"  Entry {broken_index} hash does not match computed hash")
        print(f"  This indicates the entry has been modified after creation")
    print()


def demo_convenience_functions():
    """Demonstrate convenience functions."""
    print("=" * 70)
    print("CONVENIENCE FUNCTIONS DEMO")
    print("=" * 70)
    print()
    
    # Create sample entry
    entries = create_sample_entries()
    entry = entries[0]
    
    # Parse single entry
    print("1. parse_audit_log()")
    print("-" * 70)
    
    json_str = entry.model_dump_json()
    parsed = parse_audit_log(json_str)
    print(f"✓ Parsed entry: {parsed.log_id}")
    print()
    
    # Parse sequence
    print("2. parse_audit_log_sequence()")
    print("-" * 70)
    
    json_array = json.dumps([e.model_dump() for e in entries], default=str)
    parsed_entries = parse_audit_log_sequence(json_array)
    print(f"✓ Parsed {len(parsed_entries)} entries")
    print()
    
    # Validate
    print("3. validate_audit_log()")
    print("-" * 70)
    
    try:
        validate_audit_log(parsed_entries)
        print("✓ Validation passed")
    except Exception as e:
        print(f"✗ Validation failed: {e}")
    print()
    
    # Format single
    print("4. format_audit_log()")
    print("-" * 70)
    
    formatted = format_audit_log(entry, show_zt_at=False)
    print(formatted[:200] + "...")
    print()
    
    # Format sequence
    print("5. format_audit_log_sequence()")
    print("-" * 70)
    
    formatted_seq = format_audit_log_sequence(entries, show_zt_at=False)
    print(formatted_seq[:200] + "...")
    print()


def main():
    """Run all demos."""
    print()
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 15 + "AUDIT LOG PARSER & PRETTY PRINTER" + " " * 20 + "║")
    print("║" + " " * 25 + "DEMONSTRATION" + " " * 30 + "║")
    print("╚" + "═" * 68 + "╝")
    print()
    
    demo_parsing()
    input("Press Enter to continue to pretty printing demo...")
    print()
    
    demo_pretty_printing()
    input("Press Enter to continue to tampering detection demo...")
    print()
    
    demo_tampering_detection()
    input("Press Enter to continue to convenience functions demo...")
    print()
    
    demo_convenience_functions()
    
    print()
    print("=" * 70)
    print("DEMO COMPLETE")
    print("=" * 70)
    print()
    print("Key Features Demonstrated:")
    print("  ✓ JSON parsing and deserialization")
    print("  ✓ Hash chain validation (SHA256)")
    print("  ✓ Timestamp monotonicity checking")
    print("  ✓ Required fields validation")
    print("  ✓ Pretty printing with ISO 8601 timestamps")
    print("  ✓ Component labels and formatting")
    print("  ✓ Hash chain visualization")
    print("  ✓ Tampering detection")
    print("  ✓ Convenience functions")
    print()


if __name__ == "__main__":
    main()
