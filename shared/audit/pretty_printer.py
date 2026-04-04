"""
Audit Log Pretty Printer for Zero-Trust Agentic Guardian Architecture

This module formats audit log entries in human-readable format with
ISO 8601 timestamps, labeled component identities, indented ZT-AT contents,
and visual hash chain indicators.

Requirements: 23.1, 23.2, 23.3, 23.4
"""

import json
from typing import List, Optional
from datetime import datetime

from shared.schemas.models import AuditLogEntry, ZeroTrustAuthorizationToken


class AuditLogPrettyPrinter:
    """
    Pretty printer for audit log entries
    
    Formats audit log data in human-readable format with timestamps,
    component labels, ZT-AT contents, and hash chain visualization.
    
    Requirements: 23.1, 23.2, 23.3, 23.4
    """
    
    def __init__(self, show_full_hashes: bool = False):
        """
        Initialize pretty printer
        
        Args:
            show_full_hashes: Whether to show full hashes or abbreviated
        """
        self.show_full_hashes = show_full_hashes
    
    def format(self, entry: AuditLogEntry, show_zt_at: bool = True) -> str:
        """
        Format single audit log entry as readable text
        
        Args:
            entry: AuditLogEntry object to format
            show_zt_at: Whether to include ZT-AT contents
            
        Returns:
            Formatted string
        """
        lines = [
            "Audit Log Entry",
            "=" * 60,
        ]
        
        # Format log ID
        lines.append(f"Log ID: {entry.log_id}")
        
        # Format timestamp in ISO 8601 (Requirement 23.1)
        timestamp_str = self._format_timestamp(entry.timestamp)
        lines.append(f"Timestamp: {timestamp_str}")
        
        # Display component identity with label (Requirement 23.2)
        lines.append(f"Component: {self._format_component(entry.component)}")
        lines.append(f"Event Type: {entry.event_type}")
        
        # Format action metadata
        lines.append(f"\nAction Metadata:")
        lines.append(self._format_dict(entry.action_metadata, indent=2))
        
        # Format DPoP fingerprint
        lines.append(f"\nDPoP Fingerprint: {entry.dpop_fingerprint}")
        
        # Format ZT-AT contents with indentation (Requirement 23.3)
        if entry.zt_at and show_zt_at:
            lines.append(f"\nZero-Trust Authorization Token:")
            lines.append(self._format_zt_at(entry.zt_at, indent=2))
        elif entry.zt_at:
            lines.append(f"\nZero-Trust Authorization Token: [Present]")
        else:
            lines.append(f"\nZero-Trust Authorization Token: [None]")
        
        # Display hash chain links with visual indicators (Requirement 23.4)
        lines.append(f"\nHash Chain:")
        lines.append(self._format_hash_chain_link(entry))
        
        return "\n".join(lines)
    
    def format_sequence(
        self,
        entries: List[AuditLogEntry],
        show_zt_at: bool = False,
        show_chain_visualization: bool = True
    ) -> str:
        """
        Format sequence of audit log entries
        
        Args:
            entries: List of AuditLogEntry objects
            show_zt_at: Whether to include ZT-AT contents
            show_chain_visualization: Whether to show chain visualization
            
        Returns:
            Formatted string
        """
        if not entries:
            return "No audit log entries"
        
        lines = [
            "Audit Log Sequence",
            "=" * 60,
            f"Total Entries: {len(entries)}",
            f"First Entry: {self._format_timestamp(entries[0].timestamp)}",
            f"Last Entry: {self._format_timestamp(entries[-1].timestamp)}",
            ""
        ]
        
        # Show chain visualization if requested (Requirement 23.4)
        if show_chain_visualization:
            lines.append("Hash Chain Visualization:")
            lines.append(self._format_chain_visualization(entries))
            lines.append("")
        
        # Format each entry
        for i, entry in enumerate(entries):
            lines.append(f"\n{'─' * 60}")
            lines.append(f"Entry {i + 1} of {len(entries)}")
            lines.append(f"{'─' * 60}")
            lines.append("")
            
            # Format entry details
            lines.append(f"Log ID: {entry.log_id}")
            lines.append(f"Timestamp: {self._format_timestamp(entry.timestamp)}")
            lines.append(f"Component: {self._format_component(entry.component)}")
            lines.append(f"Event Type: {entry.event_type}")
            
            # Format action metadata
            lines.append(f"\nAction Metadata:")
            lines.append(self._format_dict(entry.action_metadata, indent=2))
            
            # Format ZT-AT if present and requested
            if entry.zt_at and show_zt_at:
                lines.append(f"\nZero-Trust Authorization Token:")
                lines.append(self._format_zt_at(entry.zt_at, indent=2))
            
            # Show hash chain link
            lines.append(f"\nHash Chain:")
            lines.append(self._format_hash_chain_link(entry))
        
        return "\n".join(lines)
    
    def format_json(self, entry: AuditLogEntry, indent: int = 2) -> str:
        """
        Format audit log entry as JSON
        
        Args:
            entry: AuditLogEntry object
            indent: JSON indentation level
            
        Returns:
            JSON string
        """
        return entry.model_dump_json(indent=indent)
    
    def format_compact(self, entry: AuditLogEntry) -> str:
        """
        Format audit log entry in compact single-line format
        
        Args:
            entry: AuditLogEntry object
            
        Returns:
            Compact formatted string
        """
        timestamp_str = self._format_timestamp(entry.timestamp)
        hash_short = self._format_hash(entry.hash, full=False)
        
        return (
            f"[{timestamp_str}] {self._format_component(entry.component)} | "
            f"{entry.event_type} | hash={hash_short}"
        )
    
    def _format_timestamp(self, timestamp: datetime) -> str:
        """
        Format timestamp in ISO 8601 format (Requirement 23.1)
        
        Args:
            timestamp: Datetime object
            
        Returns:
            ISO 8601 formatted string
        """
        return timestamp.isoformat()
    
    def _format_component(self, component: str) -> str:
        """
        Display component identity with label (Requirement 23.2)
        
        Args:
            component: Component name
            
        Returns:
            Formatted component string with label
        """
        # Map component names to descriptive labels
        component_labels = {
            "planner": "Planner Service",
            "intent-engine": "Intent Engine",
            "safety-agent": "Safety Agent",
            "permission-broker": "Permission Broker",
            "executor": "Executor Agent",
            "audit": "Audit Service"
        }
        
        label = component_labels.get(component, component.title())
        return f"{label} ({component})"
    
    def _format_hash(self, hash_value: str, full: bool = None) -> str:
        """
        Format hash value
        
        Args:
            hash_value: Hash string
            full: Whether to show full hash (overrides instance setting)
            
        Returns:
            Formatted hash string
        """
        show_full = full if full is not None else self.show_full_hashes
        
        if show_full or hash_value == "genesis":
            return hash_value
        else:
            # Show first 8 and last 8 characters
            if len(hash_value) > 16:
                return f"{hash_value[:8]}...{hash_value[-8:]}"
            return hash_value
    
    def _format_hash_chain_link(self, entry: AuditLogEntry) -> str:
        """
        Display hash chain links with visual indicators (Requirement 23.4)
        
        Args:
            entry: AuditLogEntry object
            
        Returns:
            Formatted hash chain visualization
        """
        lines = []
        
        # Previous hash
        prev_hash = self._format_hash(entry.previous_hash)
        lines.append(f"  Previous: {prev_hash}")
        
        # Visual link indicator
        lines.append(f"      ↓")
        
        # Current hash
        curr_hash = self._format_hash(entry.hash)
        lines.append(f"  Current:  {curr_hash}")
        
        return "\n".join(lines)
    
    def _format_chain_visualization(self, entries: List[AuditLogEntry]) -> str:
        """
        Create visual representation of hash chain (Requirement 23.4)
        
        Args:
            entries: List of audit log entries
            
        Returns:
            Visual chain representation
        """
        if not entries:
            return "  [Empty chain]"
        
        lines = []
        
        # Show genesis
        lines.append(f"  [genesis]")
        lines.append(f"      ↓")
        
        # Show each entry in chain
        for i, entry in enumerate(entries):
            hash_short = self._format_hash(entry.hash, full=False)
            component_short = entry.component[:15]
            lines.append(f"  [{i+1}] {component_short} | {hash_short}")
            
            if i < len(entries) - 1:
                lines.append(f"      ↓")
        
        return "\n".join(lines)
    
    def _format_zt_at(self, zt_at: ZeroTrustAuthorizationToken, indent: int = 0) -> str:
        """
        Format ZT-AT contents with indentation (Requirement 23.3)
        
        Args:
            zt_at: ZeroTrustAuthorizationToken object
            indent: Indentation level (spaces)
            
        Returns:
            Formatted ZT-AT string
        """
        prefix = " " * indent
        lines = []
        
        lines.append(f"{prefix}Plan ID: {zt_at.plan_id}")
        lines.append(f"{prefix}Task ID: {zt_at.task_id}")
        lines.append(f"{prefix}Action: {zt_at.action}")
        lines.append(f"{prefix}Provider: {zt_at.provider}")
        lines.append(f"{prefix}Issued At: {self._format_timestamp(zt_at.issued_at)}")
        lines.append(f"{prefix}Expires At: {self._format_timestamp(zt_at.expires_at)}")
        lines.append(f"{prefix}Nonce: {zt_at.nonce}")
        
        # Format policy approval
        lines.append(f"{prefix}Policy Approval:")
        lines.append(f"{prefix}  Decision: {zt_at.policy_approval.decision}")
        lines.append(f"{prefix}  Reason: {zt_at.policy_approval.reason}")
        lines.append(f"{prefix}  Signer: {zt_at.policy_approval.signer_identity}")
        lines.append(f"{prefix}  Timestamp: {self._format_timestamp(zt_at.policy_approval.timestamp)}")
        
        # Format intent signature
        lines.append(f"{prefix}Intent Signature:")
        hash_short = self._format_hash(zt_at.intent_signature.hash, full=False)
        lines.append(f"{prefix}  Hash: {hash_short}")
        lines.append(f"{prefix}  Actions: {', '.join(zt_at.intent_signature.allowed_actions)}")
        lines.append(f"{prefix}  Timestamp: {self._format_timestamp(zt_at.intent_signature.timestamp)}")
        
        # Broker signature
        broker_sig_short = zt_at.broker_signature[:16] + "..." if len(zt_at.broker_signature) > 16 else zt_at.broker_signature
        lines.append(f"{prefix}Broker Signature: {broker_sig_short}")
        
        return "\n".join(lines)
    
    def _format_dict(self, data: dict, indent: int = 0) -> str:
        """
        Format dictionary with indentation
        
        Args:
            data: Dictionary to format
            indent: Indentation level (spaces)
            
        Returns:
            Formatted string
        """
        prefix = " " * indent
        lines = []
        
        for key, value in data.items():
            if isinstance(value, dict):
                lines.append(f"{prefix}{key}:")
                lines.append(self._format_dict(value, indent + 2))
            elif isinstance(value, list):
                lines.append(f"{prefix}{key}: [{', '.join(str(v) for v in value)}]")
            else:
                lines.append(f"{prefix}{key}: {value}")
        
        return "\n".join(lines)
    
    def format_summary(self, entries: List[AuditLogEntry]) -> str:
        """
        Format summary statistics for audit log sequence
        
        Args:
            entries: List of audit log entries
            
        Returns:
            Formatted summary string
        """
        if not entries:
            return "No audit log entries"
        
        # Calculate statistics
        components = {}
        event_types = {}
        
        for entry in entries:
            components[entry.component] = components.get(entry.component, 0) + 1
            event_types[entry.event_type] = event_types.get(entry.event_type, 0) + 1
        
        lines = [
            "Audit Log Summary",
            "=" * 60,
            f"Total Entries: {len(entries)}",
            f"Time Range: {self._format_timestamp(entries[0].timestamp)} to {self._format_timestamp(entries[-1].timestamp)}",
            "",
            "Entries by Component:",
        ]
        
        for component, count in sorted(components.items()):
            lines.append(f"  {self._format_component(component)}: {count}")
        
        lines.append("")
        lines.append("Entries by Event Type:")
        
        for event_type, count in sorted(event_types.items()):
            lines.append(f"  {event_type}: {count}")
        
        # Hash chain status
        lines.append("")
        lines.append("Hash Chain:")
        first_hash = self._format_hash(entries[0].hash, full=False)
        last_hash = self._format_hash(entries[-1].hash, full=False)
        lines.append(f"  First: {first_hash}")
        lines.append(f"  Last: {last_hash}")
        
        return "\n".join(lines)


def format_audit_log(
    entry: AuditLogEntry,
    show_zt_at: bool = True,
    show_full_hashes: bool = False
) -> str:
    """
    Format single audit log entry as readable text (convenience function)
    
    Args:
        entry: AuditLogEntry object
        show_zt_at: Whether to include ZT-AT contents
        show_full_hashes: Whether to show full hashes
        
    Returns:
        Formatted string
    """
    printer = AuditLogPrettyPrinter(show_full_hashes=show_full_hashes)
    return printer.format(entry, show_zt_at=show_zt_at)


def format_audit_log_sequence(
    entries: List[AuditLogEntry],
    show_zt_at: bool = False,
    show_chain_visualization: bool = True,
    show_full_hashes: bool = False
) -> str:
    """
    Format sequence of audit log entries (convenience function)
    
    Args:
        entries: List of AuditLogEntry objects
        show_zt_at: Whether to include ZT-AT contents
        show_chain_visualization: Whether to show chain visualization
        show_full_hashes: Whether to show full hashes
        
    Returns:
        Formatted string
    """
    printer = AuditLogPrettyPrinter(show_full_hashes=show_full_hashes)
    return printer.format_sequence(
        entries,
        show_zt_at=show_zt_at,
        show_chain_visualization=show_chain_visualization
    )


def format_audit_log_json(entry: AuditLogEntry, indent: int = 2) -> str:
    """
    Format audit log entry as JSON (convenience function)
    
    Args:
        entry: AuditLogEntry object
        indent: JSON indentation level
        
    Returns:
        JSON string
    """
    printer = AuditLogPrettyPrinter()
    return printer.format_json(entry, indent=indent)
