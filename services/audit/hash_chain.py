"""Hash chain computation for audit log integrity.

This module implements cryptographic hash chaining where each entry's hash
is computed as SHA256(previous_hash || entry_data). This creates a tamper-evident
chain where any modification breaks the chain and is detectable.

Requirements: 10.3
"""

import hashlib
import json
from typing import Dict, Any, List
from datetime import datetime

from shared.logging import JSONLogger
from .config import config


logger = JSONLogger(__name__)


class HashChainComputer:
    """Computes and verifies cryptographic hash chains for audit logs."""
    
    def __init__(self, genesis_hash: str = None):
        """Initialize hash chain computer.
        
        Args:
            genesis_hash: Initial hash for the chain (default: "genesis")
        """
        self.genesis_hash = genesis_hash or config.genesis_hash
        logger.info(f"Initialized hash chain computer with genesis: {self.genesis_hash}")
    
    def compute_entry_hash(
        self,
        previous_hash: str,
        log_id: str,
        component: str,
        event_type: str,
        action_metadata: Dict[str, Any],
        zt_at: Dict[str, Any] | None,
        dpop_fingerprint: str,
        timestamp: datetime
    ) -> str:
        """Compute hash for an audit log entry.
        
        The hash is computed as: SHA256(previous_hash || entry_data)
        where entry_data is a canonical JSON representation of the entry fields.
        
        Args:
            previous_hash: Hash of the previous entry in the chain
            log_id: Unique log entry identifier
            component: Service that generated the log
            event_type: Type of event
            action_metadata: Action-specific data
            zt_at: Optional ZT-AT dictionary
            dpop_fingerprint: DPoP key fingerprint
            timestamp: Event timestamp
            
        Returns:
            SHA256 hash as hexadecimal string
            
        Requirements: 10.3
        """
        # Create canonical entry data structure
        entry_data = {
            "log_id": log_id,
            "component": component,
            "event_type": event_type,
            "action_metadata": action_metadata,
            "zt_at": zt_at,
            "dpop_fingerprint": dpop_fingerprint,
            "timestamp": timestamp.isoformat() if isinstance(timestamp, datetime) else timestamp
        }
        
        # Convert to canonical JSON (sorted keys, no whitespace)
        entry_json = json.dumps(entry_data, sort_keys=True, separators=(',', ':'))
        
        # Compute hash: SHA256(previous_hash || entry_json)
        hash_input = previous_hash + entry_json
        hash_bytes = hashlib.sha256(hash_input.encode('utf-8')).digest()
        hash_hex = hash_bytes.hex()
        
        logger.debug(
            f"Computed hash for entry {log_id}: {hash_hex[:16]}... "
            f"(previous: {previous_hash[:16]}...)"
        )
        
        return hash_hex
    
    def verify_entry_hash(
        self,
        entry_hash: str,
        previous_hash: str,
        log_id: str,
        component: str,
        event_type: str,
        action_metadata: Dict[str, Any],
        zt_at: Dict[str, Any] | None,
        dpop_fingerprint: str,
        timestamp: datetime
    ) -> bool:
        """Verify that an entry's hash is correct.
        
        Args:
            entry_hash: The stored hash to verify
            previous_hash: Hash of the previous entry
            log_id: Unique log entry identifier
            component: Service that generated the log
            event_type: Type of event
            action_metadata: Action-specific data
            zt_at: Optional ZT-AT dictionary
            dpop_fingerprint: DPoP key fingerprint
            timestamp: Event timestamp
            
        Returns:
            True if hash is valid, False otherwise
        """
        computed_hash = self.compute_entry_hash(
            previous_hash=previous_hash,
            log_id=log_id,
            component=component,
            event_type=event_type,
            action_metadata=action_metadata,
            zt_at=zt_at,
            dpop_fingerprint=dpop_fingerprint,
            timestamp=timestamp
        )
        
        is_valid = computed_hash == entry_hash
        
        if not is_valid:
            logger.warning(
                f"Hash verification failed for entry {log_id}: "
                f"expected {entry_hash[:16]}..., got {computed_hash[:16]}..."
            )
        
        return is_valid
    
    def verify_chain(self, entries: List[Dict[str, Any]]) -> tuple[bool, int | None]:
        """Verify the integrity of a complete hash chain.
        
        Args:
            entries: List of audit log entries in order
            
        Returns:
            Tuple of (is_valid, broken_index) where broken_index is the index
            of the first entry with an invalid hash, or None if chain is valid
            
        Requirements: 10.5
        """
        if not entries:
            logger.info("Empty chain is valid")
            return True, None
        
        logger.info(f"Verifying hash chain with {len(entries)} entries")
        
        for i, entry in enumerate(entries):
            # First entry should have genesis hash as previous
            if i == 0:
                expected_previous = self.genesis_hash
            else:
                expected_previous = entries[i - 1]["hash"]
            
            # Verify previous_hash matches
            if entry["previous_hash"] != expected_previous:
                logger.error(
                    f"Chain broken at entry {i} ({entry['log_id']}): "
                    f"previous_hash mismatch. Expected {expected_previous[:16]}..., "
                    f"got {entry['previous_hash'][:16]}..."
                )
                return False, i
            
            # Verify hash computation
            is_valid = self.verify_entry_hash(
                entry_hash=entry["hash"],
                previous_hash=entry["previous_hash"],
                log_id=entry["log_id"],
                component=entry["component"],
                event_type=entry["event_type"],
                action_metadata=entry["action_metadata"],
                zt_at=entry.get("zt_at"),
                dpop_fingerprint=entry["dpop_fingerprint"],
                timestamp=entry["timestamp"]
            )
            
            if not is_valid:
                logger.error(
                    f"Chain broken at entry {i} ({entry['log_id']}): "
                    f"hash verification failed"
                )
                return False, i
        
        logger.info("Hash chain verification successful")
        return True, None
    
    def detect_tampering(
        self,
        entries: List[Dict[str, Any]]
    ) -> tuple[bool, List[int]]:
        """Detect any tampering in the audit log chain.
        
        Args:
            entries: List of audit log entries in order
            
        Returns:
            Tuple of (is_tampered, tampered_indices) where tampered_indices
            contains the indices of all entries with invalid hashes
            
        Requirements: 10.5
        """
        if not entries:
            return False, []
        
        tampered_indices = []
        
        for i, entry in enumerate(entries):
            # Determine expected previous hash
            if i == 0:
                expected_previous = self.genesis_hash
            else:
                expected_previous = entries[i - 1]["hash"]
            
            # Check previous_hash link
            if entry["previous_hash"] != expected_previous:
                tampered_indices.append(i)
                continue
            
            # Verify hash computation
            is_valid = self.verify_entry_hash(
                entry_hash=entry["hash"],
                previous_hash=entry["previous_hash"],
                log_id=entry["log_id"],
                component=entry["component"],
                event_type=entry["event_type"],
                action_metadata=entry["action_metadata"],
                zt_at=entry.get("zt_at"),
                dpop_fingerprint=entry["dpop_fingerprint"],
                timestamp=entry["timestamp"]
            )
            
            if not is_valid:
                tampered_indices.append(i)
        
        is_tampered = len(tampered_indices) > 0
        
        if is_tampered:
            logger.warning(
                f"Tampering detected in {len(tampered_indices)} entries: "
                f"{tampered_indices}"
            )
        
        return is_tampered, tampered_indices
