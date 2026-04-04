"""Chain verification module for audit log integrity.

This module provides verification of the complete audit log hash chain
to detect tampering and ensure integrity.

Requirements: 10.5
"""

from typing import List, Dict, Any
from datetime import datetime

from shared.schemas import AuditLogEntry
from shared.logging import JSONLogger
from .hash_chain import HashChainComputer
from .log_storage import LogStorage


logger = JSONLogger(__name__)


class ChainVerificationResult:
    """Result of hash chain verification."""
    
    def __init__(
        self,
        is_valid: bool,
        total_entries: int,
        first_hash: str = None,
        last_hash: str = None,
        broken_index: int = None,
        tampered_indices: List[int] = None
    ):
        """Initialize verification result.
        
        Args:
            is_valid: Whether the chain is valid
            total_entries: Total number of entries in the chain
            first_hash: Hash of the first entry
            last_hash: Hash of the last entry
            broken_index: Index where chain is broken (if invalid)
            tampered_indices: List of tampered entry indices (if any)
        """
        self.is_valid = is_valid
        self.total_entries = total_entries
        self.first_hash = first_hash
        self.last_hash = last_hash
        self.broken_index = broken_index
        self.tampered_indices = tampered_indices or []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation.
        
        Returns:
            Dictionary with verification results
        """
        result = {
            "chain_valid": self.is_valid,
            "total_entries": self.total_entries,
            "first_hash": self.first_hash,
            "last_hash": self.last_hash
        }
        
        if not self.is_valid:
            result["broken_index"] = self.broken_index
            result["tampered_indices"] = self.tampered_indices
        
        return result


class ChainVerifier:
    """Verifies audit log hash chain integrity."""
    
    def __init__(
        self,
        log_storage: LogStorage = None,
        hash_chain_computer: HashChainComputer = None
    ):
        """Initialize chain verifier.
        
        Args:
            log_storage: Log storage instance (creates new if None)
            hash_chain_computer: Hash chain computer (creates new if None)
        """
        self.log_storage = log_storage or LogStorage()
        self.hash_chain = hash_chain_computer or HashChainComputer()
        
        logger.info("Initialized chain verifier")
    
    def verify_complete_chain(self) -> ChainVerificationResult:
        """Verify the integrity of the complete audit log chain.
        
        This method:
        1. Retrieves all audit log entries
        2. Verifies each entry's hash computation
        3. Verifies the chain links between entries
        4. Detects any tampering
        
        Returns:
            Verification result with details
            
        Requirements: 10.5
        """
        logger.info("Starting complete chain verification")
        
        # Get all entries
        entries = self.log_storage.get_all_entries()
        total_entries = len(entries)
        
        if total_entries == 0:
            logger.info("No entries in chain, verification successful")
            return ChainVerificationResult(
                is_valid=True,
                total_entries=0
            )
        
        # Convert to dict format for hash chain verification
        entry_dicts = []
        for entry in entries:
            entry_dict = {
                "log_id": entry.log_id,
                "component": entry.component,
                "event_type": entry.event_type,
                "action_metadata": entry.action_metadata,
                "zt_at": entry.zt_at.model_dump(mode='json') if entry.zt_at else None,
                "dpop_fingerprint": entry.dpop_fingerprint,
                "timestamp": entry.timestamp,
                "hash": entry.hash,
                "previous_hash": entry.previous_hash
            }
            entry_dicts.append(entry_dict)
        
        # Verify chain
        is_valid, broken_index = self.hash_chain.verify_chain(entry_dicts)
        
        # Detect tampering
        is_tampered, tampered_indices = self.hash_chain.detect_tampering(entry_dicts)
        
        # Get first and last hashes
        first_hash = entries[0].hash if entries else None
        last_hash = entries[-1].hash if entries else None
        
        if is_valid:
            logger.info(
                f"Chain verification successful: {total_entries} entries, "
                f"first={first_hash[:16] if first_hash else 'N/A'}..., "
                f"last={last_hash[:16] if last_hash else 'N/A'}..."
            )
        else:
            logger.error(
                f"Chain verification failed: broken at index {broken_index}, "
                f"tampered indices: {tampered_indices}"
            )
        
        return ChainVerificationResult(
            is_valid=is_valid and not is_tampered,
            total_entries=total_entries,
            first_hash=first_hash,
            last_hash=last_hash,
            broken_index=broken_index,
            tampered_indices=tampered_indices
        )
    
    def verify_entry(self, entry: AuditLogEntry) -> bool:
        """Verify a single audit log entry's hash.
        
        Args:
            entry: Audit log entry to verify
            
        Returns:
            True if entry hash is valid
        """
        zt_at_dict = entry.zt_at.model_dump(mode='json') if entry.zt_at else None
        
        is_valid = self.hash_chain.verify_entry_hash(
            entry_hash=entry.hash,
            previous_hash=entry.previous_hash,
            log_id=entry.log_id,
            component=entry.component,
            event_type=entry.event_type,
            action_metadata=entry.action_metadata,
            zt_at=zt_at_dict,
            dpop_fingerprint=entry.dpop_fingerprint,
            timestamp=entry.timestamp
        )
        
        if is_valid:
            logger.debug(f"Entry {entry.log_id} hash verification successful")
        else:
            logger.warning(f"Entry {entry.log_id} hash verification failed")
        
        return is_valid
    
    def verify_timestamp_monotonicity(self) -> tuple[bool, List[int]]:
        """Verify that timestamps are monotonically increasing.
        
        Returns:
            Tuple of (is_monotonic, out_of_order_indices)
            
        Requirements: 22.3, 22.4, 22.5
        """
        logger.info("Verifying timestamp monotonicity")
        
        entries = self.log_storage.get_all_entries()
        
        if len(entries) <= 1:
            return True, []
        
        out_of_order_indices = []
        
        for i in range(1, len(entries)):
            prev_timestamp = entries[i - 1].timestamp
            curr_timestamp = entries[i].timestamp
            
            if curr_timestamp < prev_timestamp:
                out_of_order_indices.append(i)
                logger.warning(
                    f"Timestamp out of order at index {i}: "
                    f"{prev_timestamp} > {curr_timestamp}"
                )
        
        is_monotonic = len(out_of_order_indices) == 0
        
        if is_monotonic:
            logger.info("Timestamp monotonicity verification successful")
        else:
            logger.error(
                f"Timestamp monotonicity verification failed: "
                f"{len(out_of_order_indices)} out-of-order entries"
            )
        
        return is_monotonic, out_of_order_indices
    
    def get_chain_summary(self) -> Dict[str, Any]:
        """Get a summary of the audit log chain.
        
        Returns:
            Dictionary with chain statistics
        """
        entries = self.log_storage.get_all_entries()
        total_entries = len(entries)
        
        if total_entries == 0:
            return {
                "total_entries": 0,
                "first_entry": None,
                "last_entry": None,
                "components": [],
                "event_types": []
            }
        
        # Collect statistics
        components = set()
        event_types = set()
        
        for entry in entries:
            components.add(entry.component)
            event_types.add(entry.event_type)
        
        return {
            "total_entries": total_entries,
            "first_entry": {
                "log_id": entries[0].log_id,
                "timestamp": entries[0].timestamp.isoformat(),
                "hash": entries[0].hash
            },
            "last_entry": {
                "log_id": entries[-1].log_id,
                "timestamp": entries[-1].timestamp.isoformat(),
                "hash": entries[-1].hash
            },
            "components": sorted(list(components)),
            "event_types": sorted(list(event_types))
        }
