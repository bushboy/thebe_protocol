"""Log entry storage manager for audit service.

This module manages the storage of audit log entries with hash chain computation,
storing component identity, action metadata, ZT-AT, and DPoP fingerprint.

Requirements: 10.2
"""

from typing import Optional, Dict, Any
from datetime import datetime
import uuid

from shared.schemas import AuditLogEntry, ZeroTrustAuthorizationToken
from shared.logging import JSONLogger
from .database import AuditDatabase, AuditLogEntryDB
from .hash_chain import HashChainComputer
from .config import config


logger = JSONLogger(__name__)


class LogStorage:
    """Manages audit log entry storage with hash chain integrity."""
    
    def __init__(
        self,
        database: AuditDatabase = None,
        hash_chain_computer: HashChainComputer = None
    ):
        """Initialize log storage.
        
        Args:
            database: Database instance (creates new if None)
            hash_chain_computer: Hash chain computer (creates new if None)
        """
        self.database = database or AuditDatabase()
        self.hash_chain = hash_chain_computer or HashChainComputer()
        
        # Ensure database tables exist
        self.database.create_tables()
        
        logger.info("Initialized log storage")
    
    def store_log_entry(
        self,
        component: str,
        event_type: str,
        action_metadata: Dict[str, Any],
        zt_at: Optional[ZeroTrustAuthorizationToken] = None,
        dpop_fingerprint: str = "unknown"
    ) -> AuditLogEntry:
        """Store a new audit log entry with hash chain computation.
        
        This method:
        1. Generates a unique log ID
        2. Retrieves the previous entry's hash
        3. Computes the new entry's hash using the hash chain
        4. Stores the entry in the database
        5. Returns the complete audit log entry
        
        Args:
            component: Service that generated the log
            event_type: Type of event (e.g., "action_executed", "validation_failure")
            action_metadata: Action-specific data
            zt_at: Optional Zero-Trust Authorization Token
            dpop_fingerprint: DPoP key fingerprint
            
        Returns:
            Complete audit log entry with hash chain
            
        Requirements: 10.2
        """
        # Generate unique log ID
        log_id = f"log_{uuid.uuid4().hex[:16]}"
        
        # Get current timestamp
        timestamp = datetime.utcnow()
        
        # Get previous entry hash
        last_entry = self.database.get_last_entry()
        if last_entry:
            previous_hash = last_entry.hash
            logger.debug(f"Previous entry hash: {previous_hash[:16]}...")
        else:
            previous_hash = self.hash_chain.genesis_hash
            logger.info(f"First entry in chain, using genesis hash: {previous_hash}")
        
        # Convert ZT-AT to dict if provided
        zt_at_dict = None
        if zt_at:
            zt_at_dict = zt_at.model_dump(mode='json')
        
        # Compute hash for this entry
        entry_hash = self.hash_chain.compute_entry_hash(
            previous_hash=previous_hash,
            log_id=log_id,
            component=component,
            event_type=event_type,
            action_metadata=action_metadata,
            zt_at=zt_at_dict,
            dpop_fingerprint=dpop_fingerprint,
            timestamp=timestamp
        )
        
        logger.info(
            f"Storing audit log entry: {log_id} "
            f"(component={component}, event_type={event_type}, hash={entry_hash[:16]}...)"
        )
        
        # Store in database
        db_entry = self.database.insert_entry(
            log_id=log_id,
            component=component,
            event_type=event_type,
            action_metadata=action_metadata,
            zt_at=zt_at_dict,
            dpop_fingerprint=dpop_fingerprint,
            timestamp=timestamp,
            hash=entry_hash,
            previous_hash=previous_hash
        )
        
        # Create and return AuditLogEntry model
        audit_entry = AuditLogEntry(
            log_id=log_id,
            component=component,
            event_type=event_type,
            action_metadata=action_metadata,
            zt_at=zt_at,
            dpop_fingerprint=dpop_fingerprint,
            timestamp=timestamp,
            hash=entry_hash,
            previous_hash=previous_hash
        )
        
        logger.info(f"Successfully stored audit log entry: {log_id}")
        
        return audit_entry
    
    def get_all_entries(self) -> list[AuditLogEntry]:
        """Retrieve all audit log entries.
        
        Returns:
            List of all audit log entries in order
        """
        db_entries = self.database.get_all_entries()
        
        audit_entries = []
        for db_entry in db_entries:
            # Convert ZT-AT dict back to model if present
            zt_at = None
            if db_entry.zt_at:
                try:
                    zt_at = ZeroTrustAuthorizationToken(**db_entry.zt_at)
                except Exception as e:
                    logger.warning(f"Failed to parse ZT-AT for entry {db_entry.log_id}: {str(e)}")
            
            audit_entry = AuditLogEntry(
                log_id=db_entry.log_id,
                component=db_entry.component,
                event_type=db_entry.event_type,
                action_metadata=db_entry.action_metadata,
                zt_at=zt_at,
                dpop_fingerprint=db_entry.dpop_fingerprint,
                timestamp=db_entry.timestamp,
                hash=db_entry.hash,
                previous_hash=db_entry.previous_hash
            )
            audit_entries.append(audit_entry)
        
        return audit_entries
    
    def get_entries_by_plan_id(self, plan_id: str) -> list[AuditLogEntry]:
        """Retrieve audit log entries for a specific plan.
        
        Args:
            plan_id: Plan identifier
            
        Returns:
            List of audit log entries for the plan
        """
        db_entries = self.database.get_entries_by_plan_id(plan_id)
        
        audit_entries = []
        for db_entry in db_entries:
            # Convert ZT-AT dict back to model if present
            zt_at = None
            if db_entry.zt_at:
                try:
                    zt_at = ZeroTrustAuthorizationToken(**db_entry.zt_at)
                except Exception as e:
                    logger.warning(f"Failed to parse ZT-AT for entry {db_entry.log_id}: {str(e)}")
            
            audit_entry = AuditLogEntry(
                log_id=db_entry.log_id,
                component=db_entry.component,
                event_type=db_entry.event_type,
                action_metadata=db_entry.action_metadata,
                zt_at=zt_at,
                dpop_fingerprint=db_entry.dpop_fingerprint,
                timestamp=db_entry.timestamp,
                hash=db_entry.hash,
                previous_hash=db_entry.previous_hash
            )
            audit_entries.append(audit_entry)
        
        return audit_entries
    
    def get_entries_by_component(self, component: str) -> list[AuditLogEntry]:
        """Retrieve audit log entries for a specific component.
        
        Args:
            component: Component name
            
        Returns:
            List of audit log entries for the component
        """
        db_entries = self.database.get_entries_by_component(component)
        
        audit_entries = []
        for db_entry in db_entries:
            # Convert ZT-AT dict back to model if present
            zt_at = None
            if db_entry.zt_at:
                try:
                    zt_at = ZeroTrustAuthorizationToken(**db_entry.zt_at)
                except Exception as e:
                    logger.warning(f"Failed to parse ZT-AT for entry {db_entry.log_id}: {str(e)}")
            
            audit_entry = AuditLogEntry(
                log_id=db_entry.log_id,
                component=db_entry.component,
                event_type=db_entry.event_type,
                action_metadata=db_entry.action_metadata,
                zt_at=zt_at,
                dpop_fingerprint=db_entry.dpop_fingerprint,
                timestamp=db_entry.timestamp,
                hash=db_entry.hash,
                previous_hash=db_entry.previous_hash
            )
            audit_entries.append(audit_entry)
        
        return audit_entries
    
    def get_entry_count(self) -> int:
        """Get total number of audit log entries.
        
        Returns:
            Total entry count
        """
        return self.database.get_entry_count()
