"""Database module for audit log storage with hash chain.

This module implements PostgreSQL storage for audit log entries with
cryptographic hash chaining for tamper detection.

Requirements: 10.1
"""

from typing import Optional, List
from datetime import datetime
from sqlalchemy import create_engine, Column, String, DateTime, JSON, Integer, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from contextlib import contextmanager

from shared.logging import JSONLogger
from .config import config


logger = JSONLogger(__name__)

# SQLAlchemy base
Base = declarative_base()


class AuditLogEntryDB(Base):
    """Database model for audit log entries."""

    __tablename__ = "audit_log_entries"

    # Primary key - sequential ID for ordering
    id = Column(Integer, primary_key=True, autoincrement=True)

    # Log entry fields
    log_id = Column(String, unique=True, nullable=False, index=True)
    component = Column(String, nullable=False, index=True)
    event_type = Column(String, nullable=False, index=True)
    action_metadata = Column(JSON, nullable=False)
    zt_at = Column(JSON, nullable=True)  # Optional ZT-AT
    dpop_fingerprint = Column(String, nullable=False)
    timestamp = Column(DateTime, nullable=False, index=True)

    # Hash chain fields
    hash = Column(String, nullable=False, unique=True)
    previous_hash = Column(String, nullable=False)

    # Additional indexes for querying
    plan_id = Column(String, nullable=True, index=True)  # Extracted from ZT-AT for fast queries

    def __repr__(self):
        return f"<AuditLogEntry(id={self.id}, log_id={self.log_id}, component={self.component})>"


class AuditDatabase:
    """Database manager for audit log storage."""

    def __init__(self, database_url: str = None):
        """Initialize database connection.

        Args:
            database_url: PostgreSQL connection string
        """
        self.database_url = database_url or config.database_url

        # Configure engine based on database type
        if "sqlite" in self.database_url:
            # SQLite doesn't support pool_size and max_overflow
            self.engine = create_engine(
                self.database_url,
                pool_pre_ping=True  # Verify connections before using
            )
        else:
            # PostgreSQL and other databases
            self.engine = create_engine(
                self.database_url,
                pool_pre_ping=True,  # Verify connections before using
                pool_size=10,
                max_overflow=20
            )

        self.SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self.engine
        )

        logger.info(f"Initialized audit database connection")

    def create_tables(self):
        """Create database tables if they don't exist."""
        Base.metadata.create_all(bind=self.engine)
        logger.info("Created audit database tables")

    @contextmanager
    def get_session(self) -> Session:
        """Get a database session with automatic cleanup.

        Yields:
            Database session
        """
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Database session error: {str(e)}")
            raise
        finally:
            session.close()

    def insert_entry(
        self,
        log_id: str,
        component: str,
        event_type: str,
        action_metadata: dict,
        zt_at: Optional[dict],
        dpop_fingerprint: str,
        timestamp: datetime,
        hash: str,
        previous_hash: str
    ) -> AuditLogEntryDB:
        """Insert a new audit log entry (append-only).

        Args:
            log_id: Unique log entry identifier
            component: Service that generated the log
            event_type: Type of event
            action_metadata: Action-specific data
            zt_at: Optional ZT-AT dictionary
            dpop_fingerprint: DPoP key fingerprint
            timestamp: Event timestamp
            hash: Current entry hash
            previous_hash: Previous entry hash

        Returns:
            Created database entry

        Requirements: 10.1
        """
        with self.get_session() as session:
            # Extract plan_id from ZT-AT for indexing
            plan_id = None
            if zt_at and isinstance(zt_at, dict):
                plan_id = zt_at.get("plan_id")

            entry = AuditLogEntryDB(
                log_id=log_id,
                component=component,
                event_type=event_type,
                action_metadata=action_metadata,
                zt_at=zt_at,
                dpop_fingerprint=dpop_fingerprint,
                timestamp=timestamp,
                hash=hash,
                previous_hash=previous_hash,
                plan_id=plan_id
            )

            session.add(entry)
            session.flush()  # Get the ID

            logger.info(
                f"Inserted audit log entry: {log_id} "
                f"(component={component}, event_type={event_type})"
            )

            return entry

    def get_last_entry(self) -> Optional[AuditLogEntryDB]:
        """Get the most recent audit log entry.

        Returns:
            Last entry or None if no entries exist
        """
        with self.get_session() as session:
            entry = session.query(AuditLogEntryDB).order_by(
                AuditLogEntryDB.id.desc()
            ).first()

            if entry:
                # Detach from session
                session.expunge(entry)

            return entry

    def get_all_entries(self) -> List[AuditLogEntryDB]:
        """Get all audit log entries in order.

        Returns:
            List of all entries ordered by ID
        """
        with self.get_session() as session:
            entries = session.query(AuditLogEntryDB).order_by(
                AuditLogEntryDB.id.asc()
            ).all()

            # Detach from session
            for entry in entries:
                session.expunge(entry)

            return entries

    def get_entries_by_plan_id(self, plan_id: str) -> List[AuditLogEntryDB]:
        """Get all audit log entries for a specific plan.

        Args:
            plan_id: Plan identifier

        Returns:
            List of entries for the plan
        """
        with self.get_session() as session:
            entries = session.query(AuditLogEntryDB).filter(
                AuditLogEntryDB.plan_id == plan_id
            ).order_by(
                AuditLogEntryDB.id.asc()
            ).all()

            # Detach from session
            for entry in entries:
                session.expunge(entry)

            return entries

    def get_entries_by_component(self, component: str) -> List[AuditLogEntryDB]:
        """Get all audit log entries for a specific component.

        Args:
            component: Component name

        Returns:
            List of entries for the component
        """
        with self.get_session() as session:
            entries = session.query(AuditLogEntryDB).filter(
                AuditLogEntryDB.component == component
            ).order_by(
                AuditLogEntryDB.id.asc()
            ).all()

            # Detach from session
            for entry in entries:
                session.expunge(entry)

            return entries

    def get_entry_count(self) -> int:
        """Get total number of audit log entries.

        Returns:
            Total entry count
        """
        with self.get_session() as session:
            count = session.query(AuditLogEntryDB).count()
            return count

    def health_check(self) -> bool:
        """Check database connectivity.

        Returns:
            True if database is accessible
        """
        try:
            with self.get_session() as session:
                session.execute(text("SELECT 1"))
            return True
        except Exception as e:
            logger.error(f"Database health check failed: {str(e)}")
            return False
