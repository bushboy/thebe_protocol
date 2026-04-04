"""Audit Service FastAPI application.

This service maintains cryptographically chained, append-only audit logs
for the Zero-Trust Agentic Guardian Architecture. It provides endpoints
for logging events, verifying chain integrity, and querying logs.

Requirements: 10.4
"""

from fastapi import FastAPI, HTTPException, status, Query
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional, List
from datetime import datetime

from shared.schemas import AuditLogEntry, ZeroTrustAuthorizationToken
from shared.logging import setup_logging, JSONLogger
from shared.errors import setup_error_handlers, AuditIntegrityError
from .config import config
from .log_storage import LogStorage
from .chain_verifier import ChainVerifier


# Setup logging
setup_logging(level="INFO")
logger = JSONLogger(__name__)

# Global instances
log_storage = LogStorage()
chain_verifier = ChainVerifier(log_storage=log_storage)


# Create FastAPI application
app = FastAPI(
    title="Audit Service",
    description="Cryptographically chained audit logging for Zero-Trust Agentic Guardian",
    version="1.0.0"
)

# Set up error handlers
setup_error_handlers(app)


# Request/Response models
class LogRequest(BaseModel):
    """Request model for logging an audit entry."""
    component: str = Field(..., description="Service that generated the log")
    event_type: str = Field(..., description="Type of event")
    action_metadata: Dict[str, Any] = Field(..., description="Action-specific data")
    zt_at: Optional[ZeroTrustAuthorizationToken] = Field(None, description="Associated ZT-AT")
    dpop_fingerprint: str = Field(default="unknown", description="DPoP key fingerprint")


class LogResponse(BaseModel):
    """Response model for log creation."""
    log_id: str = Field(..., description="Unique log entry ID")
    hash: str = Field(..., description="Current entry hash")
    previous_hash: str = Field(..., description="Previous entry hash")
    timestamp: datetime = Field(..., description="Entry timestamp")


class VerifyResponse(BaseModel):
    """Response model for chain verification."""
    chain_valid: bool = Field(..., description="Whether the chain is valid")
    total_entries: int = Field(..., description="Total number of entries")
    first_hash: Optional[str] = Field(None, description="Hash of first entry")
    last_hash: Optional[str] = Field(None, description="Hash of last entry")
    broken_index: Optional[int] = Field(None, description="Index where chain is broken")
    tampered_indices: Optional[List[int]] = Field(None, description="Indices of tampered entries")


class LogsResponse(BaseModel):
    """Response model for log queries."""
    logs: List[AuditLogEntry] = Field(..., description="List of audit log entries")
    total_count: int = Field(..., description="Total number of matching entries")


class HealthResponse(BaseModel):
    """Response model for health check."""
    status: str
    version: str
    database_healthy: bool
    total_entries: int


@app.post("/log", response_model=LogResponse, status_code=status.HTTP_201_CREATED)
async def log_entry(request: LogRequest) -> LogResponse:
    """Log a new audit entry with hash chain computation.
    
    This endpoint:
    1. Receives audit log data from services
    2. Computes hash chain link
    3. Stores entry in database
    4. Returns log ID and hash information
    
    Args:
        request: Log request with event data
        
    Returns:
        Log response with ID and hash information
        
    Requirements: 10.4, 10.1, 10.2, 10.3
    """
    try:
        logger.info(
            f"Received log request from component: {request.component}, "
            f"event_type: {request.event_type}"
        )
        
        # Store log entry with hash chain
        audit_entry = log_storage.store_log_entry(
            component=request.component,
            event_type=request.event_type,
            action_metadata=request.action_metadata,
            zt_at=request.zt_at,
            dpop_fingerprint=request.dpop_fingerprint
        )
        
        logger.info(
            f"Successfully logged entry: {audit_entry.log_id} "
            f"(hash: {audit_entry.hash[:16]}...)"
        )
        
        return LogResponse(
            log_id=audit_entry.log_id,
            hash=audit_entry.hash,
            previous_hash=audit_entry.previous_hash,
            timestamp=audit_entry.timestamp
        )
        
    except Exception as e:
        logger.error(f"Error logging entry: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "internal_error",
                "message": "Failed to log audit entry"
            }
        )


@app.get("/verify", response_model=VerifyResponse, status_code=status.HTTP_200_OK)
async def verify_chain() -> VerifyResponse:
    """Verify the integrity of the complete audit log chain.
    
    This endpoint:
    1. Retrieves all audit log entries
    2. Verifies hash chain integrity
    3. Detects any tampering
    4. Returns verification results
    
    Returns:
        Verification response with chain status
        
    Requirements: 10.4, 10.5
    """
    try:
        logger.info("Received chain verification request")
        
        # Verify complete chain
        result = chain_verifier.verify_complete_chain()
        
        if result.is_valid:
            logger.info(
                f"Chain verification successful: {result.total_entries} entries"
            )
        else:
            logger.error(
                f"Chain verification failed: broken at index {result.broken_index}"
            )
        
        return VerifyResponse(
            chain_valid=result.is_valid,
            total_entries=result.total_entries,
            first_hash=result.first_hash,
            last_hash=result.last_hash,
            broken_index=result.broken_index,
            tampered_indices=result.tampered_indices
        )
        
    except Exception as e:
        logger.error(f"Error verifying chain: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "internal_error",
                "message": "Failed to verify audit chain"
            }
        )


@app.get("/logs", response_model=LogsResponse, status_code=status.HTTP_200_OK)
async def get_logs(
    plan_id: Optional[str] = Query(None, description="Filter by plan ID"),
    component: Optional[str] = Query(None, description="Filter by component"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of entries to return")
) -> LogsResponse:
    """Query audit log entries with optional filters.
    
    This endpoint supports filtering by:
    - plan_id: Get all entries for a specific plan
    - component: Get all entries from a specific service
    
    Args:
        plan_id: Optional plan ID filter
        component: Optional component filter
        limit: Maximum number of entries to return
        
    Returns:
        List of matching audit log entries
        
    Requirements: 10.4
    """
    try:
        logger.info(
            f"Received logs query request: plan_id={plan_id}, "
            f"component={component}, limit={limit}"
        )
        
        # Apply filters
        if plan_id:
            entries = log_storage.get_entries_by_plan_id(plan_id)
            logger.info(f"Found {len(entries)} entries for plan_id: {plan_id}")
        elif component:
            entries = log_storage.get_entries_by_component(component)
            logger.info(f"Found {len(entries)} entries for component: {component}")
        else:
            entries = log_storage.get_all_entries()
            logger.info(f"Retrieved all {len(entries)} entries")
        
        # Apply limit
        total_count = len(entries)
        entries = entries[:limit]
        
        return LogsResponse(
            logs=entries,
            total_count=total_count
        )
        
    except Exception as e:
        logger.error(f"Error querying logs: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "internal_error",
                "message": "Failed to query audit logs"
            }
        )


@app.get("/health", response_model=HealthResponse, status_code=status.HTTP_200_OK)
async def health_check() -> HealthResponse:
    """Health check endpoint.
    
    Returns service status, database connectivity, and entry count.
    
    Returns:
        Health status response
        
    Requirements: 10.4
    """
    # Check database health
    database_healthy = log_storage.database.health_check()
    
    # Get entry count
    try:
        total_entries = log_storage.get_entry_count()
    except Exception:
        total_entries = -1
    
    return HealthResponse(
        status="healthy" if database_healthy else "degraded",
        version="1.0.0",
        database_healthy=database_healthy,
        total_entries=total_entries
    )


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "main:app",
        host=config.host,
        port=config.port,
        reload=True,
        log_config=None  # Use our custom logging
    )
