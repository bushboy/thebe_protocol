"""Executor Agent FastAPI application.

This service executes individual actions against providers using
Zero-Trust Authorization Tokens (ZT-AT) and provider-specific tokens.
It implements replay prevention and comprehensive audit logging.

Requirements: 9.5
"""

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional
from datetime import datetime
import uuid

from shared.schemas import ZeroTrustAuthorizationToken
from shared.logging import setup_logging, JSONLogger
from shared.action_params_hash import compute_action_params_hash
from shared.pendo import track_event
from shared.errors import (
    setup_error_handlers,
    TokenExpiredError,
    InvalidSignatureError,
    ZTATReplayError,
    ProviderAPIError
)
from .config import config
from .ztat_validator import ZTATValidator, ZTATValidationError
from .replay_prevention import ReplayPrevention, ReplayPreventionError
from .provider_executor import ProviderExecutor, ProviderExecutionError
from .audit_logger import AuditLogger, AuditLoggerError


# Setup logging
setup_logging(level="INFO")
logger = JSONLogger(__name__)

# Global instances
ztat_validator = ZTATValidator()
replay_prevention = ReplayPrevention(
    redis_host=config.redis_host,
    redis_port=config.redis_port,
    redis_db=config.redis_db,
    redis_password=config.redis_password if config.redis_password else None
)
provider_executor = ProviderExecutor()
audit_logger = AuditLogger()


# Create FastAPI application
app = FastAPI(
    title="Executor Agent",
    description="Action execution service for Agentic Guardian",
    version="1.0.0"
)

# Set up error handlers
setup_error_handlers(app)


# Request/Response models
class ProviderToken(BaseModel):
    """Provider-specific access token."""
    access_token: str = Field(..., description="Provider access token")
    token_type: str = Field(default="Bearer", description="Token type")


class ExecuteRequest(BaseModel):
    """Request model for action execution."""
    zt_at: ZeroTrustAuthorizationToken = Field(..., description="Zero-Trust Authorization Token")
    provider_token: ProviderToken = Field(..., description="Provider-specific token")
    action_params: Dict[str, Any] = Field(default_factory=dict, description="Action-specific parameters")


class ExecutionResult(BaseModel):
    """Result of action execution."""
    execution_id: str = Field(..., description="Unique execution identifier")
    status: str = Field(..., description="Execution status (success or failure)")
    result: Optional[Dict[str, Any]] = Field(None, description="Action result data")
    error: Optional[str] = Field(None, description="Error message if failed")
    timestamp: datetime = Field(..., description="Execution timestamp")


class HealthResponse(BaseModel):
    """Response model for health check."""
    status: str
    version: str
    redis_healthy: bool


@app.post("/execute", response_model=ExecutionResult, status_code=status.HTTP_200_OK)
async def execute(request: ExecuteRequest) -> ExecutionResult:
    """Execute an action using ZT-AT and provider token.

    This endpoint:
    1. Validates ZT-AT structure and signatures
    2. Checks ZT-AT expiration
    3. Prevents replay attacks using Redis
    4. Extracts provider and action from ZT-AT
    5. Generates DPoP proof for provider API call
    6. Executes action using provider SDK
    7. Logs execution to Audit Service
    8. Returns execution result

    Args:
        request: Execution request with ZT-AT and provider token

    Returns:
        Execution result with status and data

    Requirements: 9.5, 9.1, 9.2, 9.3, 9.4, 9.6, 10.2
    """
    execution_id = str(uuid.uuid4())
    logger.info(
        f"Received execution request (ID: {execution_id}) for "
        f"plan: {request.zt_at.plan_id}, task: {request.zt_at.task_id}"
    )

    try:
        # Step 1: Validate ZT-AT structure and signatures
        try:
            ztat_validator.validate_ztat(request.zt_at)
        except ZTATValidationError as e:
            logger.error(f"ZT-AT validation failed: {str(e)}")

            # Log validation failure to Audit Service
            await audit_logger.log_validation_failure(
                zt_at=request.zt_at,
                failure_reason=str(e),
                failure_type="ztat_validation_error",
                reasoning_trace={
                    "decision": "DENY",
                    "component": "executor",
                    "stage": "validation",
                    "attempted_action": request.zt_at.action,
                    "provider": request.zt_at.provider,
                    "plan_id": request.zt_at.plan_id,
                    "task_id": request.zt_at.task_id,
                    "failure_type": "ztat_validation_error",
                    "reason": str(e),
                    "intent_analysis": {
                        "semantic_match_score": request.zt_at.policy_approval.semantic_similarity_score,
                        "semantic_match_threshold": request.zt_at.policy_approval.semantic_match_threshold,
                    },
                },
            )

            await track_event(
                "ztat_validation_failed",
                properties={
                    "plan_id": request.zt_at.plan_id,
                    "task_id": request.zt_at.task_id,
                    "action": request.zt_at.action,
                    "provider": request.zt_at.provider,
                    "failure_reason": str(e)[:200],
                    "failure_type": "ztat_validation_error",
                    "ztat_expires_at": str(request.zt_at.expires_at),
                },
            )

            # Determine appropriate error response
            if "expired" in str(e).lower():
                raise TokenExpiredError(
                    message=f"ZT-AT expired: {str(e)}",
                    details={"zt_at_expires_at": str(request.zt_at.expires_at)}
                )
            else:
                raise InvalidSignatureError(
                    message=f"ZT-AT validation failed: {str(e)}"
                )

        # Step 2: Check for replay attacks
        try:
            replay_prevention.check_and_mark_used(request.zt_at)
        except ReplayPreventionError as e:
            logger.error(f"Replay attack detected: {str(e)}")

            # Log replay attempt to Audit Service
            await audit_logger.log_validation_failure(
                zt_at=request.zt_at,
                failure_reason=str(e),
                failure_type="replay_detected",
                reasoning_trace={
                    "decision": "DENY",
                    "component": "executor",
                    "stage": "replay_prevention",
                    "attempted_action": request.zt_at.action,
                    "provider": request.zt_at.provider,
                    "plan_id": request.zt_at.plan_id,
                    "task_id": request.zt_at.task_id,
                    "failure_type": "replay_detected",
                    "reason": str(e),
                    "ztat_nonce": request.zt_at.nonce,
                },
            )

            await track_event(
                "replay_attack_detected",
                properties={
                    "plan_id": request.zt_at.plan_id,
                    "task_id": request.zt_at.task_id,
                    "action": request.zt_at.action,
                    "provider": request.zt_at.provider,
                    "ztat_nonce": request.zt_at.nonce[:32] if request.zt_at.nonce else "",
                },
            )

            raise ZTATReplayError(
                message="ZT-AT has already been used for execution",
                details={"zt_at_nonce": request.zt_at.nonce}
            )

        # Step 3: Verify action parameters are exactly what was authorized
        expected_params_hash = request.zt_at.action_params_hash
        if not expected_params_hash:
            logger.error("ZT-AT missing action_params_hash; refusing execution")
            await audit_logger.log_validation_failure(
                zt_at=request.zt_at,
                failure_reason="ZT-AT missing action parameter binding",
                failure_type="missing_action_params_hash",
                reasoning_trace={
                    "decision": "DENY",
                    "component": "executor",
                    "stage": "parameter_binding",
                    "attempted_action": request.zt_at.action,
                    "provider": request.zt_at.provider,
                    "plan_id": request.zt_at.plan_id,
                    "task_id": request.zt_at.task_id,
                    "failure_type": "missing_action_params_hash",
                    "reason": "ZT-AT missing action parameter binding",
                },
            )
            raise InvalidSignatureError(
                message="ZT-AT missing action parameter binding",
                details={"reason": "missing_action_params_hash"}
            )

        received_params_hash = compute_action_params_hash(request.action_params)
        if received_params_hash != expected_params_hash:
            logger.error(
                "Action parameter tampering detected for execution %s: expected=%s received=%s",
                execution_id,
                expected_params_hash,
                received_params_hash
            )
            await audit_logger.log_validation_failure(
                zt_at=request.zt_at,
                failure_reason="Action parameters do not match authorized token",
                failure_type="action_params_mismatch",
                reasoning_trace={
                    "decision": "DENY",
                    "component": "executor",
                    "stage": "parameter_binding",
                    "attempted_action": request.zt_at.action,
                    "provider": request.zt_at.provider,
                    "plan_id": request.zt_at.plan_id,
                    "task_id": request.zt_at.task_id,
                    "failure_type": "action_params_mismatch",
                    "reason": "Action parameters do not match authorized token",
                    "expected_action_params_hash": expected_params_hash,
                    "received_action_params_hash": received_params_hash,
                },
            )

            await track_event(
                "action_params_tampering_detected",
                properties={
                    "execution_id": execution_id,
                    "plan_id": request.zt_at.plan_id,
                    "task_id": request.zt_at.task_id,
                    "action": request.zt_at.action,
                    "provider": request.zt_at.provider,
                    "expected_params_hash": expected_params_hash[:32],
                    "received_params_hash": received_params_hash[:32],
                },
            )

            raise InvalidSignatureError(
                message="Action parameters do not match authorized token",
                details={
                    "expected_action_params_hash": expected_params_hash,
                    "received_action_params_hash": received_params_hash
                }
            )

        # Step 4: Execute action against provider
        try:
            result = await provider_executor.execute_action(
                zt_at=request.zt_at,
                provider_token=request.provider_token.access_token,
                action_params=request.action_params
            )

            execution_status = "success"
            error_message = None

            logger.info(
                f"Action executed successfully (ID: {execution_id}): "
                f"{request.zt_at.provider}:{request.zt_at.action}"
            )

            await track_event(
                "action_executed_successfully",
                properties={
                    "execution_id": execution_id,
                    "plan_id": request.zt_at.plan_id,
                    "task_id": request.zt_at.task_id,
                    "action": request.zt_at.action,
                    "provider": request.zt_at.provider,
                    "execution_status": execution_status,
                },
            )

        except ProviderExecutionError as e:
            logger.error(f"Provider execution failed: {str(e)}")

            execution_status = "failure"
            error_message = str(e)
            result = None

            # Log execution failure to Audit Service
            await audit_logger.log_execution(
                zt_at=request.zt_at,
                execution_id=execution_id,
                status=execution_status,
                result=result,
                error=error_message
            )

            await track_event(
                "action_execution_failed",
                properties={
                    "execution_id": execution_id,
                    "plan_id": request.zt_at.plan_id,
                    "task_id": request.zt_at.task_id,
                    "action": request.zt_at.action,
                    "provider": request.zt_at.provider,
                    "error_message": error_message[:200],
                },
            )

            raise ProviderAPIError(
                provider=request.zt_at.provider,
                error_message=str(e),
                details={"action": request.zt_at.action}
            )

        # Step 5: Log successful execution to Audit Service
        try:
            await audit_logger.log_execution(
                zt_at=request.zt_at,
                execution_id=execution_id,
                status=execution_status,
                result=result,
                error=error_message
            )
        except AuditLoggerError as e:
            # Log audit failure but don't fail the execution
            logger.error(f"Failed to log to Audit Service: {str(e)}")

        # Step 6: Return execution result
        return ExecutionResult(
            execution_id=execution_id,
            status=execution_status,
            result=result,
            error=error_message,
            timestamp=datetime.utcnow()
        )

    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        logger.error(f"Unexpected error during execution: {str(e)}", exc_info=True)

        # Log internal error to Audit Service
        try:
            await audit_logger.log_validation_failure(
                zt_at=request.zt_at,
                failure_reason=str(e),
                failure_type="internal_error"
            )
        except Exception:
            pass

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "internal_error",
                "message": "An unexpected error occurred during execution"
            }
        )


@app.get("/health", response_model=HealthResponse, status_code=status.HTTP_200_OK)
async def health_check() -> HealthResponse:
    """Health check endpoint.

    Returns service status and Redis connectivity information.

    Returns:
        Health status response

    Requirements: 9.5
    """
    # Check Redis health
    redis_healthy = replay_prevention.health_check()

    return HealthResponse(
        status="healthy" if redis_healthy else "degraded",
        version="1.0.0",
        redis_healthy=redis_healthy
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
