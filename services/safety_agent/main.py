"""Safety Agent FastAPI application.

This service evaluates proposed actions against OPA policies and signs approvals.
It acts as the policy enforcement point in the authorization chain.

Requirements: 7.4
"""

from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel, Field
from typing import List, Dict, Any

from shared.schemas import IntentSignature, PolicyDecision
from shared.logging import setup_logging, JSONLogger
from shared.errors import setup_error_handlers, AuthorizationError
from .config import config
from .policy_evaluator import PolicyEvaluator
from .middleware import require_authentication


# Setup logging
setup_logging(level="INFO")
logger = JSONLogger(__name__)

# Global policy evaluator instance
policy_evaluator = PolicyEvaluator()


# Create FastAPI application
app = FastAPI(
    title="Safety Agent",
    description="Policy evaluation service for Zero-Trust Agentic Guardian",
    version="1.0.0"
)

# Set up error handlers
setup_error_handlers(app)


# Request/Response models
class TaskGraphItem(BaseModel):
    """Individual task in the execution graph."""
    task_id: str = Field(..., description="Unique task identifier")
    action: str = Field(..., description="Action to be performed")
    provider: str = Field(..., description="Target provider (github, slack, etc.)")
    dependencies: List[str] = Field(default_factory=list, description="Task dependencies")
    action_category: str = Field(default="standard", description="Action category")
    estimated_cost: float = Field(default=0.0, description="Estimated cost")


class RequesterIdentity(BaseModel):
    """Identity of the requesting service."""
    service: str = Field(..., description="Service name")
    certificate_subject: str = Field(..., description="Certificate subject")


class EvaluateRequest(BaseModel):
    """Request model for policy evaluation."""
    plan_id: str = Field(..., description="Unique plan identifier")
    task_graph: List[TaskGraphItem] = Field(..., description="Tasks to evaluate")
    intent_signature: IntentSignature = Field(..., description="Intent signature from Intent Engine")
    requester_identity: RequesterIdentity = Field(..., description="Identity of requester")
    context: Dict[str, Any] = Field(..., description="Evaluation context (user_id, role, etc.)")


class EvaluateResponse(BaseModel):
    """Response model for policy evaluation."""
    decision: str = Field(..., pattern="^(ALLOW|DENY)$", description="Policy decision")
    policy_approval: PolicyDecision = Field(..., description="Signed policy approval")


class HealthResponse(BaseModel):
    """Response model for health check."""
    status: str
    version: str
    opa_healthy: bool


@app.post("/evaluate", response_model=EvaluateResponse, status_code=status.HTTP_200_OK)
async def evaluate(
    request: EvaluateRequest,
    auth: dict = Depends(require_authentication)
) -> EvaluateResponse:
    """Evaluate proposed actions against OPA policies.
    
    This endpoint validates the requester identity, evaluates all tasks in the
    graph against OPA policies, and returns a signed policy approval or denial.
    
    Args:
        request: Evaluation request with task graph and context
        auth: Authentication information (injected by middleware)
        
    Returns:
        Policy decision with cryptographic signature
        
    Requirements: 7.4, 7.1, 7.2, 7.3, 7.5
    """
    try:
        logger.info(f"Received evaluation request for plan: {request.plan_id}")
        
        # Validate requester identity (Planner + Intent Engine)
        is_authorized = policy_evaluator.validate_requester_identity(
            certificate_identity=auth.get("certificate_identity", ""),
            jwt_claims=auth.get("jwt_claims", {})
        )
        
        if not is_authorized:
            logger.error("Unauthorized requester attempted policy evaluation")
            raise AuthorizationError(
                message="Only Planner and Intent Engine can request policy evaluation",
                error_code="unauthorized"
            )
        
        # Convert task graph items to dict format for evaluator
        task_graph_dicts = [task.model_dump() for task in request.task_graph]
        
        # Evaluate task graph against policies
        policy_decision = policy_evaluator.evaluate_task_graph(
            task_graph=task_graph_dicts,
            intent_signature=request.intent_signature,
            context=request.context
        )
        
        logger.info(
            f"Policy evaluation complete for plan {request.plan_id}: {policy_decision.decision}"
        )
        
        return EvaluateResponse(
            decision=policy_decision.decision,
            policy_approval=policy_decision
        )
        
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "validation_error", "message": str(e)}
        )
    except Exception as e:
        logger.error(f"Error evaluating policies: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "message": "Failed to evaluate policies"}
        )


@app.get("/health", response_model=HealthResponse, status_code=status.HTTP_200_OK)
async def health_check() -> HealthResponse:
    """Health check endpoint.
    
    Returns service status and OPA connectivity information.
    
    Returns:
        Health status response
        
    Requirements: 7.4
    """
    # Check OPA health
    opa_healthy = policy_evaluator.opa_client.health_check()
    
    return HealthResponse(
        status="healthy" if opa_healthy else "degraded",
        version="1.0.0",
        opa_healthy=opa_healthy
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
