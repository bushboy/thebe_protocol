"""Planner Service FastAPI application.

This service accepts user goals and generates task execution plans with
intent signatures from the Intent Engine.

Requirements: 5.1, 5.6
"""

from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
import time
import uuid

from shared.schemas import IntentSignature, PolicyDecision
from shared.logging import setup_logging, JSONLogger
from shared.errors import setup_error_handlers, ServiceUnavailableError
from .config import config
from .task_graph_generator import TaskGraphGenerator
from .intent_engine_client import IntentEngineClient
from .middleware import require_authentication
from .orchestrator.graph import get_compiled_graph


# Setup logging
setup_logging(level="INFO")
logger = JSONLogger(__name__)

# Global instances
task_graph_generator = TaskGraphGenerator()
intent_engine_client = IntentEngineClient()


# Create FastAPI application
app = FastAPI(
    title="Planner Service",
    description="Task planning service for Zero-Trust Agentic Guardian",
    version="1.0.0"
)

# Set up error handlers
setup_error_handlers(app)


# Request/Response models
class PlanRequest(BaseModel):
    """Request model for creating a plan."""
    user_goal: str = Field(..., min_length=1, description="User's stated goal")
    user_id: str = Field(..., description="User identifier")
    context: Dict[str, Any] = Field(
        default_factory=dict,
        description="Context including role, allowed_providers, etc."
    )


class TaskGraphItem(BaseModel):
    """Individual task in the execution graph."""
    task_id: str = Field(..., description="Unique task identifier")
    action: str = Field(..., description="Action to be performed")
    provider: str = Field(..., description="Target provider (github, slack, etc.)")
    dependencies: List[str] = Field(default_factory=list, description="Task dependencies")


class PlanResponse(BaseModel):
    """Response model for plan creation."""
    plan_id: str = Field(..., description="Unique plan identifier")
    task_graph: List[TaskGraphItem] = Field(..., description="Task execution graph")
    intent_signature: IntentSignature = Field(..., description="Intent signature from Intent Engine")


class FastPlanResponse(BaseModel):
    """Response model for /plan-fast – includes policy decision and pipeline latency."""
    plan_id: str = Field(..., description="Unique plan identifier")
    task_graph: List[TaskGraphItem] = Field(..., description="Task execution graph")
    intent_signature: IntentSignature = Field(..., description="Intent signature from Intent Engine")
    policy_decision: PolicyDecision = Field(..., description="Signed policy approval from Safety Agent")
    blocked: bool = Field(..., description="True when the safety agent blocked execution")
    block_reason: str = Field(default="", description="Human-readable block reason (empty when allowed)")
    pipeline_latency_ms: float = Field(..., description="End-to-end in-process pipeline latency in milliseconds")


class HealthResponse(BaseModel):
    """Response model for health check."""
    status: str
    version: str


@app.post("/plan", response_model=PlanResponse, status_code=status.HTTP_200_OK)
async def create_plan(
    request: PlanRequest,
    auth: dict = Depends(require_authentication)
) -> PlanResponse:
    """Create a task execution plan from user goal.

    This endpoint:
    1. Validates authentication (JWT + DPoP + mTLS)
    2. Generates a task graph from the user goal
    3. Requests an intent signature from the Intent Engine
    4. Returns the plan with intent signature

    Args:
        request: Plan request with user goal and context
        auth: Authentication information (injected by middleware)

    Returns:
        Plan response with task graph and intent signature

    Requirements: 5.1, 5.3, 5.4, 5.5
    """
    try:
        logger.info(f"Received plan request from user: {request.user_id}")
        logger.info(f"User goal: {request.user_goal[:100]}...")

        # Generate unique plan ID
        plan_id = str(uuid.uuid4())

        # Generate task graph
        task_graph = task_graph_generator.generate_task_graph(
            user_goal=request.user_goal,
            context=request.context
        )

        logger.info(f"Generated task graph with {len(task_graph)} tasks for plan {plan_id}")

        # Extract allowed actions from task graph
        allowed_actions = [
            f"{task['provider']}:{task['action']}"
            for task in task_graph
        ]

        # Propagate caller access token to downstream services.
        access_token = auth.get("access_token") or auth.get("jwt_claims", {}).get("access_token")
        if not access_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "error": "invalid_token",
                    "message": "Missing access token in authentication context"
                }
            )

        # Request intent signature from Intent Engine
        try:
            intent_signature = await intent_engine_client.sign_intent(
                user_goal=request.user_goal,
                allowed_actions=allowed_actions,
                access_token=access_token
            )
        except Exception as e:
            logger.error(f"Failed to obtain intent signature: {str(e)}", exc_info=True)
            raise ServiceUnavailableError(
                service_name="Intent Engine",
                details={"error": str(e)}
            )

        # Convert task graph to response format
        task_graph_items = [TaskGraphItem(**task) for task in task_graph]

        logger.info(f"Plan {plan_id} created successfully with intent signature")

        return PlanResponse(
            plan_id=plan_id,
            task_graph=task_graph_items,
            intent_signature=intent_signature
        )

    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except ServiceUnavailableError as e:
        # Re-raise service unavailable errors as Bad Gateway (502)
        # 502 is more appropriate when a downstream service is unavailable
        logger.error(f"Service unavailable: {str(e)}")
        raise HTTPException(
            status_code=502,
            detail={"error": "bad_gateway", "message": str(e)}
        )
    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "validation_error", "message": str(e)}
        )
    except Exception as e:
        logger.error(f"Error creating plan: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "message": "Failed to create plan"}
        )


@app.post("/plan-fast", response_model=FastPlanResponse, status_code=status.HTTP_200_OK)
async def create_plan_fast(
    request: PlanRequest,
    auth: dict = Depends(require_authentication)
) -> FastPlanResponse:
    """Create a task execution plan using the in-process LangGraph orchestrator.

    This endpoint replaces three sequential HTTP service-to-service calls
    (Planner → Intent Engine → Safety Agent) with a single in-process
    LangGraph pipeline, eliminating network round-trips for hardware-latency-
    only execution.

    The endpoint:
    1. Validates authentication (JWT + DPoP + mTLS)
    2. Invokes the compiled LangGraph with three nodes:
       - ``planner``      – generates task graph (TaskGraphGenerator, in-process)
       - ``intent_engine``– signs intent (IntentSigner, in-process)
       - ``safety_agent`` – evaluates OPA policies (PolicyEvaluator, one OPA hop)
    3. Returns plan, intent signature, policy decision, and pipeline latency

    Args:
        request: Plan request with user goal and context
        auth: Authentication information (injected by middleware)

    Returns:
        FastPlanResponse with full pipeline result and measured latency

    Requirements: Gap 1 – LangGraph hooks for zero-latency interception.
    """
    try:
        logger.info(f"[plan-fast] Received request from user: {request.user_id}")
        logger.info(f"[plan-fast] Goal: {request.user_goal[:100]}…")

        plan_id = str(uuid.uuid4())

        # Build initial pipeline state
        initial_state = {
            "user_goal": request.user_goal,
            "user_id": request.user_id,
            "context": request.context,
            "plan_id": plan_id,
            "blocked": False,
            "block_reason": "",
            "error": None,
        }

        # Invoke the compiled LangGraph pipeline and measure wall-clock latency
        t0 = time.perf_counter()
        final_state = await get_compiled_graph().ainvoke(initial_state)
        pipeline_latency_ms = (time.perf_counter() - t0) * 1000

        logger.info(
            f"[plan-fast] Pipeline complete in {pipeline_latency_ms:.1f} ms "
            f"| plan_id={plan_id} "
            f"| blocked={final_state.get('blocked', False)}"
        )

        # Surface unexpected node errors
        if final_state.get("error"):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={"error": "pipeline_error", "message": final_state["error"]},
            )

        task_graph = final_state.get("task_graph", [])
        intent_signature: Optional[IntentSignature] = final_state.get("intent_signature")
        policy_decision: Optional[PolicyDecision] = final_state.get("policy_decision")
        blocked: bool = final_state.get("blocked", False)
        block_reason: str = final_state.get("block_reason", "")

        # If the planner or intent engine blocked before producing a signature /
        # decision we still need valid objects for the response model.
        if intent_signature is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "error": "pipeline_blocked",
                    "message": block_reason or "Pipeline blocked before intent signature was produced",
                },
            )

        if policy_decision is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "error": "pipeline_blocked",
                    "message": block_reason or "Pipeline blocked before policy decision was produced",
                },
            )

        task_graph_items = [TaskGraphItem(**task) for task in task_graph]

        return FastPlanResponse(
            plan_id=plan_id,
            task_graph=task_graph_items,
            intent_signature=intent_signature,
            policy_decision=policy_decision,
            blocked=blocked,
            block_reason=block_reason,
            pipeline_latency_ms=round(pipeline_latency_ms, 2),
        )

    except HTTPException:
        raise
    except ValueError as exc:
        logger.error(f"[plan-fast] Validation error: {exc}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "validation_error", "message": str(exc)},
        )
    except Exception as exc:
        logger.error(f"[plan-fast] Unexpected error: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "message": "Failed to execute planning pipeline"},
        )


@app.get("/health", response_model=HealthResponse, status_code=status.HTTP_200_OK)
async def health_check() -> HealthResponse:
    """Health check endpoint.

    Returns service status and version information.

    Returns:
        Health status response

    Requirements: 5.6
    """
    return HealthResponse(
        status="healthy",
        version="1.0.0"
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
