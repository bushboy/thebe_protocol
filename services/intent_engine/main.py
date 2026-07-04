"""Intent Engine FastAPI application.

This service generates and verifies intent signatures using semantic embeddings
to detect prompt injection and intent drift.

Requirements: 6.4, 6.5
"""

from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel, Field
from typing import List
from contextlib import asynccontextmanager

from shared.schemas import IntentSignature
from shared.logging import setup_logging, JSONLogger
from shared.errors import setup_error_handlers
from shared.pendo import track_event
from .config import config
from .intent_signer import IntentSigner
from .middleware import require_authentication


# Setup logging
setup_logging(level="INFO")
logger = JSONLogger(__name__)

# Global intent signer instance
intent_signer = IntentSigner()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup and shutdown events."""
    # Startup: Load the sentence-transformer model
    logger.info(f"Loading sentence-transformer model: {config.model_name}")
    intent_signer.load_model()
    logger.info("Model loaded successfully")

    yield

    # Shutdown
    logger.info("Shutting down Intent Engine service")


# Create FastAPI application
app = FastAPI(
    title="Intent Engine",
    description="Semantic intent verification service for Zero-Trust Agentic Guardian",
    version="1.0.0",
    lifespan=lifespan
)

# Set up error handlers
setup_error_handlers(app)


# Request/Response models
class SignIntentRequest(BaseModel):
    """Request model for signing intent."""
    user_goal: str = Field(..., min_length=1, description="User's stated goal")
    allowed_actions: List[str] = Field(..., min_length=1, description="List of permitted action types")


class SignIntentResponse(BaseModel):
    """Response model for signed intent."""
    intent_signature: IntentSignature


class VerifyIntentRequest(BaseModel):
    """Request model for verifying intent."""
    intent_signature: IntentSignature
    proposed_action: str = Field(..., min_length=1, description="Proposed action to verify")


class VerifyIntentResponse(BaseModel):
    """Response model for intent verification."""
    aligned: bool = Field(..., description="Whether action aligns with intent")
    similarity_score: float = Field(..., description="Cosine similarity score")
    threshold: float = Field(..., description="Configured similarity threshold")


class HealthResponse(BaseModel):
    """Response model for health check."""
    status: str
    version: str
    model: str


@app.post("/sign-intent", response_model=SignIntentResponse, status_code=status.HTTP_200_OK)
async def sign_intent(
    request: SignIntentRequest,
    auth: dict = Depends(require_authentication)
) -> SignIntentResponse:
    """Generate an intent signature for a user goal.

    This endpoint creates a cryptographic signature containing semantic embeddings
    and allowed actions for the user's stated goal.

    Args:
        request: Sign intent request with user goal and allowed actions
        auth: Authentication information (injected by middleware)

    Returns:
        Intent signature with embedding, hash, and cryptographic signature

    Requirements: 6.4, 6.1, 6.2
    """
    try:
        logger.info(f"Signing intent for goal: {request.user_goal[:50]}...")

        intent_signature = intent_signer.sign_intent(
            user_goal=request.user_goal,
            allowed_actions=request.allowed_actions
        )

        logger.info(f"Intent signature generated with hash: {intent_signature.hash}")

        await track_event(
            "intent_signature_generated",
            properties={
                "intent_hash": intent_signature.hash[:32],
                "allowed_actions_count": len(request.allowed_actions),
                "semantic_similarity_score": intent_signature.semantic_similarity_score,
                "semantic_match_threshold": intent_signature.semantic_match_threshold,
                "goal_length": len(request.user_goal),
            },
        )

        return SignIntentResponse(intent_signature=intent_signature)

    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "validation_error", "message": str(e)}
        )
    except Exception as e:
        logger.error(f"Error signing intent: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "message": "Failed to sign intent"}
        )


@app.post("/verify-intent", response_model=VerifyIntentResponse, status_code=status.HTTP_200_OK)
async def verify_intent(
    request: VerifyIntentRequest,
    auth: dict = Depends(require_authentication)
) -> VerifyIntentResponse:
    """Verify if a proposed action aligns with the original intent.

    This endpoint computes semantic similarity between the original intent
    and a proposed action to detect prompt injection or intent drift.

    Args:
        request: Verify intent request with intent signature and proposed action
        auth: Authentication information (injected by middleware)

    Returns:
        Alignment decision with similarity score

    Requirements: 6.5, 6.3
    """
    try:
        logger.info(f"Verifying intent for action: {request.proposed_action[:50]}...")

        result = intent_signer.verify_intent(
            intent_signature=request.intent_signature,
            proposed_action=request.proposed_action
        )

        logger.info(
            f"Intent verification complete: aligned={result['aligned']}, "
            f"similarity={result['similarity_score']:.3f}"
        )

        await track_event(
            "intent_verification_completed",
            properties={
                "aligned": result["aligned"],
                "similarity_score": result["similarity_score"],
                "threshold": result["threshold"],
                "proposed_action": request.proposed_action[:100],
            },
        )

        return VerifyIntentResponse(**result)

    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "validation_error", "message": str(e)}
        )
    except Exception as e:
        logger.error(f"Error verifying intent: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "message": "Failed to verify intent"}
        )


@app.get("/health", response_model=HealthResponse, status_code=status.HTTP_200_OK)
async def health_check() -> HealthResponse:
    """Health check endpoint.

    Returns service status and configuration information.

    Returns:
        Health status response

    Requirements: 6.4
    """
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        model=config.model_name
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
