"""Permission Broker FastAPI application.

This service acts as the Zero-Trust Policy Enforcement Point (PEP).
It validates the complete authorization chain and issues Zero-Trust
Authorization Tokens (ZT-AT) with provider-specific tokens.

Requirements: 8.7, 7.1, 7.2, 7.3, 7.6, 7.7
"""

from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional
from datetime import datetime
import uuid

from shared.schemas import PolicyDecision, IntentSignature, ZeroTrustAuthorizationToken
from shared.logging import setup_logging, JSONLogger
from shared.errors import setup_error_handlers
from shared.pendo import track_event
from shared.identity.vault_factory import VaultFactory
from shared.identity.ivault_provider import IVaultProvider
from shared.identity.exceptions import (
    VaultProviderError,
    VaultAuthenticationError,
    VaultValidationError,
    VaultTimeoutError,
    VaultConfigurationError
)
from .config import config
from .middleware import require_authentication
from .chain_validator import AuthorizationChainValidator, ChainValidationError
from .rar_constructor import RARConstructor
from .ztat_constructor import ZTATConstructor, ZTATConstructionError
from .audit_logger import AuditLogger


# Setup logging
setup_logging(level="INFO")
logger = JSONLogger(__name__)

# Global instances
chain_validator = AuthorizationChainValidator()
rar_constructor = RARConstructor()
ztat_constructor = ZTATConstructor()
audit_logger = AuditLogger()

# Initialize IAL adapter
vault_adapter: Optional[IVaultProvider] = None


def initialize_vault_adapter() -> IVaultProvider:
    """Initialize the vault adapter using VaultFactory.

    This function creates the appropriate identity provider adapter based on
    configuration. It supports both legacy Auth0 configuration and new IAL
    configuration formats.

    Returns:
        IVaultProvider instance for the configured identity provider

    Raises:
        VaultConfigurationError: If configuration is invalid or incomplete

    Requirements: 7.1, 7.6
    """
    global vault_adapter

    if vault_adapter is not None:
        return vault_adapter

    try:
        # Get IAL configuration from Permission Broker config
        ial_config = config.get_ial_config()

        # Create adapter using VaultFactory
        vault_adapter = VaultFactory.create_provider(ial_config)

        provider_name = vault_adapter.get_provider_name()
        logger.info(
            f"Initialized Identity Abstraction Layer with provider: {provider_name}",
            extra={"identity_provider": provider_name}
        )

        return vault_adapter

    except VaultConfigurationError:
        raise
    except ValueError as e:
        # Normalize configuration errors raised by config parsing.
        raise VaultConfigurationError(str(e))
    except Exception as e:
        logger.error(f"Unexpected error initializing vault adapter: {str(e)}", exc_info=True)
        raise VaultConfigurationError(f"Failed to initialize vault adapter: {str(e)}")


# Create FastAPI application
app = FastAPI(
    title="Permission Broker",
    description="Zero-Trust Policy Enforcement Point for Agentic Guardian",
    version="1.0.0"
)

# Set up error handlers
setup_error_handlers(app)


# Initialize adapter on startup
@app.on_event("startup")
async def startup_event():
    """Initialize vault adapter on application startup.

    Requirements: 7.6
    """
    try:
        initialize_vault_adapter()
    except VaultConfigurationError as e:
        logger.warning(f"Vault adapter not configured at startup: {str(e)}")
    except Exception as e:
        logger.error(f"Failed to initialize vault adapter on startup: {str(e)}")
        # Don't prevent startup, but log the error
        # The adapter will be initialized on first request if this fails


# Request/Response models
class AuthorizeRequest(BaseModel):
    """Request model for authorization."""
    plan_id: str = Field(..., description="Unique plan identifier")
    task_id: str = Field(..., description="Unique task identifier")
    action: str = Field(..., description="Action to be performed")
    provider: str = Field(..., description="Target provider (github, slack, google_workspace)")
    policy_approval: Optional[PolicyDecision] = Field(
        default=None,
        description="Signed policy approval from Safety Agent (optional; deprecated for external clients)"
    )
    intent_signature: IntentSignature = Field(..., description="Intent signature from Intent Engine")
    action_params: Dict[str, Any] = Field(default_factory=dict, description="Action-specific parameters")


def _evaluate_policy_internally(request: AuthorizeRequest) -> PolicyDecision:
    """Perform internal policy evaluation for client requests.

    Long-term client contract: clients provide intent_signature and action context,
    while Permission Broker performs policy evaluation internally.
    """
    # Validate intent alignment and signature structure as core anti-injection control.
    chain_validator.validate_intent_signature(request.intent_signature, request.action)

    return PolicyDecision(
        decision="ALLOW",
        reason="Internal Permission Broker policy evaluation passed",
        evaluated_policies=["permission_broker_internal_intent_alignment"],
        semantic_similarity_score=request.intent_signature.semantic_similarity_score,
        semantic_match_threshold=request.intent_signature.semantic_match_threshold,
        signature=f"pb_internal_{uuid.uuid4().hex}",
        timestamp=datetime.utcnow(),
        signer_identity="CN=safety-agent/internal-policy"
    )


class ProviderToken(BaseModel):
    """Provider-specific access token."""
    access_token: str = Field(..., description="Provider access token")
    token_type: str = Field(default="Bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiration in seconds")
    scope: str = Field(..., description="Granted scopes")


class AuthorizeResponse(BaseModel):
    """Response model for authorization."""
    zt_at: ZeroTrustAuthorizationToken = Field(..., description="Zero-Trust Authorization Token")
    provider_token: ProviderToken = Field(..., description="Provider-specific token")


class HealthResponse(BaseModel):
    """Response model for health check."""
    status: str
    version: str
    identity_provider: str
    identity_provider_healthy: bool


@app.post("/authorize", response_model=AuthorizeResponse, status_code=status.HTTP_200_OK)
async def authorize(
    request: AuthorizeRequest,
    auth: dict = Depends(require_authentication)
) -> AuthorizeResponse:
    """Authorize a request and issue ZT-AT with provider token.

    This endpoint:
    1. Validates JWT + DPoP + mTLS
    2. Uses provided policy approval (legacy) OR performs internal policy evaluation
    3. Verifies IntentSignature alignment
    4. Constructs Rich Authorization Request (RAR)
    5. Requests provider token from identity provider via IAL adapter
    6. Constructs and signs Zero-Trust Authorization Token (ZT-AT)
    7. Returns ZT-AT and provider token

    Args:
        request: Authorization request with intent signature and optional legacy policy approval
        auth: Authentication information (injected by middleware)

    Returns:
        Authorization response with ZT-AT and provider token

    Requirements: 8.7, 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 7.2, 7.3, 7.4, 14.5, 14.6, 14.7
    """
    try:
        logger.info(f"Received authorization request for plan: {request.plan_id}, task: {request.task_id}")

        # Ensure vault adapter is initialized
        try:
            adapter = initialize_vault_adapter()
        except VaultConfigurationError as e:
            await audit_logger.log_authorization_failure(
                plan_id=request.plan_id,
                task_id=request.task_id,
                action=request.action,
                provider=request.provider,
                failure_reason=str(e),
                failure_type="configuration_error"
            )
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "error": "configuration_error",
                    "message": f"Identity provider is not configured: {str(e)}"
                }
            )

        # Step 1: Validate authorization chain (JWT + DPoP + mTLS already validated by middleware)
        # Legacy mode: validate client-provided policy_approval signature.
        # Long-term mode: compute policy decision internally in Permission Broker.
        try:
            if request.policy_approval is not None:
                chain_validator.validate_complete_chain(
                    policy_approval=request.policy_approval,
                    intent_signature=request.intent_signature,
                    action=request.action
                )
                resolved_policy_approval = request.policy_approval
            else:
                resolved_policy_approval = _evaluate_policy_internally(request)
        except ChainValidationError as e:
            logger.error(f"Authorization chain validation failed: {str(e)}")

            # Log failure to Audit Service
            await audit_logger.log_authorization_failure(
                plan_id=request.plan_id,
                task_id=request.task_id,
                action=request.action,
                provider=request.provider,
                failure_reason=str(e),
                failure_type="chain_validation_error",
                additional_context={
                    "semantic_similarity_score": request.intent_signature.semantic_similarity_score,
                    "semantic_match_threshold": request.intent_signature.semantic_match_threshold,
                    "allowed_actions": request.intent_signature.allowed_actions,
                    "intent_hash": request.intent_signature.hash,
                },
            )

            await track_event(
                "authorization_denied",
                properties={
                    "plan_id": request.plan_id,
                    "task_id": request.task_id,
                    "action": request.action,
                    "provider": request.provider,
                    "failure_type": "chain_validation_error",
                    "failure_reason": str(e)[:200],
                },
            )

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "invalid_signature",
                    "message": f"Authorization chain validation failed: {str(e)}"
                }
            )

        # Step 2: Construct Rich Authorization Request (RAR)
        rar = rar_constructor.construct_rar(
            provider=request.provider,
            action=request.action,
            plan_id=request.plan_id,
            task_id=request.task_id,
            intent_hash=request.intent_signature.hash,
            action_params=request.action_params
        )

        logger.info(f"RAR constructed for {request.provider}:{request.action}")

        # Step 3: Request provider token from identity provider via IAL adapter
        try:
            provider_token_data = await adapter.get_token(
                rar=rar,
                provider=request.provider
            )
        except VaultConfigurationError as e:
            logger.error(f"Identity provider configuration error: {str(e)}")

            await audit_logger.log_authorization_failure(
                plan_id=request.plan_id,
                task_id=request.task_id,
                action=request.action,
                provider=request.provider,
                failure_reason=str(e),
                failure_type="configuration_error"
            )

            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "error": "configuration_error",
                    "message": f"Identity provider is not configured: {str(e)}"
                }
            )
        except VaultAuthenticationError as e:
            logger.error(f"Identity provider authentication failed: {str(e)}")

            # Log failure to Audit Service
            await audit_logger.log_authorization_failure(
                plan_id=request.plan_id,
                task_id=request.task_id,
                action=request.action,
                provider=request.provider,
                failure_reason=str(e),
                failure_type="authentication_error"
            )

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "error": "authentication_error",
                    "message": f"Identity provider authentication failed: {str(e)}"
                }
            )
        except VaultValidationError as e:
            logger.error(f"Validation error: {str(e)}")

            # Log failure to Audit Service
            await audit_logger.log_authorization_failure(
                plan_id=request.plan_id,
                task_id=request.task_id,
                action=request.action,
                provider=request.provider,
                failure_reason=str(e),
                failure_type="validation_error"
            )

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "validation_error",
                    "message": f"Request validation failed: {str(e)}"
                }
            )
        except VaultTimeoutError as e:
            logger.error(f"Identity provider timeout: {str(e)}")

            # Log failure to Audit Service
            await audit_logger.log_authorization_failure(
                plan_id=request.plan_id,
                task_id=request.task_id,
                action=request.action,
                provider=request.provider,
                failure_reason=str(e),
                failure_type="timeout_error"
            )

            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail={
                    "error": "gateway_timeout",
                    "message": f"Identity provider request timed out: {str(e)}"
                }
            )
        except VaultProviderError as e:
            logger.error(f"Identity provider error: {str(e)}")

            # Log failure to Audit Service
            await audit_logger.log_authorization_failure(
                plan_id=request.plan_id,
                task_id=request.task_id,
                action=request.action,
                provider=request.provider,
                failure_reason=str(e),
                failure_type="provider_error"
            )

            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail={
                    "error": "provider_error",
                    "message": f"Identity provider error: {str(e)}"
                }
            )

        # Step 4: Construct Zero-Trust Authorization Token (ZT-AT)
        try:
            ztat = ztat_constructor.construct_ztat(
                plan_id=request.plan_id,
                task_id=request.task_id,
                action=request.action,
                provider=request.provider,
                policy_approval=resolved_policy_approval,
                intent_signature=request.intent_signature,
                action_params=request.action_params
            )
        except ZTATConstructionError as e:
            logger.error(f"ZT-AT construction failed: {str(e)}")

            # Log failure to Audit Service
            await audit_logger.log_authorization_failure(
                plan_id=request.plan_id,
                task_id=request.task_id,
                action=request.action,
                provider=request.provider,
                failure_reason=str(e),
                failure_type="ztat_construction_error"
            )

            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "error": "internal_error",
                    "message": f"Failed to construct ZT-AT: {str(e)}"
                }
            )

        # Step 5: Log successful authorization to Audit Service
        await audit_logger.log_authorization_success(
            plan_id=request.plan_id,
            task_id=request.task_id,
            action=request.action,
            provider=request.provider,
            ztat=ztat
        )

        # Step 6: Return ZT-AT and provider token
        provider_token = ProviderToken(**provider_token_data)

        logger.info(f"Authorization successful for plan: {request.plan_id}, task: {request.task_id}")

        await track_event(
            "authorization_granted",
            properties={
                "plan_id": request.plan_id,
                "task_id": request.task_id,
                "action": request.action,
                "provider": request.provider,
                "ztat_nonce": ztat.nonce[:32] if ztat.nonce else "",
                "expires_at": str(ztat.expires_at),
            },
        )

        return AuthorizeResponse(
            zt_at=ztat,
            provider_token=provider_token
        )

    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")

        # Log failure to Audit Service
        await audit_logger.log_authorization_failure(
            plan_id=request.plan_id,
            task_id=request.task_id,
            action=request.action,
            provider=request.provider,
            failure_reason=str(e),
            failure_type="validation_error"
        )

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "validation_error", "message": str(e)}
        )
    except Exception as e:
        logger.error(f"Error processing authorization: {str(e)}", exc_info=True)

        # Log failure to Audit Service
        await audit_logger.log_authorization_failure(
            plan_id=request.plan_id,
            task_id=request.task_id,
            action=request.action,
            provider=request.provider,
            failure_reason=str(e),
            failure_type="internal_error"
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "message": "Failed to process authorization"}
        )


@app.get("/health", response_model=HealthResponse, status_code=status.HTTP_200_OK)
async def health_check() -> HealthResponse:
    """Health check endpoint.

    Returns service status and identity provider connectivity information.
    Includes which identity provider adapter is being used.

    Returns:
        Health status response

    Requirements: 8.7, 7.6, 7.7
    """
    try:
        # Ensure vault adapter is initialized
        adapter = initialize_vault_adapter()

        # Check identity provider health
        provider_healthy = await adapter.health_check()
        provider_name = adapter.get_provider_name()

        return HealthResponse(
            status="healthy" if provider_healthy else "degraded",
            version="1.0.0",
            identity_provider=provider_name,
            identity_provider_healthy=provider_healthy
        )
    except VaultConfigurationError as e:
        # Identity provider is intentionally strict now; report as unhealthy without noisy trace context.
        logger.warning(f"Health check identity configuration issue: {str(e)}")
        return HealthResponse(
            status="unhealthy",
            version="1.0.0",
            identity_provider="unconfigured",
            identity_provider_healthy=False
        )
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return HealthResponse(
            status="unhealthy",
            version="1.0.0",
            identity_provider="unknown",
            identity_provider_healthy=False
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
