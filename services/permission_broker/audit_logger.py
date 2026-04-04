"""Audit logging client for Permission Broker.

This module handles logging validation failures and authorization events
to the Audit Service.

Requirements: 8.8
"""

import httpx
from datetime import datetime
from typing import Dict, Any, Optional

from shared.schemas import ZeroTrustAuthorizationToken
from shared.logging import JSONLogger
from .config import config


logger = JSONLogger(__name__)


class AuditLoggerError(Exception):
    """Exception raised when audit logging fails."""
    pass


class AuditLogger:
    """Client for logging events to Audit Service."""

    def __init__(self):
        """Initialize audit logger."""
        self.audit_service_url = config.audit_service_url
        self.timeout = 5.0

    async def log_authorization_failure(
        self,
        plan_id: str,
        task_id: str,
        action: str,
        provider: str,
        failure_reason: str,
        failure_type: str,
        additional_context: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log an authorization failure to the Audit Service.

        Args:
            plan_id: Unique plan identifier
            task_id: Unique task identifier
            action: Requested action
            provider: Target provider
            failure_reason: Human-readable failure reason
            failure_type: Type of failure (e.g., "invalid_signature", "intent_misaligned")
            additional_context: Additional context information

        Requirements: 8.8
        """
        logger.info(f"Logging authorization failure for plan: {plan_id}, task: {task_id}")

        semantic_score = None
        semantic_threshold = None
        if additional_context:
            semantic_score = additional_context.get("semantic_similarity_score")
            semantic_threshold = additional_context.get("semantic_match_threshold")

        reasoning_trace = {
            "decision": "DENY",
            "component": "permission-broker",
            "stage": "authorization",
            "attempted_action": action,
            "provider": provider,
            "plan_id": plan_id,
            "task_id": task_id,
            "failure_type": failure_type,
            "reason": failure_reason,
            "intent_analysis": {
                "semantic_match_score": semantic_score,
                "semantic_match_threshold": semantic_threshold,
            },
        }

        # Construct audit log entry
        log_entry = {
            "component": "permission-broker",
            "event_type": "authorization_failure",
            "action_metadata": {
                "plan_id": plan_id,
                "task_id": task_id,
                "action": action,
                "provider": provider,
                "failure_reason": failure_reason,
                "failure_type": failure_type,
                "reasoning_trace": reasoning_trace,
            },
            "zt_at": None,  # No ZT-AT issued for failures
            "dpop_fingerprint": "unknown",  # Would extract from request in production
            "timestamp": datetime.now().isoformat()
        }

        # Add additional context if provided
        if additional_context:
            log_entry["action_metadata"]["additional_context"] = additional_context

        # Send to Audit Service
        await self._send_log_entry(log_entry)

    async def log_authorization_success(
        self,
        plan_id: str,
        task_id: str,
        action: str,
        provider: str,
        ztat: ZeroTrustAuthorizationToken,
        dpop_fingerprint: str = "unknown"
    ) -> None:
        """Log a successful authorization to the Audit Service.

        Args:
            plan_id: Unique plan identifier
            task_id: Unique task identifier
            action: Authorized action
            provider: Target provider
            ztat: Issued ZT-AT
            dpop_fingerprint: DPoP key fingerprint
        """
        logger.info(f"Logging authorization success for plan: {plan_id}, task: {task_id}")

        reasoning_trace = {
            "decision": "ALLOW",
            "component": "permission-broker",
            "stage": "authorization",
            "attempted_action": action,
            "provider": provider,
            "plan_id": plan_id,
            "task_id": task_id,
            "intent_analysis": {
                "semantic_match_score": ztat.policy_approval.semantic_similarity_score,
                "semantic_match_threshold": ztat.policy_approval.semantic_match_threshold,
                "intent_hash": ztat.intent_signature.hash,
                "allowed_actions": ztat.intent_signature.allowed_actions,
            },
            "policy_evaluation": {
                "decision": ztat.policy_approval.decision,
                "reason": ztat.policy_approval.reason,
                "evaluated_policies": ztat.policy_approval.evaluated_policies,
            },
        }

        # Construct audit log entry
        log_entry = {
            "component": "permission-broker",
            "event_type": "authorization_success",
            "action_metadata": {
                "plan_id": plan_id,
                "task_id": task_id,
                "action": action,
                "provider": provider,
                "ztat_nonce": ztat.nonce,
                "expires_at": ztat.expires_at.isoformat(),
                "reasoning_trace": reasoning_trace,
            },
            "zt_at": ztat.model_dump(mode="json"),
            "dpop_fingerprint": dpop_fingerprint,
            "timestamp": datetime.now().isoformat()
        }

        # Send to Audit Service
        await self._send_log_entry(log_entry)

    async def _send_log_entry(self, log_entry: Dict[str, Any]) -> None:
        """Send log entry to Audit Service.

        Args:
            log_entry: Log entry dictionary

        Raises:
            AuditLoggerError: If logging fails
        """
        if not self.audit_service_url:
            logger.warning("Audit Service URL not configured - logging locally only")
            logger.info(f"Audit log entry: {log_entry}")
            return

        try:
            await self._post_log(self.audit_service_url, log_entry)

        except httpx.TimeoutException as e:
            logger.error(f"Audit Service request timed out: {str(e)}")
            # Don't raise - log locally and continue
            logger.info(f"Local audit log: {log_entry}")
        except httpx.RequestError as e:
            logger.error(f"Audit Service request failed: {str(e)}")

            # Common local-deployment issue: HTTPS configured but service is HTTP.
            if (
                "record layer failure" in str(e).lower()
                and self.audit_service_url.startswith("https://")
            ):
                fallback_url = self.audit_service_url.replace("https://", "http://", 1)
                logger.warning(f"Retrying audit log over HTTP at {fallback_url}")
                try:
                    await self._post_log(fallback_url, log_entry)
                    logger.info("Audit log entry sent successfully via HTTP fallback")
                    return
                except Exception as fallback_error:
                    logger.error(f"Audit Service HTTP fallback failed: {str(fallback_error)}")

            # Don't raise - log locally and continue
            logger.info(f"Local audit log: {log_entry}")
        except Exception as e:
            logger.error(f"Unexpected error logging to Audit Service: {str(e)}", exc_info=True)
            # Don't raise - log locally and continue
            logger.info(f"Local audit log: {log_entry}")

    async def _post_log(self, base_url: str, log_entry: Dict[str, Any]) -> None:
        """Post one audit log entry and raise on transport/status failures."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{base_url}/log",
                json=log_entry,
                headers={"Content-Type": "application/json"}
            )

            if response.status_code not in [200, 201]:
                error_detail = response.json() if response.text else {}
                raise AuditLoggerError(
                    f"Audit Service returned {response.status_code}: {error_detail}"
                )
