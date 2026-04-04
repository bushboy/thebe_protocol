"""Audit logging client for Executor Agent.

This module logs all executions to the Audit Service with full context.

Requirements: 10.2
"""

from typing import Dict, Any, Optional
from datetime import datetime
import httpx
import hashlib

from shared.schemas import ZeroTrustAuthorizationToken
from shared.logging import JSONLogger
from .config import config


logger = JSONLogger(__name__)


class AuditLoggerError(Exception):
    """Exception raised when audit logging fails."""
    pass


class AuditLogger:
    """Client for logging to Audit Service."""

    def __init__(self, audit_service_url: Optional[str] = None):
        """Initialize audit logger.

        Args:
            audit_service_url: URL of Audit Service (defaults to config)
        """
        self.audit_service_url = audit_service_url or config.audit_service_url
        self.http_client = httpx.AsyncClient(
            timeout=10.0,
            verify=False  # In production, use proper certificate verification
        )

    async def log_execution(
        self,
        zt_at: ZeroTrustAuthorizationToken,
        execution_id: str,
        status: str,
        result: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
        dpop_fingerprint: Optional[str] = None,
        reasoning_trace: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log action execution to Audit Service.

        Args:
            zt_at: Zero-Trust Authorization Token
            execution_id: Unique execution identifier
            status: Execution status (success or failure)
            result: Execution result data (optional)
            error: Error message if failed (optional)
            dpop_fingerprint: DPoP key fingerprint (optional)

        Raises:
            AuditLoggerError: If logging fails

        Requirements: 10.2
        """
        try:
            # Construct audit log entry
            default_reasoning_trace = {
                "decision": "ALLOW" if status == "success" else "DENY",
                "component": "executor",
                "stage": "execution",
                "attempted_action": zt_at.action,
                "provider": zt_at.provider,
                "plan_id": zt_at.plan_id,
                "task_id": zt_at.task_id,
                "status": status,
                "error": error,
            }
            log_entry = {
                "component": "executor",
                "event_type": "action_executed",
                "action_metadata": {
                    "execution_id": execution_id,
                    "plan_id": zt_at.plan_id,
                    "task_id": zt_at.task_id,
                    "action": zt_at.action,
                    "provider": zt_at.provider,
                    "status": status,
                    "result": result,
                    "error": error,
                    "reasoning_trace": reasoning_trace or default_reasoning_trace,
                },
                "zt_at": zt_at.model_dump(mode='json'),
                "dpop_fingerprint": dpop_fingerprint or self._compute_default_fingerprint(),
                "timestamp": datetime.utcnow().isoformat()
            }

            # Send to Audit Service
            response = await self.http_client.post(
                f"{self.audit_service_url}/log",
                json=log_entry,
                headers={"Content-Type": "application/json"}
            )

            if response.status_code != 200:
                logger.error(
                    f"Audit Service returned error: {response.status_code} - {response.text}"
                )
                raise AuditLoggerError(
                    f"Audit Service error: {response.status_code}"
                )

            response_data = response.json()
            logger.info(
                f"Execution logged to Audit Service: {execution_id} "
                f"(log_id: {response_data.get('log_id')})"
            )

        except httpx.HTTPError as e:
            logger.error(f"HTTP error logging to Audit Service: {str(e)}")
            raise AuditLoggerError(f"Failed to log to Audit Service: {str(e)}")
        except Exception as e:
            logger.error(f"Error logging to Audit Service: {str(e)}")
            raise AuditLoggerError(f"Audit logging failed: {str(e)}")

    async def log_validation_failure(
        self,
        zt_at: ZeroTrustAuthorizationToken,
        failure_reason: str,
        failure_type: str,
        reasoning_trace: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log validation failure to Audit Service.

        Args:
            zt_at: Zero-Trust Authorization Token
            failure_reason: Reason for validation failure
            failure_type: Type of failure (e.g., expired_token, replay_detected)

        Raises:
            AuditLoggerError: If logging fails
        """
        try:
            default_reasoning_trace = {
                "decision": "DENY",
                "component": "executor",
                "stage": "validation",
                "attempted_action": zt_at.action,
                "provider": zt_at.provider,
                "plan_id": zt_at.plan_id,
                "task_id": zt_at.task_id,
                "failure_type": failure_type,
                "reason": failure_reason,
                "intent_analysis": {
                    "semantic_match_score": zt_at.policy_approval.semantic_similarity_score,
                    "semantic_match_threshold": zt_at.policy_approval.semantic_match_threshold,
                },
            }

            log_entry = {
                "component": "executor",
                "event_type": "validation_failure",
                "action_metadata": {
                    "plan_id": zt_at.plan_id,
                    "task_id": zt_at.task_id,
                    "action": zt_at.action,
                    "provider": zt_at.provider,
                    "failure_reason": failure_reason,
                    "failure_type": failure_type,
                    "reasoning_trace": reasoning_trace or default_reasoning_trace,
                },
                "zt_at": zt_at.model_dump(mode='json'),
                "dpop_fingerprint": self._compute_default_fingerprint(),
                "timestamp": datetime.utcnow().isoformat()
            }

            response = await self.http_client.post(
                f"{self.audit_service_url}/log",
                json=log_entry,
                headers={"Content-Type": "application/json"}
            )

            if response.status_code != 200:
                logger.error(
                    f"Audit Service returned error: {response.status_code} - {response.text}"
                )
            else:
                logger.info(f"Validation failure logged for plan: {zt_at.plan_id}, task: {zt_at.task_id}")

        except Exception as e:
            logger.error(f"Error logging validation failure: {str(e)}")
            # Don't raise exception for audit logging failures during validation failures

    def _compute_default_fingerprint(self) -> str:
        """Compute default DPoP fingerprint.

        In production, this would be the actual DPoP key fingerprint.
        For now, we'll use a placeholder.

        Returns:
            DPoP key fingerprint
        """
        # In production, compute from actual DPoP public key
        # For now, use a placeholder
        return hashlib.sha256(b"executor_dpop_key").hexdigest()[:16]

    async def close(self) -> None:
        """Close HTTP client."""
        await self.http_client.aclose()
