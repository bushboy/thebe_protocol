"""OPA client for policy evaluation.

This module provides a Python client wrapper for communicating with OPA
(Open Policy Agent) HTTP API to evaluate policies.
"""

import httpx
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class PolicyEvaluationResult(BaseModel):
    """Result of a policy evaluation."""

    allow: bool = Field(..., description="Whether the action is allowed")
    deny_reasons: List[str] = Field(default_factory=list, description="List of denial reasons if not allowed")

    model_config = {
        "json_schema_extra": {
            "example": {
                "allow": False,
                "deny_reasons": ["Destructive GitHub action 'delete_branch' requires admin role"]
            }
        }
    }


class OPAError(Exception):
    """Exception raised when OPA evaluation fails."""
    pass


class OPAClient:
    """Client for evaluating policies against OPA.

    This client communicates with an OPA server via HTTP API to evaluate
    policies defined in Rego language.

    Attributes:
        opa_url: Base URL of the OPA server
        policy_path: Path to the policy package (e.g., "agentic_guardian/decision")
        timeout: HTTP request timeout in seconds
    """

    def __init__(
        self,
        opa_url: str = "http://localhost:8181",
        policy_path: str = "agentic_guardian/decision",
        timeout: float = 5.0
    ):
        """Initialize OPA client.

        Args:
            opa_url: Base URL of the OPA server (default: http://localhost:8181)
            policy_path: Path to the policy package (default: agentic_guardian/decision)
            timeout: HTTP request timeout in seconds (default: 5.0)
        """
        self.opa_url = opa_url.rstrip("/")
        self.policy_path = policy_path
        self.timeout = timeout
        self._client = httpx.Client(timeout=timeout)

    def evaluate(self, input_data: Dict[str, Any]) -> PolicyEvaluationResult:
        """Evaluate a policy against the provided input.

        Args:
            input_data: Input data for policy evaluation. Should contain:
                - action: The action being requested
                - provider: The provider (github, slack, etc.)
                - context: Context including role, spending_limit, etc.
                - action_category: Category of the action
                - intent_alignment_score: Similarity score from Intent Engine
                - estimated_cost: Estimated cost for spending limit checks

        Returns:
            PolicyEvaluationResult with allow decision and any denial reasons

        Raises:
            OPAError: If OPA server is unreachable or returns an error

        Example:
            >>> client = OPAClient()
            >>> result = client.evaluate({
            ...     "action": "delete_branch",
            ...     "provider": "github",
            ...     "context": {"role": "developer"},
            ...     "action_category": "destructive",
            ...     "intent_alignment_score": 0.8
            ... })
            >>> print(result.allow)
            False
            >>> print(result.deny_reasons)
            ["Destructive GitHub action 'delete_branch' requires admin role"]
        """
        url = f"{self.opa_url}/v1/data/{self.policy_path}"

        try:
            response = self._client.post(
                url,
                json={"input": input_data}
            )
            response.raise_for_status()

            result_data = response.json()

            # OPA returns result in {"result": {...}} format
            if "result" not in result_data:
                raise OPAError(f"Invalid OPA response format: {result_data}")

            decision = result_data["result"]

            # Extract allow and deny_reasons from decision
            allow = decision.get("allow", False)
            deny_reasons = list(decision.get("deny_reasons", []))

            return PolicyEvaluationResult(
                allow=allow,
                deny_reasons=deny_reasons
            )

        except httpx.HTTPStatusError as e:
            raise OPAError(f"OPA HTTP error: {e.response.status_code} - {e.response.text}")
        except httpx.RequestError as e:
            raise OPAError(f"OPA request failed: {str(e)}")
        except Exception as e:
            raise OPAError(f"OPA evaluation error: {str(e)}")

    def evaluate_batch(self, input_data_list: List[Dict[str, Any]]) -> List[PolicyEvaluationResult]:
        """Evaluate multiple policies in batch.

        Args:
            input_data_list: List of input data dictionaries for policy evaluation

        Returns:
            List of PolicyEvaluationResult objects, one for each input

        Raises:
            OPAError: If OPA server is unreachable or returns an error
        """
        results = []
        for input_data in input_data_list:
            result = self.evaluate(input_data)
            results.append(result)
        return results

    def health_check(self) -> bool:
        """Check if OPA server is healthy and reachable.

        Returns:
            True if OPA server is healthy, False otherwise
        """
        try:
            response = self._client.get(f"{self.opa_url}/health")
            return response.status_code == 200
        except Exception:
            return False

    def close(self):
        """Close the HTTP client connection."""
        self._client.close()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
