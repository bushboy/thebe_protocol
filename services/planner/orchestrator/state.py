"""Pipeline state definition for LangGraph orchestrator.

Uses TypedDict so LangGraph can track and pass state through each node
without serialisation overhead.

Requirements: Gap 1 – zero-latency interception.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from typing_extensions import TypedDict

from shared.schemas import IntentSignature, PolicyDecision


class PipelineState(TypedDict, total=False):
    """Mutable state threaded through every node in the guardian graph.

    Fields are optional (total=False) so each node only populates what it
    produces; earlier nodes' output is preserved for downstream nodes.
    """

    # ── Input ────────────────────────────────────────────────────────────────
    user_goal: str
    user_id: str
    context: Dict[str, Any]
    access_token: str
    plan_id: str

    # ── Planner node output ──────────────────────────────────────────────────
    task_graph: List[Dict[str, Any]]
    allowed_actions: List[str]

    # ── Intent Engine node output ────────────────────────────────────────────
    intent_signature: Optional[IntentSignature]

    # ── Safety Agent node output ─────────────────────────────────────────────
    policy_decision: Optional[PolicyDecision]

    # ── Control flow ─────────────────────────────────────────────────────────
    blocked: bool          # True when the Safety Agent denies the request
    block_reason: str      # Human-readable block reason for audit / demo UI
    error: Optional[str]   # Non-empty when a node raises an unexpected error
