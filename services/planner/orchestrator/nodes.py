"""LangGraph node implementations for the in-process guardian pipeline.

Each node is an ordinary Python callable that accepts and returns a
``PipelineState`` dict.  LangGraph merges each returned mapping back into the
shared state, so nodes need only populate the keys they produce.

By importing service business-logic classes directly — instead of posting HTTP
requests — we eliminate inter-service round-trips.  The only remaining I/O is:
  • The OPA query inside PolicyEvaluator (still an HTTP call to the OPA sidecar,
    but that is a single hop rather than four sequential service round-trips).

Requirements: Gap 1 – LangGraph hooks for zero-latency interception.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict

from shared.logging import JSONLogger
from .state import PipelineState

logger = JSONLogger(__name__)


# ── Lazy singletons (loaded once per process) ────────────────────────────────

_intent_signer = None
_policy_evaluator = None


def _get_intent_signer():
    """Return a warm IntentSigner, loading the model on first call."""
    global _intent_signer
    if _intent_signer is None:
        from services.intent_engine.intent_signer import IntentSigner
        _intent_signer = IntentSigner()
        _intent_signer.load_model()
        logger.info("Orchestrator: IntentSigner model loaded (singleton)")
    return _intent_signer


def _get_policy_evaluator():
    """Return a warm PolicyEvaluator, initialising OPA client on first call."""
    global _policy_evaluator
    if _policy_evaluator is None:
        from services.safety_agent.policy_evaluator import PolicyEvaluator
        _policy_evaluator = PolicyEvaluator()
        logger.info("Orchestrator: PolicyEvaluator initialised (singleton)")
    return _policy_evaluator


# ── Node 1: Planner ──────────────────────────────────────────────────────────

def planner_node(state: PipelineState) -> Dict[str, Any]:
    """Generate a task graph from the user goal.

    This node runs the same TaskGraphGenerator used by the HTTP /plan endpoint,
    meaning all destructive-keyword checks and provider-allowlisting apply here
    too.  No network I/O.
    """
    from services.planner.task_graph_generator import TaskGraphGenerator

    user_goal: str = state["user_goal"]
    context: Dict[str, Any] = state.get("context", {})

    logger.info(f"[orchestrator] planner_node: generating task graph for goal '{user_goal[:60]}…'")

    try:
        generator = TaskGraphGenerator()
        task_graph = generator.generate_task_graph(
            user_goal=user_goal,
            context=context,
        )
    except ValueError as exc:
        # Destructive-keyword rejection or unknown provider
        logger.warning(f"[orchestrator] planner_node blocked goal: {exc}")
        return {
            "task_graph": [],
            "allowed_actions": [],
            "blocked": True,
            "block_reason": str(exc),
        }

    allowed_actions = [
        f"{task['provider']}:{task['action']}"
        for task in task_graph
    ]

    logger.info(
        f"[orchestrator] planner_node: {len(task_graph)} tasks, "
        f"{len(allowed_actions)} allowed actions"
    )

    return {
        "task_graph": task_graph,
        "allowed_actions": allowed_actions,
        "blocked": False,
        "block_reason": "",
    }


# ── Node 2: Intent Engine ────────────────────────────────────────────────────

def intent_engine_node(state: PipelineState) -> Dict[str, Any]:
    """Generate a cryptographic intent signature in-process.

    Calls IntentSigner directly — no HTTP POST to the intent-engine service.
    The sentence-transformer model is kept warm via the module-level singleton.
    """
    if state.get("blocked"):
        return {}  # Short-circuit: propagate block without doing work

    user_goal: str = state["user_goal"]
    allowed_actions = state.get("allowed_actions", [])

    if not allowed_actions:
        return {
            "blocked": True,
            "block_reason": "No allowed actions produced by planner; cannot sign intent.",
        }

    logger.info(
        f"[orchestrator] intent_engine_node: signing intent for "
        f"{len(allowed_actions)} allowed actions"
    )

    try:
        signer = _get_intent_signer()
        intent_signature = signer.sign_intent(
            user_goal=user_goal,
            allowed_actions=allowed_actions,
        )
    except Exception as exc:
        logger.error(f"[orchestrator] intent_engine_node error: {exc}", exc_info=True)
        return {"error": f"Intent signing failed: {exc}", "blocked": True, "block_reason": str(exc)}

    logger.info(
        f"[orchestrator] intent_engine_node: signature hash={intent_signature.hash[:12]}… "
        f"similarity={intent_signature.semantic_similarity_score:.3f}"
    )

    return {"intent_signature": intent_signature}


# ── Node 3: Safety Agent ─────────────────────────────────────────────────────

def safety_agent_node(state: PipelineState) -> Dict[str, Any]:
    """Evaluate the task graph against OPA policies in-process.

    Calls PolicyEvaluator directly — no HTTP POST to the safety-agent service.
    The single remaining external call is OPA (one hop vs. two in the HTTP flow).
    """
    if state.get("blocked"):
        return {}  # Short-circuit: already blocked upstream

    task_graph = state.get("task_graph", [])
    intent_signature = state.get("intent_signature")
    context = state.get("context", {})
    user_goal = state.get("user_goal", "")

    if not task_graph or intent_signature is None:
        return {
            "blocked": True,
            "block_reason": "Missing task_graph or intent_signature; cannot evaluate policies.",
        }

    # Surface user_goal in context so policy denial messages can reference it
    enriched_context = {**context, "user_goal": user_goal}

    logger.info(
        f"[orchestrator] safety_agent_node: evaluating {len(task_graph)} tasks"
    )

    try:
        evaluator = _get_policy_evaluator()
        policy_decision = evaluator.evaluate_task_graph(
            task_graph=task_graph,
            intent_signature=intent_signature,
            context=enriched_context,
        )
    except Exception as exc:
        logger.error(f"[orchestrator] safety_agent_node error: {exc}", exc_info=True)
        return {"error": f"Policy evaluation failed: {exc}", "blocked": True, "block_reason": str(exc)}

    blocked = policy_decision.decision == "DENY"

    logger.info(
        f"[orchestrator] safety_agent_node: decision={policy_decision.decision} "
        f"(semantic_score={policy_decision.semantic_similarity_score})"
    )

    return {
        "policy_decision": policy_decision,
        "blocked": blocked,
        "block_reason": policy_decision.reason if blocked else "",
    }
