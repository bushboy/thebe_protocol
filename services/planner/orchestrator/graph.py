"""LangGraph graph factory for the in-process guardian pipeline.

Builds a ``StateGraph`` with three nodes:

    planner  ──►  intent_engine  ──►  safety_agent  ──►  END
                                           │ (DENY)
                                           └──────────────► END  (blocked=True)

Each edge is synchronous; the graph is compiled once per process and reused
across requests to amortise compilation overhead.

Requirements: Gap 1 – LangGraph hooks for zero-latency interception.
"""

from __future__ import annotations

from typing import Literal

from langgraph.graph import StateGraph, END

from .state import PipelineState
from .nodes import planner_node, intent_engine_node, safety_agent_node


def _route_after_safety(state: PipelineState) -> Literal["end"]:
    """Routing function – always proceeds to END.

    The safety_agent_node already sets ``blocked=True`` on DENY.
    Downstream code inspects ``state["blocked"]`` to decide what to surface
    to the caller; we always terminate the graph here.
    """
    return "end"


def build_guardian_graph() -> StateGraph:
    """Compile and return the guardian LangGraph.

    The compiled graph is a reusable callable that accepts a ``PipelineState``
    dict and returns the final state after all nodes have executed.

    Returns:
        Compiled LangGraph application.
    """
    graph = StateGraph(PipelineState)

    # ── Nodes ────────────────────────────────────────────────────────────────
    graph.add_node("planner", planner_node)
    graph.add_node("intent_engine", intent_engine_node)
    graph.add_node("safety_agent", safety_agent_node)

    # ── Edges ────────────────────────────────────────────────────────────────
    graph.set_entry_point("planner")
    graph.add_edge("planner", "intent_engine")
    graph.add_edge("intent_engine", "safety_agent")
    graph.add_conditional_edges(
        "safety_agent",
        _route_after_safety,
        {"end": END},
    )

    return graph.compile()


# Module-level compiled graph (warm singleton, shared across requests)
_compiled_graph = None


def get_compiled_graph():
    """Return the module-level compiled graph, creating it on first call."""
    global _compiled_graph
    if _compiled_graph is None:
        _compiled_graph = build_guardian_graph()
    return _compiled_graph
