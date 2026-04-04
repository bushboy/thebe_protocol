"""LangGraph in-process orchestrator for zero-latency authorization pipeline.

Replaces HTTP service-to-service calls with direct in-process function calls,
eliminating network round-trips between Planner → Intent Engine → Safety Agent.

Requirements: Gap 1 – LangGraph hooks for zero-latency interception.
"""

from .graph import build_guardian_graph
from .state import PipelineState

__all__ = ["build_guardian_graph", "PipelineState"]
