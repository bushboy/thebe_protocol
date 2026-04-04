"""OPA (Open Policy Agent) client module.

This module provides a Python client for evaluating policies against OPA.
"""

from .client import OPAClient, OPAError, PolicyEvaluationResult

__all__ = ["OPAClient", "OPAError", "PolicyEvaluationResult"]
