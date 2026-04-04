"""Canonical hashing for action parameters.

This utility is intentionally dependency-light so it can be imported by
core runtime paths without pulling optional intent parser dependencies.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict


def compute_action_params_hash(action_params: Dict[str, Any] | None) -> str:
    """Compute a deterministic SHA-256 hash for action parameters."""
    canonical = json.dumps(
        action_params or {},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
