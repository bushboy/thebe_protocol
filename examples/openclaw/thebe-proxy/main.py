"""
Thebe Proxy — Agentic Guardian Bridge for OpenClaw
===================================================
Exposes a single POST /validate endpoint that the OpenClaw hook handler
calls for every tool:call event.

Operating modes
---------------
DEV MODE  (THEBE_DEV_MODE=true, default)
  Performs a lightweight intent-alignment heuristic inline.
  No Auth0 credentials needed.  Ideal for local demos.

PRODUCTION MODE  (THEBE_DEV_MODE=false)
  Delegates to the full Agentic Guardian stack via the Planner
  /plan-fast endpoint, which runs the complete pipeline:
    user goal → Intent Engine (semantic embedding) →
    Safety Agent (OPA policy) → verdict.
  Requires Auth0 M2M credentials and a running Guardian stack.

Environment variables
---------------------
THEBE_DEV_MODE              true | false        (default: true)
THEBE_API_KEY               Shared secret checked in X-Thebe-Key header
THEBE_MIN_ALIGNMENT_SCORE   Float 0–1           (default: 0.85)
THEBE_GUARDIAN_URL          Base URL of Planner service (default: http://planner:8000)
THEBE_GUARDIAN_BEARER_TOKEN Bearer token for Guardian API auth (production)
LOG_LEVEL                   INFO | DEBUG | WARNING  (default: INFO)
"""

import logging
import os
import re
from typing import Any

import httpx
from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(levelname)s  %(name)s  %(message)s",
)
logger = logging.getLogger("thebe-proxy")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEV_MODE: bool = os.getenv("THEBE_DEV_MODE", "true").lower() == "true"
THEBE_API_KEY: str = os.getenv("THEBE_API_KEY", "")
MIN_ALIGNMENT_SCORE: float = float(os.getenv("THEBE_MIN_ALIGNMENT_SCORE", "0.85"))
GUARDIAN_URL: str = os.getenv("THEBE_GUARDIAN_URL", "http://planner:8000").rstrip("/")
GUARDIAN_BEARER: str = os.getenv("THEBE_GUARDIAN_BEARER_TOKEN", "")

# ---------------------------------------------------------------------------
# High-risk tool catalogue (used in dev mode)
# ---------------------------------------------------------------------------

# Tools that warrant a human-approval gate even when intent is aligned.
_HIGH_RISK_TOOLS: frozenset[str] = frozenset(
    {
        "shell_execute",
        "bash",
        "run_command",
        "exec",
        "write_file",
        "delete_file",
        "remove_file",
        "move_file",
        "send_email",
        "send_message",
        "db_query",
        "sql_execute",
        "http_request",
        "fetch_url",
        "stripe_charge",
        "payment_execute",
        "create_webhook",
        "deploy",
    }
)

# Regex patterns inside stringified args that signal destructive intent.
# Kept as compiled patterns for efficiency across many requests.
_DESTRUCTIVE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"rm\s+-[rRfF]+",           # rm -rf / rm -fr
        r"drop\s+table",            # SQL DROP TABLE
        r"truncate\s+table",        # SQL TRUNCATE TABLE
        r"delete\s+from",           # SQL DELETE FROM
        r"format\s+(disk|drive|/)", # disk formatting
        r"--force",                 # force flags
        r"shutdown\s+(-h|-r|now)",  # system shutdown/reboot
        r":\s*\(\)\s*\{.*\}\s*;",  # fork bomb pattern
        r">\s*/dev/(sd|hd|nvme)",   # direct disk writes
    ]
]

# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class ValidateRequest(BaseModel):
    userIntent: str
    toolName: str
    args: dict[str, Any]
    sessionId: str


class ValidateResponse(BaseModel):
    decision: str           # "ALLOW" | "DENY"
    reasoning_trace: str
    requires_human_approval: bool
    alignment_score: float


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Thebe Proxy",
    description="Agentic Guardian Bridge for OpenClaw",
    version="1.0.0",
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _enforce_api_key(x_thebe_key: str | None) -> None:
    """Reject requests that do not carry the correct API key.

    If THEBE_API_KEY is not set the check is skipped (useful in isolated
    local dev environments, but not recommended for production).
    """
    if THEBE_API_KEY and x_thebe_key != THEBE_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-Thebe-Key header.",
        )


def _lightweight_evaluate(req: ValidateRequest) -> ValidateResponse:
    """Lightweight intent-alignment heuristic for dev / demo mode.

    NOT a replacement for the full Guardian stack.  This check is
    intentionally simple to keep demo setup friction-free.

    Algorithm
    ---------
    1. Scan stringified args for known destructive patterns.
    2. Compute a naive token-overlap score between intent words and tool name.
    3. Apply the MIN_ALIGNMENT_SCORE threshold.
    4. Flag high-risk tool names for human approval.
    """
    args_str = str(req.args)

    # 1. Destructive-pattern scan
    matched = [p.pattern for p in _DESTRUCTIVE_PATTERNS if p.search(args_str)]
    if matched:
        return ValidateResponse(
            decision="DENY",
            reasoning_trace=(
                f"Destructive pattern(s) detected in args: {matched}. "
                f"Original intent was: '{req.userIntent}'. "
                "The proposed action does not align with the stated goal."
            ),
            requires_human_approval=False,
            alignment_score=0.0,
        )

    # 2. Naive token-overlap alignment score
    intent_tokens = set(req.userIntent.lower().split())
    tool_tokens = set(req.toolName.lower().replace("_", " ").split())
    overlap = len(intent_tokens & tool_tokens) / max(len(tool_tokens), 1)
    score = round(min(1.0, 0.70 + overlap * 0.30), 4)

    # 3. Threshold check
    if score < MIN_ALIGNMENT_SCORE:
        return ValidateResponse(
            decision="DENY",
            reasoning_trace=(
                f"Alignment score {score:.3f} is below threshold {MIN_ALIGNMENT_SCORE}. "
                f"Tool '{req.toolName}' does not appear related to "
                f"the stated intent: '{req.userIntent}'."
            ),
            requires_human_approval=False,
            alignment_score=score,
        )

    # 4. High-risk gate
    is_high_risk = req.toolName in _HIGH_RISK_TOOLS

    return ValidateResponse(
        decision="ALLOW",
        reasoning_trace=(
            f"Intent aligned (score {score:.3f}). "
            f"Tool '{req.toolName}' is permitted for goal: '{req.userIntent[:80]}'."
        ),
        requires_human_approval=is_high_risk,
        alignment_score=score,
    )


async def _guardian_evaluate(req: ValidateRequest) -> ValidateResponse:
    """Delegate evaluation to the full Agentic Guardian stack.

    Calls the Planner's /plan-fast endpoint which orchestrates:
      Intent Engine (semantic embedding + signing) →
      Safety Agent (OPA policy evaluation) →
      Returns a blocked/allowed verdict with reasoning.

    Authentication
    --------------
    Requires a valid Bearer token in THEBE_GUARDIAN_BEARER_TOKEN.
    In a production deployment this token is obtained via Auth0 M2M
    client-credentials flow prior to calling this function.
    """
    plan_payload = {
        "user_goal": req.userIntent,
        "user_id": req.sessionId,
        "context": {
            "tool_name": req.toolName,
            "args": req.args,
            "session_id": req.sessionId,
        },
    }

    headers: dict[str, str] = {"Content-Type": "application/json"}
    if GUARDIAN_BEARER:
        headers["Authorization"] = f"Bearer {GUARDIAN_BEARER}"

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                f"{GUARDIAN_URL}/plan-fast",
                json=plan_payload,
                headers=headers,
            )
            response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        logger.error(
            "Guardian returned HTTP %d: %s",
            exc.response.status_code,
            exc.response.text[:200],
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Guardian returned HTTP {exc.response.status_code}.",
        )
    except httpx.RequestError as exc:
        logger.error("Failed to reach Guardian at %s: %s", GUARDIAN_URL, exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Guardian is unreachable. Check THEBE_GUARDIAN_URL.",
        )

    data: dict[str, Any] = response.json()
    blocked: bool = data.get("blocked", False)
    block_reason: str = data.get("block_reason", "")

    return ValidateResponse(
        decision="DENY" if blocked else "ALLOW",
        reasoning_trace=block_reason if blocked else "Agentic Guardian approved.",
        requires_human_approval=False,
        alignment_score=0.0 if blocked else 1.0,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.post("/validate", response_model=ValidateResponse)
async def validate(
    req: ValidateRequest,
    x_thebe_key: str | None = Header(default=None),
) -> ValidateResponse:
    """Validate a proposed OpenClaw tool call against the Agentic Guardian.

    Returns a verdict indicating whether the action should be allowed,
    denied, or escalated for human approval.
    """
    _enforce_api_key(x_thebe_key)

    logger.info(
        "session=%s tool=%s intent='%s'",
        req.sessionId,
        req.toolName,
        req.userIntent[:80],
    )

    if DEV_MODE:
        verdict = _lightweight_evaluate(req)
    else:
        verdict = await _guardian_evaluate(req)

    logger.info(
        "session=%s tool=%s decision=%s score=%.3f human_approval=%s",
        req.sessionId,
        req.toolName,
        verdict.decision,
        verdict.alignment_score,
        verdict.requires_human_approval,
    )
    return verdict


@app.get("/health")
async def health() -> dict[str, Any]:
    """Liveness probe used by Docker Compose and Kubernetes readiness checks."""
    return {
        "status": "ok",
        "dev_mode": DEV_MODE,
        "guardian_url": GUARDIAN_URL if not DEV_MODE else None,
        "min_alignment_score": MIN_ALIGNMENT_SCORE,
    }
