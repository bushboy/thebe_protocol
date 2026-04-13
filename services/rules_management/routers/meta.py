"""Router: meta endpoints — providers catalogue, schema, and health check."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from ..models import ErrorResponse, HealthResponse
from ..opa_manager import OPAManager
from ..store import RulesStore

router = APIRouter(tags=["Meta"])


def _get_store() -> RulesStore:
    from ..main import get_store
    return get_store()


def _get_opa() -> OPAManager:
    from ..main import get_opa
    return get_opa()


# ---------------------------------------------------------------------------
# GET /health
# ---------------------------------------------------------------------------


@router.get("/health", response_model=HealthResponse)
async def health(
    store: RulesStore = Depends(_get_store),
    opa: OPAManager = Depends(_get_opa),
) -> HealthResponse:
    """Service health — checks OPA connectivity and store readability."""
    opa_ok = await opa.health_check()
    store_ok = store.is_readable()

    if opa_ok and store_ok:
        svc_status = "healthy"
    elif store_ok:
        svc_status = "degraded"
    else:
        svc_status = "unhealthy"

    return HealthResponse(
        status=svc_status,
        opa_reachable=opa_ok,
        store_readable=store_ok,
        version="1.0.0",
    )


# ---------------------------------------------------------------------------
# GET /rules/providers
# ---------------------------------------------------------------------------

_PROVIDERS: dict[str, dict] = {
    "github": {
        "name": "GitHub",
        "description": "GitHub repository and branch management actions",
        "known_safe_actions": [
            "create_branch",
            "create_pr",
            "create_pull_request",
            "create_issue",
            "add_label",
            "add_assignee",
            "add_reviewer",
            "merge_pr",
            "merge_pull_request",
            "update_issue",
            "close_issue",
            "reopen_issue",
            "comment_on_issue",
            "comment_on_pr",
            "approve_review",
            "request_changes",
        ],
        "dangerous_actions": [
            "delete_branch",
            "delete_repository",
            "force_push",
        ],
    },
    "aws": {
        "name": "Amazon Web Services",
        "description": "AWS cloud resource management actions",
        "known_safe_actions": [
            "describe_instances",
            "describe_services",
            "list_objects",
            "read_logs",
        ],
        "dangerous_actions": [
            "create_instance",
            "terminate_instance",
        ],
    },
    "gcp": {
        "name": "Google Cloud Platform",
        "description": "GCP cloud resource management actions",
        "known_safe_actions": [
            "describe_instances",
            "list_resources",
            "read_logs",
        ],
        "dangerous_actions": [
            "provision_resources",
            "delete_resources",
        ],
    },
    "azure": {
        "name": "Microsoft Azure",
        "description": "Azure cloud resource management actions",
        "known_safe_actions": [
            "describe_instances",
            "list_resources",
            "read_logs",
        ],
        "dangerous_actions": [
            "deploy_infrastructure",
        ],
    },
    "slack": {
        "name": "Slack",
        "description": "Slack workspace messaging and channel management",
        "known_safe_actions": [
            "send_message",
            "post_message",
            "create_channel",
            "add_member",
            "update_channel_topic",
            "set_channel_description",
        ],
        "dangerous_actions": [],
    },
    "google_workspace": {
        "name": "Google Workspace",
        "description": "Google Docs, Sheets, and Slides management",
        "known_safe_actions": [
            "create_document",
            "update_document",
            "share_document",
            "create_spreadsheet",
            "create_presentation",
        ],
        "dangerous_actions": [],
    },
}


@router.get("/rules/providers")
async def list_providers() -> dict:
    """Return supported providers with their known safe and dangerous actions."""
    return {"providers": _PROVIDERS}


# ---------------------------------------------------------------------------
# GET /rules/schema
# ---------------------------------------------------------------------------

_CONDITION_TYPES = [
    {
        "type": "action_equals",
        "label": "Action",
        "field": "input.action",
        "value_type": "string",
        "allowed_operators": ["eq", "neq", "contains", "startswith", "not_contains"],
    },
    {
        "type": "provider_equals",
        "label": "Provider",
        "field": "input.provider",
        "value_type": "string",
        "allowed_operators": ["eq", "neq"],
    },
    {
        "type": "role_equals",
        "label": "Role",
        "field": "input.context.role",
        "value_type": "string",
        "allowed_operators": ["eq", "neq"],
    },
    {
        "type": "cost_threshold",
        "label": "Estimated Cost (USD)",
        "field": "input.estimated_cost",
        "value_type": "number",
        "allowed_operators": ["gt", "gte", "lt", "lte"],
    },
    {
        "type": "action_category",
        "label": "Action Category",
        "field": "input.action_category",
        "value_type": "string",
        "allowed_operators": ["eq", "neq"],
    },
    {
        "type": "intent_score",
        "label": "Intent Alignment Score",
        "field": "input.intent_alignment_score",
        "value_type": "number",
        "allowed_operators": ["gt", "gte", "lt", "lte"],
    },
]

_OPERATORS = [
    {"op": "eq",           "label": "equals"},
    {"op": "neq",          "label": "not equals"},
    {"op": "gt",           "label": "greater than"},
    {"op": "gte",          "label": "greater than or equal"},
    {"op": "lt",           "label": "less than"},
    {"op": "lte",          "label": "less than or equal"},
    {"op": "contains",     "label": "contains"},
    {"op": "startswith",   "label": "starts with"},
    {"op": "not_contains", "label": "does not contain"},
]

_CATEGORIES = [
    "github",
    "spending",
    "filesystem",
    "intent",
    "access_control",
    "security",
    "system",
    "slack",
    "google_workspace",
    "aws",
    "gcp",
    "azure",
    "custom",
]

_SAMPLE_INPUTS: dict[str, dict] = {
    "github": {
        "action": "delete_branch",
        "provider": "github",
        "action_category": "destructive",
        "estimated_cost": 0.0,
        "intent_alignment_score": 0.9,
        "context": {"role": "developer", "service": "guardian"},
        "action_params": {"repository": "org/repo", "branch": "feature/test"},
    },
    "spending": {
        "action": "create_instance",
        "provider": "aws",
        "action_category": "compute",
        "estimated_cost": 250.0,
        "intent_alignment_score": 0.95,
        "context": {"role": "developer", "spending_limit": 100.0},
        "action_params": {"instance_type": "m5.xlarge"},
    },
    "slack": {
        "action": "send_message",
        "provider": "slack",
        "action_category": "communication",
        "estimated_cost": 0.0,
        "intent_alignment_score": 0.92,
        "context": {"role": "developer"},
        "action_params": {"channel": "#general", "text": "Hello!"},
    },
    "default": {
        "action": "create_branch",
        "provider": "github",
        "action_category": "standard",
        "estimated_cost": 0.0,
        "intent_alignment_score": 0.85,
        "context": {
            "role": "developer",
            "service": "guardian",
            "allowed_categories": ["standard", "read"],
        },
        "action_params": {},
    },
}


@router.get("/rules/schema")
async def get_schema() -> dict:
    """Return the JSON schema for form/DSL rule building.

    Includes condition type descriptors, operator labels, allowed categories,
    and sample OPA input documents per category to pre-seed the test sandbox.
    """
    return {
        "condition_types": _CONDITION_TYPES,
        "operators": _OPERATORS,
        "categories": _CATEGORIES,
        "sample_inputs": _SAMPLE_INPUTS,
        "dsl_schema": {
            "description": "DSLConditionNode — JSON schema",
            "oneOf": [
                {
                    "type": "object",
                    "required": ["op", "conditions"],
                    "properties": {
                        "op": {"type": "string", "enum": ["AND", "OR"]},
                        "conditions": {"type": "array", "minItems": 1},
                    },
                },
                {
                    "type": "object",
                    "required": ["field", "op", "value"],
                    "properties": {
                        "field": {"type": "string"},
                        "op": {
                            "type": "string",
                            "enum": [o["op"] for o in _OPERATORS],
                        },
                        "value": {"oneOf": [{"type": "string"}, {"type": "number"}]},
                    },
                },
            ],
        },
    }
