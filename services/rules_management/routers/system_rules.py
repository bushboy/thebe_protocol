"""Router: system rules — list, toggle, and param-update."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status

from ..manifest import SYSTEM_RULES_BY_ID, SYSTEM_RULES_MANIFEST
from ..models import (
    ErrorResponse,
    ParamUpdateRequest,
    SystemRuleResponse,
    SystemRuleState,
    ToggleRequest,
)
from ..opa_manager import OPAError, OPAManager
from ..store import RulesStore
from shared.pendo import track_event

router = APIRouter(prefix="/rules/system", tags=["System Rules"])


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _get_store() -> RulesStore:
    from ..main import get_store
    return get_store()


def _get_opa() -> OPAManager:
    from ..main import get_opa
    return get_opa()


def _merge_rule_response(rule_id: str, store: RulesStore) -> SystemRuleResponse:
    """Merge manifest descriptor with persisted state into a response object."""
    manifest = SYSTEM_RULES_BY_ID.get(rule_id)
    if manifest is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=ErrorResponse(
                error="rule_not_found",
                message=f"System rule '{rule_id}' does not exist",
            ).model_dump(),
        )
    state = store.get_system_rule_state(rule_id)
    if state is None:
        # Initialise from manifest defaults on first access
        state = SystemRuleState(
            rule_id=rule_id,
            enabled=manifest.enabled_by_default,
            param_values={p.name: p.default for p in manifest.parameters},
            last_modified=_utcnow(),
        )
    return SystemRuleResponse(
        rule_id=manifest.rule_id,
        name=manifest.name,
        description=manifest.description,
        category=manifest.category,
        source=manifest.source,
        enabled=state.enabled,
        parameters=manifest.parameters,
        param_values=state.param_values,
        opa_rule_block=manifest.opa_rule_block,
        last_modified=state.last_modified,
    )


# ---------------------------------------------------------------------------
# GET /rules/system
# ---------------------------------------------------------------------------


@router.get("", response_model=list[SystemRuleResponse])
async def list_system_rules(
    store: RulesStore = Depends(_get_store),
) -> list[SystemRuleResponse]:
    """Return all system rules with their current enabled state and param values."""
    return [_merge_rule_response(r.rule_id, store) for r in SYSTEM_RULES_MANIFEST]


# ---------------------------------------------------------------------------
# POST /rules/system/{rule_id}/toggle
# ---------------------------------------------------------------------------


@router.post(
    "/{rule_id}/toggle",
    response_model=SystemRuleResponse,
    responses={404: {"model": ErrorResponse}, 502: {"model": ErrorResponse}},
)
async def toggle_system_rule(
    rule_id: str,
    body: ToggleRequest,
    store: RulesStore = Depends(_get_store),
    opa: OPAManager = Depends(_get_opa),
) -> SystemRuleResponse:
    """Enable or disable a system rule.

    For OPA-source rules the rules_config data document is updated so OPA
    picks up the change immediately.  For Safety Agent rules the change is
    reflected in rules_store.json which the Safety Agent reads on every
    evaluation.
    """
    manifest = SYSTEM_RULES_BY_ID.get(rule_id)
    if manifest is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=ErrorResponse(
                error="rule_not_found",
                message=f"System rule '{rule_id}' does not exist",
            ).model_dump(),
        )

    current_state = store.get_system_rule_state(rule_id)
    if current_state is None:
        current_state = SystemRuleState(
            rule_id=rule_id,
            enabled=manifest.enabled_by_default,
            param_values={p.name: p.default for p in manifest.parameters},
            last_modified=_utcnow(),
        )

    new_state = SystemRuleState(
        rule_id=rule_id,
        enabled=body.enabled,
        param_values=current_state.param_values,
        last_modified=_utcnow(),
        modified_by="api",
    )
    store.set_system_rule_state(new_state)

    # Push updated rules_config to OPA
    try:
        rules_config = store.build_rules_config()
        await opa.push_rules_config(rules_config)
    except OPAError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=ErrorResponse(
                error="opa_unavailable",
                message=f"Rule saved but OPA sync failed: {exc}",
            ).model_dump(),
        ) from exc

    await track_event(
        "system_rule_toggled",
        properties={
            "rule_id": rule_id,
            "rule_name": manifest.name[:100],
            "enabled": body.enabled,
            "category": manifest.category or "",
            "modified_by": "api",
        },
    )

    return _merge_rule_response(rule_id, store)


# ---------------------------------------------------------------------------
# PATCH /rules/system/{rule_id}/params
# ---------------------------------------------------------------------------


@router.patch(
    "/{rule_id}/params",
    response_model=SystemRuleResponse,
    responses={
        404: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
        502: {"model": ErrorResponse},
    },
)
async def update_system_rule_params(
    rule_id: str,
    body: ParamUpdateRequest,
    store: RulesStore = Depends(_get_store),
    opa: OPAManager = Depends(_get_opa),
) -> SystemRuleResponse:
    """Update the parameter values for a system rule (e.g. spending limit)."""
    manifest = SYSTEM_RULES_BY_ID.get(rule_id)
    if manifest is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=ErrorResponse(
                error="rule_not_found",
                message=f"System rule '{rule_id}' does not exist",
            ).model_dump(),
        )

    if not manifest.parameters:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=ErrorResponse(
                error="no_params",
                message=f"System rule '{rule_id}' has no configurable parameters",
            ).model_dump(),
        )

    # Validate param names and bounds
    param_descriptors = {p.name: p for p in manifest.parameters}
    validated: dict[str, Any] = {}
    for key, val in body.param_values.items():
        if key not in param_descriptors:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=ErrorResponse(
                    error="unknown_param",
                    message=f"Unknown parameter '{key}' for rule '{rule_id}'",
                ).model_dump(),
            )
        desc = param_descriptors[key]
        if desc.type == "number":
            try:
                num = float(val)
            except (TypeError, ValueError):
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=ErrorResponse(
                        error="invalid_param_type",
                        message=f"Parameter '{key}' must be a number",
                    ).model_dump(),
                )
            if desc.minimum is not None and num < desc.minimum:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=ErrorResponse(
                        error="param_out_of_range",
                        message=(
                            f"Parameter '{key}' value {num} is below "
                            f"minimum {desc.minimum}"
                        ),
                    ).model_dump(),
                )
            if desc.maximum is not None and num > desc.maximum:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=ErrorResponse(
                        error="param_out_of_range",
                        message=(
                            f"Parameter '{key}' value {num} exceeds "
                            f"maximum {desc.maximum}"
                        ),
                    ).model_dump(),
                )
            validated[key] = num
        else:
            validated[key] = val

    current_state = store.get_system_rule_state(rule_id)
    if current_state is None:
        current_state = SystemRuleState(
            rule_id=rule_id,
            enabled=manifest.enabled_by_default,
            param_values={p.name: p.default for p in manifest.parameters},
            last_modified=_utcnow(),
        )

    merged_params = {**current_state.param_values, **validated}
    new_state = SystemRuleState(
        rule_id=rule_id,
        enabled=current_state.enabled,
        param_values=merged_params,
        last_modified=_utcnow(),
        modified_by="api",
    )
    store.set_system_rule_state(new_state)

    try:
        rules_config = store.build_rules_config()
        await opa.push_rules_config(rules_config)
    except OPAError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=ErrorResponse(
                error="opa_unavailable",
                message=f"Params saved but OPA sync failed: {exc}",
            ).model_dump(),
        ) from exc

    await track_event(
        "system_rule_params_updated",
        properties={
            "rule_id": rule_id,
            "rule_name": manifest.name[:100],
            "updated_params": ", ".join(validated.keys())[:200],
            "param_count": len(validated),
            "category": manifest.category or "",
            "modified_by": "api",
        },
    )

    return _merge_rule_response(rule_id, store)


# ---------------------------------------------------------------------------
# DELETE /rules/system/{rule_id}  — always 405
# ---------------------------------------------------------------------------


@router.delete("/{rule_id}", status_code=status.HTTP_405_METHOD_NOT_ALLOWED)
async def delete_system_rule_forbidden(rule_id: str) -> ErrorResponse:
    """System rules cannot be deleted — only toggled."""
    raise HTTPException(
        status_code=status.HTTP_405_METHOD_NOT_ALLOWED,
        detail=ErrorResponse(
            error="method_not_allowed",
            message="System rules cannot be deleted. Use the toggle endpoint to disable them.",
        ).model_dump(),
    )


# ---------------------------------------------------------------------------
# POST /rules/system/initialize  — one-time Rego injection
# ---------------------------------------------------------------------------


@router.post(
    "/initialize",
    summary="One-time injection of disabled_rules guards into policies.rego",
    responses={502: {"model": ErrorResponse}},
)
async def initialize_system_policy(
    opa: OPAManager = Depends(_get_opa),
) -> dict:
    """Idempotent: inject 'not <rule_block> in data.rules_config.disabled_rules'
    into the monolithic policies.rego and reload it in OPA.

    Safe to call multiple times — already-present guards are skipped.
    """
    from ..config import config
    from ..manifest import SYSTEM_RULES_MANIFEST

    rule_block_map = {
        r.opa_rule_block: r.opa_rule_block
        for r in SYSTEM_RULES_MANIFEST
        if r.opa_rule_block
    }

    try:
        results = await opa.initialize_system_policy(
            policy_file=config.opa_policy_file,
            rule_block_map=rule_block_map,
        )
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=ErrorResponse(
                error="policy_file_not_found",
                message=str(exc),
            ).model_dump(),
        ) from exc
    except OPAError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=ErrorResponse(
                error="opa_unavailable",
                message=str(exc),
            ).model_dump(),
        ) from exc

    await track_event(
        "system_policy_initialized",
        properties={
            "rule_count": len(rule_block_map),
            "guards_injected": results.get("injected", 0) if isinstance(results, dict) else 0,
            "already_present_count": results.get("already_present", 0) if isinstance(results, dict) else 0,
        },
    )

    return {"status": "ok", "results": results}
