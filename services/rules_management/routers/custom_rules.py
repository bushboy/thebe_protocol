"""Router: custom rules — CRUD, toggle, and test sandbox."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status

from ..models import (
    CreateCustomRuleRequest,
    CustomRule,
    CustomRuleResponse,
    ErrorResponse,
    RuleMode,
    TestRuleRequest,
    TestRuleResponse,
    ToggleRequest,
)
from ..opa_manager import OPAError, OPAManager
from ..store import RulesStore
from ..transpiler import RegoTranspiler, TranspileError

router = APIRouter(prefix="/rules/custom", tags=["Custom Rules"])

_transpiler = RegoTranspiler()


def _transpile_test_request(body: TestRuleRequest) -> str:
    """Transpile a TestRuleRequest directly without Pydantic field-level validation.

    This avoids re-running the CreateCustomRuleRequest model_validator (which
    rejects empty/None conditions), allowing the transpiler itself to surface
    the error naturally for the test sandbox endpoint.
    """
    if body.mode == RuleMode.form:
        if not body.conditions:
            raise TranspileError("Form mode requires at least one condition")
        if not body.deny_message:
            raise TranspileError("Form mode requires a deny_message")
        # Build a minimal stub that satisfies transpile_form attribute access
        class _Stub:
            mode = RuleMode.form
            name = "__test__"
            conditions = body.conditions
            deny_message = body.deny_message
        return _transpiler.transpile_form(_Stub(), rule_id="__test__")  # type: ignore[arg-type]

    if body.mode == RuleMode.dsl:
        if body.rule is None:
            raise TranspileError("DSL mode requires a 'rule' condition tree")
        if not body.deny_message_template:
            raise TranspileError("DSL mode requires a deny_message_template")

        class _DslStub:
            mode = RuleMode.dsl
            name = "__test__"
            rule = body.rule
            deny_message_template = body.deny_message_template
        return _transpiler.transpile_dsl(_DslStub(), rule_id="__test__")  # type: ignore[arg-type]

    if body.mode == RuleMode.raw:
        if not body.rego:
            raise TranspileError("Raw mode requires a 'rego' string")

        class _RawStub:
            mode = RuleMode.raw
            name = "__test__"
            rego = body.rego
        return _transpiler.wrap_raw(_RawStub(), rule_id="__test__")  # type: ignore[arg-type]

    raise TranspileError(f"Unknown rule mode: {body.mode}")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _get_store() -> RulesStore:
    from ..main import get_store
    return get_store()


def _get_opa() -> OPAManager:
    from ..main import get_opa
    return get_opa()


def _to_response(rule: CustomRule) -> CustomRuleResponse:
    return CustomRuleResponse(
        rule_id=rule.rule_id,
        mode=rule.mode,
        name=rule.name,
        category=rule.category,
        description=rule.description,
        enabled=rule.enabled,
        generated_rego=rule.generated_rego,
        created_at=rule.created_at,
        updated_at=rule.updated_at,
    )


def _opa_policy_id(rule_id: str) -> str:
    """Derive a safe OPA policy ID from a UUID."""
    return f"custom_{rule_id.replace('-', '_')}"


# ---------------------------------------------------------------------------
# GET /rules/custom
# ---------------------------------------------------------------------------


@router.get("", response_model=list[CustomRuleResponse])
async def list_custom_rules(
    store: RulesStore = Depends(_get_store),
) -> list[CustomRuleResponse]:
    """Return all custom rules."""
    return [_to_response(r) for r in store.list_custom_rules()]


# ---------------------------------------------------------------------------
# GET /rules/custom/{rule_id}
# ---------------------------------------------------------------------------


@router.get(
    "/{rule_id}",
    response_model=CustomRuleResponse,
    responses={404: {"model": ErrorResponse}},
)
async def get_custom_rule(
    rule_id: str,
    store: RulesStore = Depends(_get_store),
) -> CustomRuleResponse:
    """Return a single custom rule including its generated Rego."""
    rule = store.get_custom_rule(rule_id)
    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=ErrorResponse(
                error="rule_not_found",
                message=f"Custom rule '{rule_id}' does not exist",
            ).model_dump(),
        )
    return _to_response(rule)


# ---------------------------------------------------------------------------
# POST /rules/custom/test   (must be declared before /{rule_id} routes)
# ---------------------------------------------------------------------------


@router.post(
    "/test",
    response_model=TestRuleResponse,
    responses={422: {"model": ErrorResponse}, 502: {"model": ErrorResponse}},
)
async def test_rule(
    body: TestRuleRequest,
    opa: OPAManager = Depends(_get_opa),
) -> TestRuleResponse:
    """Test a rule definition against a sample input without persisting or deploying.

    The rule is deployed to OPA as a temporary policy, evaluated, then removed.
    """
    # Transpile directly from TestRuleRequest fields, bypassing CreateCustomRuleRequest
    # validators (which reject incomplete/empty conditions used in error-path tests).
    try:
        generated_rego = _transpile_test_request(body)
    except TranspileError as exc:
        return TestRuleResponse(
            generated_rego="",
            opa_decision={},
            allow=False,
            deny_reasons=[],
            valid=False,
            validation_errors=[str(exc)],
        )

    # Compile check
    compile_errors = await opa.compile_check(generated_rego)
    if compile_errors:
        return TestRuleResponse(
            generated_rego=generated_rego,
            opa_decision={},
            allow=False,
            deny_reasons=[],
            valid=False,
            validation_errors=compile_errors,
        )

    # Evaluate against sample input (deploy, evaluate, clean up)
    try:
        opa_decision = await opa.evaluate_with_policy(generated_rego, body.sample_input)
    except OPAError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=ErrorResponse(
                error="opa_unavailable",
                message=str(exc),
            ).model_dump(),
        ) from exc

    allow: bool = opa_decision.get("allow", True)
    deny_reasons: list[str] = list(opa_decision.get("deny_reasons", []))

    return TestRuleResponse(
        generated_rego=generated_rego,
        opa_decision=opa_decision,
        allow=allow,
        deny_reasons=deny_reasons,
        valid=True,
        validation_errors=[],
    )


# ---------------------------------------------------------------------------
# POST /rules/custom
# ---------------------------------------------------------------------------


@router.post(
    "",
    response_model=CustomRuleResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        409: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
        502: {"model": ErrorResponse},
    },
)
async def create_custom_rule(
    body: CreateCustomRuleRequest,
    store: RulesStore = Depends(_get_store),
    opa: OPAManager = Depends(_get_opa),
) -> CustomRuleResponse:
    """Create and deploy a new custom rule (form, dsl, or raw mode)."""
    rule_id = str(uuid.uuid4())

    # Transpile
    try:
        generated_rego = _transpiler.transpile(body, rule_id)
    except TranspileError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=ErrorResponse(
                error="transpile_error",
                message=str(exc),
            ).model_dump(),
        ) from exc

    # Compile check
    compile_errors = await opa.compile_check(generated_rego)
    if compile_errors:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=ErrorResponse(
                error="invalid_rego",
                message="; ".join(compile_errors),
            ).model_dump(),
        )

    opa_id = _opa_policy_id(rule_id)
    now = _utcnow()

    rule = CustomRule(
        rule_id=rule_id,
        mode=body.mode,
        name=body.name,
        category=body.category,
        description=body.description,
        enabled=body.enabled,
        source_definition=body.model_dump(mode="json"),
        generated_rego=generated_rego,
        opa_policy_id=opa_id,
        created_at=now,
        updated_at=now,
    )

    # Persist first, then deploy (so we can clean up if OPA fails)
    try:
        store.add_custom_rule(rule)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=ErrorResponse(
                error="rule_id_conflict",
                message=str(exc),
            ).model_dump(),
        ) from exc

    # Deploy to OPA only if rule is enabled
    if body.enabled:
        try:
            await opa.put_policy(opa_id, generated_rego)
        except OPAError as exc:
            # Roll back store entry
            try:
                store.delete_custom_rule(rule_id)
            except KeyError:
                pass
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=ErrorResponse(
                    error="opa_unavailable",
                    message=f"Rule saved but OPA deployment failed: {exc}",
                ).model_dump(),
            ) from exc

    return _to_response(rule)


# ---------------------------------------------------------------------------
# PUT /rules/custom/{rule_id}
# ---------------------------------------------------------------------------


@router.put(
    "/{rule_id}",
    response_model=CustomRuleResponse,
    responses={
        404: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
        502: {"model": ErrorResponse},
    },
)
async def update_custom_rule(
    rule_id: str,
    body: CreateCustomRuleRequest,
    store: RulesStore = Depends(_get_store),
    opa: OPAManager = Depends(_get_opa),
) -> CustomRuleResponse:
    """Replace an existing custom rule with a new definition."""
    existing = store.get_custom_rule(rule_id)
    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=ErrorResponse(
                error="rule_not_found",
                message=f"Custom rule '{rule_id}' does not exist",
            ).model_dump(),
        )

    try:
        generated_rego = _transpiler.transpile(body, rule_id)
    except TranspileError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=ErrorResponse(
                error="transpile_error",
                message=str(exc),
            ).model_dump(),
        ) from exc

    compile_errors = await opa.compile_check(generated_rego)
    if compile_errors:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=ErrorResponse(
                error="invalid_rego",
                message="; ".join(compile_errors),
            ).model_dump(),
        )

    updated_rule = CustomRule(
        rule_id=rule_id,
        mode=body.mode,
        name=body.name,
        category=body.category,
        description=body.description,
        enabled=body.enabled,
        source_definition=body.model_dump(mode="json"),
        generated_rego=generated_rego,
        opa_policy_id=existing.opa_policy_id,
        created_at=existing.created_at,
        updated_at=_utcnow(),
        created_by=existing.created_by,
    )

    store.update_custom_rule(updated_rule)

    opa_id = existing.opa_policy_id
    try:
        if body.enabled:
            await opa.put_policy(opa_id, generated_rego)
        else:
            await opa.delete_policy(opa_id)
    except OPAError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=ErrorResponse(
                error="opa_unavailable",
                message=f"Rule updated in store but OPA sync failed: {exc}",
            ).model_dump(),
        ) from exc

    return _to_response(updated_rule)


# ---------------------------------------------------------------------------
# POST /rules/custom/{rule_id}/toggle
# ---------------------------------------------------------------------------


@router.post(
    "/{rule_id}/toggle",
    response_model=CustomRuleResponse,
    responses={404: {"model": ErrorResponse}, 502: {"model": ErrorResponse}},
)
async def toggle_custom_rule(
    rule_id: str,
    body: ToggleRequest,
    store: RulesStore = Depends(_get_store),
    opa: OPAManager = Depends(_get_opa),
) -> CustomRuleResponse:
    """Enable or disable a custom rule without changing its definition."""
    rule = store.get_custom_rule(rule_id)
    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=ErrorResponse(
                error="rule_not_found",
                message=f"Custom rule '{rule_id}' does not exist",
            ).model_dump(),
        )

    rule.enabled = body.enabled
    rule.updated_at = _utcnow()
    store.update_custom_rule(rule)

    try:
        if body.enabled:
            await opa.put_policy(rule.opa_policy_id, rule.generated_rego)
        else:
            await opa.delete_policy(rule.opa_policy_id)
    except OPAError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=ErrorResponse(
                error="opa_unavailable",
                message=f"Toggle saved but OPA sync failed: {exc}",
            ).model_dump(),
        ) from exc

    return _to_response(rule)


# ---------------------------------------------------------------------------
# DELETE /rules/custom/{rule_id}
# ---------------------------------------------------------------------------


@router.delete(
    "/{rule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    responses={404: {"model": ErrorResponse}, 502: {"model": ErrorResponse}},
)
async def delete_custom_rule(
    rule_id: str,
    store: RulesStore = Depends(_get_store),
    opa: OPAManager = Depends(_get_opa),
) -> None:
    """Delete a custom rule and remove it from OPA."""
    rule = store.get_custom_rule(rule_id)
    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=ErrorResponse(
                error="rule_not_found",
                message=f"Custom rule '{rule_id}' does not exist",
            ).model_dump(),
        )

    # Remove from OPA first (best effort)
    try:
        await opa.delete_policy(rule.opa_policy_id)
    except OPAError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=ErrorResponse(
                error="opa_unavailable",
                message=f"OPA removal failed; rule NOT deleted from store: {exc}",
            ).model_dump(),
        ) from exc

    try:
        store.delete_custom_rule(rule_id)
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=ErrorResponse(
                error="rule_not_found",
                message=str(exc),
            ).model_dump(),
        ) from exc
