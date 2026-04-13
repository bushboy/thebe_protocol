"""Pydantic data models for the Rules Management API."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal, Optional, Union

from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class RuleSource(str, Enum):
    opa = "opa"
    safety_agent = "safety_agent"


class RuleMode(str, Enum):
    form = "form"
    dsl = "dsl"
    raw = "raw"


class ConditionOperator(str, Enum):
    eq = "eq"
    neq = "neq"
    gt = "gt"
    gte = "gte"
    lt = "lt"
    lte = "lte"
    contains = "contains"
    startswith = "startswith"
    not_contains = "not_contains"


class ConditionType(str, Enum):
    action_equals = "action_equals"
    provider_equals = "provider_equals"
    role_equals = "role_equals"
    cost_threshold = "cost_threshold"
    action_category = "action_category"
    intent_score = "intent_score"


# ---------------------------------------------------------------------------
# Parameter descriptor (for system rules with editable params)
# ---------------------------------------------------------------------------


class RuleParameter(BaseModel):
    name: str = Field(..., description="Machine-readable parameter key")
    label: str = Field(..., description="Human-readable label for the UI")
    type: Literal["number", "string", "boolean"] = Field(
        ..., description="Value type"
    )
    default: Any = Field(..., description="Default value")
    minimum: Optional[float] = Field(
        None, description="Minimum value (numeric params only)"
    )
    maximum: Optional[float] = Field(
        None, description="Maximum value (numeric params only)"
    )
    description: str = Field("", description="Tooltip description")


# ---------------------------------------------------------------------------
# System Rule manifest models
# ---------------------------------------------------------------------------


class SystemRule(BaseModel):
    """Static descriptor of a system-embedded rule (read from manifest)."""

    rule_id: str
    name: str
    category: str
    source: RuleSource
    opa_policy_id: Optional[str] = None
    opa_rule_block: Optional[str] = None
    parameters: list[RuleParameter] = []
    enabled_by_default: bool = True
    description: str = ""


class SystemRuleState(BaseModel):
    """Persisted runtime state of a system rule."""

    rule_id: str
    enabled: bool
    param_values: dict[str, Any] = {}
    last_modified: datetime
    modified_by: str = "system"


class SystemRuleResponse(BaseModel):
    """Response shape for a system rule (manifest + runtime state merged)."""

    rule_id: str
    name: str
    category: str
    source: RuleSource
    enabled: bool
    parameters: list[RuleParameter]
    param_values: dict[str, Any]
    opa_rule_block: Optional[str]
    last_modified: datetime
    description: str = ""


# ---------------------------------------------------------------------------
# Toggle / Param-update request models
# ---------------------------------------------------------------------------


class ToggleRequest(BaseModel):
    enabled: bool


class ParamUpdateRequest(BaseModel):
    param_values: dict[str, Any] = Field(
        ..., description="Key/value map of parameter name → new value"
    )


# ---------------------------------------------------------------------------
# Custom Rule — condition building blocks
# ---------------------------------------------------------------------------


class FormCondition(BaseModel):
    """A single condition in a Form-mode rule."""

    type: ConditionType
    operator: ConditionOperator
    value: Union[str, float, bool]

    @field_validator("operator")
    @classmethod
    def operator_compatible_with_type(
        cls, v: ConditionOperator, info: Any
    ) -> ConditionOperator:
        numeric_types = {ConditionType.cost_threshold, ConditionType.intent_score}
        string_types = {
            ConditionType.action_equals,
            ConditionType.provider_equals,
            ConditionType.role_equals,
            ConditionType.action_category,
        }
        numeric_ops = {
            ConditionOperator.gt,
            ConditionOperator.gte,
            ConditionOperator.lt,
            ConditionOperator.lte,
        }
        string_only_ops = {
            ConditionOperator.contains,
            ConditionOperator.startswith,
            ConditionOperator.not_contains,
        }

        condition_type = info.data.get("type")
        if condition_type in numeric_types and v in string_only_ops:
            raise ValueError(
                f"Operator '{v}' is not valid for numeric condition type '{condition_type}'"
            )
        if condition_type in string_types and v in numeric_ops:
            raise ValueError(
                f"Operator '{v}' is not valid for string condition type '{condition_type}'"
            )
        return v


class DSLLeafCondition(BaseModel):
    """A leaf condition in a DSL-mode rule tree."""

    field: str = Field(
        ...,
        description="OPA input field path, e.g. 'input.provider' or 'input.context.role'",
    )
    op: ConditionOperator
    value: Union[str, float, bool]


class DSLConditionNode(BaseModel):
    """A logical AND/OR node in a DSL-mode rule tree."""

    op: Literal["AND", "OR"]
    conditions: list[Union[DSLConditionNode, DSLLeafCondition]] = Field(
        ..., min_length=1
    )


DSLConditionNode.model_rebuild()


# ---------------------------------------------------------------------------
# Custom Rule — request / storage / response models
# ---------------------------------------------------------------------------


class CreateCustomRuleRequest(BaseModel):
    """Request body for POST /rules/custom and PUT /rules/custom/{id}."""

    mode: RuleMode
    name: str = Field(..., min_length=1, max_length=100)
    category: str = Field(..., min_length=1, max_length=50)
    description: str = ""
    enabled: bool = True

    # Form mode fields
    conditions: Optional[list[FormCondition]] = None
    deny_message: Optional[str] = None

    # DSL mode fields
    rule: Optional[DSLConditionNode] = None
    deny_message_template: Optional[str] = None

    # Raw mode field
    rego: Optional[str] = None

    @model_validator(mode="after")
    def validate_mode_fields(self) -> CreateCustomRuleRequest:
        if self.mode == RuleMode.form:
            if not self.conditions:
                raise ValueError("Form mode requires at least one condition")
            if not self.deny_message:
                raise ValueError("Form mode requires a deny_message")
        elif self.mode == RuleMode.dsl:
            if self.rule is None:
                raise ValueError("DSL mode requires a 'rule' condition tree")
            if not self.deny_message_template:
                raise ValueError("DSL mode requires a deny_message_template")
        elif self.mode == RuleMode.raw:
            if not self.rego:
                raise ValueError("Raw mode requires a 'rego' string")
        return self


class CustomRule(BaseModel):
    """Full stored representation of a custom rule."""

    rule_id: str
    mode: RuleMode
    name: str
    category: str
    description: str
    enabled: bool
    source_definition: dict = Field(
        ..., description="Original request payload stored verbatim"
    )
    generated_rego: str = Field(
        ..., description="Transpiled Rego that is deployed to OPA"
    )
    opa_policy_id: str = Field(
        ..., description="Policy ID used in OPA (custom_<uuid_prefix>)"
    )
    created_at: datetime
    updated_at: datetime
    created_by: str = "system"


class CustomRuleResponse(BaseModel):
    """Public response shape for a custom rule."""

    rule_id: str
    mode: RuleMode
    name: str
    category: str
    description: str
    enabled: bool
    generated_rego: str
    created_at: datetime
    updated_at: datetime


# ---------------------------------------------------------------------------
# Test sandbox models
# ---------------------------------------------------------------------------


class TestRuleRequest(BaseModel):
    """Test a rule definition against a sample input without persisting."""

    mode: RuleMode

    # Form mode
    conditions: Optional[list[FormCondition]] = None
    deny_message: Optional[str] = None

    # DSL mode
    rule: Optional[DSLConditionNode] = None
    deny_message_template: Optional[str] = None

    # Raw mode
    rego: Optional[str] = None

    sample_input: dict = Field(
        ..., description="OPA input document to evaluate the rule against"
    )


class TestRuleResponse(BaseModel):
    generated_rego: str
    opa_decision: dict
    allow: bool
    deny_reasons: list[str]
    valid: bool
    validation_errors: list[str]


# ---------------------------------------------------------------------------
# Health response
# ---------------------------------------------------------------------------


class HealthResponse(BaseModel):
    status: Literal["healthy", "degraded", "unhealthy"]
    opa_reachable: bool
    store_readable: bool
    version: str = "1.0.0"


# ---------------------------------------------------------------------------
# Error response
# ---------------------------------------------------------------------------


class ErrorResponse(BaseModel):
    error: str
    message: str
