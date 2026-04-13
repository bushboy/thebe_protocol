"""RegoTranspiler — converts Form and DSL rule definitions into Rego policy strings.

The transpiler is a pure function module with no side effects.  It produces
complete, stand-alone Rego modules (including the package declaration) that
can be POSTed directly to OPA's /v1/policies/{id} endpoint.
"""

from __future__ import annotations

import re
from typing import Union

from .models import (
    ConditionOperator,
    ConditionType,
    CreateCustomRuleRequest,
    DSLConditionNode,
    DSLLeafCondition,
    FormCondition,
    RuleMode,
)

# Mapping from ConditionType to the OPA input field path
_FIELD_MAP: dict[ConditionType, str] = {
    ConditionType.action_equals: "input.action",
    ConditionType.provider_equals: "input.provider",
    ConditionType.role_equals: "input.context.role",
    ConditionType.cost_threshold: "input.estimated_cost",
    ConditionType.action_category: "input.action_category",
    ConditionType.intent_score: "input.intent_alignment_score",
}

# Mapping from ConditionOperator to Rego comparison operator
_OP_MAP: dict[ConditionOperator, str] = {
    ConditionOperator.eq: "==",
    ConditionOperator.neq: "!=",
    ConditionOperator.gt: ">",
    ConditionOperator.gte: ">=",
    ConditionOperator.lt: "<",
    ConditionOperator.lte: "<=",
}

# Placeholders in deny_message_template that map to sprintf format strings
_TEMPLATE_FIELD_RE = re.compile(r"\{\{(input\.[^}]+)\}\}")


class TranspileError(ValueError):
    """Raised when a rule definition cannot be converted to valid Rego."""


class RegoTranspiler:
    """Converts Form and DSL rule definitions to Rego deny[msg] blocks."""

    PACKAGE = "package agentic_guardian"

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def transpile(self, rule: CreateCustomRuleRequest, rule_id: str) -> str:
        """Return a complete Rego module string for the given rule."""
        if rule.mode == RuleMode.form:
            return self.transpile_form(rule, rule_id)
        if rule.mode == RuleMode.dsl:
            return self.transpile_dsl(rule, rule_id)
        if rule.mode == RuleMode.raw:
            return self.wrap_raw(rule, rule_id)
        raise TranspileError(f"Unknown rule mode: {rule.mode}")

    # ------------------------------------------------------------------
    # Form mode
    # ------------------------------------------------------------------

    def transpile_form(self, rule: CreateCustomRuleRequest, rule_id: str) -> str:
        """Transpile a Form rule to a single deny[msg] block."""
        if not rule.conditions:
            raise TranspileError("Form rule must have at least one condition")
        if not rule.deny_message:
            raise TranspileError("Form rule must have a deny_message")

        lines: list[str] = [
            self.PACKAGE,
            "",
            f"# Rule: {rule.name} (id: {rule_id})",
            "deny[msg] {",
            f'    not "{rule_id}" in data.rules_config.custom_disabled_rules',
        ]
        for cond in rule.conditions:
            lines.append(f"    {self._form_condition_to_rego(cond)}")

        # Escape any double-quotes inside the message
        safe_msg = rule.deny_message.replace('"', '\\"')
        lines.append(f'    msg := "{safe_msg}"')
        lines.append("}")

        return "\n".join(lines)

    def _form_condition_to_rego(self, condition: FormCondition) -> str:
        field = _FIELD_MAP[condition.type]
        value = condition.value

        if condition.operator == ConditionOperator.contains:
            return f'contains({field}, {self._rego_value(value)})'
        if condition.operator == ConditionOperator.startswith:
            return f'startswith({field}, {self._rego_value(value)})'
        if condition.operator == ConditionOperator.not_contains:
            return f'not contains({field}, {self._rego_value(value)})'

        op_str = _OP_MAP.get(condition.operator)
        if op_str is None:
            raise TranspileError(
                f"Unsupported operator '{condition.operator}' for form condition"
            )
        return f"{field} {op_str} {self._rego_value(value)}"

    # ------------------------------------------------------------------
    # DSL mode
    # ------------------------------------------------------------------

    def transpile_dsl(self, rule: CreateCustomRuleRequest, rule_id: str) -> str:
        """Transpile a DSL rule tree to one or more deny[msg] blocks."""
        if rule.rule is None:
            raise TranspileError("DSL rule must have a 'rule' condition tree")
        if not rule.deny_message_template:
            raise TranspileError("DSL rule must have a deny_message_template")

        msg_expr = self._template_to_rego(rule.deny_message_template)

        lines: list[str] = [
            self.PACKAGE,
            "",
            f"# Rule: {rule.name} (id: {rule_id})",
        ]

        # OR nodes produce multiple deny blocks; AND nodes produce one
        if rule.rule.op == "OR":
            # Each child of the top-level OR becomes its own deny block
            for child in rule.rule.conditions:
                child_lines = self._flatten_node(child)
                lines.append("deny[msg] {")
                lines.append(
                    f'    not "{rule_id}" in data.rules_config.custom_disabled_rules'
                )
                for cl in child_lines:
                    lines.append(f"    {cl}")
                lines.append(f"    {msg_expr}")
                lines.append("}")
                lines.append("")
        else:
            body_lines = self._flatten_node(rule.rule)
            lines.append("deny[msg] {")
            lines.append(
                f'    not "{rule_id}" in data.rules_config.custom_disabled_rules'
            )
            for bl in body_lines:
                lines.append(f"    {bl}")
            lines.append(f"    {msg_expr}")
            lines.append("}")

        return "\n".join(lines)

    def _node_to_rego_lines(
        self, node: Union[DSLConditionNode, DSLLeafCondition]
    ) -> list[str]:
        """Flatten an AND node (or leaf) into a list of Rego body lines.

        Only called when the top-level op is AND; the OR path is handled
        separately in transpile_dsl before this method is reached.
        """
        return self._flatten_node(node)

    def _flatten_node(
        self, node: Union[DSLConditionNode, DSLLeafCondition]
    ) -> list[str]:
        """Recursively flatten a condition node into Rego body lines.

        Supports AND nesting.  A leaf produces one line.  Nested OR is not
        supported — callers that need OR must split at the top level.
        """
        if isinstance(node, DSLLeafCondition):
            return [self._dsl_leaf_to_rego(node)]
        if node.op == "AND":
            result: list[str] = []
            for child in node.conditions:
                result.extend(self._flatten_node(child))
            return result
        raise TranspileError(
            "Nested OR inside a condition tree is not supported. "
            "Use a top-level OR node to generate multiple deny blocks."
        )

    def _dsl_leaf_to_rego(self, leaf: DSLLeafCondition) -> str:
        field = leaf.field
        value = leaf.value

        if leaf.op == ConditionOperator.contains:
            return f"contains({field}, {self._rego_value(value)})"
        if leaf.op == ConditionOperator.startswith:
            return f"startswith({field}, {self._rego_value(value)})"
        if leaf.op == ConditionOperator.not_contains:
            return f"not contains({field}, {self._rego_value(value)})"

        op_str = _OP_MAP.get(leaf.op)
        if op_str is None:
            raise TranspileError(f"Unsupported DSL operator: {leaf.op}")
        return f"{field} {op_str} {self._rego_value(value)}"

    def _template_to_rego(self, template: str) -> str:
        """Convert a message template with {{input.field}} placeholders to a
        Rego sprintf assignment."""
        placeholders = _TEMPLATE_FIELD_RE.findall(template)
        if not placeholders:
            safe = template.replace('"', '\\"')
            return f'msg := "{safe}"'

        # Replace each {{input.field}} with %s
        fmt_str = _TEMPLATE_FIELD_RE.sub("%s", template)
        fmt_str = fmt_str.replace('"', '\\"')
        fields = ", ".join(placeholders)
        return f'msg := sprintf("{fmt_str}", [{fields}])'

    # ------------------------------------------------------------------
    # Raw mode
    # ------------------------------------------------------------------

    def wrap_raw(self, rule: CreateCustomRuleRequest, rule_id: str) -> str:
        """Wrap raw Rego with package declaration if not already present."""
        if rule.rego is None:
            raise TranspileError("Raw mode requires a 'rego' string")

        rego = rule.rego.strip()

        # Structural validation: must contain deny[msg]
        if "deny[msg]" not in rego:
            raise TranspileError(
                "Raw Rego must contain at least one 'deny[msg]' rule"
            )

        # Safety: must not redefine allow or decision at the top level
        for forbidden in ("^allow\\s*[={]", "^decision\\s*[={]"):
            if re.search(forbidden, rego, re.MULTILINE):
                raise TranspileError(
                    "Raw Rego must not redefine 'allow' or 'decision' rules"
                )

        # Prepend package if absent
        if not rego.startswith("package"):
            rego = f"{self.PACKAGE}\n\n# Rule: {rule.name} (id: {rule_id})\n{rego}"

        return rego

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _rego_value(value: Union[str, float, bool]) -> str:
        """Format a Python value as a Rego literal."""
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, str):
            escaped = value.replace('"', '\\"')
            return f'"{escaped}"'
        # float / int
        return str(value)
