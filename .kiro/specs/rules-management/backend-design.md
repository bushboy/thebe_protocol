# Design Document: Rules Management API (Backend)

## Overview

The Rules Management API is a new FastAPI microservice that sits alongside the existing
Zero-Trust Agentic Guardian services. It provides a single control plane for:

1. **Surfacing and toggling** the rules already embedded in the system (OPA Rego policies
   and the Safety Agent Python whitelist / dangerous-pattern checks).
2. **Creating and deploying custom rules** at three levels of sophistication:
   - Structured Form rules (business users, no-code)
   - JSON DSL rules (power users, transpiled to Rego)
   - Raw Rego rules (policy engineers, full OPA power)

The service has **no coupling to the existing Guardian service codebases**. It
communicates with OPA through the OPA REST Management API and writes a shared
`rules_config.json` file that the Safety Agent reads before each evaluation.

---

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│                    Rules Management API                     │
│                   (FastAPI, port 8010)                      │
│                                                             │
│  POST /rules/system/{rule_id}/toggle                        │
│  PATCH /rules/system/{rule_id}/params                       │
│  GET  /rules/system                                         │
│                                                             │
│  GET  /rules/custom                                         │
│  POST /rules/custom          (form | dsl | raw)             │
│  PUT  /rules/custom/{rule_id}                               │
│  DELETE /rules/custom/{rule_id}                             │
│  POST /rules/custom/{rule_id}/toggle                        │
│  POST /rules/custom/test                                    │
│                                                             │
│  GET  /rules/providers                                      │
│  GET  /rules/schema                                         │
│  GET  /health                                               │
└───────────────┬──────────────────────────┬─────────────────┘
                │                          │
                ▼                          ▼
   ┌────────────────────┐      ┌──────────────────────────┐
   │  rules_store.json  │      │  OPA REST API            │
   │  (shared volume)   │      │  PUT /v1/policies/{id}   │
   │                    │      │  GET /v1/policies        │
   │  system_rules[]    │      │  DELETE /v1/policies/{id}│
   │  custom_rules[]    │      │  POST /v1/data (eval)    │
   └────────┬───────────┘      └──────────────────────────┘
            │
            ▼
   ┌─────────────────────┐
   │  Safety Agent       │
   │  (reads store on    │
   │   every evaluation) │
   └─────────────────────┘
```

---

## System Rules Registry

System rules are those already present in the codebase. They are **discovered at startup**
and persisted in `rules_store.json`. They cannot be deleted, only toggled and
parameterised.

### Rule Sources

| Source | Location | Discovery Method |
|---|---|---|
| OPA Rego | `infra/opa/policies.rego` | Static parse of `deny[msg]` blocks at startup |
| Safety Agent whitelist | `services/safety_agent/policy_evaluator.py` | Manifest embedded in this service |
| Safety Agent patterns | `services/safety_agent/policy_evaluator.py` | Manifest embedded in this service |

### System Rule Manifest (embedded, not discovered from source)

The Rules Management API ships with a static manifest of all known system rules.
This avoids runtime coupling to the Safety Agent source code.

```python
SYSTEM_RULES_MANIFEST = [
    # --- OPA Rules ---
    SystemRule(
        rule_id="opa-github-delete-branch",
        name="Block destructive branch deletion without admin role",
        category="github",
        source="opa",
        opa_policy_id="agentic_guardian",          # existing monolithic policy
        opa_rule_block="deny_delete_branch",        # logical name within Rego
        parameters=[],
        enabled_by_default=True,
    ),
    SystemRule(
        rule_id="opa-github-delete-repo",
        name="Block repository deletion without admin role",
        category="github",
        source="opa",
        opa_policy_id="agentic_guardian",
        opa_rule_block="deny_delete_repository",
        parameters=[],
        enabled_by_default=True,
    ),
    SystemRule(
        rule_id="opa-github-force-push",
        name="Block force-push without admin role",
        category="github",
        source="opa",
        opa_policy_id="agentic_guardian",
        opa_rule_block="deny_force_push",
        parameters=[],
        enabled_by_default=True,
    ),
    SystemRule(
        rule_id="opa-spending-aws",
        name="AWS spending limit on create_instance",
        category="spending",
        source="opa",
        opa_policy_id="agentic_guardian",
        opa_rule_block="deny_spending_aws",
        parameters=[
            RuleParameter(
                name="spending_limit",
                label="Spending Limit (USD)",
                type="number",
                default=100.0,
                description="Maximum estimated cost before action is denied",
            )
        ],
        enabled_by_default=True,
    ),
    SystemRule(
        rule_id="opa-spending-gcp",
        name="GCP spending limit on provision_resources",
        category="spending",
        source="opa",
        opa_policy_id="agentic_guardian",
        opa_rule_block="deny_spending_gcp",
        parameters=[
            RuleParameter(
                name="spending_limit",
                label="Spending Limit (USD)",
                type="number",
                default=100.0,
                description="Maximum estimated cost before action is denied",
            )
        ],
        enabled_by_default=True,
    ),
    SystemRule(
        rule_id="opa-spending-azure",
        name="Azure spending limit on deploy_infrastructure",
        category="spending",
        source="opa",
        opa_policy_id="agentic_guardian",
        opa_rule_block="deny_spending_azure",
        parameters=[
            RuleParameter(
                name="spending_limit",
                label="Spending Limit (USD)",
                type="number",
                default=100.0,
                description="Maximum estimated cost before action is denied",
            )
        ],
        enabled_by_default=True,
    ),
    SystemRule(
        rule_id="opa-action-category",
        name="Restrict actions to allowed categories per service",
        category="access_control",
        source="opa",
        opa_policy_id="agentic_guardian",
        opa_rule_block="deny_action_category",
        parameters=[],
        enabled_by_default=True,
    ),
    SystemRule(
        rule_id="opa-intent-alignment",
        name="Intent alignment threshold enforcement",
        category="intent",
        source="opa",
        opa_policy_id="agentic_guardian",
        opa_rule_block="deny_intent_alignment",
        parameters=[
            RuleParameter(
                name="threshold",
                label="Minimum Alignment Score",
                type="number",
                default=0.7,
                minimum=0.0,
                maximum=1.0,
                description="Similarity scores below this threshold are denied",
            )
        ],
        enabled_by_default=True,
    ),
    SystemRule(
        rule_id="opa-filesystem-destructive",
        name="Block destructive filesystem operations without admin role",
        category="filesystem",
        source="opa",
        opa_policy_id="agentic_guardian",
        opa_rule_block="deny_destructive_filesystem",
        parameters=[],
        enabled_by_default=True,
    ),
    SystemRule(
        rule_id="opa-system-commands",
        name="Block system-level commands (shutdown, reboot, etc.)",
        category="system",
        source="opa",
        opa_policy_id="agentic_guardian",
        opa_rule_block="deny_system_commands",
        parameters=[],
        enabled_by_default=True,
    ),
    SystemRule(
        rule_id="opa-batch-destructive",
        name="Block batch destructive operations",
        category="filesystem",
        source="opa",
        opa_policy_id="agentic_guardian",
        opa_rule_block="deny_batch_destructive",
        parameters=[],
        enabled_by_default=True,
    ),
    # --- Safety Agent Rules ---
    SystemRule(
        rule_id="sa-action-whitelist",
        name="Known safe action whitelist per provider",
        category="access_control",
        source="safety_agent",
        opa_policy_id=None,
        opa_rule_block=None,
        parameters=[],
        enabled_by_default=True,
    ),
    SystemRule(
        rule_id="sa-dangerous-patterns",
        name="Dangerous pattern detection in action names",
        category="security",
        source="safety_agent",
        opa_policy_id=None,
        opa_rule_block=None,
        parameters=[],
        enabled_by_default=True,
    ),
    SystemRule(
        rule_id="sa-intent-alignment-check",
        name="Action alignment with intent signature allowed_actions",
        category="intent",
        source="safety_agent",
        opa_policy_id=None,
        opa_rule_block=None,
        parameters=[],
        enabled_by_default=True,
    ),
]
```

### OPA Toggling Strategy

The existing `policies.rego` is a monolithic file. Toggling individual rules is implemented
via **Rego data injection**: OPA's `data` document is used to pass a `disabled_rules` set.
The Rego policy is updated once (at setup) to check this set before each deny block:

```rego
# Added to policies.rego once during setup
disabled_rules := data.rules_config.disabled_rules

deny[msg] {
    not disabled_rules["deny_delete_branch"]
    input.action == "delete_branch"
    input.provider == "github"
    input.context.role != "admin"
    msg := "Destructive GitHub action 'delete_branch' requires admin role"
}
```

The Rules Management API writes to OPA's `/v1/data/rules_config` endpoint:

```json
{
  "disabled_rules": ["deny_delete_branch", "deny_spending_gcp"],
  "spending_limits": {
    "aws": 500.0,
    "gcp": 200.0,
    "azure": 300.0
  },
  "intent_alignment_threshold": 0.75
}
```

Safety Agent rules (source=`safety_agent`) are toggled via a flag in `rules_store.json`
that the Safety Agent reads before each check (see Safety Agent integration below).

---

## Custom Rules

Custom rules are new rules that do not exist in the current codebase. They are authored
via three modes:

### Mode 1 — Form Rule (business users)

A set of supported condition types with a constrained UI. The backend accepts a structured
`FormRule` object and transpiles it to Rego before storing and deploying.

**Supported condition types:**

| Type | Field | Operators | Value Type |
|---|---|---|---|
| `action_equals` | `input.action` | eq, neq | string |
| `provider_equals` | `input.provider` | eq, neq | string |
| `role_equals` | `input.context.role` | eq, neq | string |
| `cost_threshold` | `input.estimated_cost` | gt, gte, lt, lte | number |
| `action_category` | `input.action_category` | eq, neq | string |
| `intent_score` | `input.intent_alignment_score` | gt, gte, lt, lte | number |

All conditions within a rule are AND-combined. Multiple form rules are OR-combined
(each becomes its own `deny[msg]` block).

**Example FormRule request:**
```json
{
  "mode": "form",
  "name": "ZA Region Spending Limit",
  "category": "spending",
  "description": "AWS spending limit specific to ZA finance team",
  "conditions": [
    {"type": "action_equals",   "operator": "eq",  "value": "create_instance"},
    {"type": "provider_equals", "operator": "eq",  "value": "aws"},
    {"type": "cost_threshold",  "operator": "gt",  "value": 500.0},
    {"type": "role_equals",     "operator": "neq", "value": "finance-admin"}
  ],
  "deny_message": "Exceeds ZA region AWS spending limit of $500"
}
```

**Generated Rego:**
```rego
deny[msg] {
    input.action == "create_instance"
    input.provider == "aws"
    input.estimated_cost > 500.0
    input.context.role != "finance-admin"
    msg := "Exceeds ZA region AWS spending limit of $500"
}
```

### Mode 2 — DSL Rule (power users)

A JSON schema that supports all OPA input fields and logical connectives. The backend
transpiles it to Rego. Supports AND/OR nesting, string functions (`contains`, `startswith`),
and sprintf for dynamic messages.

**Example DSL request:**
```json
{
  "mode": "dsl",
  "name": "Block all delete actions on production provider",
  "category": "github",
  "description": "Prevent any delete-prefixed action on the prod provider",
  "rule": {
    "op": "AND",
    "conditions": [
      {"field": "input.provider", "op": "eq",       "value": "github"},
      {"field": "input.action",   "op": "contains", "value": "delete"}
    ]
  },
  "deny_message_template": "Action '{{input.action}}' blocked on production GitHub provider"
}
```

**Generated Rego:**
```rego
deny[msg] {
    input.provider == "github"
    contains(input.action, "delete")
    msg := sprintf("Action '%s' blocked on production GitHub provider", [input.action])
}
```

### Mode 3 — Raw Rego Rule (policy engineers)

The full Rego `deny[msg]` block is submitted as a string. The backend validates that:
- It parses as valid Rego (OPA compile check via `POST /v1/compile`)
- It is a `deny[msg]` rule (structural check)
- It does not redefine the `allow` or `decision` rules
- It is scoped to the `agentic_guardian` package

**Example Raw request:**
```json
{
  "mode": "raw",
  "name": "Block non-whitelisted Slack channels",
  "category": "slack",
  "description": "Only allow messages to channels in the approved list",
  "rego": "deny[msg] {\n  input.provider == \"slack\"\n  input.action == \"send_message\"\n  not input.action_params.channel in data.rules_config.slack_approved_channels\n  msg := sprintf(\"Channel '%s' is not in the approved Slack channels list\", [input.action_params.channel])\n}"
}
```

---

## Data Models

```python
from enum import Enum
from typing import Any, Literal, Optional, Union
from pydantic import BaseModel, Field
from datetime import datetime


# --- Enums ---

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


# --- Parameter descriptor (for system rules) ---

class RuleParameter(BaseModel):
    name: str
    label: str
    type: Literal["number", "string", "boolean"]
    default: Any
    minimum: Optional[float] = None
    maximum: Optional[float] = None
    description: str = ""


# --- System Rule ---

class SystemRule(BaseModel):
    rule_id: str
    name: str
    category: str
    source: RuleSource
    opa_policy_id: Optional[str] = None
    opa_rule_block: Optional[str] = None
    parameters: list[RuleParameter] = []
    enabled_by_default: bool = True

class SystemRuleState(BaseModel):
    """Persisted runtime state of a system rule."""
    rule_id: str
    enabled: bool
    param_values: dict[str, Any] = {}
    last_modified: datetime
    modified_by: str = "system"


# --- Custom Rule ---

class FormCondition(BaseModel):
    type: ConditionType
    operator: ConditionOperator
    value: Union[str, float, bool]

class DSLConditionNode(BaseModel):
    op: Literal["AND", "OR"]
    conditions: list[Union["DSLConditionNode", "DSLLeafCondition"]]

class DSLLeafCondition(BaseModel):
    field: str                   # e.g. "input.provider"
    op: ConditionOperator
    value: Union[str, float, bool]

DSLConditionNode.model_rebuild()

class CreateCustomRuleRequest(BaseModel):
    mode: RuleMode
    name: str = Field(..., min_length=1, max_length=100)
    category: str = Field(..., min_length=1)
    description: str = ""
    enabled: bool = True
    # Form mode
    conditions: Optional[list[FormCondition]] = None
    deny_message: Optional[str] = None
    # DSL mode
    rule: Optional[DSLConditionNode] = None
    deny_message_template: Optional[str] = None
    # Raw mode
    rego: Optional[str] = None

class CustomRule(BaseModel):
    rule_id: str                 # UUID
    mode: RuleMode
    name: str
    category: str
    description: str
    enabled: bool
    source_definition: dict      # original request payload stored verbatim
    generated_rego: str          # transpiled Rego (all modes)
    opa_policy_id: str           # "{rule_id}" used as OPA policy ID
    created_at: datetime
    updated_at: datetime
    created_by: str = "system"


# --- Responses ---

class SystemRuleResponse(BaseModel):
    rule_id: str
    name: str
    category: str
    source: RuleSource
    enabled: bool
    parameters: list[RuleParameter]
    param_values: dict[str, Any]
    opa_rule_block: Optional[str]
    last_modified: datetime

class CustomRuleResponse(BaseModel):
    rule_id: str
    mode: RuleMode
    name: str
    category: str
    description: str
    enabled: bool
    generated_rego: str
    created_at: datetime
    updated_at: datetime

class RulesListResponse(BaseModel):
    system_rules: list[SystemRuleResponse]
    custom_rules: list[CustomRuleResponse]
    total_system: int
    total_custom: int

class TestRuleRequest(BaseModel):
    """Test a rule definition against a sample input before saving."""
    mode: RuleMode
    conditions: Optional[list[FormCondition]] = None
    deny_message: Optional[str] = None
    rule: Optional[DSLConditionNode] = None
    deny_message_template: Optional[str] = None
    rego: Optional[str] = None
    sample_input: dict            # OPA input document to test against

class TestRuleResponse(BaseModel):
    generated_rego: str
    opa_decision: dict            # raw OPA decision output
    allow: bool
    deny_reasons: list[str]
    valid: bool
    validation_errors: list[str]
```

---

## API Endpoints

### System Rules

| Method | Path | Description |
|---|---|---|
| `GET` | `/rules/system` | List all system rules with current state |
| `POST` | `/rules/system/{rule_id}/toggle` | Enable or disable a system rule |
| `PATCH` | `/rules/system/{rule_id}/params` | Update parameter values (e.g. spending limit) |

**Toggle request body:**
```json
{ "enabled": false }
```

**Params update request body:**
```json
{ "param_values": { "spending_limit": 500.0 } }
```

### Custom Rules

| Method | Path | Description |
|---|---|---|
| `GET` | `/rules/custom` | List all custom rules |
| `GET` | `/rules/custom/{rule_id}` | Get a single custom rule (with full Rego) |
| `POST` | `/rules/custom` | Create a new custom rule (form, dsl, or raw mode) |
| `PUT` | `/rules/custom/{rule_id}` | Replace a custom rule |
| `DELETE` | `/rules/custom/{rule_id}` | Delete and undeploy a custom rule from OPA |
| `POST` | `/rules/custom/{rule_id}/toggle` | Enable or disable without deleting |
| `POST` | `/rules/custom/test` | Test a rule definition against a sample input |

### Meta

| Method | Path | Description |
|---|---|---|
| `GET` | `/rules/providers` | List supported providers and their known safe actions |
| `GET` | `/rules/schema` | Return JSON schema for form/DSL rule building |
| `GET` | `/health` | Service health: OPA connectivity, store status |

---

## Transpiler Design

The `RegoTranspiler` class handles Modes 1 and 2. It is a pure function with no side
effects — it takes a rule definition and returns a Rego string.

```python
class RegoTranspiler:

    def transpile_form(self, rule: CreateCustomRuleRequest, rule_id: str) -> str:
        """Transpile a FormRule to a single deny[msg] block."""
        ...

    def transpile_dsl(self, rule: CreateCustomRuleRequest, rule_id: str) -> str:
        """Transpile a DSL rule tree to a deny[msg] block using recursive descent."""
        ...

    def wrap_raw(self, rule: CreateCustomRuleRequest, rule_id: str) -> str:
        """Return the raw Rego string as-is after validation."""
        ...

    def _condition_to_rego(self, condition: FormCondition) -> str:
        """Map a FormCondition to a Rego expression."""
        field_map = {
            ConditionType.action_equals:   "input.action",
            ConditionType.provider_equals:  "input.provider",
            ConditionType.role_equals:      "input.context.role",
            ConditionType.cost_threshold:   "input.estimated_cost",
            ConditionType.action_category:  "input.action_category",
            ConditionType.intent_score:     "input.intent_alignment_score",
        }
        op_map = {
            ConditionOperator.eq:  "==",
            ConditionOperator.neq: "!=",
            ConditionOperator.gt:  ">",
            ConditionOperator.gte: ">=",
            ConditionOperator.lt:  "<",
            ConditionOperator.lte: "<=",
        }
        field = field_map[condition.type]
        value = (
            f'"{condition.value}"'
            if isinstance(condition.value, str)
            else str(condition.value).lower()
        )
        if condition.operator in (ConditionOperator.contains,
                                   ConditionOperator.startswith):
            return f'{condition.operator.value}({field}, {value})'
        if condition.operator == ConditionOperator.not_contains:
            return f'not contains({field}, {value})'
        return f"{field} {op_map[condition.operator]} {value}"
```

---

## OPA Integration

### OPA Management API calls

```python
class OPAManager:

    async def put_data(self, path: str, data: dict) -> None:
        """Write to OPA data document. Used for disabled_rules, param overrides."""
        await self.client.put(f"/v1/data/{path}", json=data)

    async def put_policy(self, policy_id: str, rego: str) -> None:
        """Deploy a Rego policy module. Used for custom rules."""
        await self.client.put(
            f"/v1/policies/{policy_id}",
            content=rego,
            headers={"Content-Type": "text/plain"},
        )

    async def delete_policy(self, policy_id: str) -> None:
        """Remove a Rego policy module."""
        await self.client.delete(f"/v1/policies/{policy_id}")

    async def evaluate(self, input_doc: dict) -> dict:
        """Evaluate a sample input against all loaded policies."""
        resp = await self.client.post(
            "/v1/data/agentic_guardian/decision",
            json={"input": input_doc},
        )
        return resp.json()["result"]

    async def compile_check(self, rego: str) -> list[str]:
        """Return list of compile errors, empty if valid."""
        ...
```

### Data document structure pushed to OPA

```
PUT /v1/data/rules_config
{
  "disabled_rules": ["deny_delete_branch"],
  "spending_limits": {
    "aws": 500.0,
    "gcp": 100.0,
    "azure": 100.0
  },
  "intent_alignment_threshold": 0.7,
  "sa_disabled_rules": ["sa-dangerous-patterns"],
  "slack_approved_channels": ["#general", "#engineering"]
}
```

---

## Safety Agent Integration

The Safety Agent reads `rules_store.json` (or the OPA data document via a sidecar call)
before the three check phases:

```python
# In policy_evaluator.py — modified to consult rules config

class PolicyEvaluator:

    def _load_rules_config(self) -> dict:
        """Load current rules config from shared store."""
        try:
            with open(config.rules_store_path) as f:
                return json.load(f)
        except Exception:
            return {}   # fail open: use all rules if config unreadable

    def evaluate_task_graph(self, ...):
        rules_config = self._load_rules_config()
        sa_disabled = set(rules_config.get("sa_disabled_rules", []))

        # Dangerous pattern check — skipped if disabled
        if "sa-dangerous-patterns" not in sa_disabled:
            if self._check_for_dangerous_patterns(action):
                ...

        # Whitelist check — skipped if disabled
        if "sa-action-whitelist" not in sa_disabled:
            if not self._is_known_safe_action(action, provider):
                ...

        # Intent alignment check — skipped if disabled
        if "sa-intent-alignment-check" not in sa_disabled:
            if not self._check_action_alignment(action, intent_signature):
                ...
```

The OPA rules are toggled via the `disabled_rules` data document — no Safety Agent code
changes needed for those.

---

## Persistence

`rules_store.json` is a flat JSON file on a shared volume. Structure:

```json
{
  "version": 1,
  "updated_at": "2026-04-10T18:00:00Z",
  "system_rules": [
    {
      "rule_id": "opa-spending-aws",
      "enabled": true,
      "param_values": { "spending_limit": 500.0 },
      "last_modified": "2026-04-10T18:00:00Z",
      "modified_by": "system"
    }
  ],
  "custom_rules": [
    {
      "rule_id": "550e8400-e29b-41d4-a716-446655440001",
      "mode": "form",
      "name": "ZA Spending Limit",
      "category": "spending",
      "description": "AWS limit for ZA finance team",
      "enabled": true,
      "source_definition": { "...": "..." },
      "generated_rego": "deny[msg] { ... }",
      "opa_policy_id": "custom_550e8400",
      "created_at": "2026-04-10T18:00:00Z",
      "updated_at": "2026-04-10T18:00:00Z",
      "created_by": "system"
    }
  ]
}
```

For production: replace with PostgreSQL. The API abstracts persistence behind a
`RulesStore` interface so the backend can be swapped.

---

## Rego Modification Strategy for System Rule Toggling

The monolithic `policies.rego` file is modified **once** during initial setup by the
Rules Management API to inject the `disabled_rules` guard into each `deny[msg]` block.
After that, toggling is purely a data document update — no Rego file changes.

**Before (original):**
```rego
deny[msg] {
    input.action == "delete_branch"
    input.provider == "github"
    input.context.role != "admin"
    msg := "..."
}
```

**After (modified once at setup):**
```rego
deny[msg] {
    not "deny_delete_branch" in data.rules_config.disabled_rules
    input.action == "delete_branch"
    input.provider == "github"
    input.context.role != "admin"
    msg := "..."
}
```

A `setup` endpoint (`POST /rules/system/initialize`) performs this one-time Rego
modification and is idempotent (safe to call multiple times).

---

## Error Handling

All errors follow the same `ErrorResponse` envelope:

```json
{ "error": "rule_not_found", "message": "Rule 'opa-spending-aws' does not exist" }
```

| Scenario | HTTP | Error Code |
|---|---|---|
| Rule not found | 404 | `rule_not_found` |
| Invalid Rego (raw mode) | 422 | `invalid_rego` |
| DSL transpile failure | 422 | `transpile_error` |
| Form condition unsupported | 422 | `unsupported_condition` |
| OPA unreachable | 502 | `opa_unavailable` |
| Store read/write error | 500 | `store_error` |
| Rule ID conflict | 409 | `rule_id_conflict` |

---

## Service Configuration

All configuration via environment variables:

| Variable | Default | Description |
|---|---|---|
| `OPA_URL` | `http://localhost:8181` | OPA REST API base URL |
| `RULES_STORE_PATH` | `/shared/rules_store.json` | Path to persistence file |
| `SERVICE_PORT` | `8010` | Port for this service |
| `LOG_LEVEL` | `INFO` | Logging level |
| `CORS_ORIGINS` | `http://localhost:3000` | Allowed frontend origins |

---

## Correctness Properties

1. **Toggle idempotence**: Disabling an already-disabled rule twice leaves it disabled.
2. **OPA round-trip**: Every custom rule's generated Rego successfully compiles in OPA.
3. **Form→Rego fidelity**: A FormRule with N AND-conditions produces exactly N Rego body
   literals plus one `msg` assignment.
4. **Test endpoint isolation**: `POST /rules/custom/test` never persists or deploys.
5. **Delete undeployment**: Deleting a custom rule removes its policy from OPA.
6. **Param bounds**: Numeric parameters reject values outside their `minimum`/`maximum`.
7. **System rules indestructible**: `DELETE /rules/system/{id}` returns 405 Method Not Allowed.
