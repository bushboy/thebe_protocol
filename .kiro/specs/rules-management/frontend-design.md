# Design Document: Rules Management UI (Frontend)

## Overview

The Rules Management UI is a **standalone Next.js application** — a separate codebase with
zero coupling to the Thebe Protocol / Guardian services. It communicates exclusively with
the Rules Management API (backend) over HTTP.

**Tech stack:**
- Next.js 14 (App Router, TypeScript)
- Tailwind CSS
- shadcn/ui (Radix UI primitives)
- Lucide React (icons)
- Monaco Editor (Rego editor for raw mode)
- Zod (schema validation on forms)
- React Hook Form
- TanStack Query v5 (data fetching + cache invalidation)
- `next/font` + Inter

---

## Application Structure

```
thebe-rules-ui/                        ← new standalone repo / directory
├── app/
│   ├── layout.tsx                     ← Root layout (sidebar nav, header)
│   ├── page.tsx                       ← Redirect to /rules/system
│   ├── rules/
│   │   ├── system/
│   │   │   └── page.tsx               ← System rules table
│   │   └── custom/
│   │       ├── page.tsx               ← Custom rules table
│   │       └── new/
│   │           └── page.tsx           ← Rule builder (form/dsl/raw)
│   └── api/                           ← Next.js API routes (proxy to backend)
│       └── rules/
│           └── [...path]/route.ts     ← Transparent proxy to Rules API
├── components/
│   ├── layout/
│   │   ├── AppShell.tsx
│   │   ├── Sidebar.tsx
│   │   └── TopBar.tsx
│   ├── system-rules/
│   │   ├── SystemRulesTable.tsx
│   │   ├── SystemRuleRow.tsx
│   │   ├── RuleToggle.tsx
│   │   └── ParamEditor.tsx
│   ├── custom-rules/
│   │   ├── CustomRulesTable.tsx
│   │   ├── CustomRuleRow.tsx
│   │   └── DeleteRuleDialog.tsx
│   ├── rule-builder/
│   │   ├── RuleBuilderTabs.tsx        ← Tab switcher: Form / DSL / Raw
│   │   ├── FormRuleBuilder.tsx        ← Mode 1: structured form
│   │   ├── DSLRuleBuilder.tsx         ← Mode 2: JSON DSL editor
│   │   ├── RawRegoEditor.tsx          ← Mode 3: Monaco editor
│   │   ├── RegoPreview.tsx            ← Read-only Monaco showing generated Rego
│   │   └── RuleTestSandbox.tsx        ← Test panel with sample input editor
│   └── shared/
│       ├── CategoryBadge.tsx
│       ├── SourceBadge.tsx
│       ├── StatusIndicator.tsx
│       └── ConfirmDialog.tsx
├── lib/
│   ├── api-client.ts                  ← Typed fetch wrappers for Rules API
│   ├── types.ts                       ← TypeScript types mirroring backend models
│   ├── rego-schema.ts                 ← Zod schemas for form/DSL validation
│   └── constants.ts                   ← Condition types, operators, providers
├── hooks/
│   ├── useSystemRules.ts
│   ├── useCustomRules.ts
│   └── useRuleTest.ts
├── public/
│   └── thebe-logo.svg
├── .env.local.example
├── next.config.ts
├── tailwind.config.ts
├── tsconfig.json
└── package.json
```

---

## Page Designs

### 1. System Rules Page (`/rules/system`)

The primary overview page. Shows all hardcoded Guardian rules in a data table.

**Layout:**

```
┌──────────────────────────────────────────────────────────────────┐
│ ☰  Thebe Protocol          Rules Management          [●] OPA Live │
├────────────┬─────────────────────────────────────────────────────┤
│            │                                                       │
│ System     │  System Rules                       14 rules         │
│ Rules   ←  │  ─────────────────────────────────────────────────  │
│            │  Filter: [All Categories ▼]  [All Sources ▼]  [🔍]  │
│ Custom     │                                                       │
│ Rules      │  Rule                      Category  Source  Enabled │
│            │  ──────────────────────────────────────────────────  │
│ + New Rule │  Block destructive branch  GitHub    OPA     ● ON    │
│            │    [Edit Params]                                      │
│            │  ──────────────────────────────────────────────────  │
│            │  AWS spending limit         Spending  OPA     ● ON    │
│            │    Limit: $100.00 [✏ Edit]                           │
│            │  ──────────────────────────────────────────────────  │
│            │  Intent alignment threshold Intent    OPA     ● ON    │
│            │    Threshold: 0.70 [✏ Edit]                          │
│            │  ──────────────────────────────────────────────────  │
│            │  Known safe action whitelist Access    SA      ● ON   │
│            │  ──────────────────────────────────────────────────  │
│            │  Dangerous pattern detection Security  SA      ○ OFF  │
│            │  ──────────────────────────────────────────────────  │
│            │                                                       │
└────────────┴─────────────────────────────────────────────────────┘
```

**Key interactions:**
- **Toggle switch** — calls `POST /rules/system/{id}/toggle`. Optimistic update with
  rollback on error. Disabled rules show a muted row style.
- **Inline param edit** — clicking "✏ Edit" opens a small inline form below the row.
  Numeric inputs with min/max validation. "Save" calls `PATCH /rules/system/{id}/params`.
- **Filter bar** — client-side filter on category and source badges.
- **OPA Live indicator** — green dot if health check returns OPA as reachable.

**SystemRulesTable columns:**

| Column | Content |
|---|---|
| Rule name | Full name + description tooltip |
| Category | `<CategoryBadge>` (color-coded) |
| Source | `<SourceBadge>` (`OPA` blue, `Safety Agent` purple) |
| Parameters | Inline display of current values, edit button if params exist |
| Enabled | shadcn `<Switch>` |

---

### 2. Custom Rules Page (`/rules/custom`)

Lists all custom rules authored by operators.

```
┌──────────────────────────────────────────────────────────────────┐
│ ☰  Thebe Protocol          Rules Management          [●] OPA Live │
├────────────┬─────────────────────────────────────────────────────┤
│            │                                                       │
│ System     │  Custom Rules                        3 rules         │
│ Rules      │  ─────────────────────────────────────────────────  │
│            │                            [+ New Custom Rule]       │
│ Custom     │                                                       │
│ Rules   ←  │  Rule              Mode  Category  Created   Enabled │
│            │  ──────────────────────────────────────────────────  │
│ + New Rule │  ZA Spending Limit  Form  Spending  10 Apr 26  ● ON  │
│            │    [View Rego] [Edit] [Delete]                        │
│            │  ──────────────────────────────────────────────────  │
│            │  Block prod deletes DSL   GitHub    10 Apr 26  ● ON  │
│            │    [View Rego] [Edit] [Delete]                        │
│            │  ──────────────────────────────────────────────────  │
│            │  Slack channel lock Raw   Slack     10 Apr 26  ○ OFF │
│            │    [View Rego] [Edit] [Delete]                        │
│            │                                                       │
└────────────┴─────────────────────────────────────────────────────┘
```

**Key interactions:**
- **View Rego** — slides open a read-only Monaco panel showing the deployed Rego.
- **Edit** — navigates to the rule builder pre-populated with the rule's data.
- **Delete** — opens `<ConfirmDialog>` before calling `DELETE /rules/custom/{id}`.
- **Toggle** — same as system rules.
- **Mode badge** — `Form` (green), `DSL` (amber), `Raw` (red).

---

### 3. Rule Builder Page (`/rules/custom/new` and `/rules/custom/{id}/edit`)

Three-tab interface. The active tab determines which mode is used when saving.

#### Overall layout:

```
┌──────────────────────────────────────────────────────────────────┐
│  ← Back     New Custom Rule                                       │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  Name: [                                               ]          │
│  Category: [Spending ▼]    Description: [             ]          │
│                                                                   │
│  ┌──────────┬──────────┬──────────────────────────────┐          │
│  │  Form    │   DSL    │   Raw Rego                   │          │
│  └──────────┴──────────┴──────────────────────────────┘          │
│  ┌────────────────────────────────────────────────────┐          │
│  │  [Tab content — see below]                         │          │
│  └────────────────────────────────────────────────────┘          │
│                                                                   │
│  Generated Rego Preview                                           │
│  ┌────────────────────────────────────────────────────┐          │
│  │  deny[msg] {                                        │          │
│  │    input.action == "create_instance"                │          │
│  │    input.provider == "aws"                          │          │
│  │    input.estimated_cost > 500                       │          │
│  │    msg := "Exceeds ZA limit of $500"                │          │
│  │  }                                                  │          │
│  └────────────────────────────────────────────────────┘          │
│                                                                   │
│  ┌──────────────── Test Sandbox ─────────────────┐               │
│  │  Sample Input (JSON)        │  Result          │               │
│  │  {                         │  ✓ ALLOW         │               │
│  │    "action": "create_inst" │  No denials       │               │
│  │    "provider": "aws",      │                   │               │
│  │    "estimated_cost": 300,  │                   │               │
│  │    "context": {            │                   │               │
│  │      "role": "developer"   │                   │               │
│  │    }                       │                   │               │
│  │  }                         │                   │               │
│  │            [▶ Run Test]    │                   │               │
│  └────────────────────────────────────────────────┘               │
│                                                                   │
│                             [Cancel]  [Save & Deploy]             │
└──────────────────────────────────────────────────────────────────┘
```

#### Tab 1 — Form Mode

Condition builder with Add/Remove rows:

```
  Conditions (all must be true — AND)
  ┌──────────────────────────────────────────────────────────────┐
  │  [Action           ▼]  [equals        ▼]  [create_instance] │  ✕
  │  [Provider         ▼]  [equals        ▼]  [aws            ] │  ✕
  │  [Estimated cost   ▼]  [greater than  ▼]  [500            ] │  ✕
  │  [Role             ▼]  [not equals    ▼]  [finance-admin  ] │  ✕
  └──────────────────────────────────────────────────────────────┘
  [+ Add Condition]

  Deny message:  [Exceeds ZA region AWS spending limit of $500    ]
```

- Condition type dropdown shows a grouped list: Action fields, Context fields,
  Financial, Intent.
- Operator dropdown is context-sensitive (string conditions show eq/neq/contains,
  numeric show gt/gte/lt/lte).
- Value field adapts: number input for cost/threshold, free text for strings.
- Rego preview regenerates live on every form change.

#### Tab 2 — DSL Mode

JSON editor (Monaco, small, JSON mode) alongside a live Rego preview:

```
  DSL Definition (JSON)
  ┌────────────────────────────────────────────────┐
  │  {                                              │
  │    "op": "AND",                                 │
  │    "conditions": [                              │
  │      { "field": "input.provider",               │
  │        "op": "eq", "value": "github" },         │
  │      { "field": "input.action",                 │
  │        "op": "contains", "value": "delete" }    │
  │    ]                                            │
  │  }                                              │
  └────────────────────────────────────────────────┘

  Deny message template:
  [Action '{{input.action}}' blocked on production GitHub    ]

  [Validate DSL]  ← calls POST /rules/custom/test with empty sample_input
```

- Monaco editor in JSON mode with schema-driven autocomplete (JSON Schema for
  `DSLConditionNode` loaded as a Monaco schema).
- Validation errors appear inline below the editor.

#### Tab 3 — Raw Rego Mode

Full Monaco editor in Rego mode:

```
  ┌────────────────────────────────────────────────────────────────┐
  │ package agentic_guardian                                        │
  │                                                                 │
  │ deny[msg] {                                                     │
  │     input.provider == "slack"                                   │
  │     input.action == "send_message"                              │
  │     not input.action_params.channel in                          │
  │         data.rules_config.slack_approved_channels               │
  │     msg := sprintf("Channel '%s' not approved",                 │
  │         [input.action_params.channel])                          │
  │ }                                                               │
  └────────────────────────────────────────────────────────────────┘

  ⚠  Raw Rego mode. Rule must use the agentic_guardian package and
     define exactly one deny[msg] block.

  [Validate Rego]  ← calls compile check endpoint
```

- Monaco in `rego` language mode (custom language registration with basic tokenizer).
- "Validate Rego" calls `POST /rules/custom/test` with an empty sample to trigger the
  compile check. Errors are shown as red inline markers using Monaco's marker API.

#### Rego Preview (shared, below all tabs)

- Read-only Monaco editor, `rego` language mode, height ~120px.
- Updates live as the form/DSL changes.
- In raw mode, mirrors the editor content.
- Hidden when the current mode's content is invalid.

#### Test Sandbox (shared, below Rego preview)

Split panel:
- **Left**: Monaco editor in JSON mode with a sample OPA input document. Pre-populated
  with a plausible example based on the conditions defined.
- **Right**: Result display:
  - `✓ ALLOW` (green) or `✗ DENY` (red) badge.
  - Denial reasons list.
  - Raw OPA response expandable.
- "Run Test" calls `POST /rules/custom/test` with the current rule definition and the
  sample input.

---

## Component Details

### `<RuleToggle>`

```tsx
interface RuleToggleProps {
  ruleId: string;
  enabled: boolean;
  source: "opa" | "safety_agent";
  onToggle: (ruleId: string, enabled: boolean) => void;
}
```

- Renders a shadcn `<Switch>`.
- Optimistic update: flips immediately, shows a spinner overlay if the API call takes
  longer than 300ms, rolls back on error with a toast notification.
- Disabled state: greyed out row, faded text.

### `<ParamEditor>`

Inline expandable form for editable parameters on system rules.

```tsx
interface ParamEditorProps {
  ruleId: string;
  parameters: RuleParameter[];
  currentValues: Record<string, number | string | boolean>;
  onSave: (ruleId: string, values: Record<string, any>) => void;
}
```

- Opens below the rule row with a slide-down animation.
- Number inputs with step, min, max from the `RuleParameter` descriptor.
- "Save" / "Cancel" buttons; "Save" calls `PATCH /rules/system/{id}/params`.

### `<CategoryBadge>`

Color-coded pill badge:

| Category | Color |
|---|---|
| `github` | blue |
| `spending` | amber |
| `filesystem` | orange |
| `intent` | violet |
| `access_control` | teal |
| `security` | red |
| `system` | slate |
| `slack` | green |

### `<RuleTestSandbox>`

Uses TanStack Query `useMutation` for the test call. Shows a skeleton on loading.
Sample input is pre-seeded from `GET /rules/schema` which returns example input shapes
per category.

---

## API Client (`lib/api-client.ts`)

Typed wrappers around `fetch`. Errors throw a `RulesApiError` with `code` and `message`.

```typescript
const BASE_URL = process.env.NEXT_PUBLIC_RULES_API_URL ?? "http://localhost:8010";

export async function listSystemRules(): Promise<SystemRuleResponse[]> { ... }
export async function toggleSystemRule(ruleId: string, enabled: boolean): Promise<void> { ... }
export async function updateSystemRuleParams(
  ruleId: string, paramValues: Record<string, unknown>
): Promise<void> { ... }

export async function listCustomRules(): Promise<CustomRuleResponse[]> { ... }
export async function getCustomRule(ruleId: string): Promise<CustomRuleResponse> { ... }
export async function createCustomRule(req: CreateCustomRuleRequest): Promise<CustomRuleResponse> { ... }
export async function updateCustomRule(
  ruleId: string, req: CreateCustomRuleRequest
): Promise<CustomRuleResponse> { ... }
export async function deleteCustomRule(ruleId: string): Promise<void> { ... }
export async function toggleCustomRule(ruleId: string, enabled: boolean): Promise<void> { ... }
export async function testRule(req: TestRuleRequest): Promise<TestRuleResponse> { ... }

export async function getHealth(): Promise<HealthResponse> { ... }
export async function getProviders(): Promise<ProvidersResponse> { ... }
export async function getRulesSchema(): Promise<RulesSchemaResponse> { ... }
```

---

## TypeScript Types (`lib/types.ts`)

Mirror the backend Pydantic models exactly:

```typescript
export type RuleSource = "opa" | "safety_agent";
export type RuleMode = "form" | "dsl" | "raw";
export type ConditionOperator = "eq" | "neq" | "gt" | "gte" | "lt" | "lte" | "contains" | "startswith" | "not_contains";
export type ConditionType = "action_equals" | "provider_equals" | "role_equals" | "cost_threshold" | "action_category" | "intent_score";

export interface RuleParameter {
  name: string;
  label: string;
  type: "number" | "string" | "boolean";
  default: number | string | boolean;
  minimum?: number;
  maximum?: number;
  description: string;
}

export interface SystemRuleResponse {
  rule_id: string;
  name: string;
  category: string;
  source: RuleSource;
  enabled: boolean;
  parameters: RuleParameter[];
  param_values: Record<string, unknown>;
  opa_rule_block: string | null;
  last_modified: string;
}

export interface FormCondition {
  type: ConditionType;
  operator: ConditionOperator;
  value: string | number | boolean;
}

export interface DSLConditionNode {
  op: "AND" | "OR";
  conditions: Array<DSLConditionNode | DSLLeafCondition>;
}

export interface DSLLeafCondition {
  field: string;
  op: ConditionOperator;
  value: string | number | boolean;
}

export interface CreateCustomRuleRequest {
  mode: RuleMode;
  name: string;
  category: string;
  description?: string;
  enabled?: boolean;
  // form
  conditions?: FormCondition[];
  deny_message?: string;
  // dsl
  rule?: DSLConditionNode;
  deny_message_template?: string;
  // raw
  rego?: string;
}

export interface CustomRuleResponse {
  rule_id: string;
  mode: RuleMode;
  name: string;
  category: string;
  description: string;
  enabled: boolean;
  generated_rego: string;
  created_at: string;
  updated_at: string;
}

export interface TestRuleRequest {
  mode: RuleMode;
  conditions?: FormCondition[];
  deny_message?: string;
  rule?: DSLConditionNode;
  deny_message_template?: string;
  rego?: string;
  sample_input: Record<string, unknown>;
}

export interface TestRuleResponse {
  generated_rego: string;
  opa_decision: Record<string, unknown>;
  allow: boolean;
  deny_reasons: string[];
  valid: boolean;
  validation_errors: string[];
}

export interface HealthResponse {
  status: "healthy" | "degraded" | "unhealthy";
  opa_reachable: boolean;
  store_readable: boolean;
}
```

---

## Data Fetching Strategy

Uses TanStack Query v5:

```typescript
// hooks/useSystemRules.ts
export function useSystemRules() {
  return useQuery({
    queryKey: ["system-rules"],
    queryFn: listSystemRules,
    staleTime: 30_000,
  });
}

export function useToggleSystemRule() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ ruleId, enabled }: { ruleId: string; enabled: boolean }) =>
      toggleSystemRule(ruleId, enabled),
    onMutate: async ({ ruleId, enabled }) => {
      // Optimistic update
      await qc.cancelQueries({ queryKey: ["system-rules"] });
      const prev = qc.getQueryData(["system-rules"]);
      qc.setQueryData(["system-rules"], (old: SystemRuleResponse[]) =>
        old.map(r => r.rule_id === ruleId ? { ...r, enabled } : r)
      );
      return { prev };
    },
    onError: (_err, _vars, context) => {
      qc.setQueryData(["system-rules"], context?.prev);
      toast.error("Failed to toggle rule");
    },
    onSettled: () => qc.invalidateQueries({ queryKey: ["system-rules"] }),
  });
}
```

---

## Routing (App Router)

| URL | Page |
|---|---|
| `/` | Redirects to `/rules/system` |
| `/rules/system` | System rules table |
| `/rules/custom` | Custom rules table |
| `/rules/custom/new` | Rule builder (create) |
| `/rules/custom/[id]/edit` | Rule builder (edit) |

---

## UI States

### Empty States

- No custom rules: illustration + "Create your first rule" CTA button.
- No system rules (OPA unreachable): error banner + retry button.

### Loading States

- Tables show shadcn `<Skeleton>` rows (3 rows) while fetching.
- Toggle switch shows a loading spinner overlay during the API call.

### Error States

- API errors surface as `toast.error(message)` (shadcn Sonner).
- OPA unreachable: a persistent amber `Alert` banner at the top of all pages.

---

## Environment Variables

`.env.local.example`:

```bash
# URL of the Rules Management API backend
NEXT_PUBLIC_RULES_API_URL=http://localhost:8010
```

---

## Deployment

The frontend is a standalone Next.js app. It can be:

1. **Standalone**: `npm run build && npm start` (port 3000)
2. **Docker**: single `Dockerfile` using `node:20-alpine` multi-stage build
3. **docker-compose** (with the Rules Management API):

```yaml
services:
  rules-ui:
    build: ./thebe-rules-ui
    ports:
      - "3000:3000"
    environment:
      - NEXT_PUBLIC_RULES_API_URL=http://rules-api:8010
    depends_on:
      - rules-api

  rules-api:
    build: ./services/rules-management
    ports:
      - "8010:8010"
    environment:
      - OPA_URL=http://opa:8181
      - RULES_STORE_PATH=/shared/rules_store.json
    volumes:
      - shared-data:/shared
    depends_on:
      - opa

  opa:
    image: openpolicyagent/opa:latest
    command: run --server --addr 0.0.0.0:8181
    ports:
      - "8181:8181"

volumes:
  shared-data:
```

---

## Key Design Decisions

- **No server-side data fetching for rules** — all rule data is fetched client-side via
  TanStack Query. This keeps the Next.js pages as thin shells and avoids SSR complexity
  for an admin tool where SEO is irrelevant.
- **Monaco Editor for Rego and DSL** — loaded lazily with `dynamic(() => import(...),
  { ssr: false })` to avoid SSR issues with browser-only APIs.
- **Progressive disclosure** — the Form tab is shown first and is the default. DSL and
  Raw tabs are accessible but not forced on business users.
- **Optimistic updates** — toggle and param update operations update the UI immediately
  for responsiveness, rolling back on error.
- **No auth in the UI itself** — authentication is delegated to the deployment layer
  (nginx basic auth, Auth0 hosted login, or mTLS at the network boundary). The UI is an
  internal admin tool.
- **`/api/rules/[...path]`** proxy route (optional) — can be used to avoid CORS issues
  in development by proxying frontend requests through Next.js to the backend.
