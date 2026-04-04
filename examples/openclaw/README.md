# OpenClaw × Agentic Guardian (Thebe)

> Install a **Security Brain** into OpenClaw's execution loop.
> OpenClaw provides the *hands* (filesystem, shell, APIs).
> Thebe provides the *Conscience*.

---

## What This Integration Does

Every time OpenClaw tries to execute a tool (`shell_execute`, `write_file`, `http_request`, etc.), the Guardian intercepts the call and asks:

> *"Does this action actually match what the user originally asked for?"*

Three security breakthroughs are demonstrated:

| Capability | How it works |
|---|---|
| **Semantic Kill-Switch** | If a prompt injection tricks OpenClaw into running `rm -rf /`, the Guardian sees that "delete" does not match the original "summarise" intent and blocks the process instantly. |
| **Identity Abstraction** | OpenClaw never sees real API keys. It only receives a Thebe-Session-ID; the Guardian injects the actual secret at the last millisecond of the tool call. |
| **Reasoning Trace** | Every verdict is logged with a human-readable explanation, making AI operations fully POPIA / GDPR auditable. |

---

## Directory Layout

```
examples/openclaw/
├── HOOK.md                       # OpenClaw hook metadata
├── handler.ts                    # OpenClaw hook handler (copy to ~/.openclaw/hooks/)
├── .env.example                  # Environment variables for ~/.openclaw/.env
├── docker-compose.yml            # Quick-start: Thebe Proxy only (dev mode)
├── thebe-proxy/
│   ├── main.py                   # Standalone FastAPI proxy service
│   ├── requirements.txt
│   └── Dockerfile
└── README.md                     # This file
```

---

## Quick Start (Five Minutes, No Auth0)

### Step 1 — Start the Thebe Proxy

From the **repository root**:

```bash
docker compose -f examples/openclaw/docker-compose.yml up --build
```

The proxy starts in **dev mode** (`THEBE_DEV_MODE=true`), performing a
lightweight intent-alignment heuristic without needing any Auth0 credentials.

Verify it is running:

```bash
curl http://localhost:8000/health
# → {"status":"ok","dev_mode":true,...}
```

### Step 2 — Install the OpenClaw Hook

```bash
mkdir -p ~/.openclaw/hooks/agentic-guardian

cp examples/openclaw/HOOK.md    ~/.openclaw/hooks/agentic-guardian/
cp examples/openclaw/handler.ts ~/.openclaw/hooks/agentic-guardian/
```

### Step 3 — Configure OpenClaw

```bash
cp examples/openclaw/.env.example ~/.openclaw/.env
# Edit ~/.openclaw/.env if you need a different endpoint or key.
```

That's it. Every subsequent OpenClaw tool call will now pass through the
Guardian shield.

---

## How the Hook Works

```
OpenClaw                    Thebe Proxy                  Agentic Guardian Stack
   │                             │                                │
   │  tool:call event            │                                │
   ├────────────────────────────>│                                │
   │                             │  POST /validate                │
   │                             │  { userIntent, toolName,       │
   │                             │    args, sessionId }           │
   │                             │                                │
   │                             │  [dev mode]                    │
   │                             │  heuristic check ──────────>   │
   │                             │                                │
   │                             │  [production mode]             │
   │                             │  POST /plan-fast ──────────>   │
   │                             │  Intent Engine + Safety Agent  │
   │                             │  OPA policy evaluation         │
   │                             │<───────────────────────────────│
   │                             │                                │
   │  { decision, reasoning,     │                                │
   │    requires_human_approval }│                                │
   │<────────────────────────────│                                │
   │                             │                                │
   │  DENY  → block + log        │                                │
   │  APPROVAL → ask user        │                                │
   │  ALLOW → execute            │                                │
```

---

## Production Setup — Full Guardian Stack

For a production deployment the Thebe Proxy delegates to the complete
Agentic Guardian microservice pipeline.

### Prerequisites

- Auth0 tenant with M2M applications configured (see `infra/auth0/`)
- mTLS certificates generated (see `scripts/`)
- Running Guardian stack

### Step 1 — Start everything together

```bash
docker compose \
  -f infra/docker/docker-compose.yml \
  -f examples/openclaw/docker-compose.yml \
  up --build
```

### Step 2 — Enable production mode

Edit `examples/openclaw/docker-compose.yml` (or override via env):

```yaml
THEBE_DEV_MODE: "false"
THEBE_GUARDIAN_URL: "http://planner:8002"
THEBE_GUARDIAN_BEARER_TOKEN: "<auth0-m2m-access-token>"
```

In a real deployment the Bearer token is fetched automatically from Auth0
using client-credentials flow.  Add a token-refresh sidecar or use a service
mesh with automatic token injection.

### Step 3 — Enable cross-network communication

Uncomment the `ztag-internal` network entries in
`examples/openclaw/docker-compose.yml` so the proxy can reach the Planner
on the Guardian's internal network.

---

## Environment Variables

### Thebe Proxy (`docker-compose.yml`)

| Variable | Default | Description |
|---|---|---|
| `THEBE_DEV_MODE` | `true` | `true` = lightweight heuristic; `false` = full Guardian |
| `THEBE_API_KEY` | `demo-api-key` | Shared secret checked in `X-Thebe-Key` header |
| `THEBE_MIN_ALIGNMENT_SCORE` | `0.85` | Minimum acceptable intent-alignment score |
| `THEBE_GUARDIAN_URL` | `http://planner:8002` | Planner service base URL (production) |
| `THEBE_GUARDIAN_BEARER_TOKEN` | _(empty)_ | Auth0 M2M token for Guardian API auth |
| `THEBE_PORT` | `8000` | Host port the proxy is published on |
| `LOG_LEVEL` | `INFO` | Logging verbosity |

### OpenClaw (`~/.openclaw/.env`)

| Variable | Default | Description |
|---|---|---|
| `THEBE_ENDPOINT` | `http://localhost:8000` | URL of the Thebe Proxy |
| `THEBE_API_KEY` | `demo-api-key` | Must match the proxy's `THEBE_API_KEY` |
| `THEBE_MIN_ALIGNMENT_SCORE` | `0.85` | Hook-level threshold (second defence layer) |
| `THEBE_FAIL_OPEN` | `false` | Whether to allow actions if the proxy is unreachable |

---

## Testing the Shield

### Prompt-injection block (should be DENY)

```bash
curl -s -X POST http://localhost:8000/validate \
  -H "Content-Type: application/json" \
  -H "X-Thebe-Key: demo-api-key" \
  -d '{
    "userIntent": "Summarise the quarterly report",
    "toolName": "shell_execute",
    "args": {"command": "rm -rf /var/data"},
    "sessionId": "test-session-001"
  }' | python3 -m json.tool
```

Expected: `"decision": "DENY"` — destructive pattern detected.

### Intent drift block (should be DENY)

```bash
curl -s -X POST http://localhost:8000/validate \
  -H "Content-Type: application/json" \
  -H "X-Thebe-Key: demo-api-key" \
  -d '{
    "userIntent": "Summarise the quarterly report",
    "toolName": "stripe_charge",
    "args": {"amount": 9999, "currency": "usd"},
    "sessionId": "test-session-002"
  }' | python3 -m json.tool
```

Expected: `"decision": "DENY"` — alignment score below threshold.

### Legitimate action (should be ALLOW with human approval)

```bash
curl -s -X POST http://localhost:8000/validate \
  -H "Content-Type: application/json" \
  -H "X-Thebe-Key: demo-api-key" \
  -d '{
    "userIntent": "Send the summary report to the team",
    "toolName": "send_email",
    "args": {"to": "team@company.com", "subject": "Q4 Summary"},
    "sessionId": "test-session-003"
  }' | python3 -m json.tool
```

Expected: `"decision": "ALLOW"`, `"requires_human_approval": true` — email
dispatch is a high-risk tool and requires explicit user consent.

---

## Architecture Reference

```
User Prompt
    │
    ▼
OpenClaw Agent Loop
    │
    │  tool:call event
    ▼
handler.ts  ──────────────  POST /validate  ──────────────► Thebe Proxy
                                                                  │
                                                    ┌─────────────┴──────────────┐
                                                    │ dev mode                   │ prod mode
                                                    │ heuristic check            │ Planner /plan-fast
                                                    │                            │    ├─ Intent Engine
                                                    │                            │    │  (semantic embeddings)
                                                    │                            │    └─ Safety Agent
                                                    │                            │       (OPA policies)
                                                    └─────────────┬──────────────┘
                                                                  │
                                                    ◄─────────────┘
                                              { decision, reasoning_trace,
                                                requires_human_approval,
                                                alignment_score }
    │
    ├─ DENY            →  block: true   (action rejected, reason logged)
    ├─ requires_approval → requireApproval: true  (user prompted)
    └─ ALLOW           →  block: false  (action proceeds)
```

---

## Audit Trail

In production mode every verdict is logged through the Audit Service as a
cryptographically hash-chained entry.  OpenClaw's logs will contain a
**Guardian Verdict** field for every tool call, providing a tamper-evident
record suitable for POPIA / GDPR compliance review.

---

## Publishing the SDK

Once `@delegant/thebe-sdk` is published to npm you can replace the inline
`ThebeProxy` class in `handler.ts` with:

```typescript
import { ThebeProxy } from '@delegant/thebe-sdk';
```

The published SDK will include TypeScript types, automatic token refresh, and
retry logic with exponential back-off.
