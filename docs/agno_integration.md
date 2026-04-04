# Integrating the Zero-Trust Agentic Guardian with Agno

[Agno](https://docs.agno.com) is a lightweight Python framework for building multi-agent AI systems. This document explains how to use Agno agents and teams as clients of the Zero-Trust Agentic Guardian (ZTAG), giving your AI workflows the same cryptographic authorization chain — mTLS + JWT + DPoP → Intent Engine → Safety Agent → Permission Broker → Executor — that protects every internal service call.

## Contents

1. [Architecture Fit](#architecture-fit)
2. [Prerequisites](#prerequisites)
3. [Client Authentication Primer](#client-authentication-primer)
4. [GuardianClient — Reusable Auth Helper](#guardianclient--reusable-auth-helper)
5. [GuardianToolkit — Agno Toolkit](#guardiantoolkit--agno-toolkit)
6. [Example 1 — Simple Planning Agent](#example-1--simple-planning-agent)
7. [Example 2 — Full Authorization Flow Agent](#example-2--full-authorization-flow-agent)
8. [Example 3 — Multi-Agent Team with Guardian Security Layer](#example-3--multi-agent-team-with-guardian-security-layer)
9. [Example 4 — Structured Output with Guardian Schemas](#example-4--structured-output-with-guardian-schemas)
10. [Example 5 — Prompt-Injection Resistance Test](#example-5--prompt-injection-resistance-test)
11. [Error Handling](#error-handling)
12. [Configuration Reference](#configuration-reference)
13. [Security Considerations](#security-considerations)

---

## Architecture Fit

An Agno agent becomes an **external client** of ZTAG. The two externally exposed endpoints are:

| Endpoint | Guardian Service | Port |
|---|---|---|
| `POST /plan` | Planner | 8002 |
| `POST /authorize` | Permission Broker | 8004 |

All internal services (Intent Engine, Safety Agent, Executor, Audit) are called by the Guardian itself; your Agno agent never reaches them directly.

```
Agno Agent
  |
  |── agno tool: plan_task()
  |        POST /plan → Planner (8002)
  |                       ↓ (internal)
  |                 Intent Engine → Safety Agent
  |                       ↓ (response)
  |        ◀── IntentSignature + TaskGraph
  |
  |── agno tool: authorize_action()
           POST /authorize → Permission Broker (8004)
                               ↓ (internal if no policy_approval sent)
                         policy evaluation
                               ↓
                         Provider Token (Auth0 Token Vault)
                               ↓ (response)
           ◀── ZeroTrustAuthorizationToken + ProviderToken
```

---

## Prerequisites

```bash
pip install agno httpx cryptography PyJWT pydantic
```

The Guardian services must be running:

```bash
docker-compose -f infra/docker/docker-compose.yml up
```

You need:

- **Auth0 M2M credentials** — `client_id` and `client_secret` for a machine-to-machine application registered in your Auth0 tenant. The app must be authorised for the ZTAG audience.
- **DPoP RSA key pair** — 2048-bit RSA key for generating per-request proof-of-possession tokens.
- **mTLS client certificate** — signed by the internal root CA (`infra/certificates/root_ca.crt`). Required in environments where mTLS is enforced; can be omitted for local development when the services are configured to skip certificate validation.

---

## Client Authentication Primer

Every call to the Planner or Permission Broker requires three things in the HTTP headers:

| Header | Contains | Purpose |
|---|---|---|
| `Authorization` | `Bearer <JWT>` | Proves identity via Auth0 M2M token |
| `DPoP` | DPoP proof JWT | Binds the JWT to this specific HTTP request (method + URI + token hash) |
| `X-Client-Certificate` | PEM-encoded client cert | mTLS identity assertion |

**JWT** is obtained from Auth0 with a client credentials grant, valid for 5 minutes.

**DPoP proof** is a short-lived JWT (60 s) that you sign with your own RSA private key. Its payload includes:
- `jti` — unique UUID
- `htm` — HTTP method (`POST`)
- `htu` — full URL
- `iat` — current Unix timestamp
- `ath` — SHA-256 of the current access token (base64url, no padding)

---

## GuardianClient — Reusable Auth Helper

The `GuardianClient` handles token acquisition, DPoP proof generation, and mTLS configuration so that every Agno tool call is correctly authenticated.

```python
# guardian_client.py
"""
Reusable authentication client for the Zero-Trust Agentic Guardian.
Handles JWT acquisition, DPoP proof generation, and mTLS setup.
"""

import hashlib
import base64
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend


@dataclass
class GuardianClientConfig:
    """Configuration for authenticating with the Zero-Trust Agentic Guardian."""

    # Auth0 M2M credentials
    auth0_domain: str          # e.g. "your-tenant.auth0.com"
    client_id: str
    client_secret: str
    audience: str              # e.g. "https://ztag.api"

    # Service URLs
    planner_url: str = "http://localhost:8002"
    permission_broker_url: str = "http://localhost:8004"

    # DPoP key (RSA 2048). If not supplied, one is generated in-memory at startup.
    dpop_private_key_path: Optional[str] = None

    # mTLS certificates (optional for local dev)
    mtls_client_cert_path: Optional[str] = None
    mtls_client_key_path: Optional[str] = None
    mtls_ca_cert_path: Optional[str] = None


class GuardianClient:
    """
    Manages JWT lifecycle, DPoP proof generation, and mTLS for calls to ZTAG.

    Usage:
        config = GuardianClientConfig(
            auth0_domain="your-tenant.auth0.com",
            client_id="...",
            client_secret="...",
            audience="https://ztag.api",
        )
        client = GuardianClient(config)

        headers = client.auth_headers("POST", "http://localhost:8002/plan")
        response = httpx.post(url, json=payload, headers=headers)
    """

    _TOKEN_EXPIRY_BUFFER_SECONDS = 30

    def __init__(self, config: GuardianClientConfig) -> None:
        self._config = config
        self._access_token: Optional[str] = None
        self._token_expires_at: float = 0.0
        self._dpop_private_key = self._load_or_generate_dpop_key()
        self._dpop_public_key_jwk = self._build_public_key_jwk()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def auth_headers(self, method: str, url: str) -> dict[str, str]:
        """Return the three authentication headers required by ZTAG."""
        access_token = self._get_access_token()
        dpop_proof = self._generate_dpop_proof(method, url, access_token)
        headers: dict[str, str] = {
            "Authorization": f"Bearer {access_token}",
            "DPoP": dpop_proof,
        }
        if self._config.mtls_client_cert_path:
            cert_pem = Path(self._config.mtls_client_cert_path).read_text()
            headers["X-Client-Certificate"] = cert_pem
        return headers

    def build_httpx_client(self) -> httpx.Client:
        """Build an httpx.Client pre-configured for mTLS if certificates are available."""
        kwargs: dict = {}
        if self._config.mtls_client_cert_path and self._config.mtls_client_key_path:
            kwargs["cert"] = (
                self._config.mtls_client_cert_path,
                self._config.mtls_client_key_path,
            )
        if self._config.mtls_ca_cert_path:
            kwargs["verify"] = self._config.mtls_ca_cert_path
        return httpx.Client(**kwargs)

    # ------------------------------------------------------------------
    # JWT management
    # ------------------------------------------------------------------

    def _get_access_token(self) -> str:
        if time.time() < self._token_expires_at - self._TOKEN_EXPIRY_BUFFER_SECONDS:
            return self._access_token  # type: ignore[return-value]
        return self._refresh_access_token()

    def _refresh_access_token(self) -> str:
        response = httpx.post(
            f"https://{self._config.auth0_domain}/oauth/token",
            json={
                "grant_type": "client_credentials",
                "client_id": self._config.client_id,
                "client_secret": self._config.client_secret,
                "audience": self._config.audience,
            },
            timeout=10,
        )
        response.raise_for_status()
        data = response.json()
        self._access_token = data["access_token"]
        self._token_expires_at = time.time() + data.get("expires_in", 300)
        return self._access_token  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # DPoP proof generation
    # ------------------------------------------------------------------

    def _generate_dpop_proof(self, method: str, url: str, access_token: str) -> str:
        """Generate a signed DPoP proof JWT binding this request to the access token."""
        ath = base64.urlsafe_b64encode(
            hashlib.sha256(access_token.encode()).digest()
        ).rstrip(b"=").decode()

        payload = {
            "jti": str(uuid.uuid4()),
            "htm": method.upper(),
            "htu": url,
            "iat": int(time.time()),
            "ath": ath,
        }
        # RS256 with the public key embedded in the header as JWK
        headers = {
            "typ": "dpop+jwt",
            "alg": "RS256",
            "jwk": self._dpop_public_key_jwk,
        }
        return jwt.encode(payload, self._dpop_private_key, algorithm="RS256", headers=headers)

    # ------------------------------------------------------------------
    # Key helpers
    # ------------------------------------------------------------------

    def _load_or_generate_dpop_key(self):
        if self._config.dpop_private_key_path:
            key_bytes = Path(self._config.dpop_private_key_path).read_bytes()
            return serialization.load_pem_private_key(key_bytes, password=None)
        # Generate an ephemeral key for this process lifetime
        return rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

    def _build_public_key_jwk(self) -> dict:
        """Convert the RSA public key to JWK format for DPoP headers."""
        pub = self._dpop_private_key.public_key()
        pub_numbers = pub.public_key().public_numbers() if hasattr(pub, "public_key") else pub.public_numbers()  # type: ignore[attr-defined]

        def _int_to_base64url(n: int) -> str:
            length = (n.bit_length() + 7) // 8
            return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()

        return {
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "n": _int_to_base64url(pub_numbers.n),
            "e": _int_to_base64url(pub_numbers.e),
        }
```

---

## GuardianToolkit — Agno Toolkit

Wrap the two external Guardian endpoints as an Agno `Toolkit` so that any Agno agent can call `plan_task` and `authorize_action` directly.

```python
# guardian_toolkit.py
"""
Agno Toolkit wrapping the Zero-Trust Agentic Guardian's two external endpoints:
  - plan_task()      → POST /plan      (Planner, port 8002)
  - authorize_action() → POST /authorize (Permission Broker, port 8004)
  - get_audit_logs() → GET  /logs      (Audit, port 8006, if accessible)
"""

import json
from typing import Optional

import httpx
from agno.tools import Toolkit

from guardian_client import GuardianClient, GuardianClientConfig


class GuardianToolkit(Toolkit):
    """
    Agno Toolkit that gives agents secure, policy-enforced access to external
    providers through the Zero-Trust Agentic Guardian.

    All calls are authenticated with JWT + DPoP (+ mTLS when configured).
    """

    def __init__(self, config: GuardianClientConfig) -> None:
        super().__init__(name="zero_trust_guardian")
        self._client = GuardianClient(config)
        self._http = self._client.build_httpx_client()

        # Register tools the LLM may invoke
        self.register(self.plan_task)
        self.register(self.authorize_action)

    # ------------------------------------------------------------------
    # Tool: plan_task
    # ------------------------------------------------------------------

    def plan_task(self, user_goal: str, user_id: str = "agno-agent") -> str:
        """
        Submit a natural-language goal to the Guardian Planner.

        The Planner generates a task graph, obtains an IntentSignature (384-dim
        semantic embedding + RSA cryptographic signature) from the Intent Engine,
        and returns a structured plan.

        Returns a JSON string with:
          - plan_id: unique plan identifier
          - task_graph: list of tasks with action, provider, and parameters
          - intent_signature: cryptographic proof of goal intent

        Args:
            user_goal: Natural-language description of what should be achieved.
            user_id:   Identifier for the requesting user or agent.
        """
        url = f"{self._client._config.planner_url}/plan"
        headers = self._client.auth_headers("POST", url)
        headers["Content-Type"] = "application/json"
        payload = {"user_goal": user_goal, "user_id": user_id, "context": {}}

        response = self._http.post(url, json=payload, headers=headers, timeout=30)
        response.raise_for_status()
        return response.text  # JSON string; Agno passes strings back to the LLM

    # ------------------------------------------------------------------
    # Tool: authorize_action
    # ------------------------------------------------------------------

    def authorize_action(
        self,
        plan_id: str,
        task_id: str,
        action: str,
        provider: str,
        intent_signature_json: str,
        action_params_json: Optional[str] = None,
    ) -> str:
        """
        Request authorization for a single action via the Permission Broker.

        The broker validates the intent signature, runs policy evaluation
        internally, exchanges a Rich Authorization Request (RAR) with the
        identity vault, and returns a Zero-Trust Authorization Token (ZT-AT)
        plus a short-lived provider token.

        Returns a JSON string with:
          - zt_at: ZeroTrustAuthorizationToken (carry this to the Executor)
          - provider_token: { access_token, token_type, expires_in, scope }

        Args:
            plan_id:               ID returned by plan_task.
            task_id:               Specific task ID from the task_graph.
            action:                Action identifier, e.g. "github:create_branch".
            provider:              Provider name, e.g. "github".
            intent_signature_json: JSON-serialised IntentSignature from plan_task.
            action_params_json:    Optional JSON object of action-specific parameters.
        """
        url = f"{self._client._config.permission_broker_url}/authorize"
        headers = self._client.auth_headers("POST", url)
        headers["Content-Type"] = "application/json"

        intent_signature = json.loads(intent_signature_json)
        action_params = json.loads(action_params_json) if action_params_json else {}

        payload = {
            "plan_id": plan_id,
            "task_id": task_id,
            "action": action,
            "provider": provider,
            "intent_signature": intent_signature,
            "action_params": action_params,
        }

        response = self._http.post(url, json=payload, headers=headers, timeout=30)
        response.raise_for_status()
        return response.text
```

---

## Example 1 — Simple Planning Agent

An agent that translates a user's natural-language request into a Guardian task plan and formats the output for the user.

```python
# examples/agno_planning_agent.py
"""
Example 1: Agno agent that uses the Guardian Planner to create secure task plans.

Run:
    GUARDIAN_AUTH0_DOMAIN=tenant.auth0.com \
    GUARDIAN_CLIENT_ID=xxx \
    GUARDIAN_CLIENT_SECRET=yyy \
    GUARDIAN_AUDIENCE=https://ztag.api \
    python examples/agno_planning_agent.py
"""

import json
import os

from agno.agent import Agent
from agno.models.openai import OpenAIChat

from guardian_client import GuardianClientConfig
from guardian_toolkit import GuardianToolkit


def build_config() -> GuardianClientConfig:
    return GuardianClientConfig(
        auth0_domain=os.environ["GUARDIAN_AUTH0_DOMAIN"],
        client_id=os.environ["GUARDIAN_CLIENT_ID"],
        client_secret=os.environ["GUARDIAN_CLIENT_SECRET"],
        audience=os.environ["GUARDIAN_AUDIENCE"],
        planner_url=os.getenv("GUARDIAN_PLANNER_URL", "http://localhost:8002"),
        permission_broker_url=os.getenv("GUARDIAN_BROKER_URL", "http://localhost:8004"),
    )


# Construct toolkit and agent once
toolkit = GuardianToolkit(build_config())

planning_agent = Agent(
    name="SecurePlanningAgent",
    model=OpenAIChat(id="gpt-4o"),
    tools=[toolkit],
    instructions=[
        "You are a secure task planning assistant backed by a Zero-Trust authorization system.",
        "When the user asks you to do something, call plan_task() with their goal.",
        "Present the resulting task_graph as a numbered list.",
        "Mention the plan_id so the user can reference it for authorization.",
        "NEVER attempt to execute actions yourself — they must go through the Guardian.",
    ],
    markdown=True,
)


if __name__ == "__main__":
    response = planning_agent.run(
        "Create a new feature branch called 'feature/zero-trust-audit' "
        "in the org/my-service GitHub repository and open a draft pull request for it."
    )
    print(response.content)
```

**Expected output:**

```
I've submitted your goal to the Zero-Trust Guardian Planner. Here is the approved task plan:

**Plan ID:** `3a4a68a7-cc3b-4efd-9a8c-e9f53f9e9f18`

**Tasks:**

1. **task_001** — `github:create_branch`
   - Repository: `org/my-service`
   - Branch: `feature/zero-trust-audit`

2. **task_002** — `github:create_pr`
   - Title: `[Draft] Zero-Trust Audit Feature`
   - Base branch: `main`

The plan has been cryptographically signed with an IntentSignature. Use the plan ID
and task IDs to authorize each action through the Permission Broker.
```

---

## Example 2 — Full Authorization Flow Agent

This agent completes the full cycle: plan → authorize each task → report the ZT-ATs to the user.

```python
# examples/agno_authorization_agent.py
"""
Example 2: Full plan → authorize cycle using Guardian Planner and Permission Broker.
"""

import json
import os

from agno.agent import Agent
from agno.models.openai import OpenAIChat

from guardian_client import GuardianClientConfig
from guardian_toolkit import GuardianToolkit


toolkit = GuardianToolkit(
    GuardianClientConfig(
        auth0_domain=os.environ["GUARDIAN_AUTH0_DOMAIN"],
        client_id=os.environ["GUARDIAN_CLIENT_ID"],
        client_secret=os.environ["GUARDIAN_CLIENT_SECRET"],
        audience=os.environ["GUARDIAN_AUDIENCE"],
    )
)

authorization_agent = Agent(
    name="ZeroTrustAuthorizationAgent",
    model=OpenAIChat(id="gpt-4o"),
    tools=[toolkit],
    instructions=[
        "You coordinate secure execution of multi-step tasks using the Zero-Trust Guardian.",
        "Step 1: Call plan_task() with the user's goal.",
        "Step 2: For each task in the task_graph, call authorize_action() using the "
        "plan_id, task_id, action, provider, and the intent_signature from step 1.",
        "Step 3: Return a summary of authorized actions and their ZT-AT expiry times.",
        "If authorize_action() returns a 403 or 422 error, report it clearly — "
        "this means the Safety Agent denied the request due to policy violation.",
    ],
    markdown=True,
)


if __name__ == "__main__":
    response = authorization_agent.run(
        "I need to create a branch 'hotfix/cve-2026-001' and push a security patch commit "
        "to the org/payment-service repository on GitHub."
    )
    print(response.content)
```

**What happens internally:**

1. `plan_task("Create a branch hotfix/cve-2026-001 ...")` → Planner calls Intent Engine (semantic embedding + signature) and returns a task graph.
2. Agent parses the task graph JSON, extracts each `task_id`, `action`, `provider`, and the `intent_signature`.
3. Agent calls `authorize_action(...)` for each task → Permission Broker validates the intent signature, evaluates OPA policies, calls Token Vault for a GitHub token, and returns a ZT-AT.
4. Agent presents the authorization summary to the user.

---

## Example 3 — Multi-Agent Team with Guardian Security Layer

Use Agno's `Team` to build a multi-agent system where a **SecurityCoordinator** routes through the Guardian before specialized workers execute actions.

```python
# examples/agno_guardian_team.py
"""
Example 3: Agno Team — SecurityCoordinator delegates to specialists, all
authorization flows through the Zero-Trust Guardian.

Team layout:
  SecurityCoordinator (Team leader)
      ├── PlannerAgent      — calls Guardian Planner
      ├── AuthorizerAgent   — calls Guardian Permission Broker
      └── ReporterAgent     — formats results for the user (no external calls)
"""

import os

from agno.agent import Agent
from agno.models.openai import OpenAIChat
from agno.team import Team

from guardian_client import GuardianClientConfig
from guardian_toolkit import GuardianToolkit


_config = GuardianClientConfig(
    auth0_domain=os.environ["GUARDIAN_AUTH0_DOMAIN"],
    client_id=os.environ["GUARDIAN_CLIENT_ID"],
    client_secret=os.environ["GUARDIAN_CLIENT_SECRET"],
    audience=os.environ["GUARDIAN_AUDIENCE"],
)

# Each agent in the team has its own toolkit instance
# (in practice they share the same GuardianClient TCP connection pool)
planner_toolkit = GuardianToolkit(_config)
authorizer_toolkit = GuardianToolkit(_config)


planner_agent = Agent(
    name="PlannerAgent",
    role="Creates secure task plans through the Zero-Trust Guardian Planner",
    model=OpenAIChat(id="gpt-4o"),
    tools=[planner_toolkit],
    instructions=[
        "Call plan_task() with the goal provided by the SecurityCoordinator.",
        "Return the full JSON response including plan_id and intent_signature.",
        "Do not summarize or truncate the intent_signature — it must be passed verbatim.",
    ],
)

authorizer_agent = Agent(
    name="AuthorizerAgent",
    role="Obtains Zero-Trust Authorization Tokens for each task in a plan",
    model=OpenAIChat(id="gpt-4o"),
    tools=[authorizer_toolkit],
    instructions=[
        "Given a plan_id, task list, and intent_signature JSON from the PlannerAgent, "
        "call authorize_action() for each task.",
        "If any authorization returns a denial, stop and report the denial reason.",
        "Return a JSON array of authorized ZT-ATs for successful authorizations.",
    ],
)

reporter_agent = Agent(
    name="ReporterAgent",
    role="Formats authorization results into a clear, user-friendly summary",
    model=OpenAIChat(id="gpt-4o"),
    instructions=[
        "Given a list of authorized ZT-ATs from the AuthorizerAgent, "
        "format them as a readable summary showing: action, provider, expiry, and "
        "the first 8 characters of the nonce.",
        "If any ZT-AT is missing, flag it.",
    ],
)

security_team = Team(
    name="ZeroTrustOpsTeam",
    agents=[planner_agent, authorizer_agent, reporter_agent],
    model=OpenAIChat(id="gpt-4o"),
    instructions=[
        "You are the SecurityCoordinator for a Zero-Trust multi-agent system.",
        "Workflow:",
        "  1. Ask PlannerAgent to create a task plan for the user's goal.",
        "  2. Pass the plan_id, task list, and intent_signature to AuthorizerAgent.",
        "  3. Pass the ZT-ATs to ReporterAgent for formatting.",
        "  4. Never execute actions yourself — your job is to coordinate safely.",
    ],
    markdown=True,
)


if __name__ == "__main__":
    response = security_team.run(
        "Set up a new Slack channel called '#incident-response' "
        "and invite users alice@company.com and bob@company.com."
    )
    print(response.content)
```

---

## Example 4 — Structured Output with Guardian Schemas

Agno's `response_model` parameter lets you parse LLM responses directly into Pydantic models. Here we reuse the Guardian's own `ZeroTrustAuthorizationToken` shape for type-safe downstream processing.

```python
# examples/agno_structured_output.py
"""
Example 4: Agno agent returning a structured PlanSummary Pydantic model
that mirrors Guardian's schemas, enabling type-safe downstream code.
"""

import json
import os
from typing import List, Optional

from pydantic import BaseModel
from agno.agent import Agent
from agno.models.openai import OpenAIChat

from guardian_client import GuardianClientConfig
from guardian_toolkit import GuardianToolkit


# ---------------------------------------------------------------------------
# Structured output schema (mirrors Guardian's models)
# ---------------------------------------------------------------------------

class TaskItem(BaseModel):
    task_id: str
    action: str
    provider: str
    description: str
    action_params: dict = {}


class PlanSummary(BaseModel):
    plan_id: str
    goal: str
    task_count: int
    tasks: List[TaskItem]
    intent_hash: str           # first 16 chars of SHA-256 hash for display
    is_high_risk: bool         # True if any task is destructive (delete/drop/remove)
    risk_reason: Optional[str] = None


# ---------------------------------------------------------------------------
# Agent with structured output
# ---------------------------------------------------------------------------

toolkit = GuardianToolkit(
    GuardianClientConfig(
        auth0_domain=os.environ["GUARDIAN_AUTH0_DOMAIN"],
        client_id=os.environ["GUARDIAN_CLIENT_ID"],
        client_secret=os.environ["GUARDIAN_CLIENT_SECRET"],
        audience=os.environ["GUARDIAN_AUDIENCE"],
    )
)

structured_planner = Agent(
    name="StructuredPlannerAgent",
    model=OpenAIChat(id="gpt-4o"),
    tools=[toolkit],
    response_model=PlanSummary,
    instructions=[
        "Call plan_task() with the user's goal.",
        "Parse the JSON response and populate the PlanSummary fields.",
        "Set is_high_risk=True if any action contains 'delete', 'drop', 'remove', or 'destroy'.",
        "intent_hash must be the first 16 characters of the intent_signature.hash field.",
    ],
)


if __name__ == "__main__":
    result: PlanSummary = structured_planner.run(
        "Archive and delete the staging environment database for project X."
    ).content  # type: ignore[assignment]

    print(f"Plan ID   : {result.plan_id}")
    print(f"Goal      : {result.goal}")
    print(f"Tasks     : {result.task_count}")
    print(f"Risk      : {'HIGH ⚠️' if result.is_high_risk else 'normal'}")
    if result.risk_reason:
        print(f"Reason    : {result.risk_reason}")
    print()
    for task in result.tasks:
        print(f"  [{task.task_id}] {task.action} via {task.provider}")
```

---

## Example 5 — Prompt-Injection Resistance Test

Demonstrate that the Guardian correctly rejects an agent that has been prompted to perform an action outside its declared intent.

```python
# examples/agno_injection_test.py
"""
Example 5: Verify that the Guardian's semantic alignment check blocks
a prompt-injection attack even when an Agno agent is manipulated.

The original goal is "list GitHub repositories".
The injected goal tries to escalate to "delete_repo" — which is not in
the allowed_actions from the original intent signature.

Expected: authorize_action() returns HTTP 422 / 403 (policy DENY).
"""

import json
import os

import httpx

from guardian_client import GuardianClientConfig, GuardianClient


config = GuardianClientConfig(
    auth0_domain=os.environ["GUARDIAN_AUTH0_DOMAIN"],
    client_id=os.environ["GUARDIAN_CLIENT_ID"],
    client_secret=os.environ["GUARDIAN_CLIENT_SECRET"],
    audience=os.environ["GUARDIAN_AUDIENCE"],
)
gc = GuardianClient(config)
http = gc.build_httpx_client()


def test_prompt_injection_blocked():
    # Step 1: Obtain a legitimate plan for a safe goal
    planner_url = f"{config.planner_url}/plan"
    plan_resp = http.post(
        planner_url,
        json={"user_goal": "List all GitHub repositories in the org", "user_id": "test-agent"},
        headers={**gc.auth_headers("POST", planner_url), "Content-Type": "application/json"},
        timeout=30,
    )
    plan_resp.raise_for_status()
    plan = plan_resp.json()
    plan_id = plan["plan_id"]
    intent_sig = plan["intent_signature"]

    print(f"Plan created: {plan_id}")
    print(f"Allowed actions: {intent_sig['allowed_actions']}")
    # Expected: ["github:list_repos"] — delete_repo NOT present

    # Step 2: Attacker attempts to authorize a destructive action using
    # the intent signature obtained for the safe goal
    broker_url = f"{config.permission_broker_url}/authorize"
    try:
        auth_resp = http.post(
            broker_url,
            json={
                "plan_id": plan_id,
                "task_id": "injected_task",
                "action": "github:delete_repo",          # ← injected escalation
                "provider": "github",
                "intent_signature": intent_sig,          # ← from the safe goal
                "action_params": {"repository": "org/prod-data"},
            },
            headers={**gc.auth_headers("POST", broker_url), "Content-Type": "application/json"},
            timeout=30,
        )
        if auth_resp.status_code in (422, 403):
            print(
                f"\n✅ Injection blocked — HTTP {auth_resp.status_code}\n"
                f"   Reason: {auth_resp.json().get('detail', auth_resp.text)}"
            )
        else:
            print(f"\n❌ UNEXPECTED SUCCESS — HTTP {auth_resp.status_code}")
            print(auth_resp.json())
    except httpx.HTTPStatusError as exc:
        print(f"\n✅ Injection blocked — {exc.response.status_code}: {exc.response.text}")


if __name__ == "__main__":
    test_prompt_injection_blocked()
```

**Why this works:** The Permission Broker's chain validator checks that `github:delete_repo` appears in `intent_signature.allowed_actions`. It does not — the original goal was `list_repos` — so the cosine similarity between the injected action and the original goal falls below the 0.7 threshold and the request is rejected with `ChainValidationError`.

---

## Error Handling

### Guardian error codes your tools may receive

| HTTP Status | Guardian meaning | Agno tool response |
|---|---|---|
| `401 Unauthorized` | JWT expired, DPoP invalid, or mTLS cert rejected | Refresh token then retry once; raise on second failure |
| `403 Forbidden` | Caller identity not recognised (e.g. requester_identity check in Safety Agent) | Fatal — do not retry; report to user |
| `422 Unprocessable Entity` | Intent misalignment (prompt injection) or schema validation failure | Fatal — action is policy-denied; report block reason |
| `429 Too Many Requests` | Rate-limited by Auth0 or Guardian | Back off with exponential delay |
| `503 Service Unavailable` | Upstream Guardian service (OPA, Vault, Redis) unhealthy | Check `/health`; surface to user |

### Retry decorator for transient failures

```python
import functools
import time
import httpx


def retry_on_transient(max_attempts: int = 3, backoff: float = 1.0):
    """Decorator that retries on 429 and 503, raises immediately on 401/403/422."""

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            last_exc = None
            for attempt in range(max_attempts):
                try:
                    return fn(*args, **kwargs)
                except httpx.HTTPStatusError as exc:
                    if exc.response.status_code in (401, 403, 422):
                        raise  # policy or auth errors are not retryable
                    last_exc = exc
                    time.sleep(backoff * (2 ** attempt))
            raise last_exc  # type: ignore[misc]
        return wrapper
    return decorator
```

Apply to toolkit methods:

```python
@retry_on_transient(max_attempts=3)
def plan_task(self, user_goal: str, user_id: str = "agno-agent") -> str:
    ...
```

---

## Configuration Reference

| Environment variable | Default | Description |
|---|---|---|
| `GUARDIAN_AUTH0_DOMAIN` | — | Auth0 tenant domain, e.g. `tenant.auth0.com` |
| `GUARDIAN_CLIENT_ID` | — | Auth0 M2M app client ID |
| `GUARDIAN_CLIENT_SECRET` | — | Auth0 M2M app client secret |
| `GUARDIAN_AUDIENCE` | — | Auth0 audience for ZTAG, e.g. `https://ztag.api` |
| `GUARDIAN_PLANNER_URL` | `http://localhost:8002` | Planner base URL |
| `GUARDIAN_BROKER_URL` | `http://localhost:8004` | Permission Broker base URL |
| `GUARDIAN_DPOP_KEY_PATH` | — | Path to RSA private key PEM file for DPoP proofs |
| `GUARDIAN_MTLS_CLIENT_CERT` | — | Path to client certificate PEM |
| `GUARDIAN_MTLS_CLIENT_KEY` | — | Path to client private key PEM |
| `GUARDIAN_MTLS_CA_CERT` | — | Path to root CA cert PEM for server verification |

---

## Security Considerations

### Do not log or persist tokens

`GuardianClient` holds the JWT access token in memory for the process lifetime. Do not write `access_token` or provider tokens to structured logs, files, or tracing systems. They are short-lived by design (≤ 5 minutes for JWT, ≤ 300 s for ZT-AT).

### DPoP key rotation

If `dpop_private_key_path` is set, rotate the key whenever you rotate service credentials. If left unset, an ephemeral key is generated per process restart — which is fine for development but means new DPoP proofs are invalid across a Guardian process restart until existing JWTs expire.

### intent_signature must not be re-used across plans

Each call to `plan_task()` returns a new `intent_signature` tied to the SHA-256 hash of the exact user goal string. Re-using a signature from one plan with a different `plan_id` or action set will fail the chain validator's embedding and hash checks.

### Validate LLM-generated action_params

Before forwarding `action_params` from an LLM to `authorize_action()`, sanitize and validate the structure. The Guardian's `action_params_hash` binds params to the ZT-AT at authorization time and the Executor validates that hash again at execution, so tampering is detected — but an LLM could still generate unexpected parameter values (e.g. an unintended repository name).

```python
# Validate before authorizing
ALLOWED_REPOS = {"org/my-service", "org/payment-service"}

def safe_authorize_github_action(toolkit, plan_id, task_id, action, intent_sig, params):
    repo = params.get("repository", "")
    if repo not in ALLOWED_REPOS:
        raise ValueError(f"Repository '{repo}' is not in the allow-list.")
    return toolkit.authorize_action(
        plan_id, task_id, action, "github",
        json.dumps(intent_sig), json.dumps(params),
    )
```

### Prefer omitting policy_approval in client requests

The modern zero-trust path has the Permission Broker evaluate policy internally. Do not send a `policy_approval` field from your Agno agent — this avoids the legacy path and ensures the broker's own OPA evaluation is always the authoritative policy check.
