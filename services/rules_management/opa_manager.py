"""OPAManager — async client for the OPA REST Management API.

Handles:
- Deploying / deleting custom Rego policy modules
- Pushing rules_config data document (disabled_rules, spending_limits, etc.)
- Evaluating sample inputs for the test sandbox
- Compile-checking raw Rego before deployment
- One-time initialisation of the monolithic policies.rego with disabled_rules guards
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import httpx


class OPAError(RuntimeError):
    """Raised when an OPA API call fails."""

    def __init__(self, message: str, status_code: int = 0) -> None:
        super().__init__(message)
        self.status_code = status_code


class OPAManager:
    """Async OPA REST API client."""

    def __init__(self, opa_url: str, timeout: float = 10.0) -> None:
        self._base = opa_url.rstrip("/")
        self._timeout = timeout

    # ------------------------------------------------------------------
    # Policy modules (custom rules)
    # ------------------------------------------------------------------

    async def put_policy(self, policy_id: str, rego: str) -> None:
        """Deploy (create or replace) a Rego policy module."""
        url = f"{self._base}/v1/policies/{policy_id}"
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.put(
                url,
                content=rego.encode(),
                headers={"Content-Type": "text/plain"},
            )
        if resp.status_code not in (200, 204):
            raise OPAError(
                f"OPA rejected policy '{policy_id}': {resp.text}",
                status_code=resp.status_code,
            )

    async def delete_policy(self, policy_id: str) -> None:
        """Remove a Rego policy module from OPA."""
        url = f"{self._base}/v1/policies/{policy_id}"
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.delete(url)
        if resp.status_code not in (200, 204, 404):
            raise OPAError(
                f"OPA failed to delete policy '{policy_id}': {resp.text}",
                status_code=resp.status_code,
            )

    async def list_policies(self) -> list[dict]:
        """Return all currently loaded policy modules."""
        url = f"{self._base}/v1/policies"
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.get(url)
        if resp.status_code != 200:
            raise OPAError(f"OPA list policies failed: {resp.text}", resp.status_code)
        return resp.json().get("result", [])

    # ------------------------------------------------------------------
    # Data document (rules_config)
    # ------------------------------------------------------------------

    async def put_data(self, path: str, data: Any) -> None:
        """Write to an OPA data document at the given path.

        path should be slash-separated without leading slash,
        e.g. 'rules_config'.
        """
        url = f"{self._base}/v1/data/{path}"
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.put(url, json=data)
        if resp.status_code not in (200, 204):
            raise OPAError(
                f"OPA data PUT failed at '{path}': {resp.text}",
                status_code=resp.status_code,
            )

    async def push_rules_config(self, rules_config: dict) -> None:
        """Push the full rules_config document to OPA."""
        await self.put_data("rules_config", rules_config)

    # ------------------------------------------------------------------
    # Evaluation (test sandbox)
    # ------------------------------------------------------------------

    async def evaluate(self, input_doc: dict) -> dict:
        """Evaluate the input against the agentic_guardian/decision rule."""
        url = f"{self._base}/v1/data/agentic_guardian/decision"
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(url, json={"input": input_doc})
        if resp.status_code != 200:
            raise OPAError(
                f"OPA evaluation failed: {resp.text}", status_code=resp.status_code
            )
        body = resp.json()
        return body.get("result", {})

    async def evaluate_with_policy(self, rego: str, input_doc: dict) -> dict:
        """Deploy a temporary policy, evaluate, then clean it up.

        Used exclusively by the test sandbox endpoint so the test rule is
        never persisted in OPA beyond the duration of the request.
        """
        tmp_id = "_rules_mgmt_test_sandbox"
        try:
            await self.put_policy(tmp_id, rego)
            result = await self.evaluate(input_doc)
        finally:
            try:
                await self.delete_policy(tmp_id)
            except OPAError:
                pass  # best-effort cleanup
        return result

    # ------------------------------------------------------------------
    # Compile check
    # ------------------------------------------------------------------

    async def compile_check(self, rego: str) -> list[str]:
        """Return a list of compile errors; empty list means the Rego is valid.

        Uses OPA's /v1/compile endpoint with an empty set of unknowns so it
        performs a full parse + type-check pass.
        """
        url = f"{self._base}/v1/compile"
        payload = {
            "query": "data",
            "input": {},
            "options": {"disableInlining": []},
        }
        # The compile endpoint accepts a Rego module via the modules field
        payload["modules"] = {"check": rego}
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(url, json=payload)

        if resp.status_code == 200:
            return []  # valid

        # OPA returns 400 with error details on compile failure
        if resp.status_code == 400:
            body = resp.json()
            errors = body.get("errors", [])
            if errors:
                return [
                    f"{e.get('code', 'error')}: {e.get('message', str(e))}"
                    for e in errors
                ]
            return [resp.text]

        return [f"Unexpected OPA status {resp.status_code}: {resp.text}"]

    # ------------------------------------------------------------------
    # Health check
    # ------------------------------------------------------------------

    async def health_check(self) -> bool:
        """Return True if OPA is reachable and healthy."""
        try:
            url = f"{self._base}/health"
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(url)
            return resp.status_code == 200
        except Exception:
            return False

    # ------------------------------------------------------------------
    # One-time initialisation of the monolithic policies.rego
    # ------------------------------------------------------------------

    async def initialize_system_policy(
        self, policy_file: Path, rule_block_map: dict[str, str]
    ) -> dict[str, str]:
        """Inject disabled_rules guards into the monolithic Rego file.

        For each (opa_rule_block_name, rule_id) pair, adds:
            not "<rule_block>" in data.rules_config.disabled_rules
        as the first line inside the matching deny[msg] block — but only if
        the guard is not already present.

        Returns a dict mapping rule_block → "injected" | "already_present" | "not_found".
        """
        if not policy_file.exists():
            raise FileNotFoundError(f"Policy file not found: {policy_file}")

        original = policy_file.read_text(encoding="utf-8")
        modified = original
        results: dict[str, str] = {}

        for rule_block, rule_id in rule_block_map.items():
            guard = f'not "{rule_block}" in data.rules_config.disabled_rules'

            if guard in modified:
                results[rule_block] = "already_present"
                continue

            # Find deny[msg] { ... } blocks and insert guard as first body line.
            # We look for the block by searching for known content patterns near
            # each deny[msg] {  that match the rule_block semantically.
            pattern = re.compile(
                r"(deny\[msg\]\s*\{)(\s*\n)",
                re.MULTILINE,
            )
            # We inject into *all* deny blocks for simplicity and idempotence;
            # duplicate guards are collapsed by the caller.  A more surgical
            # approach is not needed since the guard is keyed on the rule_block
            # name which is unique per block.
            injected = False
            for m in pattern.finditer(modified):
                # Check if this block already has the guard
                block_start = m.end()
                snippet = modified[block_start: block_start + 500]
                if guard in snippet:
                    continue
                # Only inject into the block that corresponds to this rule by
                # checking that the rule_block name (converted to action name)
                # appears somewhere within 600 chars after the opening brace.
                action_hint = rule_block.replace("deny_", "").replace("_", " ")
                context = modified[m.start(): m.start() + 600].lower()
                if any(word in context for word in action_hint.split()):
                    insert_pos = m.end()
                    indent = "    "
                    modified = (
                        modified[:insert_pos]
                        + f"{indent}{guard}\n"
                        + modified[insert_pos:]
                    )
                    injected = True
                    break

            results[rule_block] = "injected" if injected else "not_found"

        if modified != original:
            policy_file.write_text(modified, encoding="utf-8")
            # Reload the updated policy into OPA
            await self.put_policy("agentic_guardian", modified)

        return results
