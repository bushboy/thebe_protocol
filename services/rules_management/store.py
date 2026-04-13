"""RulesStore — JSON-file persistence layer for the Rules Management service.

Abstracts all read/write access to rules_store.json.  The file is the single
source of truth for:
  - System rule states (enabled flag + param overrides)
  - Custom rule definitions (Rego, metadata)

The store is also written as `rules_config` inside the store so the Safety
Agent can read SA-specific flags (sa_disabled_rules) from the same file.

Thread safety: a threading.Lock guards every write.  For multi-process
deployments, replace this module with a database-backed implementation that
satisfies the same interface.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .manifest import SYSTEM_RULES_BY_ID, SYSTEM_RULES_MANIFEST
from .models import CustomRule, SystemRuleState


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class RulesStore:
    """Reads and writes rules_store.json atomically."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._ensure_file()

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    def _ensure_file(self) -> None:
        """Create the store file with defaults if it does not exist."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if not self._path.exists():
            self._write(_default_store())

    # ------------------------------------------------------------------
    # Low-level I/O
    # ------------------------------------------------------------------

    def _read(self) -> dict:
        try:
            with self._path.open("r", encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            raise RuntimeError(f"Cannot read rules store: {exc}") from exc

    def _write(self, data: dict) -> None:
        data["updated_at"] = _utcnow().isoformat()
        tmp = self._path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)
        tmp.replace(self._path)

    # ------------------------------------------------------------------
    # System rules
    # ------------------------------------------------------------------

    def get_system_rule_states(self) -> dict[str, SystemRuleState]:
        data = self._read()
        result: dict[str, SystemRuleState] = {}
        for raw in data.get("system_rules", []):
            state = SystemRuleState(**raw)
            result[state.rule_id] = state
        return result

    def get_system_rule_state(self, rule_id: str) -> Optional[SystemRuleState]:
        return self.get_system_rule_states().get(rule_id)

    def set_system_rule_state(self, state: SystemRuleState) -> None:
        with self._lock:
            data = self._read()
            rules = data.get("system_rules", [])
            updated = False
            for i, r in enumerate(rules):
                if r["rule_id"] == state.rule_id:
                    rules[i] = state.model_dump(mode="json")
                    updated = True
                    break
            if not updated:
                rules.append(state.model_dump(mode="json"))
            data["system_rules"] = rules
            self._write_with_config_sync(data)

    # ------------------------------------------------------------------
    # Custom rules
    # ------------------------------------------------------------------

    def list_custom_rules(self) -> list[CustomRule]:
        data = self._read()
        return [CustomRule(**r) for r in data.get("custom_rules", [])]

    def get_custom_rule(self, rule_id: str) -> Optional[CustomRule]:
        for rule in self.list_custom_rules():
            if rule.rule_id == rule_id:
                return rule
        return None

    def add_custom_rule(self, rule: CustomRule) -> None:
        with self._lock:
            data = self._read()
            rules = data.get("custom_rules", [])
            if any(r["rule_id"] == rule.rule_id for r in rules):
                raise ValueError(f"Rule '{rule.rule_id}' already exists")
            rules.append(rule.model_dump(mode="json"))
            data["custom_rules"] = rules
            self._write(data)

    def update_custom_rule(self, rule: CustomRule) -> None:
        with self._lock:
            data = self._read()
            rules = data.get("custom_rules", [])
            for i, r in enumerate(rules):
                if r["rule_id"] == rule.rule_id:
                    rules[i] = rule.model_dump(mode="json")
                    data["custom_rules"] = rules
                    self._write(data)
                    return
            raise KeyError(f"Rule '{rule.rule_id}' not found")

    def delete_custom_rule(self, rule_id: str) -> None:
        with self._lock:
            data = self._read()
            before = len(data.get("custom_rules", []))
            data["custom_rules"] = [
                r for r in data.get("custom_rules", []) if r["rule_id"] != rule_id
            ]
            if len(data["custom_rules"]) == before:
                raise KeyError(f"Rule '{rule_id}' not found")
            self._write(data)

    # ------------------------------------------------------------------
    # rules_config sync (read by Safety Agent + OPA data document)
    # ------------------------------------------------------------------

    def build_rules_config(self) -> dict[str, Any]:
        """Build the rules_config dict that is pushed to OPA as data and
        read by the Safety Agent."""
        states = self.get_system_rule_states()

        # OPA disabled rule blocks
        disabled_opa: list[str] = []
        for rule_id, state in states.items():
            manifest_entry = SYSTEM_RULES_BY_ID.get(rule_id)
            if (
                manifest_entry
                and manifest_entry.opa_rule_block
                and not state.enabled
            ):
                disabled_opa.append(manifest_entry.opa_rule_block)

        # SA disabled rule IDs
        sa_disabled = [
            rule_id
            for rule_id, state in states.items()
            if rule_id.startswith("sa-") and not state.enabled
        ]

        # Spending limits from param overrides
        spending_limits: dict[str, float] = {}
        for rule_id, state in states.items():
            if rule_id == "opa-spending-aws":
                spending_limits["aws"] = float(
                    state.param_values.get("spending_limit", 100.0)
                )
            elif rule_id == "opa-spending-gcp":
                spending_limits["gcp"] = float(
                    state.param_values.get("spending_limit", 100.0)
                )
            elif rule_id == "opa-spending-azure":
                spending_limits["azure"] = float(
                    state.param_values.get("spending_limit", 100.0)
                )

        # Intent threshold
        intent_state = states.get("opa-intent-alignment")
        intent_threshold = float(
            intent_state.param_values.get("threshold", 0.7)
            if intent_state
            else 0.7
        )

        return {
            "disabled_rules": disabled_opa,
            "sa_disabled_rules": sa_disabled,
            "spending_limits": spending_limits,
            "intent_alignment_threshold": intent_threshold,
        }

    def _write_with_config_sync(self, data: dict) -> None:
        """Write store data and embed rules_config for the Safety Agent."""
        # Rebuild rules_config inline from the data being written
        states_raw = data.get("system_rules", [])
        states = {r["rule_id"]: SystemRuleState(**r) for r in states_raw}

        disabled_opa = []
        sa_disabled = []
        spending_limits: dict[str, float] = {}
        intent_threshold = 0.7

        for rule_id, state in states.items():
            manifest_entry = SYSTEM_RULES_BY_ID.get(rule_id)
            if manifest_entry and manifest_entry.opa_rule_block and not state.enabled:
                disabled_opa.append(manifest_entry.opa_rule_block)
            if rule_id.startswith("sa-") and not state.enabled:
                sa_disabled.append(rule_id)
            if rule_id == "opa-spending-aws":
                spending_limits["aws"] = float(
                    state.param_values.get("spending_limit", 100.0)
                )
            elif rule_id == "opa-spending-gcp":
                spending_limits["gcp"] = float(
                    state.param_values.get("spending_limit", 100.0)
                )
            elif rule_id == "opa-spending-azure":
                spending_limits["azure"] = float(
                    state.param_values.get("spending_limit", 100.0)
                )
            elif rule_id == "opa-intent-alignment":
                intent_threshold = float(
                    state.param_values.get("threshold", 0.7)
                )

        data["rules_config"] = {
            "disabled_rules": disabled_opa,
            "sa_disabled_rules": sa_disabled,
            "spending_limits": spending_limits,
            "intent_alignment_threshold": intent_threshold,
        }
        self._write(data)

    def is_readable(self) -> bool:
        try:
            self._read()
            return True
        except Exception:
            return False


# ------------------------------------------------------------------
# Default store factory
# ------------------------------------------------------------------


def _default_store() -> dict:
    """Generate an initial store populated from the manifest defaults."""
    now = _utcnow().isoformat()
    system_rules = [
        {
            "rule_id": rule.rule_id,
            "enabled": rule.enabled_by_default,
            "param_values": {p.name: p.default for p in rule.parameters},
            "last_modified": now,
            "modified_by": "system",
        }
        for rule in SYSTEM_RULES_MANIFEST
    ]
    return {
        "version": 1,
        "updated_at": now,
        "system_rules": system_rules,
        "custom_rules": [],
        "rules_config": {
            "disabled_rules": [],
            "sa_disabled_rules": [],
            "spending_limits": {"aws": 100.0, "gcp": 100.0, "azure": 100.0},
            "intent_alignment_threshold": 0.7,
        },
    }
