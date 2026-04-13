"""Static manifest of all system-embedded rules.

This module defines every rule that already exists in the Guardian codebase
(OPA Rego policies and Safety Agent checks) so the Rules Management API can
surface, toggle, and parameterise them without importing Guardian source code.
"""

from .models import RuleParameter, RuleSource, SystemRule

SYSTEM_RULES_MANIFEST: list[SystemRule] = [
    # ------------------------------------------------------------------
    # OPA Rules — GitHub
    # ------------------------------------------------------------------
    SystemRule(
        rule_id="opa-github-delete-branch",
        name="Block destructive branch deletion without admin role",
        description=(
            "Prevents the 'delete_branch' action on GitHub unless the "
            "requester has the 'admin' role."
        ),
        category="github",
        source=RuleSource.opa,
        opa_policy_id="agentic_guardian",
        opa_rule_block="deny_delete_branch",
        parameters=[],
        enabled_by_default=True,
    ),
    SystemRule(
        rule_id="opa-github-delete-repo",
        name="Block repository deletion without admin role",
        description=(
            "Prevents the 'delete_repository' action on GitHub unless the "
            "requester has the 'admin' role."
        ),
        category="github",
        source=RuleSource.opa,
        opa_policy_id="agentic_guardian",
        opa_rule_block="deny_delete_repository",
        parameters=[],
        enabled_by_default=True,
    ),
    SystemRule(
        rule_id="opa-github-force-push",
        name="Block force-push without admin role",
        description=(
            "Prevents the 'force_push' action on GitHub unless the "
            "requester has the 'admin' role."
        ),
        category="github",
        source=RuleSource.opa,
        opa_policy_id="agentic_guardian",
        opa_rule_block="deny_force_push",
        parameters=[],
        enabled_by_default=True,
    ),
    # ------------------------------------------------------------------
    # OPA Rules — Spending limits
    # ------------------------------------------------------------------
    SystemRule(
        rule_id="opa-spending-aws",
        name="AWS spending limit on create_instance",
        description=(
            "Denies 'create_instance' actions on AWS when the estimated cost "
            "exceeds the configured spending limit."
        ),
        category="spending",
        source=RuleSource.opa,
        opa_policy_id="agentic_guardian",
        opa_rule_block="deny_spending_aws",
        parameters=[
            RuleParameter(
                name="spending_limit",
                label="Spending Limit (USD)",
                type="number",
                default=100.0,
                minimum=0.0,
                description="Maximum estimated cost in USD before the action is denied",
            )
        ],
        enabled_by_default=True,
    ),
    SystemRule(
        rule_id="opa-spending-gcp",
        name="GCP spending limit on provision_resources",
        description=(
            "Denies 'provision_resources' actions on GCP when the estimated cost "
            "exceeds the configured spending limit."
        ),
        category="spending",
        source=RuleSource.opa,
        opa_policy_id="agentic_guardian",
        opa_rule_block="deny_spending_gcp",
        parameters=[
            RuleParameter(
                name="spending_limit",
                label="Spending Limit (USD)",
                type="number",
                default=100.0,
                minimum=0.0,
                description="Maximum estimated cost in USD before the action is denied",
            )
        ],
        enabled_by_default=True,
    ),
    SystemRule(
        rule_id="opa-spending-azure",
        name="Azure spending limit on deploy_infrastructure",
        description=(
            "Denies 'deploy_infrastructure' actions on Azure when the estimated cost "
            "exceeds the configured spending limit."
        ),
        category="spending",
        source=RuleSource.opa,
        opa_policy_id="agentic_guardian",
        opa_rule_block="deny_spending_azure",
        parameters=[
            RuleParameter(
                name="spending_limit",
                label="Spending Limit (USD)",
                type="number",
                default=100.0,
                minimum=0.0,
                description="Maximum estimated cost in USD before the action is denied",
            )
        ],
        enabled_by_default=True,
    ),
    # ------------------------------------------------------------------
    # OPA Rules — Access control / categories
    # ------------------------------------------------------------------
    SystemRule(
        rule_id="opa-action-category",
        name="Restrict actions to allowed categories per service",
        description=(
            "Denies any action whose category is not in the "
            "'allowed_categories' list defined in the evaluation context."
        ),
        category="access_control",
        source=RuleSource.opa,
        opa_policy_id="agentic_guardian",
        opa_rule_block="deny_action_category",
        parameters=[],
        enabled_by_default=True,
    ),
    # ------------------------------------------------------------------
    # OPA Rules — Intent alignment
    # ------------------------------------------------------------------
    SystemRule(
        rule_id="opa-intent-alignment",
        name="Intent alignment threshold enforcement",
        description=(
            "Denies any action whose intent alignment score falls below the "
            "configured minimum threshold (default 0.7)."
        ),
        category="intent",
        source=RuleSource.opa,
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
                description=(
                    "Cosine similarity scores below this value are denied. "
                    "Range: 0.0 – 1.0."
                ),
            )
        ],
        enabled_by_default=True,
    ),
    # ------------------------------------------------------------------
    # OPA Rules — Filesystem
    # ------------------------------------------------------------------
    SystemRule(
        rule_id="opa-filesystem-destructive",
        name="Block destructive filesystem operations without admin role",
        description=(
            "Denies destructive filesystem operations (delete, wipe, erase, etc.) "
            "unless the requester has the 'admin' role. Also blocks admin operations "
            "targeting critical system paths."
        ),
        category="filesystem",
        source=RuleSource.opa,
        opa_policy_id="agentic_guardian",
        opa_rule_block="deny_destructive_filesystem",
        parameters=[],
        enabled_by_default=True,
    ),
    # ------------------------------------------------------------------
    # OPA Rules — System commands
    # ------------------------------------------------------------------
    SystemRule(
        rule_id="opa-system-commands",
        name="Block system-level commands",
        description=(
            "Denies system-level commands such as shutdown, reboot, halt, "
            "poweroff, kill_process, and format_drive from being executed "
            "through the Guardian."
        ),
        category="system",
        source=RuleSource.opa,
        opa_policy_id="agentic_guardian",
        opa_rule_block="deny_system_commands",
        parameters=[],
        enabled_by_default=True,
    ),
    # ------------------------------------------------------------------
    # OPA Rules — Batch destructive
    # ------------------------------------------------------------------
    SystemRule(
        rule_id="opa-batch-destructive",
        name="Block batch destructive operations",
        description=(
            "Denies destructive operations that also contain batch keywords "
            "such as 'batch', 'mass', 'all', 'recursive', or 'everyone'."
        ),
        category="filesystem",
        source=RuleSource.opa,
        opa_policy_id="agentic_guardian",
        opa_rule_block="deny_batch_destructive",
        parameters=[],
        enabled_by_default=True,
    ),
    # ------------------------------------------------------------------
    # Safety Agent Rules
    # ------------------------------------------------------------------
    SystemRule(
        rule_id="sa-action-whitelist",
        name="Known safe action whitelist per provider",
        description=(
            "Rejects any action that is not in the hardcoded whitelist of "
            "known-safe actions for the target provider. Evaluated inside the "
            "Safety Agent before OPA is consulted."
        ),
        category="access_control",
        source=RuleSource.safety_agent,
        opa_policy_id=None,
        opa_rule_block=None,
        parameters=[],
        enabled_by_default=True,
    ),
    SystemRule(
        rule_id="sa-dangerous-patterns",
        name="Dangerous pattern detection in action names",
        description=(
            "Scans action names for dangerous substrings (delete, destroy, wipe, "
            "format, purge, shutdown, etc.) and rejects them before OPA evaluation."
        ),
        category="security",
        source=RuleSource.safety_agent,
        opa_policy_id=None,
        opa_rule_block=None,
        parameters=[],
        enabled_by_default=True,
    ),
    SystemRule(
        rule_id="sa-intent-alignment-check",
        name="Action alignment with intent signature allowed_actions",
        description=(
            "Verifies that the proposed action appears in the "
            "'allowed_actions' list of the intent signature. Actions not "
            "present are blocked as intent-misaligned."
        ),
        category="intent",
        source=RuleSource.safety_agent,
        opa_policy_id=None,
        opa_rule_block=None,
        parameters=[],
        enabled_by_default=True,
    ),
]

# Index by rule_id for O(1) lookup
SYSTEM_RULES_BY_ID: dict[str, SystemRule] = {
    r.rule_id: r for r in SYSTEM_RULES_MANIFEST
}
