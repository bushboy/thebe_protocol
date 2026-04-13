package agentic_guardian

# Default decision is to deny
default allow = false

# ---------------------------------------------------------------------------
# rules_config — populated by the Rules Management API via OPA data document.
# Defaults ensure the policy works even before the API has pushed any data.
# ---------------------------------------------------------------------------

default_disabled_rules := set()
default_spending_limits := {"aws": 100.0, "gcp": 100.0, "azure": 100.0}
default_intent_threshold := 0.7

disabled_rules := data.rules_config.disabled_rules if {
    data.rules_config.disabled_rules
} else := default_disabled_rules

spending_limits := data.rules_config.spending_limits if {
    data.rules_config.spending_limits
} else := default_spending_limits

intent_threshold := data.rules_config.intent_alignment_threshold if {
    data.rules_config.intent_alignment_threshold
} else := default_intent_threshold

# custom_disabled_rules — used by dynamically deployed custom rule modules
custom_disabled_rules := data.rules_config.custom_disabled_rules if {
    data.rules_config.custom_disabled_rules
} else := set()

# ---------------------------------------------------------------------------
# Collect all denial reasons
# ---------------------------------------------------------------------------

# --- GitHub: destructive actions ---

deny[msg] {
    not "deny_delete_branch" in disabled_rules
    input.action == "delete_branch"
    input.provider == "github"
    input.context.role != "admin"
    msg := "Destructive GitHub action 'delete_branch' requires admin role"
}

deny[msg] {
    not "deny_delete_repository" in disabled_rules
    input.action == "delete_repository"
    input.provider == "github"
    input.context.role != "admin"
    msg := "Destructive GitHub action 'delete_repository' requires admin role"
}

deny[msg] {
    not "deny_force_push" in disabled_rules
    input.action == "force_push"
    input.provider == "github"
    input.context.role != "admin"
    msg := "Destructive GitHub action 'force_push' requires admin role"
}

# --- Spending limits (configurable via rules_config) ---

deny[msg] {
    not "deny_spending_aws" in disabled_rules
    input.action == "create_instance"
    input.provider == "aws"
    limit := spending_limits.aws
    input.estimated_cost > limit
    msg := sprintf("Action exceeds AWS spending limit: $%.2f > $%.2f", [input.estimated_cost, limit])
}

deny[msg] {
    not "deny_spending_gcp" in disabled_rules
    input.action == "provision_resources"
    input.provider == "gcp"
    limit := spending_limits.gcp
    input.estimated_cost > limit
    msg := sprintf("Action exceeds GCP spending limit: $%.2f > $%.2f", [input.estimated_cost, limit])
}

deny[msg] {
    not "deny_spending_azure" in disabled_rules
    input.action == "deploy_infrastructure"
    input.provider == "azure"
    limit := spending_limits.azure
    input.estimated_cost > limit
    msg := sprintf("Action exceeds Azure spending limit: $%.2f > $%.2f", [input.estimated_cost, limit])
}

# --- Action category allowlist ---

deny[msg] {
    not "deny_action_category" in disabled_rules
    not action_category_allowed
    msg := sprintf("Action category '%s' is not in allowed categories for service '%s'", [input.action_category, input.context.service])
}

# --- Intent alignment threshold (configurable via rules_config) ---

deny[msg] {
    not "deny_intent_alignment" in disabled_rules
    input.intent_alignment_score < intent_threshold
    msg := sprintf("Intent alignment score %.2f is below threshold %.2f", [input.intent_alignment_score, intent_threshold])
}

# --- Filesystem destructive operations ---

deny[msg] {
    not "deny_destructive_filesystem" in disabled_rules
    is_destructive_filesystem_operation
    input.context.role != "admin"
    msg := sprintf("Destructive filesystem operation '%s' requires admin role", [input.action])
}

deny[msg] {
    not "deny_destructive_filesystem" in disabled_rules
    is_destructive_filesystem_operation
    input.context.role == "admin"
    has_dangerous_scope
    msg := sprintf("Operation '%s' would affect critical system paths - denied: %v", [input.action, input.action_params.targets])
}

# --- System commands ---

deny[msg] {
    not "deny_system_commands" in disabled_rules
    is_system_level_command
    msg := sprintf("System-level command '%s' is not allowed through Guardian", [input.action])
}

# --- Batch destructive operations ---

deny[msg] {
    not "deny_batch_destructive" in disabled_rules
    is_batch_destructive_operation
    msg := sprintf("Batch destructive operation '%s' is not permitted", [input.action])
}

# Helper rule to check if action category is allowed
action_category_allowed {
    input.action_category == input.context.allowed_categories[_]
}

# Destructive filesystem actions
destructive_fs_actions = {
    "delete_directory",
    "delete_files",
    "remove_recursive",
    "rm_recursive",
    "delete_all_files",
    "wipe_directory",
    "format_volume",
    "erase_partition",
    "destroy_data",
    "purge_directory"
}

is_destructive_filesystem_operation {
    lower_action := lower(input.action)
    destructive_fs_actions[_] == lower_action
}

is_destructive_filesystem_operation {
    # Check for dangerous patterns in action name
    action_lower := lower(input.action)
    dangerous_patterns := ["delete", "remove", "wipe", "destroy", "erase", "format"]
    any_pattern := dangerous_patterns[_]
    contains(action_lower, any_pattern)
    # And it looks like a filesystem operation
    contains(action_lower, "file") or contains(action_lower, "dir") or
    contains(action_lower, "path") or contains(action_lower, "folder") or
    contains(action_lower, "directory")
}

# Critical system paths that must be protected
critical_paths = {
    "/",
    "/bin",
    "/sbin",
    "/boot",
    "/usr/bin",
    "/usr/sbin",
    "/etc",
    "/sys",
    "/proc",
    "/dev",
    "/root",
    "/home",
    "/var/log",
    "/opt"
}

has_dangerous_scope {
    targets := input.action_params.targets
    targets != null
    target := targets[_]
    critical_paths[_] == target
}

has_dangerous_scope {
    targets := input.action_params.targets
    targets != null
    target := targets[_]
    # Check if target starts with any critical path
    critical := critical_paths[_]
    startswith(target, critical)
}

# System-level commands that shouldn't go through Guardian
system_level_actions = {
    "shutdown",
    "reboot",
    "halt",
    "poweroff",
    "change_permissions",
    "modify_firewall",
    "kill_process",
    "terminate_service",
    "uninstall_kernel",
    "format_drive"
}

is_system_level_command {
    lower_action := lower(input.action)
    system_level_actions[_] == lower_action
}

# Batch destructive operations
batch_destructive_keywords = ["batch", "mass", "all", "recursive", "everyone"]

is_batch_destructive_operation {
    is_destructive_filesystem_operation
    action_lower := lower(input.action)
    any_keyword := batch_destructive_keywords[_]
    contains(action_lower, any_keyword)
}

# Allow decision if no denials
allow {
    count(deny) == 0
}

# Policy decision structure
decision = {
    "allow": allow,
    "deny_reasons": deny
}
