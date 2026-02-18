package terraform.grafana.general

import rego.v1

# ============================================================
# General Governance Policies
# Blast radius limits, deletion protection, provider checks
# ============================================================

# Maximum number of resources that can be destroyed in a single plan
max_deletions := 5

# All Grafana resource changes
grafana_resources contains r if {
    r := input.resource_changes[_]
    startswith(r.type, "grafana_")
}

# Count of resources being deleted
deletions := [r |
    r := grafana_resources[_]
    r.change.actions[_] == "delete"
]

# DENY: Blast radius - too many deletions in a single plan
deny contains msg if {
    count(deletions) > max_deletions
    msg := sprintf("GENERAL-001: Plan deletes %v Grafana resources (max allowed: %v). Break into smaller changes.", [count(deletions), max_deletions])
}

# Count of all resources being created or modified
all_changes := [r |
    r := grafana_resources[_]
    r.change.actions[_] != "no-op"
    r.change.actions[_] != "read"
]

# Maximum total changes in a single plan
max_total_changes := 30

# DENY: Blast radius - too many total changes
deny contains msg if {
    count(all_changes) > max_total_changes
    msg := sprintf("GENERAL-002: Plan modifies %v Grafana resources (max allowed: %v). Break into smaller changes.", [count(all_changes), max_total_changes])
}

# --- Provider Version Check ---

# WARN: Ensure a minimum Terraform version
minimum_terraform := "1.5.0"

warn contains msg if {
    v := input.terraform_version
    semver.compare(v, minimum_terraform) < 0
    msg := sprintf("GENERAL-003: Terraform version %v is below minimum %v", [v, minimum_terraform])
}

# --- Protected Resource Types (require extra caution) ---

protected_types := [
    "grafana_organization",
    "grafana_service_account",
    "grafana_notification_policy",
]

# WARN: Modifications to protected resource types
warn contains msg if {
    r := grafana_resources[_]
    r.type in protected_types
    r.change.actions[_] == "delete"
    msg := sprintf("GENERAL-004: Deleting protected resource type '%v' at %v - requires review", [r.type, r.address])
}

warn contains msg if {
    r := grafana_resources[_]
    r.type in protected_types
    r.change.actions[_] == "update"
    msg := sprintf("GENERAL-005: Updating protected resource type '%v' at %v - requires review", [r.type, r.address])
}
