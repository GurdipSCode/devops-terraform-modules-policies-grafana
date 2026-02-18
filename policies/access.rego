package terraform.grafana.access

import rego.v1

# ============================================================
# Access Control & Service Account Policies
# Enforces standards for API keys, service accounts, and RBAC
# ============================================================

# --- Service Accounts ---

service_account_resources contains r if {
    r := input.resource_changes[_]
    r.type == "grafana_service_account"
    r.change.actions[_] != "delete"
}

# Disallowed roles for service accounts (principle of least privilege)
disallowed_sa_roles := ["Admin"]

# DENY: Service accounts must not be created with Admin role
deny contains msg if {
    r := service_account_resources[_]
    role := r.change.after.role
    role in disallowed_sa_roles
    msg := sprintf("ACCESS-001: %v - service account role '%v' is not permitted. Use a more restrictive role.", [r.address, role])
}

# DENY: Service accounts must have a name
deny contains msg if {
    r := service_account_resources[_]
    not r.change.after.name
    msg := sprintf("ACCESS-002: %v - service account must have a name", [r.address])
}

# DENY: Service accounts must not be disabled at creation
deny contains msg if {
    r := service_account_resources[_]
    r.change.after.is_disabled == true
    msg := sprintf("ACCESS-003: %v - creating a disabled service account is not allowed; remove it instead", [r.address])
}

# --- Service Account Tokens ---

sa_token_resources contains r if {
    r := input.resource_changes[_]
    r.type == "grafana_service_account_token"
    r.change.actions[_] != "delete"
}

# WARN: Service account tokens without expiration
warn contains msg if {
    r := sa_token_resources[_]
    not r.change.after.expiration
    msg := sprintf("ACCESS-004: %v - service account token has no expiration; consider setting one for security", [r.address])
}

# --- API Keys (legacy, prefer service accounts) ---

api_key_resources contains r if {
    r := input.resource_changes[_]
    r.type == "grafana_api_key"
    r.change.actions[_] != "delete"
}

# WARN: API keys are deprecated; use service accounts instead
warn contains msg if {
    r := api_key_resources[_]
    msg := sprintf("ACCESS-005: %v - grafana_api_key is deprecated; migrate to grafana_service_account + token", [r.address])
}

# DENY: API keys must not have Admin role
deny contains msg if {
    r := api_key_resources[_]
    r.change.after.role == "Admin"
    msg := sprintf("ACCESS-006: %v - API key must not have Admin role", [r.address])
}

# --- RBAC Role Assignments ---

role_assignment_resources contains r if {
    r := input.resource_changes[_]
    r.type == "grafana_role_assignment"
    r.change.actions[_] != "delete"
}

# WARN: Review any custom role assignments
warn contains msg if {
    r := role_assignment_resources[_]
    msg := sprintf("ACCESS-007: %v - custom role assignment detected; ensure it follows least privilege", [r.address])
}
