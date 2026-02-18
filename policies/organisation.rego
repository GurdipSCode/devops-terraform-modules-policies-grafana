package terraform.grafana.organization

import rego.v1

# ============================================================
# Folder & Organization Governance Policies
# Enforces standards for folders, orgs, and teams
# ============================================================

# --- Folders ---

folder_resources contains r if {
    r := input.resource_changes[_]
    r.type == "grafana_folder"
    r.change.actions[_] != "delete"
}

# DENY: Folders must have a title
deny contains msg if {
    r := folder_resources[_]
    not r.change.after.title
    msg := sprintf("ORG-001: %v - folder must have a title", [r.address])
}

deny contains msg if {
    r := folder_resources[_]
    r.change.after.title == ""
    msg := sprintf("ORG-001: %v - folder title must not be empty", [r.address])
}

# --- Organizations ---

org_resources contains r if {
    r := input.resource_changes[_]
    r.type == "grafana_organization"
    r.change.actions[_] != "delete"
}

# DENY: Organizations must have at least one admin
deny contains msg if {
    r := org_resources[_]
    admins := r.change.after.admins
    admins != null
    count(admins) == 0
    msg := sprintf("ORG-002: %v - organization must have at least one admin", [r.address])
}

# DENY: Organization must have a name
deny contains msg if {
    r := org_resources[_]
    not r.change.after.name
    msg := sprintf("ORG-003: %v - organization must have a name", [r.address])
}

# --- Teams ---

team_resources contains r if {
    r := input.resource_changes[_]
    r.type == "grafana_team"
    r.change.actions[_] != "delete"
}

# DENY: Teams must have a name
deny contains msg if {
    r := team_resources[_]
    not r.change.after.name
    msg := sprintf("ORG-004: %v - team must have a name", [r.address])
}

# --- Folder Permissions ---

folder_permission_resources contains r if {
    r := input.resource_changes[_]
    r.type == "grafana_folder_permission"
    r.change.actions[_] != "delete"
}

# WARN: Granting Editor or Admin role to a broad audience
warn contains msg if {
    r := folder_permission_resources[_]
    perms := r.change.after.permissions[_]
    perms.role == "Editor"
    msg := sprintf("ORG-005: %v - folder grants Editor role broadly; verify this is intended", [r.address])
}
