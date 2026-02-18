package terraform.grafana.dashboard

import rego.v1

# ============================================================
# Dashboard Governance Policies
# Enforces standards for grafana_dashboard resources
# ============================================================

# Collect all dashboard resource changes
dashboard_resources contains r if {
    r := input.resource_changes[_]
    r.type == "grafana_dashboard"
    r.change.actions[_] != "delete"
}

# DENY: Dashboards must be placed in a folder (no root-level dashboards)
deny contains msg if {
    r := dashboard_resources[_]
    not r.change.after.folder
    msg := sprintf("DASHBOARD-001: %v - dashboard must be assigned to a folder (folder attribute is required)", [r.address])
}

deny contains msg if {
    r := dashboard_resources[_]
    r.change.after.folder == ""
    msg := sprintf("DASHBOARD-001: %v - dashboard folder must not be empty", [r.address])
}

# DENY: Dashboard config_json must be provided
deny contains msg if {
    r := dashboard_resources[_]
    not r.change.after.config_json
    msg := sprintf("DASHBOARD-002: %v - dashboard must have config_json defined", [r.address])
}

# WARN: Dashboards should not be overwritten without explicit flag
warn contains msg if {
    r := dashboard_resources[_]
    r.change.after.overwrite == true
    msg := sprintf("DASHBOARD-003: %v - dashboard has overwrite=true, ensure this is intentional", [r.address])
}

# DENY: Dashboard message (commit message) should be provided for audit trail
deny contains msg if {
    r := dashboard_resources[_]
    not r.change.after.message
    msg := sprintf("DASHBOARD-004: %v - dashboard should include a 'message' for change tracking", [r.address])
}
