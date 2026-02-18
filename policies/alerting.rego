package terraform.grafana.alerting

import rego.v1

# ============================================================
# Alerting & Notification Governance Policies
# Enforces standards for Grafana alerting resources
# ============================================================

# --- Alert Rules ---

alert_rule_resources contains r if {
    r := input.resource_changes[_]
    r.type == "grafana_rule_group"
    r.change.actions[_] != "delete"
}

# DENY: Alert rule groups must belong to a folder
deny contains msg if {
    r := alert_rule_resources[_]
    not r.change.after.folder_uid
    msg := sprintf("ALERT-001: %v - alert rule group must specify a folder_uid", [r.address])
}

# DENY: Alert rule groups must have a reasonable interval (>= 60s)
deny contains msg if {
    r := alert_rule_resources[_]
    interval := r.change.after.interval_seconds
    interval < 60
    msg := sprintf("ALERT-002: %v - alert evaluation interval %vs is too frequent (minimum 60s)", [r.address, interval])
}

# DENY: Alert rule groups must have a name
deny contains msg if {
    r := alert_rule_resources[_]
    not r.change.after.name
    msg := sprintf("ALERT-003: %v - alert rule group must have a name", [r.address])
}

# --- Contact Points ---

contact_point_resources contains r if {
    r := input.resource_changes[_]
    r.type == "grafana_contact_point"
    r.change.actions[_] != "delete"
}

# DENY: Contact points must have a name
deny contains msg if {
    r := contact_point_resources[_]
    not r.change.after.name
    msg := sprintf("ALERT-004: %v - contact point must have a name", [r.address])
}

# --- Notification Policies ---

notification_policy_resources contains r if {
    r := input.resource_changes[_]
    r.type == "grafana_notification_policy"
    r.change.actions[_] != "delete"
}

# DENY: Notification policy must define a default contact point
deny contains msg if {
    r := notification_policy_resources[_]
    not r.change.after.contact_point
    msg := sprintf("ALERT-005: %v - notification policy must have a default contact_point", [r.address])
}

# WARN: Notification policies with group_wait < 30s may cause noise
warn contains msg if {
    r := notification_policy_resources[_]
    gw := r.change.after.group_wait
    gw != null
    time.parse_duration_ns(gw) < 30000000000
    msg := sprintf("ALERT-006: %v - group_wait '%v' is very short, may cause alert noise", [r.address, gw])
}
