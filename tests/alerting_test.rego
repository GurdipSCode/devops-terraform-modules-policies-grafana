package terraform.grafana.alerting_test

import rego.v1

import data.terraform.grafana.alerting

# ============================================================
# Helpers
# ============================================================

mock_rule_group(addr, after) := {
    "address": addr,
    "type": "grafana_rule_group",
    "change": {
        "actions": ["create"],
        "after": after,
    },
}

mock_contact_point(addr, after) := {
    "address": addr,
    "type": "grafana_contact_point",
    "change": {
        "actions": ["create"],
        "after": after,
    },
}

mock_notification_policy(addr, after) := {
    "address": addr,
    "type": "grafana_notification_policy",
    "change": {
        "actions": ["create"],
        "after": after,
    },
}

# ============================================================
# ALERT-001: Rule group must have folder_uid
# ============================================================

test_deny_rule_group_no_folder_uid if {
    inp := {"resource_changes": [mock_rule_group("grafana_rule_group.test", {
        "name": "my-group",
        "interval_seconds": 120,
    })]}
    result := alerting.deny with input as inp
    some msg in result
    contains(msg, "ALERT-001")
}

test_allow_rule_group_with_folder_uid if {
    inp := {"resource_changes": [mock_rule_group("grafana_rule_group.test", {
        "name": "my-group",
        "folder_uid": "abc123",
        "interval_seconds": 120,
    })]}
    result := alerting.deny with input as inp
    not_contains_code(result, "ALERT-001")
}

# ============================================================
# ALERT-002: Interval must be >= 60s
# ============================================================

test_deny_rule_group_interval_too_short if {
    inp := {"resource_changes": [mock_rule_group("grafana_rule_group.test", {
        "name": "my-group",
        "folder_uid": "abc123",
        "interval_seconds": 10,
    })]}
    result := alerting.deny with input as inp
    some msg in result
    contains(msg, "ALERT-002")
}

test_allow_rule_group_interval_60 if {
    inp := {"resource_changes": [mock_rule_group("grafana_rule_group.test", {
        "name": "my-group",
        "folder_uid": "abc123",
        "interval_seconds": 60,
    })]}
    result := alerting.deny with input as inp
    not_contains_code(result, "ALERT-002")
}

test_allow_rule_group_interval_300 if {
    inp := {"resource_changes": [mock_rule_group("grafana_rule_group.test", {
        "name": "my-group",
        "folder_uid": "abc123",
        "interval_seconds": 300,
    })]}
    result := alerting.deny with input as inp
    not_contains_code(result, "ALERT-002")
}

# ============================================================
# ALERT-003: Rule group must have name
# ============================================================

test_deny_rule_group_no_name if {
    inp := {"resource_changes": [mock_rule_group("grafana_rule_group.test", {
        "folder_uid": "abc123",
        "interval_seconds": 120,
    })]}
    result := alerting.deny with input as inp
    some msg in result
    contains(msg, "ALERT-003")
}

# ============================================================
# ALERT-004: Contact point must have name
# ============================================================

test_deny_contact_point_no_name if {
    inp := {"resource_changes": [mock_contact_point("grafana_contact_point.test", {})]}
    result := alerting.deny with input as inp
    some msg in result
    contains(msg, "ALERT-004")
}

test_allow_contact_point_with_name if {
    inp := {"resource_changes": [mock_contact_point("grafana_contact_point.test", {
        "name": "slack-alerts",
    })]}
    result := alerting.deny with input as inp
    not_contains_code(result, "ALERT-004")
}

# ============================================================
# ALERT-005: Notification policy must have contact_point
# ============================================================

test_deny_notification_policy_no_contact_point if {
    inp := {"resource_changes": [mock_notification_policy("grafana_notification_policy.test", {})]}
    result := alerting.deny with input as inp
    some msg in result
    contains(msg, "ALERT-005")
}

test_allow_notification_policy_with_contact_point if {
    inp := {"resource_changes": [mock_notification_policy("grafana_notification_policy.test", {
        "contact_point": "slack-alerts",
    })]}
    result := alerting.deny with input as inp
    not_contains_code(result, "ALERT-005")
}

# ============================================================
# Deleted resources should be ignored
# ============================================================

test_ignore_deleted_rule_group if {
    inp := {"resource_changes": [{
        "address": "grafana_rule_group.test",
        "type": "grafana_rule_group",
        "change": {
            "actions": ["delete"],
            "after": {},
        },
    }]}
    result := alerting.deny with input as inp
    count(result) == 0
}

# ============================================================
# Helper
# ============================================================

not_contains_code(result, code) if {
    not any_contains(result, code)
}

any_contains(result, code) if {
    some msg in result
    contains(msg, code)
}
