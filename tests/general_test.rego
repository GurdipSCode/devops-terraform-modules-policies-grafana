package terraform.grafana.organization_test

import rego.v1

import data.terraform.grafana.organization

# ============================================================
# Helpers
# ============================================================

mock_resource(type_name, addr, after) := {
    "address": addr,
    "type": type_name,
    "change": {
        "actions": ["create"],
        "after": after,
    },
}

# ============================================================
# ORG-001: Folder must have title
# ============================================================

test_deny_folder_no_title if {
    inp := {"resource_changes": [mock_resource("grafana_folder", "grafana_folder.test", {})]}
    result := organization.deny with input as inp
    some msg in result
    contains(msg, "ORG-001")
}

test_deny_folder_empty_title if {
    inp := {"resource_changes": [mock_resource("grafana_folder", "grafana_folder.test", {
        "title": "",
    })]}
    result := organization.deny with input as inp
    some msg in result
    contains(msg, "ORG-001")
}

test_allow_folder_with_title if {
    inp := {"resource_changes": [mock_resource("grafana_folder", "grafana_folder.test", {
        "title": "Engineering",
    })]}
    result := organization.deny with input as inp
    count(result) == 0
}

# ============================================================
# ORG-002: Organization must have at least one admin
# ============================================================

test_deny_org_no_admins if {
    inp := {"resource_changes": [mock_resource("grafana_organization", "grafana_organization.test", {
        "name": "my-org",
        "admins": [],
    })]}
    result := organization.deny with input as inp
    some msg in result
    contains(msg, "ORG-002")
}

test_allow_org_with_admins if {
    inp := {"resource_changes": [mock_resource("grafana_organization", "grafana_organization.test", {
        "name": "my-org",
        "admins": ["admin@example.com"],
    })]}
    result := organization.deny with input as inp
    not_contains_code(result, "ORG-002")
}

# ============================================================
# ORG-003: Organization must have name
# ============================================================

test_deny_org_no_name if {
    inp := {"resource_changes": [mock_resource("grafana_organization", "grafana_organization.test", {
        "admins": ["admin@example.com"],
    })]}
    result := organization.deny with input as inp
    some msg in result
    contains(msg, "ORG-003")
}

# ============================================================
# ORG-004: Team must have name
# ============================================================

test_deny_team_no_name if {
    inp := {"resource_changes": [mock_resource("grafana_team", "grafana_team.test", {})]}
    result := organization.deny with input as inp
    some msg in result
    contains(msg, "ORG-004")
}

test_allow_team_with_name if {
    inp := {"resource_changes": [mock_resource("grafana_team", "grafana_team.test", {
        "name": "platform-team",
    })]}
    result := organization.deny with input as inp
    not_contains_code(result, "ORG-004")
}

# ============================================================
# ORG-005: Folder permission Editor warning
# ============================================================

test_warn_folder_permission_editor if {
    inp := {"resource_changes": [mock_resource("grafana_folder_permission", "grafana_folder_permission.test", {
        "permissions": [{"role": "Editor"}],
    })]}
    result := organization.warn with input as inp
    some msg in result
    contains(msg, "ORG-005")
}

test_no_warn_folder_permission_viewer if {
    inp := {"resource_changes": [mock_resource("grafana_folder_permission", "grafana_folder_permission.test", {
        "permissions": [{"role": "Viewer"}],
    })]}
    result := organization.warn with input as inp
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
