package terraform.grafana.access_test

import rego.v1

import data.terraform.grafana.access

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
# ACCESS-001: Service account must not have Admin role
# ============================================================

test_deny_sa_admin_role if {
    inp := {"resource_changes": [mock_resource("grafana_service_account", "grafana_service_account.test", {
        "name": "ci-bot",
        "role": "Admin",
        "is_disabled": false,
    })]}
    result := access.deny with input as inp
    some msg in result
    contains(msg, "ACCESS-001")
}

test_allow_sa_viewer_role if {
    inp := {"resource_changes": [mock_resource("grafana_service_account", "grafana_service_account.test", {
        "name": "ci-bot",
        "role": "Viewer",
        "is_disabled": false,
    })]}
    result := access.deny with input as inp
    not_contains_code(result, "ACCESS-001")
}

test_allow_sa_editor_role if {
    inp := {"resource_changes": [mock_resource("grafana_service_account", "grafana_service_account.test", {
        "name": "ci-bot",
        "role": "Editor",
        "is_disabled": false,
    })]}
    result := access.deny with input as inp
    not_contains_code(result, "ACCESS-001")
}

# ============================================================
# ACCESS-002: Service account must have name
# ============================================================

test_deny_sa_no_name if {
    inp := {"resource_changes": [mock_resource("grafana_service_account", "grafana_service_account.test", {
        "role": "Viewer",
        "is_disabled": false,
    })]}
    result := access.deny with input as inp
    some msg in result
    contains(msg, "ACCESS-002")
}

# ============================================================
# ACCESS-003: Service account must not be disabled at creation
# ============================================================

test_deny_sa_disabled if {
    inp := {"resource_changes": [mock_resource("grafana_service_account", "grafana_service_account.test", {
        "name": "ci-bot",
        "role": "Viewer",
        "is_disabled": true,
    })]}
    result := access.deny with input as inp
    some msg in result
    contains(msg, "ACCESS-003")
}

test_allow_sa_enabled if {
    inp := {"resource_changes": [mock_resource("grafana_service_account", "grafana_service_account.test", {
        "name": "ci-bot",
        "role": "Viewer",
        "is_disabled": false,
    })]}
    result := access.deny with input as inp
    not_contains_code(result, "ACCESS-003")
}

# ============================================================
# ACCESS-004: Token without expiration warning
# ============================================================

test_warn_token_no_expiration if {
    inp := {"resource_changes": [mock_resource("grafana_service_account_token", "grafana_service_account_token.test", {
        "name": "ci-token",
    })]}
    result := access.warn with input as inp
    some msg in result
    contains(msg, "ACCESS-004")
}

test_no_warn_token_with_expiration if {
    inp := {"resource_changes": [mock_resource("grafana_service_account_token", "grafana_service_account_token.test", {
        "name": "ci-token",
        "expiration": "2026-12-31T00:00:00Z",
    })]}
    result := access.warn with input as inp
    count(result) == 0
}

# ============================================================
# ACCESS-005: API key deprecation warning
# ============================================================

test_warn_api_key_deprecated if {
    inp := {"resource_changes": [mock_resource("grafana_api_key", "grafana_api_key.test", {
        "name": "legacy-key",
        "role": "Viewer",
    })]}
    result := access.warn with input as inp
    some msg in result
    contains(msg, "ACCESS-005")
}

# ============================================================
# ACCESS-006: API key must not have Admin role
# ============================================================

test_deny_api_key_admin if {
    inp := {"resource_changes": [mock_resource("grafana_api_key", "grafana_api_key.test", {
        "name": "legacy-key",
        "role": "Admin",
    })]}
    result := access.deny with input as inp
    some msg in result
    contains(msg, "ACCESS-006")
}

test_allow_api_key_viewer if {
    inp := {"resource_changes": [mock_resource("grafana_api_key", "grafana_api_key.test", {
        "name": "legacy-key",
        "role": "Viewer",
    })]}
    result := access.deny with input as inp
    not_contains_code(result, "ACCESS-006")
}

# ============================================================
# ACCESS-007: Role assignment warning
# ============================================================

test_warn_role_assignment if {
    inp := {"resource_changes": [mock_resource("grafana_role_assignment", "grafana_role_assignment.test", {
        "role_uid": "custom-role",
    })]}
    result := access.warn with input as inp
    some msg in result
    contains(msg, "ACCESS-007")
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
