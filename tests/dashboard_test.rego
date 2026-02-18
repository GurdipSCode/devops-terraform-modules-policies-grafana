package terraform.grafana.datasource_test

import rego.v1

import data.terraform.grafana.datasource

# ============================================================
# Helper
# ============================================================

mock_ds(addr, after) := {
    "address": addr,
    "type": "grafana_data_source",
    "change": {
        "actions": ["create"],
        "after": after,
    },
}

# ============================================================
# DATASOURCE-001: Allowed types
# ============================================================

test_deny_unapproved_datasource_type if {
    inp := {"resource_changes": [mock_ds("grafana_data_source.test", {
        "type": "mongodb",
        "name": "my-ds",
        "url": "https://mongo.example.com",
    })]}
    result := datasource.deny with input as inp
    some msg in result
    contains(msg, "DATASOURCE-001")
}

test_allow_approved_datasource_type if {
    inp := {"resource_changes": [mock_ds("grafana_data_source.test", {
        "type": "prometheus",
        "name": "my-prom",
        "url": "https://prom.example.com",
    })]}
    result := datasource.deny with input as inp
    count(result) == 0
}

test_allow_loki_datasource if {
    inp := {"resource_changes": [mock_ds("grafana_data_source.test", {
        "type": "loki",
        "name": "my-loki",
        "url": "https://loki.example.com",
    })]}
    result := datasource.deny with input as inp
    count(result) == 0
}

# ============================================================
# DATASOURCE-002: Name required
# ============================================================

test_deny_datasource_no_name if {
    inp := {"resource_changes": [mock_ds("grafana_data_source.test", {
        "type": "prometheus",
        "url": "https://prom.example.com",
    })]}
    result := datasource.deny with input as inp
    some msg in result
    contains(msg, "DATASOURCE-002")
}

# ============================================================
# DATASOURCE-003: Basic auth without username
# ============================================================

test_deny_basic_auth_empty_username if {
    inp := {"resource_changes": [mock_ds("grafana_data_source.test", {
        "type": "prometheus",
        "name": "my-prom",
        "url": "https://prom.example.com",
        "basic_auth_enabled": true,
        "basic_auth_username": "",
    })]}
    result := datasource.deny with input as inp
    some msg in result
    contains(msg, "DATASOURCE-003")
}

test_allow_basic_auth_with_username if {
    inp := {"resource_changes": [mock_ds("grafana_data_source.test", {
        "type": "prometheus",
        "name": "my-prom",
        "url": "https://prom.example.com",
        "basic_auth_enabled": true,
        "basic_auth_username": "admin",
    })]}
    result := datasource.deny with input as inp
    not_contains_code(result, "DATASOURCE-003")
}

# ============================================================
# DATASOURCE-004: Direct access mode warning
# ============================================================

test_warn_direct_access_mode if {
    inp := {"resource_changes": [mock_ds("grafana_data_source.test", {
        "type": "prometheus",
        "name": "my-prom",
        "url": "https://prom.example.com",
        "access_mode": "direct",
    })]}
    result := datasource.warn with input as inp
    some msg in result
    contains(msg, "DATASOURCE-004")
}

test_no_warn_proxy_access_mode if {
    inp := {"resource_changes": [mock_ds("grafana_data_source.test", {
        "type": "prometheus",
        "name": "my-prom",
        "url": "https://prom.example.com",
        "access_mode": "proxy",
    })]}
    result := datasource.warn with input as inp
    count(result) == 0
}

# ============================================================
# DATASOURCE-005: Prometheus must have URL
# ============================================================

test_deny_prometheus_no_url if {
    inp := {"resource_changes": [mock_ds("grafana_data_source.test", {
        "type": "prometheus",
        "name": "my-prom",
    })]}
    result := datasource.deny with input as inp
    some msg in result
    contains(msg, "DATASOURCE-005")
}

# ============================================================
# DATASOURCE-006: HTTPS required
# ============================================================

test_deny_http_url if {
    inp := {"resource_changes": [mock_ds("grafana_data_source.test", {
        "type": "prometheus",
        "name": "my-prom",
        "url": "http://prom.example.com",
    })]}
    result := datasource.deny with input as inp
    some msg in result
    contains(msg, "DATASOURCE-006")
}

test_allow_https_url if {
    inp := {"resource_changes": [mock_ds("grafana_data_source.test", {
        "type": "prometheus",
        "name": "my-prom",
        "url": "https://prom.example.com",
    })]}
    result := datasource.deny with input as inp
    not_contains_code(result, "DATASOURCE-006")
}

# ============================================================
# Deleted resources should be ignored
# ============================================================

test_ignore_deleted_datasource if {
    inp := {"resource_changes": [{
        "address": "grafana_data_source.test",
        "type": "grafana_data_source",
        "change": {
            "actions": ["delete"],
            "after": {},
        },
    }]}
    result := datasource.deny with input as inp
    count(result) == 0
}

# ============================================================
# Helper: check result set does not contain a specific code
# ============================================================

not_contains_code(result, code) if {
    not any_contains(result, code)
}

any_contains(result, code) if {
    some msg in result
    contains(msg, code)
}
