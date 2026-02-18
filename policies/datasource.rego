package terraform.grafana.datasource

import rego.v1

# ============================================================
# Data Source Governance Policies
# Enforces standards for grafana_data_source resources
# ============================================================

# Allowed data source types - customize to your organization
allowed_types := [
    "prometheus",
    "loki",
    "tempo",
    "elasticsearch",
    "cloudwatch",
    "influxdb",
    "postgres",
    "mysql",
    "graphite",
    "jaeger",
    "zipkin",
]

# Collect all data source resource changes
datasource_resources contains r if {
    r := input.resource_changes[_]
    r.type == "grafana_data_source"
    r.change.actions[_] != "delete"
}

# DENY: Only approved data source types are allowed
deny contains msg if {
    r := datasource_resources[_]
    ds_type := r.change.after.type
    not ds_type in allowed_types
    msg := sprintf("DATASOURCE-001: %v - data source type '%v' is not approved. Allowed types: %v", [r.address, ds_type, allowed_types])
}

# DENY: Data sources must have a name
deny contains msg if {
    r := datasource_resources[_]
    not r.change.after.name
    msg := sprintf("DATASOURCE-002: %v - data source must have a name", [r.address])
}

# DENY: Data sources should not use basic auth without secure credentials
deny contains msg if {
    r := datasource_resources[_]
    r.change.after.basic_auth_enabled == true
    r.change.after.basic_auth_username == ""
    msg := sprintf("DATASOURCE-003: %v - basic auth is enabled but username is empty", [r.address])
}

# WARN: Data sources with direct URL access should be reviewed
warn contains msg if {
    r := datasource_resources[_]
    r.change.after.access_mode == "direct"
    msg := sprintf("DATASOURCE-004: %v - data source uses 'direct' access mode; consider 'proxy' for security", [r.address])
}

# DENY: Prometheus data sources must have a valid URL
deny contains msg if {
    r := datasource_resources[_]
    r.change.after.type == "prometheus"
    not r.change.after.url
    msg := sprintf("DATASOURCE-005: %v - Prometheus data source must have a URL configured", [r.address])
}

# DENY: Data source URLs must use HTTPS in production
deny contains msg if {
    r := datasource_resources[_]
    url := r.change.after.url
    url != null
    startswith(url, "http://")
    msg := sprintf("DATASOURCE-006: %v - data source URL must use HTTPS, got: %v", [r.address, url])
}
