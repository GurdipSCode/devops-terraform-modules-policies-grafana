# devops-terraform-modules-policies-grafana

A collection of Open Policy Agent (OPA) policies written in Rego to enforce governance, security, and best practices on Grafana Terraform configurations.

## Policy Files

| File | Scope | Key Rules |
|---|---|---|
| `dashboard.rego` | Dashboards | Folder assignment, config validation, change tracking |
| `datasource.rego` | Data Sources | Allowed types, HTTPS enforcement, access mode |
| `alerting.rego` | Alerts & Notifications | Folder assignment, evaluation intervals, contact points |
| `organization.rego` | Folders, Orgs, Teams | Naming, admin requirements, permission reviews |
| `access.rego` | Service Accounts & RBAC | Least privilege, token expiry, API key deprecation |
| `general.rego` | Cross-cutting | Blast radius limits, deletion protection, version checks |
| `cloud.rego` | Grafana Cloud | Stack regions, synthetic monitoring, cloud service accounts |

## Rule Severity

- **`deny`** — Hard failures. The plan must not be applied until violations are resolved.
- **`warn`** — Advisory. Flagged for review but do not block apply.

## Quick Start

### 1. Generate a Terraform plan in JSON

```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
```

### 2. Evaluate policies with OPA CLI

```bash
# Check for deny violations
opa eval --format pretty \
  --data policies/ \
  --input tfplan.json \
  "data.terraform.grafana"

# Check only deny rules across all policy packages
opa eval --format pretty \
  --data policies/ \
  --input tfplan.json \
  "[d | d := data.terraform.grafana[_].deny[_]]"
```

### 3. Using Conftest (alternative)

```bash
conftest test tfplan.json -p policies/
```

## CI/CD Integration

Add to your pipeline (GitHub Actions example):

```yaml
- name: Terraform Plan
  run: |
    terraform plan -out=tfplan
    terraform show -json tfplan > tfplan.json

- name: OPA Policy Check
  run: |
    DENIES=$(opa eval --format json \
      --data policies/ \
      --input tfplan.json \
      "[d | d := data.terraform.grafana[_].deny[_]]" \
      | jq '.result[0].expressions[0].value')

    if [ "$DENIES" != "[]" ]; then
      echo "❌ Policy violations found:"
      echo "$DENIES" | jq -r '.[]'
      exit 1
    fi

    echo "✅ All policies passed"
```

## Customization

Each policy file has configurable values at the top. Common things to adjust:

- **`datasource.rego`** — `allowed_types` list
- **`general.rego`** — `max_deletions`, `max_total_changes`, `protected_types`
- **`cloud.rego`** — `allowed_regions`
- **`access.rego`** — `disallowed_sa_roles`

## Testing Policies

Write OPA tests alongside your policies:

```bash
opa test policies/ tests/ -v
```
