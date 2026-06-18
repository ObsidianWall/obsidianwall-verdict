# Production Deployment — Composite Governance Template

This is the recommended starting point for teams that want a single
policy governing all production deployments across cost, security,
compliance, and network domains simultaneously.

A composite policy evaluates all conditions across all declared
domains and produces one governance decision. If cost passes but
security fails, the deployment is blocked. All conditions must pass.

-----

## What this template enforces

|Condition                        |Domain  |What it checks                                     |
|---------------------------------|--------|---------------------------------------------------|
|`production_budget`              |cost    |Total projected spend does not exceed monthly limit|
|`no_open_ingress_in_production`  |security|No unrestricted inbound access rules               |
|`no_public_storage_in_production`|security|No publicly accessible storage                     |
|`all_databases_encrypted`        |security|All databases encrypted at rest                    |

-----

## When to use this template

Use this template when you want a single governance gate for your
production CI/CD pipeline. Instead of maintaining four separate
single-domain policies, one composite policy covers everything.

If you need domain-specific policies (for example, a strict HIPAA
policy only for PHI-handling infrastructure), use the domain-specific
templates in the other example directories alongside this one.

-----

## What to customize

```yaml
parameters:
  budget:
    amount: 10000.00               # Your production monthly budget
    scope: project:production      # Your production project identifier

  security:
    max_open_ingress_rules: 0      # Adjust if your architecture requires exceptions
    max_public_storage: 0          # Adjust if you have intentionally public assets
    max_unencrypted_databases: 0   # Do not adjust — production encryption is non-negotiable

  compliance:
    max_untagged_ratio: 0.0        # 0.0 = 100% tagging required
                                   # 0.1 = 90% minimum if legacy resources exist

governance:
  notifications:
    - role: platform_lead          # Your platform lead role name
    - role: security_lead          # Your security lead role name

  approvals:
    required:
      - platform_lead
      - security_lead
```

-----

## How to use

**Validate:**

```bash
verdict validate \
  --policy policies/registry/production-deployment/composite.yaml
```

**Test a compliant production plan:**

```bash
verdict test \
  --plan   samples/terraform_plan.json \
  --policy policies/registry/production-deployment/composite.yaml \
  --expect DENY_WITH_OVERRIDE
```

**Evaluate with current month spend:**

```bash
verdict evaluate \
  --plan          samples/terraform_plan.json \
  --policy        policies/registry/production-deployment/composite.yaml \
  --current-spend 3200.00 \
  --role          engineer
```

**Wire into GitHub Actions:**

```yaml
- name: Production governance gate
  uses: obsidianwall/obsidianwall-verdict@main
  with:
    plan:         samples/terraform_plan.json
    policy:       policies/registry/production-deployment/composite.yaml
    role:         engineer
    fail_on_deny: "true"
```

-----

## Extending this template

As your governance requirements grow, add conditions to this composite
policy rather than creating additional single-domain policies. The
composite model keeps one policy as the single source of truth for
production deployment authorization.