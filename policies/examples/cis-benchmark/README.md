# CIS Controls v8 — Security Baseline Template

This policy template maps ObsidianWall governance conditions to the
[CIS Controls v8](https://www.cisecurity.org/controls/v8) security
baseline. It enforces pre-deployment checks for the most commonly
violated infrastructure security controls.

-----

## What this template enforces

|Condition                 |CIS Control|What it checks                                  |
|--------------------------|-----------|------------------------------------------------|
|`no_open_ingress`         |CIS 12.2   |No unrestricted inbound access rules (0.0.0.0/0)|
|`no_public_storage`       |CIS 3.3    |No publicly accessible storage resources        |
|`no_unencrypted_databases`|CIS 3.11   |All databases encrypted at rest                 |
|`asset_inventory_complete`|CIS 1.1    |All resources tagged for asset inventory        |

-----

## What to customize

```yaml
owner: security-team        # Your security team name

parameters:
  security:
    max_open_ingress_rules: 0    # Adjust if your org allows limited exceptions
    max_public_storage: 0        # Adjust if you have intentionally public assets
    max_unencrypted_databases: 0 # Adjust only if encryption is not yet feasible

governance:
  notifications:
    - role: security_lead        # Your security lead role name
    - role: engineering_lead     # Your engineering lead role name

override:
  roles:
    - security_lead              # Who can authorize exceptions
```

-----

## How to use

**Validate the policy:**

```bash
verdict validate --policy policies/examples/cis-benchmark/security.yaml
```

**Test against a plan:**

```bash
verdict test \
  --plan   terraform_plan.json \
  --policy policies/examples/cis-benchmark/security.yaml \
  --expect ALLOW
```

**Evaluate a deployment:**

```bash
verdict evaluate \
  --plan   terraform_plan.json \
  --policy policies/examples/cis-benchmark/security.yaml \
  --role   engineer
```

-----

## CIS Controls reference

- [CIS Control 1 — Inventory and Control of Enterprise Assets](https://www.cisecurity.org/controls/inventory-and-control-of-enterprise-assets)
- [CIS Control 3 — Data Protection](https://www.cisecurity.org/controls/data-protection)
- [CIS Control 12 — Network Infrastructure Management](https://www.cisecurity.org/controls/network-infrastructure-management)

-----

## Notes

This template enforces the CIS Controls at the infrastructure
declaration layer — before deployment executes. It does not replace
runtime monitoring or periodic assessment. For a complete CIS
implementation, combine this template with your organization’s
runtime security tooling.