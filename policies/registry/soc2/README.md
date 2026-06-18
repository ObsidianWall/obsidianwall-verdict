
# SOC 2 Trust Service Criteria — Policy Templates

Two templates covering the most infrastructure-relevant SOC 2
Trust Service Criteria for engineering and security teams.
Both templates produce immutable governance artifacts that serve
as continuous CC6 and CC7 control evidence for SOC 2 audits.

---

## Templates

### cc6_access_control.yaml — CC6 Logical Access Controls

Enforces SOC 2 CC6 requirements at the infrastructure declaration
layer. Every evaluation produces a JSON audit artifact demonstrating
that access controls were verified before deployment.

| Condition | SOC 2 Criterion | What it checks |
|-----------|----------------|----------------|
| `cc6_restrict_external_access` | CC6.6 | No unrestricted inbound access from external sources |
| `cc6_restrict_data_transmission` | CC6.7 | No publicly accessible data storage |
| `cc6_logical_access_security` | CC6.1 | All databases encrypted — access security in place |
| `cc6_resource_registration` | CC6.2 | All resources tagged with owner attribution |

### cc7_monitoring.yaml — CC7 System Operations

Enforces SOC 2 CC7 requirements by ensuring the infrastructure
state is detectable and attributable. Combined with `verdict audit`,
this template provides continuous CC7 monitoring evidence without
manual log sampling.

| Condition | SOC 2 Criterion | What it checks |
|-----------|----------------|----------------|
| `cc7_configuration_monitoring` | CC7.1 | No configuration changes introducing vulnerabilities |
| `cc7_anomaly_detection` | CC7.2 | No unencrypted databases indicating control failures |
| `cc7_resource_identification` | CC7.3 | All resources tagged for security event evaluation |

---

## How ObsidianWall produces SOC 2 evidence

Every `verdict evaluate` invocation produces:

```json
{
  "decision_id": "abc3a13b-83d5-4fad-87d8",
  "timestamp": "2026-06-06T12:00:00Z",
  "policy": "soc2_cc6_access_control",
  "decision": "ALLOW",
  "conditions_passed": true,
  "trace": [...]
}
```

This artifact demonstrates that CC6 and CC7 controls were
programmatically verified at the point of deployment, for every
deployment, continuously. This is exactly the evidence SOC 2
auditors need for CC6.1 and CC7.2 — and it requires zero
manual sampling or screenshot collection.

**For SOC 2 Type II:** enable telemetry and run `verdict audit`
to produce a governance history covering the audit period.

```bash
export OW_TELEMETRY_ENABLED=true
verdict audit --format json > soc2_evidence_$(date +%Y%m%d).json
```

---

## SOC 2 Trust Service Criteria coverage

| Criterion | Template | Covered |
|-----------|----------|---------|
| CC6.1 — Logical access security | cc6_access_control.yaml | ✅ |
| CC6.2 — Access credential registration | cc6_access_control.yaml | ✅ |
| CC6.6 — External boundary protection | cc6_access_control.yaml | ✅ |
| CC6.7 — Data transmission controls | cc6_access_control.yaml | ✅ |
| CC7.1 — Configuration change detection | cc7_monitoring.yaml | ✅ |
| CC7.2 — Anomaly monitoring | cc7_monitoring.yaml | ✅ |
| CC7.3 — Security event evaluation | cc7_monitoring.yaml | ✅ |

---

## What to customize

```yaml
# cc6_access_control.yaml
parameters:
  access:
    max_open_ingress_rules: 0      # Your external access boundary
    max_public_storage: 0          # Data transmission controls
    max_unencrypted_databases: 0   # Logical access security baseline
    max_untagged_resources: 0      # Resource registration requirement

governance:
  notifications:
    - role: security_lead          # Your security lead role
    - role: ciso                   # Your CISO or security authority

# cc7_monitoring.yaml
governance:
  notifications:
    - role: security_operations    # Your SOC or security operations team
    - role: security_lead
```

---

## How to use

**Validate:**
```bash
verdict validate --policy policies/registry/soc2/cc6_access_control.yaml
verdict validate --policy policies/registry/soc2/cc7_monitoring.yaml
```

**Test:**
```bash
verdict test \
  --plan   samples/terraform_plan.json \
  --policy policies/registry/soc2/cc6_access_control.yaml \
  --expect DENY_WITH_OVERRIDE

verdict test \
  --plan   samples/terraform_plan.json \
  --policy policies/registry/soc2/cc7_monitoring.yaml \
  --expect DENY_WITH_OVERRIDE
```

**Generate audit evidence:**
```bash
export OW_TELEMETRY_ENABLED=true

verdict evaluate \
  --plan   samples/terraform_plan.json \
  --policy policies/registry/soc2/cc6_access_control.yaml \
  --role   engineer

verdict audit --format json
```

---

## SOC 2 audit readiness note

These templates enforce the technical controls. A complete SOC 2
program also requires:

- Organizational policies and procedures documentation
- Vendor management controls
- Change management processes
- Incident response procedures
- Business continuity planning

These templates address the infrastructure technical safeguards
portion of CC6 and CC7. Engage a qualified SOC 2 auditor
(Schellman, Coalfire, A-LIGN, or similar) for full readiness
assessment. Do not begin the audit period until Compass is live
and generating continuous decision history.

---

## Reference

- [SOC 2 Trust Service Criteria — AICPA](https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services)
- [CC6 Logical and Physical Access Controls](https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria)
- [CC7 System Operations](https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria)