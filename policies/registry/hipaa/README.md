# HIPAA Security Rule — PHI Infrastructure Template

This policy template maps ObsidianWall governance conditions to the
[HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
(45 CFR Part 164). It enforces technical safeguard requirements for
infrastructure that handles Protected Health Information (PHI).

-----

## What this template enforces

|Condition               |HIPAA Section      |What it checks                                 |
|------------------------|-------------------|-----------------------------------------------|
|`phi_encryption_at_rest`|§ 164.312(a)(2)(iv)|All databases storing PHI are encrypted at rest|
|`no_public_phi_exposure`|§ 164.312(e)(1)    |No PHI-handling storage is publicly accessible |
|`restricted_phi_access` |§ 164.312(a)(1)    |No unrestricted inbound access to PHI systems  |
|`phi_resource_inventory`|§ 164.312(b)       |All PHI-handling resources are tagged for audit|

-----

## Enforcement posture

This template uses **hard DENY** — HIPAA violations cannot be
self-overridden by engineers. Only the compliance officer can
authorize exceptions, and authorization requires documented
justification through the approval workflow.

This is intentional. HIPAA § 164.308(a)(1) requires that covered
entities implement policies ensuring PHI confidentiality, integrity,
and availability. A self-service override defeats that control.

-----

## What to customize

```yaml
owner: compliance-team         # Your HIPAA compliance team name

governance:
  notifications:
    - role: compliance_officer  # Your HIPAA compliance officer role
    - role: security_lead       # Your security lead role

  approvals:
    required:
      - compliance_officer      # Who must approve HIPAA exceptions
      - security_lead

override:
  roles:
    - compliance_officer        # Who can authorize override (with approval)
```

-----

## How to use

**Validate:**

```bash
verdict validate --policy policies/registry/hipaa/data_governance.yaml
```

**Test a compliant PHI plan:**

```bash
verdict test \
  --plan   samples/terraform_plan.json \
  --policy policies/registry/hipaa/data_governance.yaml \
  --expect DENY
```

**Evaluate:**

```bash
verdict evaluate \
  --plan   samples/terraform_plan.json \
  --policy policies/registry/hipaa/data_governance.yaml \
  --role   engineer
```

-----

## Important notes

This template enforces technical safeguards at the infrastructure
declaration layer. A complete HIPAA compliance program also requires:

- Administrative safeguards (§ 164.308)
- Physical safeguards (§ 164.310)
- Organizational requirements and Business Associate Agreements (§ 164.314)
- Policies and procedures documentation (§ 164.316)

This template addresses the technical safeguards section (§ 164.312)
only. It is not a substitute for legal review or a full HIPAA
compliance assessment.

-----

## Reference

- [HIPAA Security Rule — 45 CFR Part 164](https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html)
- [HHS Security Rule Guidance](https://www.hhs.gov/hipaa/for-professionals/security/guidance/index.html)