# NIST AI Risk Management Framework — AI Governance Template

This policy template maps ObsidianWall governance conditions to the
[NIST AI RMF 1.0](https://airc.nist.gov/RMF_Overview) framework.
It enforces human oversight and governance review requirements for
AI system deployments at the infrastructure layer.

-----

## What this template enforces

|Condition                          |NIST AI RMF Function  |What it checks                                      |
|-----------------------------------|----------------------|----------------------------------------------------|
|`ai_deployment_requires_governance`|GOVERN 1.1, MAP 1.5   |AI workloads require formal review before deployment|
|`gpu_instances_require_approval`   |GOVERN 4.1, MANAGE 1.3|GPU infrastructure requires AI governance approval  |

-----

## NIST AI RMF function mapping

|Function   |How this policy addresses it                                                    |
|-----------|--------------------------------------------------------------------------------|
|**GOVERN** |Policy exists (this file), accountability assigned to AI governance lead        |
|**MAP**    |Context is established before deployment — no AI workloads deploy without review|
|**MEASURE**|Deployment history recorded in audit trail via telemetry                        |
|**MANAGE** |Human oversight enforced — autonomous deployment blocked                        |

-----

## Doctrine alignment

This template directly reflects the ObsidianWall doctrine:

> AI may advise. AI may not govern.

The policy enforces that boundary at the infrastructure layer. AI
workloads that deploy without governance review create accountability
gaps that cannot be remediated retroactively. Pre-deployment
governance is the control boundary.

-----

## What to customize

```yaml
owner: ai-governance-team     # Your AI governance team

parameters:
  ai:
    max_unreviewed_gpu_deployments: 0   # 0 means all AI deployments need review
                                        # Increase if pre-approved quotas exist
    max_gpu_instances: 0                # Set to approved GPU allocation if applicable

governance:
  notifications:
    - role: ai_governance_lead          # Your AI governance lead role
    - role: security_lead               # Your security lead role

  approvals:
    required:
      - ai_governance_lead
      - security_lead
```

-----

## How to use

**Validate:**

```bash
verdict validate --policy policies/registry/nist-ai-rmf/ai_governance.yaml
```

**Test a plan with no GPU workloads (should ALLOW):**

```bash
verdict test \
  --plan   samples/terraform_plan.json \
  --policy policies/registry/nist-ai-rmf/ai_governance.yaml \
  --expect ALLOW_WITH_NOTIFICATION
```

**Evaluate:**

```bash
verdict evaluate \
  --plan   samples/terraform_plan.json \
  --policy policies/registry/nist-ai-rmf/ai_governance.yaml \
  --role   engineer
```

-----

## Reference

- [NIST AI RMF 1.0](https://airc.nist.gov/RMF_Overview)
- [NIST AI RMF Playbook](https://airc.nist.gov/Docs/2)
- [GOVERN Function](https://airc.nist.gov/Docs/2#govern)
- [MANAGE Function](https://airc.nist.gov/Docs/2#manage)