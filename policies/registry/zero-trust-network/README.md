# Zero Trust Architecture — Network and Identity Templates

Two templates implementing
[NIST SP 800-207 Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final)
principles at the infrastructure declaration layer.

---

## Templates

### network.yaml — Network controls

Enforces Zero Trust network posture: deny by default, no implicit
public access, and encryption everywhere.

| Condition | ZTA Principle | What it checks |
|-----------|--------------|----------------|
| `deny_by_default` | Never trust, always verify | No 0.0.0.0/0 inbound rules |
| `no_implicit_public_access` | Verify explicitly | No publicly exposed resources |
| `encrypt_data_at_rest` | Assume breach | All data storage encrypted |

### identity.yaml — Identity controls

Enforces Zero Trust identity posture: every resource has an explicit
owner, no implicit network trust is granted.

| Condition | ZTA Principle | What it checks |
|-----------|--------------|----------------|
| `no_implicit_network_trust` | Never trust, always verify | No unrestricted inbound access |
| `explicit_resource_ownership` | Least privilege access | All resources have owner tags |

---

## CISA Zero Trust Maturity Model alignment

| Pillar | Template | Maturity contribution |
|--------|----------|----------------------|
| Identity | identity.yaml | Explicit ownership, least privilege |
| Networks | network.yaml | Micro-segmentation, deny by default |
| Data | network.yaml | Encryption at rest enforced |
| Applications | Both | Pre-deployment authorization |

---

## What to customize

```yaml
# network.yaml
parameters:
  network:
    max_open_ingress_rules: 0    # Adjust if architecture requires limited exceptions
    max_public_exposure: 0       # Adjust if intentionally public assets exist

  security:
    max_unencrypted_databases: 0 # Do not adjust — Zero Trust requires encryption

# identity.yaml
parameters:
  identity:
    require_explicit_ownership: true

  security:
    max_open_ingress_rules: 0    # No implicit network trust

  compliance:
    max_untagged_resources: 0    # 0 = every resource must have owner tag
                                 # Increase only if legacy untagged resources exist

governance:
  notifications:
    - role: network_security_lead   # Your network security lead role
    - role: identity_lead           # Your IAM lead role
    - role: security_lead           # Your security lead role
```

---

## How to use

**Validate both templates:**

```bash
verdict validate --policy policies/registry/zero-trust-network/network.yaml
verdict validate --policy policies/registry/zero-trust-network/identity.yaml
```

**Test network policy against a compliant plan:**

```bash
verdict test \
  --plan   samples/terraform_plan.json \
  --policy policies/registry/zero-trust-network/network.yaml \
  --expect ALLOW_WITH_NOTIFICATION
```

**Test identity policy against a compliant plan:**

```bash
verdict test \
  --plan   samples/terraform_plan.json \
  --policy policies/registry/zero-trust-network/identity.yaml \
  --expect DENY_WITH_OVERRIDE
```

**Evaluate a deployment against the network policy:**

```bash
verdict evaluate \
  --plan   samples/terraform_plan.json \
  --policy policies/registry/zero-trust-network/network.yaml \
  --role   engineer
```

**Evaluate a deployment against the identity policy:**

```bash
verdict evaluate \
  --plan   samples/terraform_plan.json \
  --policy policies/registry/zero-trust-network/identity.yaml \
  --role   engineer
```

**Evaluate against both policies in sequence:**

```bash
verdict evaluate \
  --plan   samples/terraform_plan.json \
  --policy policies/registry/zero-trust-network/network.yaml \
  --role   engineer

verdict evaluate \
  --plan   samples/terraform_plan.json \
  --policy policies/registry/zero-trust-network/identity.yaml \
  --role   engineer
```

---

## Using both together

For a complete Zero Trust posture, run both policies against every
deployment. Or combine them into a single composite policy using
`policies/registry/production-deployment/composite.yaml` as a
reference for multi-domain composition.

---

## Reference

- [NIST SP 800-207 — Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [CISA Zero Trust Maturity Model](https://www.cisa.gov/zero-trust-maturity-model)
- [CISA ZTA Pillar — Networks](https://www.cisa.gov/sites/default/files/2023-04/zero_trust_maturity_model_v2_508.pdf)