
# ObsidianWall Verdict

**Pre-deployment infrastructure governance.**
Evaluate Terraform plans against governance policies before deployment executes —
catching budget overruns, policy violations, and compliance failures
before they become incidents.

[![CI](https://github.com/obsidianwall/obsidianwall-verdict/actions/workflows/verdict-ci.yml/badge.svg)](https://github.com/obsidianwall/obsidianwall-verdict/actions/workflows/verdict-ci.yml)
[![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![obsidianwall.com](https://img.shields.io/badge/platform-obsidianwall.com-5ac4f0.svg)](https://obsidianwall.com)

---

## What it does

Verdict runs as a CLI command or a GitHub Actions step. It takes a Terraform
plan and a policy file, evaluates the plan deterministically against the policy
conditions, and produces a governance decision with a full audit trail.

```
$ verdict evaluate \
    --plan  terraform_plan.json \
    --policy policies/cost/basic_budget.yaml \
    --role  engineer

  policy       basic_budget_verdict
  condition    budget_check                    ✗ FAILED
  expression   (current_spend + estimated_cost) <= budget.amount
  evaluated    (0 + 100) <= 50  →  false

  risk score   75 / 100  (critical)
  findings     cost_analysis: 2   topology: 1
  notified     budget_owner (email)   engineering_lead (slack)

  decision     DENY_WITH_OVERRIDE
  override     budget_owner may authorize
  decision_id  abc3a13b-83d5-4fad-87d8

✗ Deployment blocked by governance policy.
```

No AI guessing. No approximations. Every decision is deterministic,
reproducible, and attributable to a human-authored policy.

---

## Quickstart

**Install**

```bash
pip install obsidianwall-verdict
```

**Write a policy**

```yaml
# policies/cost/budget.yaml
apiVersion: obsidianwall.io/v1
kind: Policy

metadata:
  name: team_budget
  version: "0.1"
  owner: your-team

spec:
  inputs:
    - estimated_cost
    - current_spend

  parameters:
    budget:
      amount: 5000
      period: monthly
      flexibility: soft

  conditions:
    - id: budget_check
      expression: "(current_spend + estimated_cost) <= budget.amount"
      description: "Monthly spend must not exceed budget"

  decision:
    allow: ALLOW
    deny:  DENY_WITH_OVERRIDE
    warn:  ALLOW_WITH_NOTIFICATION

  governance:
    severity: medium
    notifications:
      - role: budget_owner
        channel: email
      - role: engineering_lead
        channel: slack

  override:
    roles:
      - budget_owner
    requires_approval: false
```

**Evaluate a plan**

```bash
# Generate your Terraform plan
terraform plan -out=tfplan
terraform show -json tfplan > terraform_plan.json

# Run governance evaluation
verdict evaluate \
  --plan   terraform_plan.json \
  --policy policies/cost/budget.yaml \
  --role   engineer
```

Verdict returns exit code `0` on ALLOW and non-zero on DENY,
blocking CI/CD pipelines automatically.

---

## GitHub Actions

Add Verdict as a governance gate in your CI/CD pipeline in one step:

```yaml
# .github/workflows/governance.yml
name: Infrastructure Governance

on:
  pull_request:
    paths: ["**.tf", "**.tfvars"]

jobs:
  governance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Generate Terraform plan
        run: |
          terraform init
          terraform plan -out=tfplan
          terraform show -json tfplan > terraform_plan.json

      - name: ObsidianWall Verdict
        id: verdict
        uses: obsidianwall/obsidianwall-verdict@main
        with:
          plan:         terraform_plan.json
          policy:       policies/cost/budget.yaml
          role:         engineer
          fail_on_deny: "true"

      - name: Governance outcome
        if: always()
        run: |
          echo "Decision:   ${{ steps.verdict.outputs.decision }}"
          echo "Risk score: ${{ steps.verdict.outputs.risk_score }}/100"
          echo "Severity:   ${{ steps.verdict.outputs.effective_severity }}"
```

Verdict posts a governance summary table to the workflow step summary
on every run. Budget owners and engineering leads receive notifications
through the channels defined in the policy.

### Action outputs

| Output | Description |
|--------|-------------|
| `decision` | `ALLOW` / `ALLOW_WITH_NOTIFICATION` / `ALLOW_WITH_APPROVAL_REQUIRED` / `DENY_WITH_OVERRIDE` / `DENY` |
| `conditions_passed` | `true` or `false` |
| `risk_score` | Integer 0–100 |
| `effective_severity` | `informational` / `low` / `medium` / `high` / `critical` |
| `decision_id` | UUID for audit trail correlation |

---

## How it works

Verdict runs a deterministic evaluation pipeline on every invocation:

```
Terraform plan
      ↓
Context builder       Parses resources, estimates cost
      ↓
Policy loader         Loads and validates the policy YAML
      ↓
Runtime normalizer    Flattens policy parameters into evaluation context
      ↓
Condition evaluator   Evaluates each condition deterministically
      ↓
Analyzer framework    Cost, topology, architecture, utilization analysis
      ↓
Risk scorer           Aggregates findings into risk score (0–100)
      ↓
Decision resolver     5-level governance decision with override routing
      ↓
Explainability        Reasoning chain, trace graph, remediation steps
      ↓
Notification manifest Stakeholder routing — never dispatched automatically
      ↓
Audit artifact        Immutable JSON record of the complete evaluation
```

Every stage is deterministic. Analyzers are advisory — they inform
the risk score but never override the condition evaluation.
The condition evaluation alone determines the governance decision.

---

## Enforcement modes

| Mode | How | What it blocks |
|------|-----|----------------|
| **CI/CD pipeline** | GitHub Actions with `fail_on_deny: true` | `terraform apply` never runs on DENY |
| **IAM access controls** | Azure Entra ID / AWS IAM restricts engineer credentials to read-only | Direct deployment from local machines impossible |
| **Standalone manual** | Run `verdict evaluate` before `terraform apply` | Governance guidance, audit trail, budget owner notification |

For hard technical enforcement, integrate Verdict into your CI/CD pipeline
and restrict cloud credentials so only the pipeline's service principal
can apply infrastructure. Engineers with read-only credentials cannot
deploy directly even if they skip Verdict locally.


---

## Governance decisions

Verdict produces one of five decisions on every evaluation:

| Decision | Meaning |
|----------|---------|
| `ALLOW` | All conditions passed. Deployment authorized. |
| `ALLOW_WITH_NOTIFICATION` | Conditions passed but high severity — stakeholders notified. |
| `ALLOW_WITH_APPROVAL_REQUIRED` | Conditions passed but formal approval required before deployment. |
| `DENY_WITH_OVERRIDE` | Conditions failed. An authorized role may override. |
| `DENY` | Conditions failed. No override permitted. Hard block. |

---

## Policy DSL

Policies are YAML files that define governance constraints for an
infrastructure change. The schema is versioned and validated on load.

### Policy structure

```
apiVersion: obsidianwall.io/v1     Protocol version
kind: Policy                        Always Policy for now

metadata:
  name:        string               Policy identifier
  version:     string               Semver string
  owner:       string               Responsible team
  description: string               Optional description

spec:
  inputs:      list[string]         Runtime context keys required
  parameters:  dict                 Policy parameters (flattened at runtime)
  conditions:  list[Condition]      Evaluated deterministically
  decision:    Decision             allow / deny / warn mappings
  governance:  GovernanceConfig     Severity, notifications, approvals
  override:    Override             Roles and approval requirements
  actions:     list[Action]         notify / log actions
```

### Condition expressions

Expressions use a restricted grammar — no `eval()`, no dynamic code:

```yaml
conditions:
  - id: budget_check
    expression: "(current_spend + estimated_cost) <= budget.amount"
    description: "Monthly spend must not exceed budget"

  - id: instance_size_check
    expression: "estimated_cost <= max_instance_cost"
    description: "No single instance may exceed cost threshold"
```

Supported operators: `<=`, `>=`, `<`, `>`, `==`
Supported arithmetic: `+`
Context resolution: dot-notation for nested parameters (`budget.amount`)

---

## Audit artifact

Every evaluation produces a complete audit artifact:

```json
{
  "decision_id":        "abc3a13b-83d5-4fad-87d8-bbe77e4b8075",
  "timestamp":          "2026-05-20T04:05:28Z",
  "policy":             "basic_budget_verdict",
  "decision":           "DENY_WITH_OVERRIDE",
  "override_possible":  true,
  "override_required":  false,
  "conditions_passed":  false,
  "effective_severity": "critical",
  "risk_summary": {
    "overall_risk_score":    75,
    "risk_severity":         "critical",
    "highest_risk_analyzer": "cost_analysis",
    "total_findings":        3
  },
  "trace": [...],
  "explanation": {
    "governance_reasoning": {...},
    "policy_reasoning":     {...},
    "trace_graph":          {...}
  },
  "notification_manifest": {...}
}
```

The artifact is written to `output/result.json` and printed to stdout.
It is suitable for storage in an audit log, S3 bucket, or compliance system.

---

## Doctrine

```
AI may advise.
AI may explain.
AI may optimize.
AI may correlate.
AI may recommend.

AI may NOT authoritatively govern.
```

Every governance decision in ObsidianWall Verdict is produced by
deterministic evaluation of human-authored policy conditions —
never by a probabilistic model.

Decisions are reproducible, explainable, and attributable to a named
policy and a named human who wrote it.

This is not an anti-AI position. The analyzer framework, recommendation
engine, and explainability pipeline all use intelligence to inform the
governance process. The boundary is authority: intelligence informs,
policy governs.

---

## Architecture

Verdict is the first executable of the ObsidianWall programmable
assurance platform.

```
┌─────────────────────────────────────────────────────┐
│  Open Governance Core  (this repo — open source)    │
│                                                     │
│  engine/       deterministic evaluation pipeline    │
│  schemas/      policy DSL and typed contracts       │
│  context/      Terraform plan parsing               │
│  audit/        structured audit logging             │
│  cli/          command-line interface               │
└─────────────────────────────────────────────────────┘
         ↓ telemetry (opt-in, anonymous)
┌─────────────────────────────────────────────────────┐
│  Intelligence Layer  (future — private)             │
│                                                     │
│  Derived optimization intelligence                  │
│  Workload pattern recognition                       │
│  Pricing behavior intelligence                      │
│  Predictive governance scoring                      │
└─────────────────────────────────────────────────────┘
         ↓ enterprise workflows
┌─────────────────────────────────────────────────────┐
│  Platform Layer  (future — paid)                    │
│                                                     │
│  Hosted policy management                           │
│  Approval workflow persistence                      │
│  Governance dashboards                              │
│  RBAC, SSO, multi-tenant                            │
│  Compliance exports                                 │
└─────────────────────────────────────────────────────┘
```

---

## Development

**Requirements:** Python 3.13+, Git

```bash
git clone https://github.com/obsidianwall/obsidianwall-verdict
cd obsidianwall-verdict

pip install -r requirements.txt

# Run the full test suite
pytest tests/ -v

# Run a sample evaluation
verdict evaluate \
  --plan  samples/terraform_plan.json \
  --policy policies/cost/basic_budget.yaml \
  --role  engineer
```

**Test suite:** 101 tests — unit, integration, and pipeline.

```bash
pytest tests/unit/        # 82 tests
pytest tests/integration/ # 11 tests
pytest tests/             # 101 tests
```

---

## Policy examples

Sample policies are in `policies/cost/`:

| Policy | Enforcement | Use case |
|--------|------------|---------|
| `basic_budget.yaml` | Soft — override available | Engineering teams with budget owner oversight |
| `strict_budget.yaml` | Hard — dual approval required | Production environments, finance-controlled budgets |

---

## Telemetry

Verdict collects anonymous usage telemetry to improve the optimization
catalog and governance intelligence. Telemetry is **opt-in** and
**disabled by default**.

```bash
# Enable in .env
OW_TELEMETRY_ENABLED=true
```

What is collected: evaluation counts, resource type distributions,
decision outcomes, condition failure patterns.

What is **never** collected: plan contents, cost amounts,
resource names, organization identifiers, policy file contents.

---

## License

Verdict is released under the
[Apache License 2.0](LICENSE).

Free to use, modify, and distribute for any purpose —
commercial or non-commercial. Attribution required.

Built on ObsidianWall — the programmable assurance platform.
[obsidianwall.com](https://obsidianwall.com)

---

## Built by

Aisha I. — [obsidianwall.com](https://obsidianwall.com)

> *"Organizations that design for programmable assurance now
> will not need to retrofit later."*