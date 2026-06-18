# ObsidianWall Verdict

**Pre-deployment infrastructure governance.**
Evaluate Terraform plans and CloudFormation templates against governance policies
before deployment executes — catching budget overruns, policy violations, and
compliance failures before they become incidents.

[![CI](https://github.com/obsidianwall/obsidianwall-verdict/actions/workflows/verdict-ci.yml/badge.svg)](https://github.com/obsidianwall/obsidianwall-verdict/actions/workflows/verdict-ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![obsidianwall.com](https://img.shields.io/badge/platform-obsidianwall.com-5ac4f0.svg)](https://obsidianwall.com)

-----

## What it does

Verdict sits between your infrastructure plan and deployment. It takes a
Terraform plan JSON or CloudFormation template, evaluates it deterministically
against your governance policies, and produces a decision — with a full
audit trail, risk score, stakeholder notifications, and explainability
built in.

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

-----

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
# Terraform
terraform plan -out=tfplan
terraform show -json tfplan > terraform_plan.json
verdict evaluate \
  --plan   terraform_plan.json \
  --policy policies/cost/budget.yaml \
  --role   engineer

# CloudFormation — auto-detected, no --format flag needed
verdict evaluate \
  --plan   template.yaml \
  --policy policies/cost/budget.yaml \
  --role   engineer
```

Verdict returns exit code `0` on ALLOW and non-zero on DENY,
blocking CI/CD pipelines automatically.

-----

## Commands

### verdict evaluate

Evaluate a Terraform plan or CloudFormation template against a governance policy.
Plan format is auto-detected from file content — no `--format` flag required.

```bash
verdict evaluate \
  --plan          terraform_plan.json \
  --policy        policies/cost/budget.yaml \
  --role          engineer \
  --current-spend 30.0
```

|Flag             |Description                                                       |
|-----------------|------------------------------------------------------------------|
|`--plan`         |Path to Terraform plan JSON or CloudFormation template (JSON/YAML)|
|`--policy`       |Path to policy YAML file                                          |
|`--role`         |Role of the user triggering the deployment                        |
|`--current-spend`|Spend already incurred this month (default: 0.0)                  |
|`--pricing`      |`table` (default, offline) or `live` (Azure Retail API)           |
|`--region`       |Cloud region for live pricing (default: eastus)                   |
|`--output`       |Path to write the audit artifact (default: output/result.json)    |

-----

### verdict coverage

Map a policy’s conditions to a compliance framework. Reports which framework
controls are addressed by your policy conditions and which controls are missing.

```bash
verdict coverage \
  --policy    policies/ai_governance/basic_ai_governance.yaml \
  --framework nist_ai_rmf
```

```
────────────────────────────────────────────────────────────────
  ObsidianWall — Compliance Coverage Report
────────────────────────────────────────────────────────────────

  Policy:     basic_ai_governance_verdict
  Framework:  NIST AI Risk Management Framework
  Coverage:   16.7%  (2 of 12 controls)

  Covered Controls
────────────────────────────────────────────────────────────────
  ✅  GOVERN-1.1             AI Policies and Procedures
               → gpu_governance_check
  ✅  MAP-1.1                AI System Categorization
               → gpu_governance_check

  Missing Controls
────────────────────────────────────────────────────────────────
  ❌  GOVERN-1.2             Accountability for AI Risk
  ❌  MANAGE-1.1             AI Risk Treatment
  ...

  10 control(s) not addressed. Add conditions covering the
  missing areas to improve coverage.
────────────────────────────────────────────────────────────────
```

|Flag         |Description                                                |
|-------------|-----------------------------------------------------------|
|`--policy`   |Path to policy YAML file                                   |
|`--framework`|Compliance framework: `hipaa`, `soc2`, `cis`, `nist_ai_rmf`|

**Supported frameworks:**

|Framework    |Controls                                                     |
|-------------|-------------------------------------------------------------|
|`hipaa`      |HIPAA Security Rule — Technical and Administrative Safeguards|
|`soc2`       |SOC 2 Trust Service Criteria                                 |
|`cis`        |CIS Controls v8                                              |
|`nist_ai_rmf`|NIST AI Risk Management Framework                            |

-----

### verdict simulate

Evaluate a policy against synthetic context values. No Terraform plan or
CloudFormation template required. Use this to test policies while writing
them, calibrate thresholds, onboard teams, or assert expected decisions in CI.

```bash
verdict simulate \
  --policy policies/cost/basic_budget.yaml \
  --set estimated_cost=150

verdict simulate \
  --policy policies/ai_governance/basic_ai_governance.yaml \
  --set ai_gpu_workloads=2
```

```
────────────────────────────────────────────────────────────────
  ObsidianWall Verdict — Simulate
────────────────────────────────────────────────────────────────

  Context
────────────────────────────────────────────────────────────────
  ai_gpu_workloads                 2

  Decision
────────────────────────────────────────────────────────────────
  🚫  DENY

  Technical Risk:    0/100
  Governance Risk:   critical
  Reason:            conditions failed hard deny

────────────────────────────────────────────────────────────────
```

Technical Risk and Governance Risk are shown as separate dimensions.
A governance DENY at Technical Risk 0 means a policy condition failed —
not that infrastructure is misconfigured. Both dimensions are needed
to understand the full governance picture.

|Flag      |Description                                       |
|----------|--------------------------------------------------|
|`--policy`|Path to policy YAML file                          |
|`--set`   |Set a context key. Repeatable. Format: `key=value`|
|`--role`  |Role of the user (default: engineer)              |
|`--output`|Optional path to write simulation result JSON     |

Exit codes: `0` ALLOW or ALLOW_WITH_NOTIFICATION, `1` DENY or DENY_WITH_OVERRIDE.

-----

### verdict sentinel scan

Verify that reality stayed aligned with the governance decision after deployment.
Compares the current plan state against the previous governance decision and
reports whether drift has occurred.

```bash
verdict sentinel scan --plan terraform_plan.json
```

Outcome types: `no_drift`, `drift_detected`, `compliance_violation`, `budget_overrun`.

-----

### verdict validate

Check that a policy file is valid before using it in an evaluation.
Useful when writing new policies — catches schema errors immediately
without needing a plan file.

```bash
verdict validate --policy policies/cost/budget.yaml
```

Returns a JSON object with `status: valid` or `status: invalid` and
the error if the policy fails validation.

-----

### verdict test

Assert that a Terraform plan produces a specific governance decision.
This is the policy regression testing command — use it to verify
your policies behave correctly and catch regressions when policies change.

```bash
verdict test \
  --plan   terraform_plan.json \
  --policy policies/cost/budget.yaml \
  --expect DENY_WITH_OVERRIDE
```

```
  ✅ Test passed

  Policy:   policies/cost/budget.yaml
  Plan:     terraform_plan.json
  Expected: DENY_WITH_OVERRIDE
  Actual:   DENY_WITH_OVERRIDE
```

|Flag       |Description                                       |
|-----------|--------------------------------------------------|
|`--plan`   |Path to Terraform plan JSON                       |
|`--policy` |Path to policy YAML file                          |
|`--expect` |Expected decision (see governance decisions table)|
|`--role`   |Role of the user (default: engineer)              |
|`--verbose`|Show full evaluation output on failure            |

Exit codes: `0` pass, `1` fail, `2` evaluation error.

-----

### verdict audit

Review governance decisions recorded over time. Verdict stores a local
history of every evaluation when telemetry is enabled, and `verdict audit`
turns that history into a governance report.

**Enable telemetry first:**

```bash
export OW_TELEMETRY_ENABLED=true
```

**Run the audit:**

```bash
verdict audit
```

```
────────────────────────────────────────────────────────────────────────
  ObsidianWall Verdict — Governance Audit
────────────────────────────────────────────────────────────────────────

  Total evaluations:  12
  Allowed:            4
  Denied:             8  (66.7%)

────────────────────────────────────────────────────────────────────────
  Domain Risk Scores  (average across recorded decisions)
────────────────────────────────────────────────────────────────────────
  Cost                      [██████░░░░░░]   50.0/100  medium
  Network / Topology        [███░░░░░░░░░]   25.0/100  low
  Architecture              [░░░░░░░░░░░░]    0.0/100  informational
  Utilization               [░░░░░░░░░░░░]    0.0/100  informational
```

|Flag        |Description                                     |
|------------|------------------------------------------------|
|`--insights`|Include governance insights and recommendations |
|`--policy`  |Filter to a specific policy name                |
|`--limit`   |Number of recent decisions to show (default: 50)|
|`--format`  |`table` (default) or `json`                     |

**Decision history is stored locally at `~/.obsidianwall/decisions.db`.**
Nothing leaves your machine.

-----

## GitHub Actions

Add Verdict as a governance gate in your CI/CD pipeline:

```yaml
# .github/workflows/governance.yml
name: Infrastructure Governance

on:
  pull_request:
    paths: ["**.tf", "**.tfvars", "**.yaml", "**.json"]

jobs:
  governance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@9f698171ed81b15d1823a05fc7211befd50c8ae0  # v6.0.3

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

### Action outputs

|Output              |Description                                                                                         |
|--------------------|----------------------------------------------------------------------------------------------------|
|`decision`          |`ALLOW` / `ALLOW_WITH_NOTIFICATION` / `ALLOW_WITH_APPROVAL_REQUIRED` / `DENY_WITH_OVERRIDE` / `DENY`|
|`conditions_passed` |`true` or `false`                                                                                   |
|`risk_score`        |Integer 0–100                                                                                       |
|`effective_severity`|`informational` / `low` / `medium` / `high` / `critical`                                            |
|`decision_id`       |UUID for audit trail correlation                                                                    |

-----

## How it works

```
Infrastructure plan (Terraform JSON or CloudFormation YAML/JSON)
      ↓
Translation Layer     Auto-detects format, parses plan, estimates cost
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

-----

## Enforcement modes

|Mode                   |How                                                                 |What it blocks                                             |
|-----------------------|--------------------------------------------------------------------|-----------------------------------------------------------|
|**CI/CD pipeline**     |GitHub Actions with `fail_on_deny: true`                            |`terraform apply` never runs on DENY                       |
|**IAM access controls**|Azure Entra ID / AWS IAM restricts engineer credentials to read-only|Direct deployment from local machines impossible           |
|**Standalone manual**  |Run `verdict evaluate` before `terraform apply`                     |Governance guidance, audit trail, budget owner notification|

For hard technical enforcement, integrate Verdict into your CI/CD pipeline
and restrict cloud credentials so only the pipeline’s service principal
can apply infrastructure. Engineers with read-only credentials cannot
deploy directly even if they skip Verdict locally.

-----

## Governance decisions

|Decision                      |Meaning                                              |
|------------------------------|-----------------------------------------------------|
|`ALLOW`                       |All conditions passed. Deployment authorized.        |
|`ALLOW_WITH_NOTIFICATION`     |Conditions passed but stakeholders are notified.     |
|`ALLOW_WITH_APPROVAL_REQUIRED`|Conditions passed but formal approval is required.   |
|`DENY_WITH_OVERRIDE`          |Conditions failed. An authorized role may override.  |
|`DENY`                        |Conditions failed. No override permitted. Hard block.|

-----

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

### Governance domains

Policies declare which governance domain they enforce. Verdict validates
conditions against the declared domain and rejects mismatches.

|Domain           |What it governs                                            |
|-----------------|-----------------------------------------------------------|
|`cost`           |Budget spend enforcement                                   |
|`security`       |Security posture — open ingress, public storage, encryption|
|`compliance`     |Tagging, naming, regulatory requirements                   |
|`resource_limits`|Instance counts, GPU limits, sizing                        |
|`network`        |Network topology, segmentation, public exposure            |
|`identity`       |IAM, MFA, privileged access                                |
|`data_governance`|PII handling, encryption, data residency                   |
|`resilience`     |Availability, DR, replica counts                           |
|`ai_governance`  |AI system controls, model provenance, GPU workloads        |
|`composite`      |Coordinates multiple domains in one policy                 |

### Condition expressions

```yaml
conditions:
  - id: budget_check
    expression: "(current_spend + estimated_cost) <= budget.amount"
    description: "Monthly spend must not exceed budget"

  - id: no_open_ingress
    expression: "open_ingress_rules <= security.max_open_ingress_rules"
    description: "No unrestricted inbound rules permitted"
```

Supported operators: `<=`, `>=`, `<`, `>`, `==`
Supported arithmetic: `+`
Context resolution: dot-notation for nested parameters (`budget.amount`)

-----

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

-----

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

-----

## Architecture

Verdict is the first executable of the ObsidianWall programmable
assurance platform.

```
┌─────────────────────────────────────────────────────┐
│  Open Governance Core  (this repo — open source)    │
│                                                     │
│  engine/       deterministic evaluation pipeline    │
│  schemas/      policy DSL and typed contracts       │
│  context/      Translation Layer (Terraform +       │
│                CloudFormation auto-detection)        │
│  telemetry/    local decision history (SQLite)      │
│  audit/        structured audit logging             │
│  cli/          command-line interface               │
└─────────────────────────────────────────────────────┘
         ↓ telemetry (opt-in, local SQLite)
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

-----

## Telemetry

Telemetry is **opt-in** and **disabled by default**. When enabled,
Verdict records governance decisions to a local SQLite database at
`~/.obsidianwall/decisions.db`. Nothing is sent anywhere remotely.

```bash
export OW_TELEMETRY_ENABLED=true
```

**What is stored:**

- Decision outcomes, risk scores, policy names
- Which conditions passed and which failed
- Override and approval events

**What is never stored:**

- Plan contents or resource configurations
- Cost amounts or budget values
- Resource names or identifiers
- Organization or team identifiers

Telemetry powers `verdict audit`. Without it, `verdict audit` has no
data to read.

-----

## Development

**Requirements:** Python 3.11+, Git

```bash
git clone https://github.com/obsidianwall/obsidianwall-verdict
cd obsidianwall-verdict
pip install -e ".[dev]"

# Run the full test suite
pytest tests/ -v

# Run a sample evaluation
verdict evaluate \
  --plan   samples/terraform_plan.json \
  --policy policies/cost/basic_budget.yaml \
  --role   engineer
```

**Test suite:** 737 tests — unit and integration.

```bash
pytest tests/unit/        # unit tests
pytest tests/integration/ # integration tests
pytest tests/             # full suite
```

**Policy examples** are in `policies/` organized by governance domain:

```
policies/
  cost/           budget enforcement
  security/       security posture
  compliance/     tagging and regulatory
  network/        topology and exposure
  identity/       IAM and Zero Trust
  ai_governance/  AI system controls
  composite/      multi-domain coordination
```

-----

## License

Verdict is released under the
[Apache License 2.0](LICENSE).

Free to use, modify, and distribute for any purpose —
commercial or non-commercial. Attribution required.

Built on ObsidianWall — the programmable assurance platform.
[obsidianwall.com](https://obsidianwall.com)

-----

## Built by

Aisha I. — [obsidianwall.com](https://obsidianwall.com)

> *“Organizations that design for programmable assurance now
> will not need to retrofit later.”*