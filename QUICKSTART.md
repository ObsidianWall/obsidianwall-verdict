# Quickstart Guide

This guide walks you through using ObsidianWall Verdict from
installation to running your first governance evaluation in CI/CD.

-----

## Step 1 — Install

```bash
pip install obsidianwall-verdict
```

Verify the install:

```bash
verdict --version
```

-----

## Step 2 — Generate an infrastructure plan

Verdict evaluates Terraform plans and CloudFormation templates before
deployment. Plan format is auto-detected from file content — no
`--format` flag required.

**Terraform:**

```bash
terraform init
terraform plan -out=tfplan
terraform show -json tfplan > terraform_plan.json
```

**CloudFormation:**

Pass your CloudFormation template directly — JSON or YAML both work:

```bash
verdict evaluate \
  --plan   template.yaml \
  --policy policies/cost/budget.yaml
```

If you do not have a project handy, use the sample plan
included in the repository:

```bash
git clone https://github.com/obsidianwall/obsidianwall-verdict
cd obsidianwall-verdict
```

The sample plan is at `samples/terraform_plan.json`.

-----

## Step 3 — Choose a policy

You have two options:

**Use an example template** from `policies/registry/` — copy one
that matches your compliance context, fill in your values, and use it.

**Use an existing domain policy** from `policies/` — these are working
policies with sample values, ready to run immediately.

For your first evaluation, use the included budget policy:

```
policies/cost/basic_budget.yaml
```

-----

## Step 4 — Validate the policy

Before evaluating, confirm your policy file is valid:

```bash
verdict validate --policy policies/cost/basic_budget.yaml
```

You should see:

```json
{
  "status": "valid",
  "policy": "policies/cost/basic_budget.yaml",
  "name": "basic_budget_verdict",
  "version": "0.1",
  "owner": "team-alpha"
}
```

-----

## Step 5 — Run your first evaluation

```bash
verdict evaluate \
  --plan   samples/terraform_plan.json \
  --policy policies/cost/basic_budget.yaml \
  --role   engineer
```

Verdict prints a full governance decision to stdout and writes an
audit artifact to `output/result.json`.

**Understanding the decision:**

|Decision                      |What it means                                             |
|------------------------------|----------------------------------------------------------|
|`ALLOW`                       |All conditions passed. Safe to deploy.                    |
|`ALLOW_WITH_NOTIFICATION`     |Conditions passed but stakeholders notified.              |
|`ALLOW_WITH_APPROVAL_REQUIRED`|Conditions passed but approval required before proceeding.|
|`DENY_WITH_OVERRIDE`          |Conditions failed. An authorized role may override.       |
|`DENY`                        |Conditions failed. No override permitted.                 |

Exit code `0` means ALLOW. Non-zero means DENY. CI/CD pipelines
respect this automatically.

-----

## Step 6 — Build your own policy from a template

Copy the template closest to your use case:

```bash
cp policies/registry/finops-cost-control/cost.yaml \
   policies/my-budget.yaml
```

Edit the values for your organization:

```yaml
parameters:
  budget:
    amount: 3000.00        # Your actual monthly budget
    scope: project:myapp   # Your project identifier
    owner: your-team       # Your budget owner role

governance:
  notifications:
    - role: your-budget-owner
      channel: email
    - role: your-engineering-lead
      channel: slack
```

Validate your customized policy:

```bash
verdict validate --policy policies/my-budget.yaml
```

-----

## Step 7 — Simulate policy decisions

Before connecting a policy to a real infrastructure plan, simulate
decisions against synthetic context values to understand how the
policy behaves at different thresholds.

```bash
# What happens when estimated cost is low?
verdict simulate \
  --policy policies/my-budget.yaml \
  --set estimated_cost=100

# What happens when it exceeds the budget?
verdict simulate \
  --policy policies/my-budget.yaml \
  --set estimated_cost=5000
```

```
  🚫  DENY

  Technical Risk:    0/100
  Governance Risk:   medium
  Reason:            conditions failed hard deny
```

Technical Risk and Governance Risk are shown as separate dimensions.
A DENY at Technical Risk 0 means a policy condition failed — not
that infrastructure is misconfigured.

Use simulate to:

- Calibrate thresholds before deploying a policy to CI/CD
- Onboard engineers to understand what a policy evaluates
- Write CI tests that assert expected decisions without a real plan

-----

## Step 8 — Check compliance coverage

After writing a policy, check how much of a compliance framework
it actually covers:

```bash
verdict coverage \
  --policy  policies/my-budget.yaml \
  --framework hipaa
```

```
────────────────────────────────────────────────────────────────
  ObsidianWall — Compliance Coverage Report
────────────────────────────────────────────────────────────────

  Policy:     my-budget
  Framework:  HIPAA Security Rule
  Coverage:   20.0%  (2 of 10 controls)

  Covered Controls
────────────────────────────────────────────────────────────────
  ✅  164.308(a)(1)          Security Management Process
               → budget_check

  Missing Controls
────────────────────────────────────────────────────────────────
  ❌  164.312(a)(1)          Access Control
  ❌  164.312(e)(1)          Transmission Security
  ...

  8 control(s) not addressed.
────────────────────────────────────────────────────────────────
```

This answers the question most governance tools cannot: *does this
policy actually cover the framework it claims to address, and what
is missing?*

**Supported frameworks:**

|Framework                        |Flag         |
|---------------------------------|-------------|
|HIPAA Security Rule              |`hipaa`      |
|SOC 2 Trust Service Criteria     |`soc2`       |
|CIS Controls v8                  |`cis`        |
|NIST AI Risk Management Framework|`nist_ai_rmf`|

-----

## Step 9 — Test your policy

Write tests to confirm your policy behaves correctly and catch
regressions when policies change:

```bash
# Test that a known-compliant plan is allowed
verdict test \
  --plan   samples/compliant_plan.json \
  --policy policies/my-budget.yaml \
  --expect ALLOW

# Test that a known-violating plan is denied
verdict test \
  --plan   samples/terraform_plan.json \
  --policy policies/my-budget.yaml \
  --expect DENY_WITH_OVERRIDE
```

If both pass, your policy is working correctly. Add these tests to
your CI pipeline to catch regressions when your policy changes.

-----

## Step 10 — Governance history

Verdict records every evaluation to a local governance history
at `~/.obsidianwall/decisions.db`. This is enabled by default.
Nothing leaves your machine.

After running a few evaluations:

```bash
verdict audit
```

For pattern analysis and recommendations:

```bash
verdict audit --insights
```

**To opt out of local governance history:**

```bash
export OW_HISTORY_ENABLED=false
```

What is stored: decision outcomes, risk scores, policy names,
condition results, override and approval events.

What is never stored: plan contents, cost amounts, resource
names, organization identifiers.

-----

## Step 11 — Wire into GitHub Actions

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
      - uses: actions/checkout@v4

      - name: Generate Terraform plan
        run: |
          terraform init
          terraform plan -out=tfplan
          terraform show -json tfplan > terraform_plan.json

      - name: Governance evaluation
        uses: obsidianwall/obsidianwall-verdict@main
        with:
          plan:         samples/terraform_plan.json
          policy:       policies/my-budget.yaml
          role:         engineer
          fail_on_deny: "true"
```

When `fail_on_deny` is `true`, DENY decisions return a non-zero
exit code and block the workflow. Engineers must remediate the
violation or get an authorized override before the deployment
can proceed.

-----

## Step 12 — For compliance frameworks

If you need governance aligned to a specific compliance standard,
start with the example templates:

|Framework              |Template location                         |
|-----------------------|------------------------------------------|
|HIPAA Security Rule    |`policies/registry/hipaa/`                |
|NIST AI RMF 1.0        |`policies/registry/nist-ai-rmf/`          |
|CIS Controls v8        |`policies/registry/cis-benchmark/`        |
|FinOps Framework       |`policies/registry/finops-cost-control/`  |
|Zero Trust Architecture|`policies/registry/zero-trust-network/`   |
|Production deployment  |`policies/registry/production-deployment/`|

Each template directory contains a README explaining the compliance
mapping and exactly what to customize.

After writing a compliance policy, run `verdict coverage` to verify
how much of the framework your conditions actually address and what
controls are still missing.

-----

## Where to save your policies

Verdict accepts any file path for `--policy`. The convention is to
keep policies alongside your infrastructure code:

```
your-infra-repo/
  main.tf                   ← Terraform
  template.yaml             ← or CloudFormation
  terraform_plan.json
  policies/
    budget.yaml             ← your customized policy
    production.yaml         ← your production composite policy
```

This keeps governance policy version-controlled alongside the
infrastructure it governs.

-----

## Next steps

- Read the full [README](README.md) for complete command reference
- Browse `policies/` for working domain policy instances
- Browse `policies/registry/` for compliance framework templates
- Run `verdict --help` to see all available commands