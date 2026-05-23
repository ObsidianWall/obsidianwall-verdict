
## **How Verdict is packaged for end users**

**Three ways to get it:**

```
1. pip install obsidianwall-verdict
   → installs verdict CLI command globally
   → works anywhere Python 3.13+ is installed

2. GitHub Actions
   uses: obsidianwall/obsidianwall-verdict@main
   → no installation needed, runs in CI automatically

3. Clone and run locally
   git clone github.com/obsidianwall/obsidianwall-verdict
   pip install -e .
   verdict evaluate ...
```

For most engineers the path is either pip install or the GitHub Action. Nobody clones a governance tool to run it.

---

**What Verdict is actually doing — plain English**

When you run `terraform apply`, Terraform reads your `.tf` files, builds a plan of what it is going to create, and then creates it. By the time you see a cloud bill, the resources already exist and are already costing money.

Verdict inserts a governance check **between the plan and the apply**:

```
terraform plan    → what will be created
      ↓
verdict evaluate  → should this be allowed?
      ↓
terraform apply   → only runs if verdict says ALLOW
```

Verdict reads the plan JSON (which describes every resource Terraform intends to create), estimates what those resources will cost, evaluates that estimate against your policy, and either allows or blocks the deployment before a single resource is created.

---
## Use Case 1

**Real walkthrough: deploying your first Azure VM on a $15/month budget**

**Step 1 — Write your Terraform**

```hcl
# main.tf
provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "rg" {
  name     = "my-first-rg"
  location = "East US"
}

resource "azurerm_virtual_machine" "web" {
  name                = "web-server"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  vm_size             = "Standard_B1s"
}
```

**Step 2 — Write your policy**

```yaml
# policies/my_budget.yaml
apiVersion: obsidianwall.io/v1
kind: Policy

metadata:
  name: personal_budget
  version: "0.1"
  owner: you

spec:
  inputs:
    - estimated_cost
    - current_spend

  parameters:
    budget:
      amount: 15
      period: monthly

  conditions:
    - id: budget_check
      expression: "(current_spend + estimated_cost) <= budget.amount"
      description: "Must stay under $15/month"

  decision:
    allow: ALLOW
    deny:  DENY

  governance:
    severity: high

  override:
    roles: []
    requires_approval: false
```

**Step 3 — Generate the Terraform plan**

```bash
terraform init
terraform plan -out=tfplan
terraform show -json tfplan > terraform_plan.json
```

This creates a `terraform_plan.json` file that describes every resource Terraform intends to create.

**Step 4 — Run Verdict**

```bash
verdict evaluate \
  --plan   terraform_plan.json \
  --policy policies/my_budget.yaml \
  --role   engineer
```

**Step 5 — Verdict evaluates**

Verdict reads the plan and sees:
```
azurerm_virtual_machine  Standard_B1s  → $12/month (from pricing table)
```

It evaluates your condition:
```
(current_spend + estimated_cost) <= budget.amount
(0 + 12) <= 15
12 <= 15  →  TRUE
```

Result:
```
  decision     ALLOW
✓ Deployment authorized.
```

**Step 6 — Deploy**

```bash
terraform apply
```

---

**Now try the same thing with a bigger VM:**

Change `vm_size = "Standard_D2s_v3"` ($50/month) and run Verdict again:

```
(0 + 50) <= 15
50 <= 15  →  FALSE

  decision     DENY
✗ Deployment blocked by governance policy.
```

`terraform apply` never runs. The resource never exists. You never get a bill for it.

---

**What Verdict does NOT do at MVP — being honest**

The cost estimation uses internal pricing tables with hardcoded approximate prices. It does not:

- Call real Azure/AWS pricing APIs
- Account for data transfer costs
- Account for storage consumed over time
- Account for reserved instance discounts
- Know current spot pricing

So `Standard_B1s` is hardcoded as `$12` in the pricing table. The real Azure price may differ slightly depending on region and current pricing. This is a known limitation at MVP stage. The value is the governance gate mechanism, not perfect cost precision.

The pricing tables are in `engine/cost_estimator.py` and will be improved as the intelligence layer matures.