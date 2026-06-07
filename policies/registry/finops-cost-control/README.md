# FinOps Framework — Cost Control Templates

Two templates for different enforcement postures. Both implement
[FinOps Framework](https://www.finops.org/framework/) principles
at the infrastructure declaration layer.

-----

## Templates

### cost.yaml — Standard enforcement

For engineering teams with a monthly budget and a budget owner who
can authorize overrides. The deployment is blocked on breach but
the budget owner can approve and proceed without formal escalation.

|Parameter           |Default|What it controls          |
|--------------------|-------|--------------------------|
|`budget.amount`     |5000.00|Monthly spend limit in USD|
|`budget.period`     |monthly|Budget reset period       |
|`budget.flexibility`|soft   |Override is available     |

### budget_strict.yaml — Hard enforcement

For production environments or finance-controlled budgets where
no self-service override is acceptable. Both the CFO office and
FinOps lead must approve before a blocked deployment can proceed.

|Parameter           |Default |What it controls                 |
|--------------------|--------|---------------------------------|
|`budget.amount`     |10000.00|Hard monthly limit in USD        |
|`budget.flexibility`|hard    |No override without dual approval|

-----

## FinOps Framework mapping

|Phase       |What this enforces                                     |
|------------|-------------------------------------------------------|
|**Inform**  |Engineers see cost impact before deployment executes   |
|**Optimize**|Budget enforcement prevents overspend at declaration   |
|**Operate** |Approval workflows create accountability for exceptions|

-----

## What to customize

```yaml
# cost.yaml
parameters:
  budget:
    amount: 5000.00          # Your actual monthly budget
    scope: project:default   # Your project or team identifier
    owner: finops-team       # Your budget owner role name

# budget_strict.yaml
parameters:
  budget:
    amount: 10000.00         # Your hard production budget limit
    scope: project:production
    owner: cfo-office        # Your finance authority
```

-----

## How to use

**Choose your template:**

- Teams with budget owner oversight → `cost.yaml`
- Production with finance controls → `budget_strict.yaml`

**Validate:**

```bash
verdict validate --policy policies/registry/finops-cost-control/cost.yaml
```

**Test against a compliant plan:**

```bash
verdict test \
  --plan   samples/terraform_plan.json \
  --policy policies/registry/finops-cost-control/cost.yaml \
  --expect ALLOW
```

```bash
verdict test \
  --plan   samples/terraform_plan.json \
  --policy policies/registry/finops-cost-control/budget_strict.yaml \
  --expect ALLOW_WITH_NOTIFICATION
```  

**Evaluate with current month spend:**

```bash
verdict evaluate \
  --plan          samples/terraform_plan.json \
  --policy        policies/registry/finops-cost-control/cost.yaml \
  --current-spend 1200.00 \
  --role          engineer
```

-----

## Reference

- [FinOps Framework](https://www.finops.org/framework/)
- [FinOps Principles](https://www.finops.org/framework/principles/)