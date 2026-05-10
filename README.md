# obsidianwall-guardrails

## A pre-deployment decision engine that blocks or approves infrastructure changes based on rules (starting with cost).

## A proactive cloud cost system to prevent going over budget.
___

# 🧱 1. FINAL REPO DECISION (NON-NEGOTIABLE FOR MVP)

## We are using ONE structure for the first executable unit:

✅ LOCKED REPO STRUCTURE (NO MORE CHANGES)

We are staying with:

```
obsidianwall-verdict/
│
├── .devcontainer/
│   ├── devcontainer.json
│   ├── Dockerfile
│   └── requirements.txt
|
├── cli/
│   ├── __init__.py
│   └── main.py
│
├── engine/
│   ├── __init__.py
│   ├── evaluator.py
│   ├── policy_loader.py
│   ├── policy_normalizer.py
│   ├── validator.py
│   ├── condition_evaluator.py
|   ├── cost_estimator.py
│   ├── decision_resolver.py
│   ├── lint_validator.py
│   ├── optimiation_catalog.py
│   └── recommender.py
│
├── schemas/
│   ├── __init__.py
│   └── policy_schema.py
│
├── context/
│   ├── __init__.py
|   ├── context_builder.py
│   └── terraform_parser.py
│
├── audit/
│   ├── __init__.py
│   └── audit_logger.py   ← ✅ THIS is where your logging file goes
│
├── policies/
│   └── cost/
│       ├── basic_budget.yaml
│       └── strict_budget.yaml
│
├── samples/
│   ├── plan_over_budget.json
│   ├── plan_under_budget.json
│   └── terraform_plan.json
│
├── output/
│   └── result.json
│
├── tests/
│   ├── test_engine.py
│   └── test_policy.py
│
├── .github/
|     └──workflows/
│            └── ci.yml
│
├── pyproject.toml
├── requirements.txt
└── README.md
```

## ✅ logging/
explicit domain
audit-focused
aligns with compliance

### Future expansion

That folder will evolve into:

```
logging/
├── audit_logger.py
├── decision_store.py
├── event_stream.py
```
-This becomes your * audit subsystem *