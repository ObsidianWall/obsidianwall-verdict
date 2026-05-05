# obsidianwall-guardrails

## A pre-deployment decision engine that blocks or approves infrastructure changes based on rules (starting with cost).

## A proactive cloud cost system to prevent going over budget.
___

# 🧱 1. FINAL REPO DECISION (NON-NEGOTIABLE FOR MVP)

## We are using ONE structure for the first executable unit:

✅ LOCKED REPO STRUCTURE (NO MORE CHANGES)

We are staying with:

```
obsidianwall-guardrails/
│
├── .devcontainer/
│   ├── devcontainer.json
│   ├── Dockerfile
│   └── requirements.txt
|
├── cli/
│   └── main.py
│
├── engine/
│   ├── evaluator.py
│   ├── policy_loader.py
│   ├── validator.py
│   ├── condition_evaluator.py
|   ├── cost_estimator.py
│   ├── decision_resolver.py
│   └── recommender.py
│
├── schemas/
│   └── policy_schema.py
│
├── context/
|   ├── context_builder.py
│   └── terraform_parser.py
│
├── audit/
│   └── audit_logger.py   ← ✅ THIS is where your logging file goes
│
├── policies/
│   └── cost/
│       ├── basic_budget.yaml
│       └── strict_budget.yaml
│
├── samples/
│   └── terraform_plan.json
│
├── output/
│   └── result.json
│
├── tests/
│   ├── test_engine.py
│   └── test_policy.py
│
├── .github/workflows/
│   └── ci.yml
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