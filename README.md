# obsidianwall-guardrails

## A pre-deployment decision engine that blocks or approves infrastructure changes based on rules (starting with cost).

## A proactive cloud cost system to prevent going over budget.
___

# 🧱 1. FINAL REPO DECISION (NON-NEGOTIABLE FOR MVP)

## We are using ONE structure for the first executable unit:

text''
obsidianwall-guardrails/
│
├── cli/
│   └── main.py
│
├── engine/
│   ├── evaluator.py
│   ├── policy_loader.py
│   ├── validator.py
│   ├── condition_evaluator.py
│   ├── decision_resolver.py
│   └── recommender.py
│
├── schemas/
│   └── policy_schema.py
│
├── policies/
│   └── cost/
│       ├── basic_budget.yaml
│       └── strict_budget.yaml
│
├── context/
│   └── terraform_parser.py
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