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
│   ├── post_create.sh
│   ├── Dockerfile
│   └── requirements.txt
|
├── cli/
│   ├── __init__.py
│   └── main.py
│
├── docs/
│   └── github_actions_example.yml
|
├── engine/
│   ├── analyzers/
|   │   ├── __init__.py
|   │   ├── architecure_analyzer.py
|   │   ├── cost_analyzer.py
|   │   ├── topology_analyzer.py
|   |   └── utilization_analyzer.py
│   ├── explainability/
|   │   ├── __init__.py
|   │   ├── explaination_builder.py
|   │   ├── governance_reasoning_chain.py
|   │   ├── policy_reasoning.py
|   │   ├── recommendation_explainer.py
|   |   └── trace_graph.py
│   ├── replay/
|   │   ├── __init__.py
|   │   ├── replay_engine.py
|   │   ├── replay_schema.py
|   |   └── simulation_engine.py
│   ├── workflows/
|   │   ├── __init__.py
|   │   ├── approval_resolver.py
|   |   └── notification_router.py
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
│   ├── orchestrator.py
│   ├── risk_scorer.py
│   └── recommender.py
│
├── schemas/
│   ├── __init__.py
│   └── policy_schema.py
|
├── scripts/
│   ├── __init__.py
│   └── parse_verdict_output.py
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
│   ├── unit/
|   │   ├── test_condition_evaluator.py
|   │   ├── test_policy_normalizer.py
|   │   ├── test_recommender.py
|   |   └── test_risk_scorer.py
│   ├── integration/
|   |   └── test_evaluator_pipeline.py
│   ├── test_engine.py
│   └── test_policy.py
│
├── .github/
|     └──workflows/
│            └── ci.yml
│
├── .dockerignore
├── .gitignore
├── Dockerfile
├── Makefile
├── action.yml
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

---

# Your current architecture is now becoming:

                ┌─────────────────────┐
                │   Policy DSL        │
                └──────────┬──────────┘
                           │
                ┌──────────▼──────────┐
                │ Policy Normalizer   │
                └──────────┬──────────┘
                           │
                ┌──────────▼──────────┐
                │   Validator Layer   │
                └──────────┬──────────┘
                           │
                ┌──────────▼──────────┐
                │ Condition Evaluator │
                └──────────┬──────────┘
                           │
                ┌──────────▼──────────┐
                │ Decision Resolver   │
                │ (Deterministic)     │
                └──────────┬──────────┘
                           │
              ┌────────────┴────────────┐
              │                         │
   ┌──────────▼──────────┐   ┌──────────▼──────────┐
   │ Recommendation Layer│   │ Structured Audit    │
   │ (Intelligent)       │   │ Logging             │
   └─────────────────────┘   └─────────────────────┘



## That is now a legitimate governance-engine architecture.

---