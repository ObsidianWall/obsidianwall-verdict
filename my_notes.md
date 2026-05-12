
Your current decision_resolver.py is now architecturally correct for deterministic governance.

Your current recommender.py is also correctly separated from enforcement logic.

You are now starting to form a real layered governance engine.

The main thing to clarify now is:

Which files are responsible for governance determinism?

In ObsidianWall Verdict, “governance determinism” is not one file.

It is an architectural property enforced across multiple layers.

These files collectively enforce determinism:

⸻

1. engine/decision_resolver.py

This is the PRIMARY deterministic enforcement layer.

It decides:

ALLOW
DENY
DENY_WITH_OVERRIDE
WARN

based ONLY on:

* validated policy
* evaluated conditions
* explicit override rules

Your current file:

decision_block = policy.spec.decision

is correct.

And THIS is the critical deterministic line:

if conditions_passed:
    return decision_block.allow, False

because:

* same inputs
* same policy
* same role

→ MUST always produce same output.

That is deterministic governance.

⸻

2. engine/condition_evaluator.py

This is ALSO part of governance determinism.

Why?

Because condition evaluation determines the boolean truth state that feeds enforcement.

Example:

(current_spend + estimated_cost) <= budget.amount

must always evaluate predictably.

This layer must NEVER:

* call AI
* use randomness
* use probabilistic logic
* mutate state
* fetch changing external data during evaluation

Otherwise decisions become nondeterministic.

⸻

3. engine/evaluator.py

This is the orchestration determinism layer.

It guarantees evaluation order.

Current sequence:

1. evaluate_conditions()
2. resolve_decision()
3. generate_suggestions()
4. audit_log()

This ordering matters enormously.

Why?

Because suggestions are intentionally AFTER decision resolution.

Meaning:

recommendation layer
CANNOT influence
enforcement layer

That is a major governance architecture principle.

⸻

4. engine/validator.py

This enforces deterministic policy validity.

Meaning:

same policy file
→ same normalized structure
→ same schema validation result.

Without deterministic validation:

* audit reproducibility breaks
* CI reproducibility breaks
* policy replay breaks

⸻

5. engine/policy_normalizer.py

This is subtle but extremely important.

Normalizer determinism means:

different legacy YAML formats
→ same canonical internal structure.

Example:

Old format:

policy:
  name: budget

New format:

metadata:
  name: budget

Normalizer ensures both become:

policy.metadata.name

internally.

That preserves deterministic execution despite DSL evolution.

⸻

6. audit/audit_logger.py

This preserves deterministic traceability.

Not deterministic DECISIONING itself.

But deterministic AUDIT REPRODUCTION.

Critical distinction.

It guarantees:

* immutable event order
* reproducible trace
* evidence chain
* timestamped decision artifacts

That matters for:

* compliance
* FinOps governance
* SOX
* SOC2
* ISO 27001
* internal audit

⸻

Which files are NOT part of governance determinism?

These are intentionally NON-authoritative:

⸻

engine/recommender.py

This is advisory intelligence only.

Meaning:

MAY change
WITHOUT changing enforcement outcome

That separation is intentional.

You can later make recommender:

* AI-driven
* probabilistic
* heuristic-based
* cloud-price-aware
* trend-aware

WITHOUT compromising governance trustworthiness.

That is exactly the right architecture.

⸻

The critical rule of ObsidianWall Verdict

This is your core architectural invariant:

Enforcement must remain deterministic.
Optimization may be intelligent.

That is an extremely important distinction.

Because enterprises will NEVER trust:

* AI-governed enforcement
* probabilistic compliance
* nondeterministic policy engines

for deployment blocking.

But they WILL trust:

deterministic enforcement
+
intelligent advisory optimization

That combination is your architectural sweet spot.

⸻

Your current architecture is now becoming:

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
   │ Recommendation Layer │   │ Structured Audit    │
   │ (Intelligent)        │   │ Logging             │
   └──────────────────────┘   └─────────────────────┘

That is now a legitimate governance-engine architecture.