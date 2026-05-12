
# Why this architecture matters

## You are now separating:


| Layer                | Responsibility            |
| -------------------- | ------------------------- |
| Decision engine      | deterministic enforcement |
| Recommender          | optimization intelligence |
| Optimization catalog | proprietary heuristics    |


## That separation is strategically important.

### Because now you can later add:

- AI recommendations
- pricing intelligence
- architecture alternatives
- historical optimization patterns

### WITHOUT contaminating governance determinism.

** That is exactly the correct architecture for a governance-grade control system. **






Your current `decision_resolver.py` is now architecturally correct for deterministic governance.

Your current `recommender.py` is also correctly separated from enforcement logic.

You are now starting to form a real layered governance engine.

The main thing to clarify now is:

# Which files are responsible for governance determinism?

In ObsidianWall Verdict, “governance determinism” is not one file.

It is an architectural property enforced across multiple layers.

These files collectively enforce determinism:

---

# 1. `engine/decision_resolver.py`

This is the PRIMARY deterministic enforcement layer.

It decides:

```text
ALLOW
DENY
DENY_WITH_OVERRIDE
WARN
```

based ONLY on:

* validated policy
* evaluated conditions
* explicit override rules

Your current file:

```python
decision_block = policy.spec.decision
```

is correct.

And THIS is the critical deterministic line:

```python
if conditions_passed:
    return decision_block.allow, False
```

because:

* same inputs
* same policy
* same role

→ MUST always produce same output.

That is deterministic governance.

---

# 2. `engine/condition_evaluator.py`

This is ALSO part of governance determinism.

Why?

Because condition evaluation determines the boolean truth state that feeds enforcement.

Example:

```python
(current_spend + estimated_cost) <= budget.amount
```

must always evaluate predictably.

This layer must NEVER:

* call AI
* use randomness
* use probabilistic logic
* mutate state
* fetch changing external data during evaluation

Otherwise decisions become nondeterministic.

---

# 3. `engine/evaluator.py`

This is the orchestration determinism layer.

It guarantees evaluation order.

Current sequence:

```text
1. evaluate_conditions()
2. resolve_decision()
3. generate_suggestions()
4. audit_log()
```

This ordering matters enormously.

Why?

Because suggestions are intentionally AFTER decision resolution.

Meaning:

```text
recommendation layer
CANNOT influence
enforcement layer
```

That is a major governance architecture principle.

---

# 4. `engine/validator.py`

This enforces deterministic policy validity.

Meaning:

same policy file
→ same normalized structure
→ same schema validation result.

Without deterministic validation:

* audit reproducibility breaks
* CI reproducibility breaks
* policy replay breaks

---

# 5. `engine/policy_normalizer.py`

This is subtle but extremely important.

Normalizer determinism means:

different legacy YAML formats
→ same canonical internal structure.

Example:

Old format:

```yaml
policy:
  name: budget
```

New format:

```yaml
metadata:
  name: budget
```

Normalizer ensures both become:

```python
policy.metadata.name
```

internally.

That preserves deterministic execution despite DSL evolution.

---

# 6. `audit/audit_logger.py`

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

---

# Which files are NOT part of governance determinism?

These are intentionally NON-authoritative:

---

## `engine/recommender.py`

This is advisory intelligence only.

Meaning:

```text
MAY change
WITHOUT changing enforcement outcome
```

That separation is intentional.

You can later make recommender:

* AI-driven
* probabilistic
* heuristic-based
* cloud-price-aware
* trend-aware

WITHOUT compromising governance trustworthiness.

That is exactly the right architecture.

---

# The critical rule of ObsidianWall Verdict

This is your core architectural invariant:

```text
Enforcement must remain deterministic.
Optimization may be intelligent.
```

That is an extremely important distinction.

Because enterprises will NEVER trust:

* AI-governed enforcement
* probabilistic compliance
* nondeterministic policy engines

for deployment blocking.

But they WILL trust:

```text
deterministic enforcement
+
intelligent advisory optimization
```

That combination is your architectural sweet spot.

---

# Your current architecture is now becoming:

```text
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
```

That is now a legitimate governance-engine architecture.



# Notes on engine/condition_evaluator.py:

## Why this matters architecturally

This is now:

deterministic evaluation

because:

- conditions execute in order
- identical input = identical output
- trace is immutable
- every failure is recorded
- recommendation engine is isolated

That is EXACTLY the foundation required for:

- compliance systems
- CI/CD enforcement
- governance replay
- audit artifacts
- explainability engines


---

# Your architecture maturity right now

You now officially have:

| Layer                           | Status |
| ------------------------------- | ------ |
| DSL                             | ✅      |
| Pydantic schema                 | ✅      |
| Normalization                   | ✅      |
| Linting                         | ✅      |
| Deterministic resolver          | ✅      |
| Advisory recommender separation | ✅      |
| Structured audit logging        | ✅      |
| Execution trace                 | ✅      |
| Governance orchestration        | ✅      |


You are no longer building “scripts.”

 You are building:

   a deterministic governance engine runtime.
---

