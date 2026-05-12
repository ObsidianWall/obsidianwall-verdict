# ObsidianWall Platform Architecture
**Version:** 0.2 — Platform Design Document  
**Status:** Working Draft  
**Classification:** Internal — Founder

---

## 1. Platform Philosophy

ObsidianWall is an **AI-native deterministic governance and decision intelligence platform** composed of specialized executables. This distinction is foundational and must never be diluted:

ObsidianWall is not a static governance platform with AI features bolted on. It is a platform where AI is designed into the architecture from day one — with a hard, non-negotiable boundary between what AI is permitted to do and what only the deterministic engine is permitted to do.

Most AI governance vendors are making a critical architectural mistake: blending probabilistic AI reasoning with enforcement authority. Enterprises, auditors, compliance teams, and CISOs cannot trust governance systems that may behave differently on the same input. ObsidianWall's architecture solves this by design.

The platform is organized around **two distinct operational planes:**

| Plane | Authority | Nature |
|-------|-----------|--------|
| Deterministic Governance Plane | Enforcement | Authoritative, reproducible, auditable |
| Probabilistic Intelligence Plane | Advisory | Intelligent, contextual, AI-powered |

These planes are permanently separate. One enforces. One advises. They never swap roles.

---

## 2. Core Architectural Principles

These principles are non-negotiable. Every design decision must be consistent with them.

**P1 — The enforcement runtime must not depend on cloud connectivity.**  
Governance decisions are made locally, inside the customer's pipeline. No phone-home required for enforcement. This is a trust requirement for enterprise and regulated environments, not a feature.

**P2 — Every executable produces the same decision contract.**  
ALLOW, DENY, WARN, OVERRIDE_REQUIRED. Every domain, every executable, same envelope. This makes the platform coherent and all downstream consumers speak one language.

**P3 — Policy is code, stored in version control.**  
Policies are YAML/DSL files committed alongside infrastructure code. Git-native. Auditable. Diff-able. No GUI required for policy management at MVP.

**P4 — Enforcement is a gate, not a suggestion.**  
Exit codes are the enforcement mechanism. A DENY returns exit code 1. The pipeline fails. This is governance, not advice.

**P5 — Executables are thin domain layers over a thick shared core.**  
All governance logic lives in the Platform SDK. Executables contribute parsers, evaluators, and policy packs for their domain. They do not reimplement governance logic.

**P6 — The SaaS control plane is additive, never required.**  
Future cloud features enhance the platform. They never replace local execution. An air-gapped deployment must always be a valid operational mode.

**P7 — AI may advise. AI may NOT authoritatively govern.**  
This is the most important principle in the entire platform.

> *AI may advise. AI may explain. AI may optimize. AI may correlate. AI may recommend.*  
> *AI may NOT authoritatively govern.*

The Probabilistic Intelligence Plane feeds intelligence into the decision output. It does not make enforcement decisions. The Deterministic Governance Plane holds exclusive enforcement authority. This principle is what makes ObsidianWall enterprise-viable, compliance-safe, and auditor-trusted.

---

## 3. The Two-Plane Architecture

### Plane 1 — Deterministic Governance Plane

This is the enforcement authority. It is fully deterministic: the same inputs always produce the same outputs. It cannot hallucinate. It cannot improvise. It cannot be probabilistic.

It evaluates policy, resolves decisions, blocks deployments, produces audit traces, and remains fully explainable and reproducible. This plane is the foundation of enterprise trust and regulatory compliance.

**Outputs:** ALLOW, DENY, WARN, OVERRIDE_REQUIRED  
**Nature:** Authoritative  
**AI involvement:** None — AI never touches this plane's decision logic

### Plane 2 — Probabilistic Intelligence Plane

This is the AI advisory layer. It operates on the output of the Deterministic Governance Plane and enriches it with intelligence: recommendations, explanations, optimization suggestions, anomaly correlations, and contextual reasoning.

AI here makes the governance output smarter and more actionable. It never changes the enforcement decision itself.

**Outputs:** Suggestions, explanations, optimizations, correlations, reasoning  
**Nature:** Advisory  
**AI involvement:** Full — this plane is AI-powered by design

**The hard boundary:**  
The Intelligence Plane feeds into the Decision Envelope's `suggestions` and `reasoning` fields. It never writes to `decision`, `override_required`, or `trace`. Those fields belong exclusively to the Governance Plane.

---

## 4. Platform Layers

### Layer 1 — CLI & Dispatch (Go)

The `obsidianwall` binary. Single entry point for all platform interaction. Written in Go for single binary distribution with no runtime dependencies — critical for frictionless CI/CD adoption.

**Responsibilities:**
- Receive and parse CLI commands
- Maintain the executable registry
- Dispatch commands to the correct executable subprocess
- Manage CI/CD adapter logic (GitHub Actions, GitLab CI, Azure DevOps, Jenkins)
- Enforce and communicate exit codes to the CI/CD system

**CLI invocation pattern:**
```bash
obsidianwall verdict evaluate \
  --plan terraform.plan.json \
  --policy ./policies/cost.yaml \
  --output ./audit/
```

---

### Layer 2 — Executable Layer (Python)

Domain-specific modules. Verdict is the first. Each executable has its own parsers, evaluators, and policy packs — but calls the Platform SDK for all core governance logic.

**Directory structure:**
```
obsidianwall/
├── executables/
│   ├── verdict/          # Cost governance (active)
│   ├── shield/           # Security governance (planned)
│   ├── comply/           # Compliance governance (planned)
│   ├── sentinel/         # Identity governance (planned)
│   ├── blueprint/        # Architecture governance (planned)
│   └── axiom/            # AI governance (planned)
```

---

### Layer 3 — Deterministic Governance Plane (Python — Platform SDK)

The enforcement core. Shared across all executables. This is where the architectural moat lives.

**Decision Engine:** Deterministic evaluation of policy rules against input. Produces one of four decisions. No probabilistic behavior. Same input always produces same output.

**Policy DSL Runtime:** Interprets policy files. Manages rule parsing, condition evaluation, threshold comparison, and policy composition.

**Audit Engine:** Generates immutable decision artifacts on every evaluation. Every decision is stamped with a unique decision ID, timestamp, input hash, policy version, and full result.

**Override Governance:** Manages the lifecycle of override requests. All overrides are tracked, attributed, and auditable.

**Traceability Engine:** Produces structured trace artifacts showing exactly which rules fired, in what order, with what inputs. Designed for audit and debugging.

**Schema Contracts (Pydantic v2):** All data crossing layer boundaries is validated. No silent failures.

**Telemetry Collector:** Local-first metrics. Decision counts, policy performance, override patterns.

---

### Layer 4 — Probabilistic Intelligence Plane (Python — AI Layer)

The AI advisory layer. Operates after the governance decision is made. Enriches output with intelligence. Never alters enforcement decisions.

**Recommendation Engine:** Generates actionable remediation suggestions for every DENY or WARN. Domain-specific suggestions registered by each executable.

**Explainability Engine:** Converts trace artifacts into human-readable explanations. Answers "why was this deployment denied?" in plain language.

**Policy Assistant (Future):** AI-assisted policy authoring. Engineer describes intent in natural language; AI generates DSL. Human approves before activation.

**Optimization Engine (Future):** Architecture alternatives, cost reduction patterns, resource right-sizing heuristics. Becomes a proprietary intelligence corpus over time.

**Anomaly Correlation (Future):** Cross-executable intelligence. Correlates cost anomalies with security misconfigurations, IAM escalations, and deployment drift patterns. This is where platform-level AI becomes uniquely powerful.

**Context Reasoning (Future):** Historical deployment analysis, risk heuristics, deployment pattern recognition.

---

### Layer 5 — Decision Output Layer (Universal Contract)

Every executable produces the same decision envelope. This is the universal output contract of the platform. The `decision` field is always set by the Governance Plane. The `suggestions` field is always set by the Intelligence Plane.

```json
{
  "decision_id": "ow-vrd-20240115-a3f9b2c1",
  "executable": "verdict",
  "version": "0.1.0",
  "timestamp": "2024-01-15T14:23:11Z",
  "decision": "DENY",
  "reason": "Proposed infrastructure exceeds monthly budget threshold by 34%.",
  "policy_version": "cost-policy-v1.2.0",
  "input_hash": "sha256:e3b0c442...",
  "trace": [
    {
      "rule": "monthly_budget_limit",
      "input": { "estimated_monthly_cost": 1340.00, "budget_limit": 1000.00 },
      "result": "FAIL",
      "message": "Estimated cost $1,340/mo exceeds budget limit $1,000/mo"
    }
  ],
  "suggestions": [
    "Downsize db.r5.2xlarge to db.r5.xlarge — saves ~$280/mo",
    "Enable auto-scaling on ECS service to reduce idle capacity",
    "Move infrequently accessed S3 data to Glacier Instant Retrieval"
  ],
  "override_required": true,
  "override_approver": "platform-team",
  "immutable": true
}
```

**Exit code contract:**
| Exit Code | Decision | Meaning |
|-----------|----------|---------|
| 0 | ALLOW | Deployment permitted |
| 1 | DENY | Deployment blocked |
| 2 | WARN | Deployment permitted with advisory |
| 3 | OVERRIDE_REQUIRED | Deployment blocked pending approval |

---

### Layer 6 — Storage Layer (Local-First)

All enforcement storage is local-first. No cloud dependency.

**Decision Artifact Store:** Structured JSON files. One file per evaluation. Immutable after write.  
**Audit Log Store:** Append-only JSONL. Every decision, override, and policy load event recorded.  
**Policy Store:** YAML/DSL files in VCS. Git is the policy management system at MVP.  
**Future SaaS Control Plane:** Additive only. Centralized policy management, dashboards, multi-team analytics, approval workflows. Enforcement runtime remains fully functional without it.

---

## 5. Technology Decision Matrix

| Concern | Technology | Rationale |
|--------|-----------|-----------|
| CLI binary | Go | Single binary, no runtime deps, CI/CD native |
| Executable dispatch | Go | Fast subprocess orchestration |
| CI/CD adapters | Go | GitHub Actions compatibility, performance |
| Policy DSL runtime | Python | Rapid iteration, rich parsing ecosystem |
| Deterministic decision engine | Python | Domain logic complexity, testability |
| Schema contracts | Python / Pydantic v2 | Type safety, validation, serialization |
| Recommendation engine | Python | Extensibility, NLP-adjacent logic |
| Explainability engine | Python | LLM integration-ready |
| Optimization engine | Python | ML/data ecosystem |
| Anomaly correlation | Python | ML/data ecosystem |
| Audit artifacts | Python | Structured JSON generation |
| Future gRPC server | Go | Performance, concurrency, SaaS control plane |
| Future ML/intelligence | Python | Ecosystem dominance |

---

## 6. Executable Roadmap

| Executable | Domain | Status |
|-----------|--------|--------|
| Verdict | Cost governance | Active — MVP |
| Shield | Security governance | Planned |
| Comply | Compliance governance | Planned |
| Sentinel | Identity governance | Planned |
| Blueprint | Architecture governance | Planned |
| Axiom | AI governance | Planned |

All executables share the Platform SDK and AI Layer. Adding a new executable requires: a domain parser, a domain evaluator, domain policy packs, and domain-specific recommendations. All governance and intelligence logic is inherited.

---

## 7. Strategic Evolution Path

**Phase 1 — CLI-First Enforcement (Now)**  
Single binary. Terraform + GitHub Actions. Verdict only. Local-first. Prove the governance category. Establish the Deterministic Governance Plane.

**Phase 2 — Workflow Moat**  
Policy packs. Reusable governance templates. Override workflows. Teams operationalize around the DSL. Switching costs emerge. Intelligence Plane begins contributing optimization recommendations.

**Phase 3 — Organizational Knowledge Moat**  
Design partner DSL evolution. Multi-team budget hierarchies. Real-world edge cases embedded. The system absorbs organizational complexity that cannot be quickly replicated.

**Phase 4 — SaaS Control Plane**  
Centralized policy management. Governance dashboards. Multi-team analytics. Approval workflows. Enforcement runtime remains local — SaaS is additive.

**Phase 5 — Intelligence Moat**  
Anonymized governance pattern corpus. Optimization intelligence. Deployment risk heuristics. Cross-executable anomaly correlation. The platform becomes governance + decision intelligence — a category of one.

---

## 8. What ObsidianWall Is Not

- Not a cost dashboard
- Not a FinOps reporting tool
- Not a cloud billing analytics platform
- Not an AI assistant that can be ignored
- Not a probabilistic governance system

ObsidianWall is a **deterministic governance runtime with AI-native decision intelligence**. It decides. It enforces. It explains. It audits. AI makes it smarter. The deterministic core makes it trustworthy.

---

*Document version 0.2 — Subject to revision through design partner feedback*
