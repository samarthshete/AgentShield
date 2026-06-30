# AgentShield — Future Implementation Strategy

> Founder + engineering strategy grounded in the actual codebase (read 2026-06-24).
> Companions: [FEATURE_PRIORITIZATION.md](./FEATURE_PRIORITIZATION.md),
> [TECH_STACK_UPGRADE_ANALYSIS.md](./TECH_STACK_UPGRADE_ANALYSIS.md),
> [V2_ARCHITECTURE_PROPOSAL.md](./V2_ARCHITECTURE_PROPOSAL.md),
> [IMMEDIATE_BUILD_PLAN.md](./IMMEDIATE_BUILD_PLAN.md).

---

## 0. What the project is, vs what it's trying to become

- **Is today:** a clean, well-tested (103 backend tests) **substring/regex scanner** for
  MCP/agent configs, with a benchmark harness, scripted dynamic simulation, optional LLM
  judges, SQLite history, a CLI, a thin FastAPI API, and a React console. Local-only.
- **Trying to become:** the **"Semgrep/Snyk for the agent trust boundary"** — a
  precision-validated, CI-native security gate that MCP server authors and agent-platform
  teams run on every PR.
- **The gap between the two is one thing:** *detection credibility*. The architecture is
  already good; the **detection method (literal string matching) and the absence of any
  independent accuracy measurement** are what currently keep it in "impressive student
  project" territory rather than "real product / senior-engineer signal."

Everything below optimizes for closing that gap **first**, then layering production +
cloud + AI-infra depth on top — because depth on top of an unvalidated detector is
résumé padding, not value.

---

## 1. Founder lens (brutally honest)

### What real problem does it solve?
A genuine, under-tooled one: **malicious or over-privileged content hidden in MCP tool
descriptions, prompt templates, and tool responses** (tool poisoning, indirect prompt
injection, unsafe permissions, exfiltration, task drift — the 5 categories in
`agentshield/rules/`). Generic SAST (Semgrep/Bandit/CodeQL) does **not** model these.

### Is the current product idea strong enough?
**The idea is strong. The current execution of the idea is not yet differentiated.**
The detection is `if marker in text.lower()` (see `rules/suspicious_patterns.py:16`,
`rules/exfiltration_checks.py:65`). That is trivially evaded by paraphrase and noisy on
prose — the project's own Phase 7 work shows noise concentrated in README text. A buyer
or a senior reviewer will immediately ask: *"How is this better than grep with a
wordlist?"* Right now there is no answer backed by data.

### Sharpest positioning (rewrite of the value prop)
> **"AgentShield is the CI security gate for MCP servers and tool-using agents. It catches
> tool-poisoning and indirect prompt injection that code scanners miss — and unlike a
> regex linter, it understands intent, with published precision/recall on a real-world
> corpus."**

The two clauses in bold ("understands intent" + "published precision/recall") are the
two things the codebase **doesn't have yet**. Building them is the entire strategy.

### Ideal user (narrow it)
**MCP server authors and agent-platform engineers who already use CI.** Not "all AI
developers." The wedge is: *you're about to publish an MCP server → one command / one
GitHub check tells you if a tool description is weaponizable.* This user already has
`scan.yml`-style habits and feels the pain acutely.

### Which pain point first?
**Tool poisoning + indirect prompt injection** (categories `SP-001`, `OV-001/002`,
`POLDYN-002/003`). They are the most agent-specific, the least covered by existing tools,
and the most viscerally scary in a demo ("this innocent-looking tool description exfils
your SSH key"). Lead with these two; treat permissions/exfil/drift as supporting.

### What's unnecessary or distracting right now?
- **The 6-page React console** is broad but low-leverage for the core value prop. It's a
  good portfolio artifact; it is **not** what makes the product credible. Don't expand it
  before detection is validated.
- **Chasing more rules / more categories.** The rule set is frozen for good reason
  (`DECISIONS.md` D16). More substring rules = more noise, not more value.
- **The Claude judge polish** (only failure-path validated) — fine as-is; don't invest
  more until there's a measured reason.

### What makes it different from existing products?
Only one thing will, durably: **measured detection quality on agent-specific threats via a
hybrid rules+semantic engine.** Packaging (CLI+CI+console) is table stakes that competitors
can copy in a week. A validated hybrid detector + a public benchmark is defensible.

### What makes someone say "this is not just a student project"?
1. A **published precision/recall/F1 number** on an independent labeled corpus. Today:
   measured on 50 labeled artifacts, but still mixed with authored challenge fixtures.
2. A **hybrid detector** where rules are a cheap pre-filter and an LLM/embedding stage
   confirms intent — with a measured reduction in false positives over rules-only.
3. A **deployed, authenticated, observable** scan service (Docker + auth + OpenTelemetry),
   not just `python -m agentshield`.

### What should the MVP prove?
**That AgentShield detects real tool-poisoning/injection in real artifacts at a defensible
precision/recall, better than a rules-only baseline.** That single proof unlocks the
pitch, the résumé bullet, and the interview story.

### What should it deliberately NOT do yet?
- No multi-tenant SaaS, billing, or org management.
- No Kafka/EKS/SageMaker (see [TECH_STACK_UPGRADE_ANALYSIS.md](./TECH_STACK_UPGRADE_ANALYSIS.md)).
- No new threat categories or new UI pages.
- No real-time runtime guardrail product (that's a different, bigger company).

---

## 2. Hiring-manager lens (signal audit)

> No invented metrics. Where a signal needs a number that doesn't exist, it's marked
> **Not measured yet** with the test that would produce it.

### Strong signals already present
- **Test discipline:** 103 passing tests, layered by concern (`tests/`). Reads senior.
- **Clean seams:** pure-function rules reused by the policy engine (`policy_engine.py:115`);
  pluggable `BaseJudge` (`llm_judge.py`); thin API over shared core (`web/app.py`). These
  are real architecture decisions a senior reviewer respects.
- **Dogfooding in CI:** `scan.yml` runs the product on itself, uploads artifacts, comments
  on PRs, gates on severity. Strong "I think in CI/CD" signal.
- **Honest engineering judgment:** stdlib-first, evidence-gated rule freeze, documented
  limitations. Maturity signal.

### Weak signals
- **Detection is naive** — a senior will spot `if marker in text.lower()` in 30 seconds and
  discount the "security" framing unless intent-aware detection exists.
- **No measured accuracy** — "100% on 9 self-authored cases" is a negative signal to anyone
  who notices the cases were written with the rules.
- **No deployment / auth / observability** — reads as "local script," not "service."
- **Zero frontend tests** — undercuts the otherwise-strong test story.
- **No cloud footprint** — nothing for a cloud/platform recruiter to grab onto.

### What looks production-grade vs toy
| Production-grade | Toy |
|---|---|
| Layered services, typed models, CI gates | Substring detection as the core IP |
| Exit-code contract, additive migrations | Single SQLite file, no FKs/indexes |
| Pluggable judge abstraction | Hand-rolled, duplicated LLM HTTP |
| Labeled eval harness + 50-artifact baseline | No auth, `CORS *`, public-only corpus still too small |

### Résumé bullets these features would create (after they're built + measured)
- *"Designed a hybrid rules+LLM detection engine for AI-agent/MCP security; reduced
  false-positive rate from **X→Y** on a 100-artifact labeled corpus (precision **P**,
  recall **R**, F1 **F**)."* — requires hybrid detector and a larger corpus.
- *"Shipped a containerized, authenticated FastAPI scan service with OpenTelemetry tracing
  of the scan pipeline and LLM calls; p95 scan latency **N ms**."* — **Not measured yet**.
- *"Built a GitHub App that scans MCP servers on every PR and posts severity-gated inline
  findings."*

### Interview talking points it would create
- "Why hybrid instead of pure-LLM or pure-rules?" → cost/latency/precision trade-off, with
  your measured numbers.
- "How did you avoid validating your detector against its own test set?" → independent
  labeled corpus design.
- "Walk me through a request from PR to finding." → the lifecycle in
  [V2_ARCHITECTURE_PROPOSAL.md](./V2_ARCHITECTURE_PROPOSAL.md).

### Architectural decisions that would impress a senior
- A **conditional triage pipeline** that routes only *ambiguous* findings to the LLM stage
  (cost-aware), measured by `llm_routing_rate` (today hardcoded `0.0` in
  `metrics/aggregator.py:129` — make it real).
- **Idempotent, cached** semantic verdicts keyed by content hash (don't re-pay for the
  same tool description).
- **Schema-versioned** persistence with real constraints.

---

## 3. Strategy in one paragraph

Freeze breadth. Spend the next cycle making the **detector credible and measured**
(labeled corpus + hybrid rules+semantic engine + real precision/recall), then make it
**deployable and observable** (Docker + auth + OpenTelemetry + structured logging), then —
and only then — add **one advanced differentiator** (a GitHub App or an autonomous
multi-step "attack-path" analyzer worth a LangGraph). Add cloud/AI-infra (Lambda, S3,
Terraform, Prometheus) **only** along the hosting path, justified per
[TECH_STACK_UPGRADE_ANALYSIS.md](./TECH_STACK_UPGRADE_ANALYSIS.md) — never for decoration.

See [IMMEDIATE_BUILD_PLAN.md](./IMMEDIATE_BUILD_PLAN.md) for the top-3 step-by-step, and
[ROADMAP.md](./ROADMAP.md) for the full phased plan.
