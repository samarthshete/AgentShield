# AgentShield — Project Master Document

> Single source of truth for what AgentShield is, why it exists, how it is built,
> and where it stands. Written from a direct read of the codebase on 2026-06-24.
> Companion docs: [ARCHITECTURE.md](./ARCHITECTURE.md), [PRODUCT.md](./PRODUCT.md),
> [TECH_STACK.md](./TECH_STACK.md), [IMPLEMENTATION_STATUS.md](./IMPLEMENTATION_STATUS.md),
> [DECISIONS.md](./DECISIONS.md), [ROADMAP.md](./ROADMAP.md),
> [METRICS_AND_OUTCOMES.md](./METRICS_AND_OUTCOMES.md),
> [ONBOARDING_FOR_AI_AGENTS.md](./ONBOARDING_FOR_AI_AGENTS.md).

---

## 1. Project name

**AgentShield** (`agentshield`, version `0.1.0`, see `pyproject.toml`).

## 2. One-line description

A local-first security evaluation framework that scans tool-using AI agent and
MCP (Model Context Protocol) configurations for risky patterns, runs deterministic
attack simulations, benchmarks its own detection quality, and emits JSON/Markdown
reports plus a SQLite history — all from a Python CLI, a thin FastAPI API, and a
React console.

## 3. Product vision

Make agent/MCP security **inspectable, testable, reproducible, and reportable**
(the four goals stated verbatim in `PROJECT.md` §2). The long-term vision is to be
the "linter + test harness for agent trust boundaries" — the thing a developer runs
in CI before shipping an MCP server or a tool-using agent, the same way they run
`ruff`, `bandit`, or `npm audit` today.

## 4. Problem being solved

Tool-using agents and MCP servers introduce a new, poorly-tooled attack surface:

- **Tool poisoning** — hidden imperative instructions buried in a tool's `description`.
- **Indirect prompt injection** — override/jailbreak text arriving through fetched
  documents or tool responses.
- **Unsafe permissions** — tools granted filesystem + network + shell at once.
- **Data exfiltration patterns** — config text that forwards API keys/secrets to
  external endpoints.
- **Task drift** — context-spoofing content that silently redirects the agent's goal.

These are the five categories AgentShield detects (`README.md`, `agentshield/rules/`).
Today most teams have **no automated, CI-friendly check** for any of them.

## 5. Why this problem matters

Every one of these is exploitable without the user ever seeing malicious text: the
payload lives in a tool manifest, a returned document, or a server config — not in
the user's prompt. As agents gain filesystem/network/shell access, a single poisoned
tool description can exfiltrate secrets or run commands. The cost of a missed issue is
high; the cost of a fast static check is near zero. AgentShield targets that gap.

## 6. Target users

| Persona | Need AgentShield serves |
|---|---|
| MCP server authors | Pre-publish lint of tool/resource/prompt text |
| Agent platform / app developers | CI gate that fails PRs introducing unsafe config |
| Security / AppSec reviewers | Reproducible reports + severity scoring for triage |
| The project author (resume/portfolio) | A credible, end-to-end security engineering artifact |

See [PRODUCT.md](./PRODUCT.md) for full personas and JTBD.

## 7. Main user workflows

1. **Static scan** — `agentshield scan <path>` → parses configs, runs 11 rules,
   scores severity, writes `findings.json` + `findings.md`, persists to SQLite, exits
   non-zero on high/critical. (`agentshield/cli.py:45`, `services/scan_service.py`).
2. **Benchmark** — `agentshield benchmark benchmarks/cases` → runs YAML test cases
   against the scanner and reports pass rate. (`cli.py:105`, `benchmarks/runner.py`).
3. **Dynamic simulation** — `agentshield simulate` → replays scripted attack traces
   through a policy engine, optionally filtered by an LLM judge. (`cli.py:182`,
   `dynamic/`, `policy/policy_engine.py`).
4. **Metrics** — `agentshield metrics` → runs scan+benchmark+simulation and writes
   `metrics.json` + `PROJECT_METRICS.md`. (`cli.py:338`, `metrics/aggregator.py`).
5. **Web console** — FastAPI (`agentshield/web/app.py`) + React app (`web/`) expose
   the same operations through a browser at `/dashboard`, `/static-scan`,
   `/dynamic-simulation`, `/benchmarks`, `/metrics`, `/run-history`.

## 8. Initial idea and how the project evolved

The original scope (`PROJECT.md`, `DECISIONS.md`) was deliberately narrow: a
**static, CLI-first, local-first scanner** with no LLM dependency, no dashboard, no
cloud. It then expanded phase by phase (the phase log lives in the gitignored
`CURRENT_STATE.md` and root `DECISIONS.md`):

- Phase 0 — Setup
- Phase 1 — Static scanner (parser + 11 rules + severity + JSON/MD + SQLite)
- Phase 2 — Benchmark harness (9 YAML cases, 100% pass)
- Phase 3 — Dynamic simulation (5 scripted scenarios + policy engine)
- Phase 4 — CI integration (two GitHub Actions workflows)
- Phase 5 — Metrics instrumentation
- Phase 6 — LLM evaluation layer (rule-based default; OpenAI + Claude judges)
- Phase 7 — Real-world validation on 29 public artifacts; two narrow rule-tuning
  passes (`EXF-003`, `PERM-003`); rule set then **frozen**.
- Phases F1–F9 — Thin FastAPI API + full React/TypeScript console.

Notably, several things originally declared **out of scope** (dashboard, dynamic
simulation, GitHub Action) were later pulled **in** scope by explicit decision.
`PROJECT.md` has been updated to distinguish the original Phase 1 scope from the
features that shipped later.

## 9. Current state of the project

**Working, tested, single-developer release at v0.1.0.** Verified on 2026-06-24:

- `pytest` → **103 passed** in ~2.7s.
- 5 CLI commands functional; FastAPI app imports and serves 8 endpoints.
- React console builds and wires all 6 pages to live endpoints.
- 11 static rules across 5 categories; benchmark suite passes 9/9.
- Phase 7 validation artifacts and results are committed under
  `benchmarks/phase7_public_artifacts/` and `docs/phase7/`.

**Caveats:** detection is pure substring/regex matching (no semantics); the "dynamic
simulation" replays project-authored scripts rather than real agents; there are no
frontend tests; the API has no auth. See [IMPLEMENTATION_STATUS.md](./IMPLEMENTATION_STATUS.md).

## 10. Final intended product

A drop-in agent-security gate: `pip install agentshield`, point it at an MCP server
or agent repo, get a severity-scored report in CI, and optionally open a local console
to inspect history. Detection quality is the differentiator — so the credible end
state pairs the fast static rules with a calibrated LLM-judge layer that suppresses
false positives, all validated against a growing public corpus.

## 11. Core features

- Config discovery + parsing (JSON / YAML / TOML / Markdown / raw text) →
  `parser/discovery.py`, `parser/mcp_parser.py`.
- MCP surface normalization (tools / resources / prompts) → `models/mcp_surface.py`.
- 11 static rules in 5 categories → `agentshield/rules/`.
- Deterministic severity scoring + 0–100 risk score → `reporting/severity.py`.
- JSON + Markdown reports + PR-comment generator → `reporting/`.
- SQLite persistence with auto-migrating schema → `storage/sqlite_store.py`.
- YAML benchmark harness with pass/fail gating → `benchmarks/`.
- Scripted dynamic attack simulation + policy engine → `dynamic/`, `policy/`.
- Pluggable LLM judges (rule-based default, OpenAI, Claude) → `dynamic/llm_judge.py`.
- Metrics aggregation → `metrics/`.
- Two GitHub Actions workflows (lint/test + security scan) → `.github/workflows/`.
- FastAPI API + React/TypeScript console → `agentshield/web/`, `web/`.

## 12. MVP scope (delivered)

CLI static scan + parsing + 11 rules + severity + JSON/MD reports + SQLite +
benchmark format. This is exactly the Phase 1 success criteria in `PROJECT.md` §14,
all of which are met.

## 13. Non-MVP / future scope

- Semantic / embedding-based detection to cut false positives and resist paraphrase
  evasion (current rules are trivially bypassed by rewording — see §19).
- Real agent-trace ingestion (replace or supplement scripted simulation).
- Per-finding (not per-`policy_id`) LLM dismissal.
- AuthN/Z + multi-tenant story if the web console is ever hosted.
- Postgres / object storage if persistence outgrows local SQLite.
- Frontend test suite; packaged/published distribution; pre-commit hook.

## 14. Full technical architecture

CLI / API / React → Scan orchestrator → Parser → Rule engine → Severity scorer →
Reports + SQLite. Dynamic path: Attack generator → Runtime simulator → Policy engine
→ Judge → Reports + SQLite. Full diagram and request lifecycle in
[ARCHITECTURE.md](./ARCHITECTURE.md).

## 15. Frontend architecture

React 18 + TypeScript + Vite + Tailwind (`web/`). `App.tsx` defines 6 routes under a
shared `AppShell`. Pages call a thin fetch wrapper (`web/src/lib/api.ts`) against
`VITE_API_BASE_URL` (default `http://127.0.0.1:8000`). Shared primitives:
`Card`, `Badge`, `LoadingState`, `ErrorState`, `EmptyState`, `PageContainer`. No
client state library, no data-fetching cache, no tests. Card/table UI only (no charts,
by decision).

## 16. Backend architecture

Python 3.11+. Pure-function service layer (`services/scan_service.py`) orchestrates
parser + rules. Pydantic v2 models everywhere (`models/`). FastAPI app
(`agentshield/web/app.py`) is an explicitly **thin** wrapper that calls the same
internal functions the CLI uses — no business logic in the web layer. No background
jobs, no async work; every request runs the scan synchronously.

## 17. Database / data model

SQLite, single file (default `./agentshield.db`). Tables (`storage/sqlite_store.py`):

- `scan_runs` — one row per static scan (risk score, counts, timing).
- `findings` — static findings, FK `scan_run_id` (not enforced as a real FK).
- `scanned_targets` — files seen in a scan.
- `dynamic_scan_runs` — one row per simulated scenario (judge metadata, counts).
- `policy_violations` — dynamic violations with `status` confirmed/dismissed.

Schema self-migrates via `_ensure_columns()` (additive `ALTER TABLE` only).
`JudgeVerdict.notes` is **not** persisted (known limitation). Relationships are by
convention only — no `FOREIGN KEY` constraints are declared (PRAGMA is set but no FK
columns are defined).

## 18. API design

REST-ish, all under `/api`, no versioning, no auth, `CORS allow_origins=["*"]`
(`agentshield/web/app.py:52`):

`GET /api/health` · `POST /api/scan` · `POST /api/benchmark` · `POST /api/simulate` ·
`GET /api/metrics` · `GET /api/history/scans` · `GET /api/history/dynamic` ·
`GET /api/runs/{run_id}`. Request/response shapes are Pydantic models in
`agentshield/web/schemas.py`. Errors use proper HTTP codes (404/400/502).

## 19. Auth / session flow

**Not found in current codebase.** There is no authentication, authorization, session,
or user model anywhere — CLI, API, or frontend. The API is open and CORS is fully
permissive. This is acceptable for the stated local-first scope but is a hard blocker
for any hosted deployment. LLM API keys (`CLAUDE_API_KEY`, `OPENAI_API_KEY`) are read
from `.env` via `config.py`; they are credentials for outbound calls, not user auth.

## 20. Agent / AI / LLM flow

LLM use is **optional and only in the dynamic-judge layer**. Default
(`RuleBasedJudge`) confirms all policy-engine violations with **zero** external calls.
When `--judge openai|claude` is selected, the judge POSTs the trace + raw violations
to the provider and parses a strict-JSON `{"dismiss_policy_ids": [...], "notes": "..."}`
response (`dynamic/llm_judge.py`). Both providers share a fail-fast error contract
(`OpenAIJudgeError` / `ClaudeJudgeError`, CLI exit code 2). The "dynamic simulator"
itself uses **no LLM** — it replays scripted `AttackPayload`s (`dynamic/attack_generator.py`,
`dynamic/runtime_simulator.py`). Per project decision, the latest Claude models should
be the default if/when AI features are expanded.

## 21. External services used

- **OpenAI Chat Completions API** (`/v1/chat/completions`) — optional judge.
- **Anthropic Messages API** (`/v1/messages`) — optional judge.
- **GitHub Actions** — CI/CD (`.github/workflows/`).

No telemetry, analytics, cloud storage, or third-party SaaS. Calls use the stdlib
`urllib` directly (no SDK dependency).

## 22. Deployment architecture

**Local development only.** No Dockerfile, no Kubernetes/Vercel/Supabase/AWS config,
no published package. "Deployment" today means: `pip install -e .` for the CLI;
`uvicorn agentshield.web.app:app` for the API; `npm run dev`/`npm run build` for the
frontend. The only shipped automation is the two GitHub Actions workflows. See
[ROADMAP.md](./ROADMAP.md) Phase 2 for the production-readiness gap.

## 23. Security considerations

- **Strength:** no `eval`/`exec`/shell-out on scanned content; scanning is read-only
  string matching, so scanning a malicious file is itself safe.
- **Secret hygiene:** `.env` is ignored locally and `git log -- .env` shows no committed
  secret history. Keep real credentials untracked and only commit `.env.example`.
- **Gap — open API:** no auth, `CORS *`. Fine locally, unsafe if exposed.
- **Note:** LLM judges send trace text (project fixtures today) to third parties when
  enabled — document this before scanning sensitive real configs with a cloud judge.

## 24. Performance considerations

Scanning is O(text length × markers) substring matching — sub-millisecond per file
(benchmark `avg_scan_time_ms` ≈ 0.11 in `reports/metrics.json`). Bottleneck is I/O and,
for cloud judges, network latency. Everything is synchronous; a large directory scan
is single-threaded but trivially fast given the workload.

## 25. Scalability considerations

Designed for single-user local runs. SQLite + synchronous FastAPI + no job queue means
the web layer won't handle concurrent heavy use. This is by explicit decision
(`DECISIONS.md`) and is fine for the current scope; horizontal scale would require
Postgres, async workers, and auth (out of scope today).

## 26. Accessibility considerations

Partial. `LoadingState` has status semantics and the F9 pass normalized responsive
layout (`CURRENT_STATE.md`), but there is no audit, no automated a11y tests, and no
documented keyboard/contrast/ARIA coverage. Treat as **Not formally measured yet**.

## 27. SEO / agent-readability considerations

SEO is N/A (local tool, no public site). **Agent-readability is strong:** thorough
Markdown docs, machine-readable JSON outputs, a stable CLI exit-code contract
(0/1/2), and this doc set. See [ONBOARDING_FOR_AI_AGENTS.md](./ONBOARDING_FOR_AI_AGENTS.md).

## 28. Known limitations

(from `CURRENT_STATE.md` plus this review)

- Static checks are pattern matching; **no semantic intent understanding** — trivially
  evaded by paraphrasing or obfuscation, and prone to false positives in prose.
- Dynamic scenarios are **scripted by the project itself** — simulation validates the
  policy engine against its own fixtures, not real agent behavior.
- Directory discovery only finds `.json/.yaml/.yml/.toml/.md`; **source files (`.py`,
  `.ts`) are only scanned when passed as an explicit single file path**
  (`parser/discovery.py:27`).
- LLM-judge dismissal is by `policy_id`, so repeated IDs are dismissed as a group.
- `JudgeVerdict.notes` are not persisted.
- Live Claude path validated only on failure responses, never a successful dismissal.
- No frontend tests; no auth; local-only deployment.

## 29. Risks

- **Detection credibility risk:** substring rules produce false positives/negatives;
  the project's own Phase 7 work shows noise concentrated in README prose. Without
  semantic detection, real-world precision is uncertain.
- **Validation-circularity risk:** benchmarks and dynamic sims are authored alongside
  the rules they test, so green results overstate real-world accuracy. The labeled eval
  corpus reduces this risk but still mixes public artifacts with authored challenge cases.
- **Secret-leak risk:** always verify real credentials remain untracked (see §23).
- **Bus-factor risk:** single author, large amount of context in gitignored docs.

## 30. Open questions

- Should detection move to embeddings/LLM-primary, or stay rules-first for speed/CI?
- How does precision/recall change as the public-only labeled corpus grows beyond the current 50-artifact mixed corpus?
- Will the web console be hosted? If so, auth + Postgres become mandatory.
- How much does source-file directory scanning change findings volume on larger repos?
- Is per-finding LLM dismissal worth the added complexity?

## 31. Final outcome and expected impact

AgentShield is a **complete, working, well-documented v0.1 security framework** that
covers the full lifecycle (scan → benchmark → simulate → report → CI → UI) for a real
and under-tooled problem. As a portfolio/credibility artifact it is strong: breadth,
test discipline, and honest self-assessment. As a production security tool its impact
is currently bounded by detection naïveté; the path to real impact runs through
semantic detection and independent validation (see [ROADMAP.md](./ROADMAP.md)).
</invoke>
