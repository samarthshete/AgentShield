# AgentShield — Implementation Status

> Snapshot from a direct source read on 2026-07-09. Backend `pytest` → **136 passed**;
> frontend `vitest` → **12 passed**. Live on Render (API) + Vercel (web) — see
> [PROJECT_STATUS.md](./PROJECT_STATUS.md).
> "Done" = code exists, is wired, and is covered by tests or a working build.

---

## 1. Completed features

| Feature | Evidence | Tests |
|---|---|---|
| File discovery (config/docs/source files, skip vendor dirs) | `parser/discovery.py` | `test_discovery.py`, `test_mcp_parser.py` |
| Config parsing + MCP surface normalization + `permission_blob` | `parser/mcp_parser.py`, `models/mcp_surface.py` | `test_mcp_parser.py` |
| 11 static rules across 5 categories | `rules/*.py` | `test_rules.py` (12) |
| Severity rank + high/critical count + 0–100 risk score | `reporting/severity.py` | `test_reporting.py` |
| JSON + Markdown reports + PR-comment body | `reporting/json_report.py`, `markdown_report.py` | `test_reporting.py` |
| SQLite persistence + additive migrations + history reads | `storage/sqlite_store.py` | covered via web/exit tests |
| `agentshield scan` w/ format, output, fail-on, db-path, verbose | `cli.py:45` | `test_exit_codes.py` (8) |
| Benchmark harness (load + run + gate) | `benchmarks/loader.py`, `runner.py` | `test_benchmark_*` (8) |
| 9 benchmark cases, 100% pass | `benchmarks/cases/*.yaml`, `reports/metrics.json` | yes |
| Labeled eval harness (P/R/F1 scorer + CLI) | `eval/scorer.py`, `benchmarks/labeled/*.labels.yaml` | `test_eval.py` (9), CI eval step |
| Dynamic simulation (5 scripted scenarios + policy engine) | `dynamic/`, `policy/policy_engine.py` | `test_dynamic.py` (48) |
| LLM judges: rule-based default + OpenAI + Claude | `dynamic/llm_judge.py` | `test_dynamic.py` |
| Metrics aggregation + rule registry + MD writer | `metrics/*.py` | `test_metrics.py` (17) |
| CI workflows (lint/test + self-scan gate + PR comment) | `.github/workflows/*.yml` | n/a (CI) |
| FastAPI API (8 endpoints) + token auth + config-driven CORS + inline-content scan | `web/app.py`, `web/schemas.py` | `test_web_api.py` |
| **Semantic confirmer** (context-aware confirm/dismiss/uncertain over rule candidates, recall-safe) | `agentshield/detect/semantic.py` | `test_semantic.py` |
| Self-serve scanning: scan pasted config content (no server path) | `services/scan_service.py` (`run_static_scan_on_text`), `web/src/pages/StaticScanPage.tsx` | `test_web_api.py`, `test_semantic.py` |
| Honest dashboard hero: labeled-eval F1/precision/recall + Wilson CI | `web/src/pages/DashboardPage.tsx`, `metrics/aggregator.py` | build |
| Light/dark theme toggle (token-driven, localStorage, system default) | `web/src/lib/theme.ts`, `components/ui/ThemeToggle.tsx` | `theme.test.ts` |
| React console (7 pages incl. Settings, live-wired, builds clean) | `web/src/**` | `lib/*.test.ts` (7) |
| **LLM confirmation tier** (optional, flag OFF): escalates only HIGH/CRITICAL `uncertain` candidates; injection-hardened, fail-safe, budget-capped, severity + confidence recall guardrails; **measured on the labeled corpus** (`gpt-4o-mini` does not beat the deterministic baseline — see [METRICS_AND_OUTCOMES.md](./METRICS_AND_OUTCOMES.md)) | `agentshield/detect/semantic.py` (`AGENTSHIELD_SEMANTIC_BACKEND=llm`) | `test_semantic.py` (16) |
| Frontend page-render tests (RTL): Static Scan + Dashboard happy/empty/error paths | `web/src/pages/*.test.tsx` | 12 frontend tests total |
| SQLite FK constraints (cascades) + indexes on FK/ordering columns | `storage/sqlite_store.py` | suite green over new schema |
| Flagship UI: severity-distribution bar + KPI stat tiles + severity-accented findings rows | `web/src/components/ui/SeverityBar.tsx`, `StatTile.tsx` | verified live |
| CI: python lint/test/eval + frontend build/test | `.github/workflows/ci.yml` | n/a (CI) |
| Production deployment: Render (API) + Vercel (web) + local compose | `Dockerfile`, `docker-compose.yml`, `render.yaml`, `web/vercel.json`, `docs/DEPLOY.md` | `docker compose` smoke test |
| Phase 7 validation corpus (29 artifacts) + results | `benchmarks/phase7_public_artifacts/`, `docs/internal/phase7/` | n/a |

## 2. Partially completed features

| Feature | What works | What's missing |
|---|---|---|
| LLM judge (Claude) | Failure paths fully validated + tested | A **successful real dismissal run** never validated (`CURRENT_STATE.md`) |
| LLM dismissal granularity | Dismiss by `policy_id` works | Per-**instance** dismissal — repeated IDs over-dismissed as a group |
| Dynamic persistence | `judge_type/model`, raw counts, status persisted | `JudgeVerdict.notes` **not** persisted (lost on exit) |
| Accessibility / responsive | F9 polish + `LoadingState` status semantics | No a11y audit, no automated checks |
| Independent eval corpus | 50 labeled artifacts, 27 hard negatives, 10+ positives/category, Wilson intervals, macro/micro/weighted metrics, severity-weighted recall, evidence validation | Needs larger independently sourced corpus before broad market accuracy claims |
| Logging config | `agentshield_log_level` setting exists | Nothing reads it; no `logging` setup |
| Metrics realism | All values trace to real runs | `rules_only_rate=1.0`, `llm_routing_rate=0.0`, `avg_scan_cost_usd=0.0` are **structural constants**, not measured rates (honestly documented in `DECISIONS.md`) |

## 3. Broken / incomplete features

No outright **broken** code was found — the suite is green and the build passes. The
"incomplete" items are scope gaps, not bugs:

- (Resolved) Production deployment now exists — Render (API) + Vercel (web) + local
  `docker-compose.yml`; see `docs/DEPLOY.md`.

## 4. Missing core features

| Missing | Why it matters | Priority |
|---|---|---|
| Independent precision/recall corpus expansion | Detection credibility is still unproven on non-self-authored data | **P0** |
| A **net-win** LLM/semantic tier | LLM tier is built, guarded, and **measured** — `gpt-4o-mini` loses to the deterministic baseline on the current corpus. A genuine gain needs a stronger model and/or a corpus with HIGH-severity prose false positives | P1 (research) |
| Persistent scan history in production | Render free disk is ephemeral; needs a paid Render disk or Postgres (FK schema is ready) | P2 |

(Resolved since 2026-07-01: frontend page-render tests now exist — `StaticScanPage.test.tsx`,
`DashboardPage.test.tsx`.)

## 5. Technical debt

- Hand-rolled HTTP for LLMs (`llm_judge.py`) duplicates ~120 near-identical lines between
  `OpenAIJudge` and `ClaudeJudge` — extractable into a shared base.
- ~~SQLite has no FK constraints/indexes~~ — resolved: FK cascades + indexes on FK/ordering
  columns landed in `storage/sqlite_store.py` (2026-07-06).
- Multiple overlapping output dirs (`reports/`, `reports-test`, `agentshield-output/`,
  `agentshield-reports/`) are produced locally; `.gitignore` covers them, but a single
  canonical output path would reduce clutter.
- Frontend fetch logic is per-page; no shared query/cache layer.

## 6. Bugs or risks found

| # | Item | Severity | Location |
|---|---|---|---|
| 1 | ~~Open API + `CORS allow_origins=["*"]`~~ — fixed: `AGENTSHIELD_API_TOKEN` gate (timing-safe) + config-driven CORS + server-side-only LLM keys (`extra="forbid"`) | Resolved | `web/app.py` |
| 2 | Rules are substring/regex (evadable); mitigated by the recall-safe semantic confirmer for prose false positives, but paraphrase/encoding evasion remains open (LLM tier built + measured — not a net win with `gpt-4o-mini`, kept flag-off) | Medium (product) | `rules/*`, `detect/semantic.py` |
| 3 | ~~No FK/indexes → possible orphan rows~~ — fixed: FK cascades + indexes | Resolved | `storage/sqlite_store.py` |
| 4 | `JudgeVerdict.notes` dropped on persist | Low | `storage/sqlite_store.py` |

No injection/`eval`/unsafe-deserialization issues found — scanning is read-only string
work, and YAML uses `safe_load`. That's a genuine positive for a security tool.

## 7. Files / modules involved (hotspots)

- Detection quality: `agentshield/rules/*`, `detect/semantic.py`, `policy/policy_engine.py`
- Validation credibility: `benchmarks/labeled/`, `eval/scorer.py`
- Persistence durability in prod: Render disk / Postgres (schema integrity now enforced in
  `storage/sqlite_store.py`)
- Frontend tests: `web/src/pages/*.test.tsx` exist; remaining pages still untested

## 8. Priority order for fixing / building

1. **P0 (days):** expand the **public-only** share of the labeled corpus → broader
   precision/recall claims in [METRICS_AND_OUTCOMES.md](./METRICS_AND_OUTCOMES.md).
2. **P1 (research):** a net-win LLM tier — stronger model and/or a corpus with HIGH-severity
   prose false positives; guardrails already in place so enabling degrades gracefully.
3. **P2:** persistent scan history in production (paid Render disk or Postgres).
4. **P2:** refactor LLM judges onto a shared HTTP base; persist judge `notes`;
   RTL tests for the remaining pages.

(Done since the last snapshot: semantic confirmer, self-serve scanning, honest dashboard
hero, LLM tier built + measured, frontend page tests, FK constraints + indexes,
API auth + CORS, Docker/Render/Vercel deploy.)
