# AgentShield — Implementation Status

> Snapshot from a direct source read on 2026-06-29. `pytest` → **116 passed**.
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
| FastAPI API (8 endpoints) + token auth + config-driven CORS | `web/app.py`, `web/schemas.py` | `test_web_api.py` (8) |
| React console (6 pages, live-wired, builds clean) | `web/src/**` | ❌ none |
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

- **No production deployment** path of any kind.

## 4. Missing core features

| Missing | Why it matters | Priority |
|---|---|---|
| Independent precision/recall corpus expansion | Detection credibility is still unproven on non-self-authored data | **P0** |
| Semantic / LLM-primary detection mode | Substring rules are paraphrase-evadable + noisy in prose | **P1** |
| Frontend tests | UI regressions are invisible | P1 |

## 5. Technical debt

- Hand-rolled HTTP for LLMs (`llm_judge.py`) duplicates ~120 near-identical lines between
  `OpenAIJudge` and `ClaudeJudge` — extractable into a shared base.
- SQLite has no FK constraints/indexes; integrity is convention-only.
- Multiple overlapping output dirs (`reports/`, `reports-test`, `agentshield-output/`,
  `agentshield-reports/`) are produced locally; `.gitignore` covers them, but a single
  canonical output path would reduce clutter.
- Frontend fetch logic is per-page; no shared query/cache layer.

## 6. Bugs or risks found

| # | Item | Severity | Location |
|---|---|---|---|
| 1 | ~~Open API + `CORS allow_origins=["*"]`~~ — fixed: `AGENTSHIELD_API_TOKEN` gate (timing-safe) + config-driven CORS + server-side-only LLM keys (`extra="forbid"`) | Resolved | `web/app.py` |
| 2 | Detection is substring/regex only (evadable, noisy) | Medium (product) | `rules/*` |
| 3 | No FK/indexes → possible orphan rows | Low | `storage/sqlite_store.py` |
| 4 | `JudgeVerdict.notes` dropped on persist | Low | `storage/sqlite_store.py` |

No injection/`eval`/unsafe-deserialization issues found — scanning is read-only string
work, and YAML uses `safe_load`. That's a genuine positive for a security tool.

## 7. Files / modules involved (hotspots)

- Detection quality: `agentshield/rules/*`, `policy/policy_engine.py`
- Validation credibility: `benchmarks/`, `dynamic/attack_generator.py`
- Persistence integrity: `storage/sqlite_store.py`
- Deploy gaps: (missing) `Dockerfile` (API auth + CORS now done in `web/app.py`)
- Frontend tests: `web/src/**` (no `*.test.tsx`)

## 8. Priority order for fixing / building

1. **P0 (done locally):** `.env` is ignored and `git log -- .env` shows no committed secret.
2. **P0 (days):** expand independent validation set with **labels** → real precision/recall in
   [METRICS_AND_OUTCOMES.md](./METRICS_AND_OUTCOMES.md).
3. **P1:** semantic detection mode (LLM-primary or embedding similarity) behind a flag.
4. **P1:** frontend test suite (Vitest + RTL) covering each page's happy/empty/error path.
5. **P2:** refactor LLM judges onto a shared HTTP base; persist judge `notes`.
6. **P2 (only if hosting):** Dockerfile, Postgres + FKs. (API auth + CORS tightening — done.)
