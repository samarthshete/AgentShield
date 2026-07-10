# AgentShield — Tech Stack

> Verified against `pyproject.toml`, `web/package.json`, and source on 2026-06-24;
> status refreshed 2026-07-09. Verdict column is a brutally honest "appropriate / reconsider" call.

---

## 1. Languages

| Language | Where | Why | Verdict |
|---|---|---|---|
| Python ≥3.11 | All backend (`agentshield/`) | Security/ML ecosystem, fast iteration, stdlib `urllib`/`sqlite3`/`tomllib` cover needs with zero extra deps | ✅ Appropriate |
| TypeScript ~5.6 | Frontend (`web/`) | Type-safe React; matches Pydantic-typed backend | ✅ Appropriate |
| YAML | Benchmark cases, CI, lint config | Human-editable test fixtures | ✅ Appropriate |

## 2. Frameworks

| Framework | Version | Where | Why | Verdict |
|---|---|---|---|---|
| Typer | ≥0.12.3 | `cli.py` | Ergonomic CLI with callbacks/validation | ✅ Appropriate |
| FastAPI | ≥0.115 | `web/app.py` | Thin typed HTTP layer over services | ✅ Appropriate (thin by design) |
| React | ^18.3 | `web/src` | Standard SPA console | ✅ Appropriate |
| Vite | ^5.4 | `web/` build | Fast dev server + bundler | ✅ Appropriate |
| React Router | ^6.28 | `App.tsx` | 6-route client navigation | ✅ Appropriate |

## 3. Libraries

| Library | Version | Purpose | Verdict |
|---|---|---|---|
| Pydantic | ≥2.8 | All data models / validation | ✅ Core, well-used |
| pydantic-settings | ≥2.4 | `.env` → `Settings` (`config.py`) | ✅ Appropriate |
| PyYAML | ≥6.0 | Parse YAML configs + benchmark cases | ✅ Appropriate |
| Rich | ≥13.7 | CLI tables/coloring | ✅ Appropriate |
| Uvicorn | ≥0.30 | ASGI server for FastAPI | ✅ Appropriate |
| Tailwind CSS | ^3.4 | Frontend styling | ✅ Appropriate |
| `urllib` (stdlib) | — | LLM API calls (`llm_judge.py`) | ⚠️ Works, but a maintained SDK (`anthropic`/`openai`) would be safer for retries, streaming, error taxonomy. Trade-off was "zero deps." |
| `sqlite3` / `tomllib` (stdlib) | — | Persistence / TOML parsing | ✅ Smart zero-dep choices |

**Frontend has no state/query/test/icon libraries** — intentionally minimal. Reasonable
for the current size; a data-fetching cache (TanStack Query) would reduce per-page fetch
boilerplate if the console grows.

## 4. Database

| Tech | Where | Why | Verdict |
|---|---|---|---|
| SQLite (single file) | `storage/sqlite_store.py` | Local-first, zero-config persistence; system of record | ✅ Appropriate for scope. FK cascades + indexes on FK/ordering columns now declared (2026-07-06). Move to Postgres only if hosted/multi-user persistence is needed (Render free disk is ephemeral). |

Schema migrations are hand-rolled additive `ALTER TABLE` via `_ensure_columns()` — fine
now, but a migration tool (Alembic) would be needed if the schema grows or an ORM is added.

## 5. Auth

**Shared-token gate** (`AGENTSHIELD_API_TOKEN`): every `/api/*` endpoint except
`/api/health` requires `Authorization: Bearer <token>` or `X-API-Key` (timing-safe
compare); CORS origins come from `AGENTSHIELD_CORS_ORIGINS`; LLM keys are resolved
server-side only. No user model/sessions — single-operator by design. **Verdict:**
✅ appropriate for a single-tenant deployed demo; OAuth/JWT only if it becomes multi-user.

## 6. Storage

Local filesystem only: reports under output dirs (`reports/`, `agentshield-output/`,
`agentshield-reports/`), DB file, and committed validation artifacts under
`benchmarks/phase7_public_artifacts/`. No object storage / cloud buckets. ✅ Appropriate.

## 7. Deployment

**Live:** API as a Docker container on **Render** (`render.yaml`, `Dockerfile`, health
check `/api/health`) and the web console as a static Vite build on **Vercel**
(`web/vercel.json`); local parity via `docker-compose.yml`. Runbook:
[DEPLOY.md](./DEPLOY.md). **Verdict:** ✅ fitting, honest infra for the scale. Remaining:
free Render plan cold-starts and has an ephemeral disk (paid disk or Postgres for durable
history); CLI still not on PyPI.

## 8. DevOps

| Tool | Where | Purpose | Verdict |
|---|---|---|---|
| GitHub Actions `ci.yml` | `.github/workflows/` | ruff lint + pytest + labeled eval + frontend build/test on push/PR | ✅ Solid |
| GitHub Actions `scan.yml` | `.github/workflows/` | Self-scan + artifacts + PR comment + fail gate | ✅ Strong, dogfoods the product |
| `.yamllint.yml` | repo root | Workflow YAML linting | ✅ Nice touch |
| setuptools | `pyproject.toml` | Packaging (editable install) | ✅ Fine; not published to PyPI yet |

## 9. Monitoring / logging

**Largely absent.** No structured logging, metrics export, error tracking, or APM.
`config.py` exposes `agentshield_log_level` but no logging is configured to honor it;
output is Rich console prints. **Verdict:** acceptable for a CLI; add `logging`
configuration and (if hosted) error tracking before production.

## 10. Testing tools

| Tool | Where | Coverage | Verdict |
|---|---|---|---|
| pytest ≥8.3 | `tests/` | **136 tests, all green** across parser, rules, semantic confirmer, eval, reporting, benchmarks, dynamic, metrics, exit codes, web API | ✅ Strong backend discipline |
| ruff ≥0.6 | CI + local | Lint | ✅ Appropriate |
| Vitest + React Testing Library | `web/src/**` | **12 tests**: lib (`api`/`settings`/`theme`) + RTL page renders (Static Scan, Dashboard) | ✅ In CI; extend RTL to remaining pages |

Backend test count by file: `test_dynamic.py` (48), `test_metrics.py` (17),
`test_semantic.py` (16), `test_rules.py` (12), `test_web_api.py` (9), `test_eval.py` (9),
`test_exit_codes.py` (8), `test_benchmark_runner.py` (5),
`test_discovery.py`/`test_benchmark_loader.py`/`test_mcp_parser.py`/`test_reporting.py` (3 each).

## 11. AI / LLM tools

| Tool | Where | Role | Verdict |
|---|---|---|---|
| OpenAI Chat Completions | `OpenAIJudge` | Primary validated LLM judge (`gpt-4o-mini` default) | ✅ Optional, fail-fast |
| Anthropic Messages | `ClaudeJudge` | Secondary judge (`claude-3-5-haiku-latest` default) | ✅ Optional. ⚠️ Validated only on failure paths. If AI features expand, default to the latest Claude models. |
| RuleBasedJudge | `llm_judge.py` | **Default**, no external call | ✅ Keeps core dependency-free |

The judge abstraction (`BaseJudge`) is clean and provider-pluggable — a genuine strength.

## 12. Stack-level verdict

The stack is **deliberately minimal, internally consistent, and well-matched to a
local-first CLI tool that now also runs as a small deployed service.** Strongest choices:
stdlib-first backend (sqlite3/tomllib/urllib), Pydantic everywhere, pure-function rules,
dogfooding via `scan.yml`, and honest right-sized deploy (Render + Vercel, no Kubernetes).
Since the original audit, FKs/indexes and frontend tests landed. The remaining choices to
**reconsider only if scope grows**: hand-rolled HTTP for LLMs (→ official SDKs), SQLite on
an ephemeral disk (→ paid disk or Postgres for durable hosted history), and the missing
structured-logging/monitoring layer.
