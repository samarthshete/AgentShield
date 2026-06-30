# AgentShield — Tech Stack

> Verified against `pyproject.toml`, `web/package.json`, and source on 2026-06-24.
> Verdict column is a brutally honest "appropriate / reconsider" call.

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
| SQLite (single file) | `storage/sqlite_store.py` | Local-first, zero-config persistence; system of record | ✅ Appropriate for scope. ⚠️ No FK constraints/indexes declared; no concurrency story. Move to Postgres only if hosted/multi-user. |

Schema migrations are hand-rolled additive `ALTER TABLE` via `_ensure_columns()` — fine
now, but a migration tool (Alembic) would be needed if the schema grows or an ORM is added.

## 5. Auth

**Not found in current codebase.** No auth framework, user model, sessions, or tokens.
The only credentials are outbound LLM API keys in `.env`. **Verdict:** acceptable for
local-only scope; a hard prerequisite (e.g. OAuth/JWT) before any deployment.

## 6. Storage

Local filesystem only: reports under output dirs (`reports/`, `agentshield-output/`,
`agentshield-reports/`), DB file, and committed validation artifacts under
`benchmarks/phase7_public_artifacts/`. No object storage / cloud buckets. ✅ Appropriate.

## 7. Deployment

**Not found** as automated infra. No Docker, Kubernetes, Vercel, Supabase, or AWS config.
Deployment = local processes (`pip install -e .`, `uvicorn`, `npm run dev/build`).
**Verdict:** matches stated scope, but production deployment is entirely unbuilt — see
[ROADMAP.md](./ROADMAP.md) Phase 2. First step would be a Dockerfile + a hosted API with
auth, or shipping the CLI to PyPI.

## 8. DevOps

| Tool | Where | Purpose | Verdict |
|---|---|---|---|
| GitHub Actions `ci.yml` | `.github/workflows/` | ruff lint + pytest on push/PR | ✅ Solid |
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
| pytest ≥8.3 | `tests/` | **103 tests, all green** across parser, rules, reporting, benchmarks, dynamic, metrics, exit codes, web API | ✅ Strong backend discipline |
| ruff ≥0.6 | CI + local | Lint | ✅ Appropriate |
| **Frontend tests** | — | **None** | ❌ Gap — add Vitest + React Testing Library |

Backend test count by file: `test_dynamic.py` (48), `test_metrics.py` (16),
`test_rules.py` (12), `test_exit_codes.py` (8), `test_benchmark_runner.py` (5),
`test_web_api.py` (5), `test_benchmark_loader.py`/`test_mcp_parser.py`/`test_reporting.py` (3 each).

## 11. AI / LLM tools

| Tool | Where | Role | Verdict |
|---|---|---|---|
| OpenAI Chat Completions | `OpenAIJudge` | Primary validated LLM judge (`gpt-4o-mini` default) | ✅ Optional, fail-fast |
| Anthropic Messages | `ClaudeJudge` | Secondary judge (`claude-3-5-haiku-latest` default) | ✅ Optional. ⚠️ Validated only on failure paths. If AI features expand, default to the latest Claude models. |
| RuleBasedJudge | `llm_judge.py` | **Default**, no external call | ✅ Keeps core dependency-free |

The judge abstraction (`BaseJudge`) is clean and provider-pluggable — a genuine strength.

## 12. Stack-level verdict

The stack is **deliberately minimal, internally consistent, and well-matched to a
local-first CLI tool.** Strongest choices: stdlib-first backend (sqlite3/tomllib/urllib),
Pydantic everywhere, pure-function rules, and dogfooding via `scan.yml`. The choices to
**reconsider only if scope grows** are: hand-rolled HTTP for LLMs (→ official SDKs),
constraint-free SQLite (→ FKs/indexes or Postgres), and the missing frontend test +
logging/monitoring layers.
