# AgentShield — Onboarding for AI Agents

> Read this first if you are an AI coding agent picking up this repo.
> It is the fast path to being productive without breaking things. Verified 2026-07-09.

---

## 1. Project summary

AgentShield is a **local-first Python security scanner for tool-using AI agents and MCP
configs.** It (a) statically scans config/doc/source files for 5 threat categories using
11 substring/regex rules plus a deterministic **semantic confirmer**, (b) runs scripted
dynamic attack simulations through a policy engine, (c) benchmarks itself with YAML cases
and a **50-artifact labeled eval corpus** (micro F1 98.08%), (d) emits JSON/Markdown
reports + SQLite history, and (e) exposes all of this via a Typer CLI, a token-gated
FastAPI API, and a React console — **deployed live on Render (API) + Vercel (web)**.
Default path uses **no LLM**; OpenAI/Claude are optional (dynamic-sim judge, and a
flag-off LLM confirmation tier).

Full context: [PROJECT_MASTER.md](./internal/PROJECT_MASTER.md) and
[ARCHITECTURE.md](./ARCHITECTURE.md).

## 2. Important files

| File | Why it matters |
|---|---|
| `agentshield/cli.py` | All 6 CLI commands; the canonical behavior |
| `agentshield/services/scan_service.py` | Static scan orchestration |
| `agentshield/services/rule_runner.py` | Runs all rule modules; routes `permission_blob` |
| `agentshield/rules/*.py` | The 11 detection rules (pure functions) |
| `agentshield/parser/discovery.py`, `mcp_parser.py` | File discovery + parsing |
| `agentshield/policy/policy_engine.py` | Dynamic policy evaluation (reuses static rules) |
| `agentshield/dynamic/attack_generator.py`, `runtime_simulator.py` | Scripted scenarios |
| `agentshield/dynamic/llm_judge.py` | `BaseJudge` + RuleBased/OpenAI/Claude |
| `agentshield/eval/scorer.py`, `benchmarks/labeled/` | Labeled precision/recall/F1 evaluation harness and corpus |
| `agentshield/detect/semantic.py` | Semantic confirmer (deterministic default + flag-off LLM backend) |
| `agentshield/storage/sqlite_store.py` | Schema, migrations, persist + reads |
| `agentshield/reporting/severity.py` | Severity rank + risk score |
| `agentshield/web/app.py`, `web/schemas.py` | FastAPI endpoints + Pydantic I/O |
| `web/src/App.tsx`, `web/src/lib/api.ts`, `web/src/pages/*` | Frontend routes + fetch + pages |
| `tests/` | 136 tests — run before and after any change |
| repo-root `DECISIONS.md`, `CURRENT_STATE.md` | Deep rationale + phase log (gitignored) |

## 3. How to run locally

```bash
# Backend (CLI)
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m agentshield scan benchmarks/fixtures --format both --output reports
python -m agentshield benchmark benchmarks/cases
python -m agentshield eval benchmarks/labeled
python -m agentshield simulate            # rule-based judge, no API key needed
python -m agentshield metrics

# Backend (API)
uvicorn agentshield.web.app:app --reload   # http://127.0.0.1:8000

# Frontend
cd web && npm install && npm run dev        # http://127.0.0.1:5173

# Tests + lint (do this before committing)
.venv/bin/pytest -q                         # expect: 136 passed
ruff check agentshield tests
cd web && npx vitest run                    # expect: 12 passed
cd web && npm run build
```

> **Entry-point gotcha (from repo-root `DECISIONS.md`):** prefer `python -m agentshield`
> over the `agentshield` console script — if the venv's python is a symlink to system
> python, the console script may miss venv site-packages.

## 4. How the app works (mental model)

- **Static:** `discover → parse → run_all_rules(scan_text, permission_blob) → Finding →
  ScanRun → report + SQLite`. Rules are pure `str -> list[RuleResult]`.
- **Dynamic:** `AttackPayload → simulate() 5-step trace → evaluate_trace() (POLSTA- reuse
  of static rules + POLDYN- per-step regex) → judge.evaluate() splits confirmed/dismissed`.
- **API/CLI/UI all call the same core functions** — never put logic in `web/app.py` or
  the React pages.

## 5. Current status

Working v0.1.0, **live in production** (Render API + Vercel web). 136 backend + 12
frontend tests green. Rule set **frozen** after Phase 7; a recall-safe semantic confirmer
runs over rule candidates by default, and labeled-eval accuracy is measured (micro F1
98.08%, recall 100%, on 50 artifacts). API is token-gated with config-driven CORS; SQLite
has FK cascades + indexes. Main gaps: the labeled corpus still mixes in authored challenge
data, the LLM tier is not a net win (flag-off), and prod scan history is ephemeral on the
free Render plan. `.env` is ignored locally; verify this remains true before broad git
adds. Canonical tracker: [PROJECT_STATUS.md](./PROJECT_STATUS.md); detail:
[IMPLEMENTATION_STATUS.md](./IMPLEMENTATION_STATUS.md).

## 6. Coding conventions

- Python ≥3.11, `from __future__ import annotations`, full type hints, Pydantic v2 models.
- Line length 100 (`ruff`, see `pyproject.toml`).
- Rules are **pure functions** returning `RuleResult`; no file/DB/network access in `rules/`.
- Severity strings are uppercase: `CRITICAL/HIGH/MEDIUM/LOW/INFO`.
- IDs: static rules `XX-NNN` (e.g. `EXF-001`); dynamic policies `POLSTA-*` / `POLDYN-*`.
- Stdlib-first; adding a dependency needs a real justification (`DECISIONS.md` D10).
- Tests live in `tests/`, named `test_*.py`; add tests with every behavior change.

## 7. Where to add new features

| Want to add… | Put it in… | Then… |
|---|---|---|
| A new detection rule | new/﻿existing `agentshield/rules/*.py` | wire in `services/rule_runner.py`; add to `metrics/rule_registry.py` probe; add `test_rules.py` cases |
| A new dynamic policy | `policy/policy_engine.py` | add `POLDYN-*` pattern + `test_dynamic.py` |
| A new attack scenario | `dynamic/attack_generator.py` | add to `_SCENARIOS`; tests |
| A new LLM provider | `dynamic/llm_judge.py` | implement `BaseJudge`; extend `get_judge()`; mirror fail-fast contract |
| A new API endpoint | `web/app.py` + `web/schemas.py` | call existing core fns only; add `test_web_api.py` |
| A new UI page | `web/src/pages/` + route in `App.tsx` | reuse `Card/Badge/LoadingState/ErrorState/EmptyState` |
| A new benchmark case | `benchmarks/cases/*.yaml` | run `agentshield benchmark benchmarks/cases` |

## 8. What NOT to touch without review

- **The frozen rule set** (`rules/*`): changing detection logic requires before/after
  evidence on the validation set (`DECISIONS.md` rule-freeze). Don't silently re-tune.
- **Exit-code contract** (0 clean / 1 findings-at-threshold / 2 bad-args): CI depends on it.
- **SQLite schema**: only additive changes via `_ensure_columns()`; never drop/rename columns.
- **Judge fail-fast contract**: never add a silent fallback to rule-based on LLM error.
- **The thin-API principle**: don't add business logic to `web/app.py` or React pages.

## 9. Common mistakes to avoid

- Assuming vendor/build output is scanned — directory discovery intentionally skips
  `.git`, `node_modules`, virtualenvs, caches, `dist`, and `build`.
- Committing secrets — `.env` is ignored locally, but don't `git add .` blindly. Keep
  `.env.example` tracked and real credentials untracked.
- Treating benchmark/sim green as proof of real accuracy — those are self-authored.
- Forgetting to update `metrics/rule_registry.py` after adding a rule (it won't appear in
  metrics otherwise).
- Editing the gitignored root `PROJECT.md`/`DECISIONS.md`/`CURRENT_STATE.md` expecting it
  to publish — those are local-only.

## 10. Next best tasks (in order)

1. **P0:** keep expanding the public-only share of the **labeled** corpus and use
   `agentshield eval benchmarks/labeled` for precision/recall
   ([METRICS_AND_OUTCOMES.md](./METRICS_AND_OUTCOMES.md)).
2. **P1 (research):** a net-win LLM confirmation tier — stronger model and/or a corpus with
   HIGH-severity prose false positives (guardrails already exist; tier stays flag-off).
3. **P2:** persistent prod scan history (paid Render disk or Postgres).
4. **P2:** RTL tests for the remaining pages; refactor the two LLM judges onto a shared
   HTTP base; persist judge `notes`.

See [ROADMAP.md](./ROADMAP.md) for the full plan.
