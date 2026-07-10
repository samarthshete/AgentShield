# AgentShield — Project Status

> **Canonical cross-session / cross-tool tracker.** Update this file (state + what's next +
> live URLs) as the final step of any work batch, and commit it. Detailed breakdowns live in
> the linked docs; this page is the at-a-glance source of truth.
>
> **Last updated:** 2026-07-09 (full docs/ sync to current outcomes; tests re-verified:
> 136 backend + 12 frontend passing)

## Live deployment
| Surface | URL | Notes |
|---|---|---|
| Web (Vercel, static) | https://agent-shield-topaz.vercel.app | Vite build; token supplied at runtime / baked `VITE_API_TOKEN` |
| API (Render, Docker) | https://agentshield-api-tcdl.onrender.com | `/api/health` → 200; token-gated; free plan cold-starts after idle |

CORS: `AGENTSHIELD_CORS_ORIGINS` on Render must list the exact Vercel origin. Runbook: [`DEPLOY.md`](./DEPLOY.md).

## Current state (on `main`, live)
- **Detection:** static rules (5 categories, 11 rules) → **semantic confirmer** tier
  (`agentshield/detect/semantic.py`) that dispositions each candidate confirm/dismiss/uncertain
  by surrounding context. Recall-safe: dismisses only HIGH/CRITICAL secret findings in clearly
  benign context (e.g. an env-var doc mention); labeled-eval **F1 98.1%, recall 100%, 2 FP**.
- **Self-serve scanning:** `POST /api/scan` accepts inline `content`; the Static Scan page has a
  **Paste config** mode — a visitor can scan their own agent/tool config, not just server paths.
- **Honest dashboard hero:** shows labeled-eval **F1 / precision / recall + Wilson 95% CI** with a
  caveat; the 9/9 benchmark is a secondary "smoke" badge (no longer the headline).
- **LLM confirmation tier (optional, flag OFF):** escalates only HIGH/CRITICAL `uncertain` cases to
  an LLM; tiered, injection-hardened, fail-safe, budget-capped, with severity + confidence recall
  guardrails. **Measured** (`gpt-4o-mini`): it does *not* beat the deterministic baseline on the
  corpus (see [`METRICS_AND_OUTCOMES.md`](./METRICS_AND_OUTCOMES.md)) — kept off by default.
- **Flagship UI:** Static Scan uses KPI stat tiles + a severity-distribution bar + severity-accented
  findings rows (`components/ui/SeverityBar.tsx`, `StatTile.tsx`) — verified live.
- **Console:** 7 pages incl. Settings; **light/dark theme** toggle; live connection indicator.
- **API:** 8 endpoints, token auth, config-driven CORS, server-side-only LLM keys.
- **Persistence:** SQLite with FK cascades + indexes on FK/ordering columns; Render disk path
  documented in `render.yaml` (needs a paid plan — free `/data` is ephemeral).
- **CI:** python lint/test/eval + frontend build/test. **Deploy:** Render + Vercel + local `docker-compose.yml`.
- **Tests:** 136 backend + 12 frontend (incl. RTL page tests) passing; ruff clean.

## Open PRs
- None from this work — all merged to `main` and live; stale branches cleaned up.

## Next up (research / paid-tier)
1. A genuine LLM-tier precision gain needs a stronger model and/or a corpus with HIGH-severity
   *prose* false positives (the deterministic tier already handles those we have).
2. Persistent scan history in production (Render paid disk or Postgres + the FK schema).

## Conventions
- Commits authored by `samarthshete`; **no** AI/co-author trailer and **no "Claude"** in messages.
- Keep this file + [`IMPLEMENTATION_STATUS.md`](./IMPLEMENTATION_STATUS.md) in sync when work lands.

## Detailed docs
- [`IMPLEMENTATION_STATUS.md`](./IMPLEMENTATION_STATUS.md) — feature-by-feature status & gaps
- [`DEPLOY.md`](./DEPLOY.md) — Vercel + Render deploy runbook
- [`METRICS_AND_OUTCOMES.md`](./METRICS_AND_OUTCOMES.md) — eval numbers & honest caveats
- [`architecture.md`](./architecture.md) — request lifecycle & data flow
- [`internal/SEMANTIC_DETECTION_DESIGN.md`](./internal/SEMANTIC_DETECTION_DESIGN.md) — semantic-layer design
