# AgentShield — Project Status

> **Canonical cross-session / cross-tool tracker.** Update this file (state + what's next +
> live URLs) as the final step of any work batch, and commit it. Detailed breakdowns live in
> the linked docs; this page is the at-a-glance source of truth.
>
> **Last updated:** 2026-07-01

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
- **Console:** 7 pages incl. Settings; **light/dark theme** toggle; live connection indicator.
- **API:** 8 endpoints, token auth, config-driven CORS, server-side-only LLM keys.
- **CI:** python lint/test/eval + frontend build/test. **Deploy:** Render + Vercel + local `docker-compose.yml`.
- **Tests:** 129 backend + 7 frontend passing; ruff clean.

## In flight / open PRs
- `feat/llm-confirmer-tier` — **LLM confirmation tier**, flag **OFF** by default
  (`AGENTSHIELD_SEMANTIC_BACKEND=llm` + a key). Tiered (only `uncertain` cases escalate),
  injection-hardened, fail-safe, budget-capped. Merging changes nothing in prod.
- `docs/project-status-tracker` — superseded by this file; safe to close.

## Next up
1. **Phase 5 — flagship UI layout** to match the Claude Design mockups (KPI tiles + severity bar + denser table).
2. Merge `feat/llm-confirmer-tier` when desired.
3. Frontend page-render tests (Vitest + RTL, P2).
4. Persistence hardening for hosting (Render disk or Postgres + FK constraints).

## Conventions
- Commits authored by `samarthshete`; **no** AI/co-author trailer and **no "Claude"** in messages.
- Keep this file + [`IMPLEMENTATION_STATUS.md`](./IMPLEMENTATION_STATUS.md) in sync when work lands.

## Detailed docs
- [`IMPLEMENTATION_STATUS.md`](./IMPLEMENTATION_STATUS.md) — feature-by-feature status & gaps
- [`DEPLOY.md`](./DEPLOY.md) — Vercel + Render deploy runbook
- [`METRICS_AND_OUTCOMES.md`](./METRICS_AND_OUTCOMES.md) — eval numbers & honest caveats
- [`architecture.md`](./architecture.md) — request lifecycle & data flow
- [`internal/SEMANTIC_DETECTION_DESIGN.md`](./internal/SEMANTIC_DETECTION_DESIGN.md) — semantic-layer design
