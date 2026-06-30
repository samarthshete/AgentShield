# AgentShield — Feature Prioritization

> Ranked future features grounded in the codebase. Scoring model (each sub-score 1–5):
>
> ```
> Priority Score = User Value + Engineering Depth + Resume Signal + Founder Value − Complexity Risk
> ```
>
> Max = 20 − 1 = 19; min = 4 − 5 = −1. No invented metrics.

---

## Scoring table (ranked)

| # | Feature | User | Eng | Resume | Founder | Complexity (−) | **Score** | Tier |
|---|---|:--:|:--:|:--:|:--:|:--:|:--:|---|
| F1 | Independent labeled validation harness + real precision/recall | 5 | 4 | 5 | 5 | 2 | **17** | Must build now |
| F2 | Hybrid rules+semantic detection engine | 5 | 5 | 5 | 5 | 4 | **16** | Must build now |
| F3 | Productionize API: auth + structured logging + OpenTelemetry + Dockerfile | 4 | 5 | 5 | 4 | 3 | **15** | Must build now |
| F4 | GitHub App (PR-native scan, inline annotations) | 5 | 4 | 4 | 5 | 3 | **15** | After MVP |
| F5 | Source-file scanning (`.py`/`.ts`/`.js`) as first-class targets | 4 | 3 | 3 | 4 | 2 | **12** | After MVP |
| F6 | Postgres + real FKs/indexes + Alembic migrations | 3 | 4 | 4 | 3 | 3 | **11** | After MVP |
| F7 | Frontend test suite (Vitest + RTL) + CI build gate | 2 | 3 | 4 | 3 | 1 | **11** | After MVP |
| F8 | Cached/idempotent semantic verdicts (content-hash keyed) | 3 | 4 | 3 | 3 | 2 | **11** | After MVP |
| F9 | Async scan jobs (queue + worker) for long semantic scans | 3 | 5 | 4 | 3 | 4 | **11** | Advanced |
| F10 | Adversarial evasion benchmark + hardening loop | 4 | 4 | 4 | 3 | 2 | **13** | After MVP |
| F11 | LangGraph "attack-path" multi-step analyzer | 4 | 5 | 5 | 4 | 5 | **13** | Advanced differentiator |
| F12 | Custom fine-tuned detector model (SageMaker/HF) | 3 | 5 | 5 | 3 | 5 | **11** | Advanced differentiator |
| F13 | Hosted multi-tenant SaaS (orgs, billing, dashboards) | 3 | 4 | 3 | 4 | 5 | **9** | Advanced |
| F14 | Real-time runtime guardrail / proxy product | 4 | 5 | 4 | 4 | 5 | **12** | Avoid for now (different company) |
| F15 | More substring rules / more threat categories | 1 | 1 | 1 | 1 | 2 | **2** | Bad idea now |
| F16 | Kafka event bus / EKS cluster for current scale | 1 | 3 | 2 | 1 | 5 | **2** | Bad idea now |

---

## Detailed feature cards

### F1 — Independent labeled validation harness + real precision/recall — **Score 17**
- **Problem:** the only accuracy claim is 100% on 9 self-authored cases; no independent
  ground truth exists (`docs/METRICS_AND_OUTCOMES.md` §3).
- **User value:** buyers/users can trust the tool. **Engineering value:** forces a clean
  eval pipeline + metrics. **Founder value:** unlocks the entire pitch. 
- **Difficulty:** Low–Med. **Impact:** High. **Resume:** High.
- **Files:** new `benchmarks/labeled/` corpus; new `agentshield/eval/scorer.py`; extend
  `metrics/aggregator.py` (`ScanMetrics`), `models/metrics.py`; new `tests/test_eval.py`.
- **Backend:** scorer computing precision/recall/F1 from labeled vs detected.
- **Frontend:** optional — surface on Metrics page later.
- **DB:** none (eval is offline) or a `labeled_findings` table if persisted.
- **Infra:** none.
- **Risks:** labeling effort; corpus must be independent of rule authoring.
- **DoD:** `agentshield eval benchmarks/labeled` prints P/R/F1; numbers land in
  `metrics.json`; reproducible in CI.

### F2 — Hybrid rules+semantic detection engine — **Score 16**
- **Problem:** detection is `if marker in text.lower()` — evadable + noisy.
- **User value:** catches paraphrased/obfuscated attacks; fewer false positives.
- **Engineering value:** real ML/LLM-systems work; cost-aware routing. **Founder:** the
  actual moat. **Resume:** the headline bullet.
- **Difficulty:** Med–High. **Impact:** High. **Resume:** High.
- **Files:** new `agentshield/detect/semantic.py`; extend `services/scan_service.py` and
  `services/rule_runner.py` to add a `--mode rules|hybrid|semantic` path; reuse the
  `BaseJudge` pattern from `dynamic/llm_judge.py`; `config.py` flags; `tests/test_semantic.py`.
- **Backend:** rules run first (cheap pre-filter); ambiguous/borderline findings + a
  sample of clean text go to an LLM/embedding stage that confirms intent and assigns
  confidence; make `llm_routing_rate` in `metrics/aggregator.py:129` real.
- **Frontend:** show confidence + which stage flagged each finding.
- **DB:** add `detection_stage`, `confidence` columns to `findings`.
- **Infra:** optional caching (F8).
- **Risks:** cost/latency; must keep rules-only default for CI speed.
- **DoD:** hybrid mode beats rules-only F1 on the F1 corpus, measured.

### F3 — Productionize the API (auth + logging + OpenTelemetry + Docker) — **Score 15**
- **Problem:** `web/app.py` has no auth, `CORS allow_origins=["*"]` (`app.py:52`), no
  logging, no tracing, no container.
- **User value:** safe to run as a shared service. **Engineering/Cloud value:** high.
  **Resume:** strong backend/platform bullet.
- **Difficulty:** Med. **Impact:** High. **Resume:** High.
- **Files:** `web/app.py` (auth dependency, CORS allowlist), `config.py` (API key/secret,
  allowed origins), new `agentshield/observability/` (logging + OTel setup), new
  `Dockerfile` + `.dockerignore`, `tests/test_web_api.py` (auth cases).
- **Backend:** API-key/JWT dependency; `structlog`/stdlib `logging` JSON config honoring
  `agentshield_log_level`; OTel spans around `run_static_scan`, `evaluate_trace`,
  `judge.evaluate` + LLM HTTP.
- **Frontend:** send auth header from `web/src/lib/api.ts`.
- **DB:** none.
- **Infra:** Dockerfile; later compose with the collector.
- **Risks:** scope creep into full IAM — keep it single-key/JWT.
- **DoD:** unauthed request → 401; traces visible; `docker run` serves the API.

### F4 — GitHub App (PR-native scanning) — **Score 15** *(after MVP)*
- **Problem:** today CI scanning is a copied workflow; a GitHub App is install-once,
  PR-native, and the natural distribution channel.
- **Files:** new `agentshield/integrations/github_app.py`; reuse `run_static_scan` +
  `pr_comment_body()` (already in `reporting/markdown_report.py`).
- **Backend:** webhook receiver, signature verify, Checks API annotations.
- **Infra:** a hosted endpoint (ties to F3 + Lambda/container).
- **DoD:** installing the app on a repo posts inline findings on PRs.

### F5–F10, F12–F16 — summarized in the scoring table above; full engineering notes for the
top-priority ones (F1–F3) are expanded in [IMMEDIATE_BUILD_PLAN.md](./IMMEDIATE_BUILD_PLAN.md).

---

## Tiering

### Must build immediately
- **F1** labeled validation + precision/recall
- **F2** hybrid rules+semantic engine
- **F3** productionized API (auth + logging + OTel + Docker)

### Build after MVP is stable
- **F4** GitHub App · **F5** source-file scanning · **F6** Postgres+FKs+Alembic ·
  **F7** frontend tests · **F8** cached semantic verdicts · **F10** adversarial benchmark

### Advanced differentiators
- **F11** LangGraph attack-path analyzer · **F12** custom fine-tuned detector ·
  **F9** async scan jobs · **F13** hosted multi-tenant SaaS

### Bad ideas / avoid for now
- **F15** more substring rules/categories (adds noise; rule set is deliberately frozen).
- **F16** Kafka/EKS at current scale (massive overkill — see tech analysis).
- **F14** runtime guardrail product (worthy, but a different and much larger company; do
  not dilute the scanner thesis).
