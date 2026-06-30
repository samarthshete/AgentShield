# AgentShield — Tech Stack Upgrade Analysis

> Honest fit analysis of each proposed technology against the **actual** architecture
> (CLI-first Python, pure-function rules in `agentshield/rules/`, scripted dynamic
> pipeline in `dynamic/` + `policy/`, SQLite in `storage/`, thin FastAPI in `web/app.py`,
> React in `web/`). No tool is recommended for decoration. Scores are 1–10 fit.

**TL;DR ranking (add in this order, only as justified):**
`GitHub Actions (have it) → OpenTelemetry → Terraform → S3/R2 → AWS Lambda → Redis →
Prometheus/Grafana → LangGraph (one feature only) → Postgres(not listed but implied) →`
**Avoid for now:** `Kafka, EKS, DynamoDB, SageMaker, LangChain (as a framework)`.

---

### LangChain
```
Technology: LangChain
Should we add it? No (Maybe for a narrow retrieval slice only)
Fit score: 3/10
Where it fits: ONLY if F2 semantic detection grows a RAG step that retrieves known
  attack-pattern exemplars to ground the LLM judgment — LangChain's retriever/vectorstore
  abstractions could wrap that.
Where it does NOT fit: The existing LLM path (dynamic/llm_judge.py) is already a clean,
  tested, provider-pluggable BaseJudge with a strict-JSON contract and fail-fast errors.
  LangChain would replace ~120 lines of explicit, debuggable code with a heavier
  abstraction and a large dependency tree — directly against the stdlib-first decision
  (DECISIONS.md D10) and the project's "explainable" ethos.
Feature it enables: Retrieval-grounded semantic detection (small part of F2).
Architecture change: Introduce a vector store + retriever; wrap LLM calls.
Implementation difficulty: Medium (and mostly undoing good existing code).
Resume/interview value: Low-Medium (LangChain is common; not a differentiator).
Risk of looking forced: High — replacing a clean abstraction with a framework reads as
  resume-keyword chasing to a senior reviewer.
Final recommendation: Do NOT adopt as a framework. If retrieval is needed, use a small
  vector lib (e.g. sqlite-vec/FAISS) behind your own interface, consistent with BaseJudge.
```

### LangGraph
```
Technology: LangGraph
Should we add it? Maybe — for exactly ONE advanced feature (F11), not the core pipeline.
Fit score: 6/10 (for F11) / 2/10 (for current linear pipeline)
Where it fits: An "attack-path analyzer" that reasons over a trace in multiple
  conditional steps. Concrete graph nodes mapping to this codebase:
    node:parse        -> parser/mcp_parser.py
    node:rule_detect  -> services/rule_runner.py (cheap pre-filter)
    node:triage       -> conditional edge: route only ambiguous findings onward
    node:semantic     -> detect/semantic.py (LLM confirm intent)
    node:exploit_path -> LLM reasons whether flagged tool + permissions form a real
                         exploit chain (e.g. read-secret tool + network tool)
    node:judge        -> dynamic/llm_judge.py
    node:aggregate    -> build DynamicScanResult
  The conditional routing (only escalate ambiguous/high-risk findings) is a genuine graph,
  not a line.
Where it does NOT fit: The current static scan and the scripted simulate() pipeline are
  strictly linear (cli.py:74, web/app.py:175). Wrapping them in LangGraph today adds a
  dependency and indirection for zero behavioral gain.
Feature it enables: F11 multi-step, conditional, agentic exploit-path analysis.
Architecture change: New graph runtime alongside (not replacing) the linear scan path.
Implementation difficulty: High.
Resume/interview value: High — "I modeled agent-security triage as a conditional state
  graph with cost-aware LLM escalation" is a strong, specific story.
Risk of looking forced: Medium — only credible if the graph has REAL conditional edges
  (escalation logic), not a straight line dressed up as a graph.
Final recommendation: Defer to the advanced-differentiator phase. Build F1+F2+F3 first.
  When you build F11, use LangGraph and document the nodes above.
```

### Agent orchestration (general)
```
Should we add it? Maybe — same answer as LangGraph; it IS the F11 use case.
Fit score: 6/10
Where it fits: Orchestrating the multi-stage triage (rules -> semantic -> exploit-path ->
  judge) with conditional escalation and parallel per-file fan-out.
Where it does NOT fit: There is no multi-agent collaboration need; this is a pipeline with
  branches, not a society of agents. Don't invent agents that talk to each other.
Feature it enables: F11.
Architecture change: A graph/orchestrator module; everything else unchanged.
Implementation difficulty: High.
Resume value: High if conditional + cost-aware; Low if cosmetic.
Risk of looking forced: Medium-High.
Final recommendation: One orchestrated feature, later. Not the core scan path.
```

### Amazon EKS
```
Should we add it? No (now) / Maybe (far-future hosted SaaS).
Fit score: 2/10 now
Where it fits: Only if AgentShield becomes a multi-tenant hosted SaaS (F13) with
  sustained concurrent load needing autoscaling + multiple services.
Where it does NOT fit: The workload is short, stateless, bursty scans. A single container
  (F3 Dockerfile) or Lambda covers the MVP and even early production. EKS = a cluster, a
  control plane, networking, and ops burden for a tool that runs sub-second scans.
Feature it enables: Horizontal autoscaling for a SaaS.
Architecture change: Containerize (have to anyway), then Helm/k8s manifests, ingress, etc.
Implementation difficulty: High.
Resume/interview value: Medium-High (k8s is a recognized signal) but hollow without real
  load to justify it.
Risk of looking forced: HIGH — classic over-engineering tell. A senior will ask "why a
  cluster for a stateless sub-second job?" and you won't have a real answer at MVP.
Final recommendation: Do NOT add now. If you ever host a SaaS at scale, revisit. For
  résumé k8s signal, prefer a small honest k8s deploy of the container, clearly labeled
  "production deployment example," not a fabricated scaling story.
```

### AWS Lambda
```
Should we add it? Yes — on the hosting path; it's the natural fit.
Fit score: 7/10
Where it fits: Scans are stateless, short, event-driven — a perfect Lambda shape. Trigger
  Lambda from the GitHub App webhook (F4) or an API Gateway POST /scan; run run_static_scan
  on the payload; write the report to S3 and metadata to the DB.
Where it does NOT fit: The default rules-only scan is sub-second, but a HYBRID/semantic scan
  (F2) that calls an LLM can exceed comfortable sync limits — there, prefer async (queue +
  worker) over a long-running Lambda, or use Lambda only for the fast path.
Feature it enables: Serverless hosted scan endpoint + GitHub App backend without managing
  servers.
Architecture change: Package agentshield as a Lambda handler (the service layer is already
  decoupled from CLI/HTTP, so this is clean); add API Gateway or function URL.
Implementation difficulty: Medium.
Resume/interview value: High — "serverless, event-driven security scanning" is a crisp,
  defensible story that MATCHES the workload.
Risk of looking forced: Low — the stateless short-job shape genuinely fits Lambda.
Final recommendation: Adopt on the hosting path (Phase 4), paired with S3 + the GitHub App.
```

### Amazon DynamoDB
```
Should we add it? No.
Fit score: 3/10
Where it fits: Marginally — append-heavy findings writes could be a DynamoDB table.
Where it does NOT fit: The access patterns are relational and query-shaped: "list scan_runs
  ordered by time," "join findings + targets for a run," "filter by severity/category"
  (see storage/sqlite_store.py list_scan_runs / get_scan_run_details). These are exactly
  what a relational DB does well and what DynamoDB makes painful (no joins, rigid key
  design, GSIs for every query). The natural upgrade is SQLite -> Postgres, not Dynamo.
Feature it enables: Nothing the relational model doesn't do better here.
Architecture change: Single-table redesign + access-pattern modeling — high effort, wrong
  direction.
Implementation difficulty: Medium-High (and a step backward for these queries).
Resume/interview value: Medium — but choosing the RIGHT store (and being able to explain
  why NOT Dynamo) is a stronger senior signal than adopting it.
Risk of looking forced: High.
Final recommendation: Do NOT add. Use Postgres (F6) when you outgrow SQLite. Being able to
  say "I rejected DynamoDB because my access patterns are relational" is itself a great
  interview answer.
```

### Amazon SageMaker
```
Should we add it? No (now) / Maybe (only if you train a custom detector, F12).
Fit score: 2/10 now
Where it fits: ONLY if F12 happens — training/hosting a fine-tuned tool-poisoning/injection
  classifier on your labeled corpus (F1). Then SageMaker (or a simpler HF endpoint) hosts it.
Where it does NOT fit: Today the project calls EXTERNAL LLM APIs (OpenAI/Anthropic) via
  urllib (llm_judge.py). There is no model to train, tune, or host. SageMaker for an API
  wrapper is pure resume-padding.
Feature it enables: Self-hosted custom detector (advanced).
Architecture change: A training pipeline + model endpoint + inference client.
Implementation difficulty: High.
Resume/interview value: High IF you actually train a model on real labeled data; otherwise
  Low and obviously forced.
Risk of looking forced: HIGH unless preceded by F1 (labeled data) + F2 (proven LLM baseline
  to beat).
Final recommendation: Do NOT add now. Revisit only after F1+F2 prove a custom model could
  beat the API baseline. A cheaper first step is a fine-tune via the provider API or a
  small HF model on a single GPU — not SageMaker infrastructure.
```

### Redis
```
Should we add it? Maybe — valuable once F2/F3 exist.
Fit score: 6/10
Where it fits: (1) Cache semantic verdicts keyed by content hash (F8) so identical tool
  descriptions aren't re-sent to the LLM — direct cost/latency win for F2. (2) Rate limiting
  + idempotency keys for the hosted API (F3). (3) Broker for async scan jobs (F9).
Where it does NOT fit: The local CLI default needs no Redis; don't add it to the core path.
Feature it enables: LLM-call caching, rate limiting, job queue.
Architecture change: Add a cache interface (no-op locally, Redis when hosted).
Implementation difficulty: Low-Medium.
Resume/interview value: Medium-High (caching an LLM pipeline for cost is a great story).
Risk of looking forced: Low if tied to a real cost/latency number from F2.
Final recommendation: Add when F2 lands, as the verdict cache + (if hosted) rate limiter.
```

### Kafka or queue system
```
Should we add it? Kafka: No. A simple queue: Maybe (with F9).
Fit score: Kafka 2/10 · SQS/Celery/RQ 6/10
Where it fits: When hybrid/semantic scans get slow, decouple request from work: API
  enqueues a scan job, a worker runs it, results land in DB/S3 (F9). SQS or Celery/RQ fits.
Where it does NOT fit: There is no event-stream/high-throughput/multi-consumer need. Kafka
  is for streaming pipelines you don't have; it's heavy ops for zero benefit here.
Feature it enables: Async long-running scans without blocking HTTP.
Architecture change: Queue + worker process; job status endpoint.
Implementation difficulty: Medium (SQS) / High (Kafka, unjustified).
Resume value: Medium (a justified queue) / Low-and-forced (Kafka).
Risk of looking forced: Kafka HIGH; SQS Low.
Final recommendation: Use a lightweight queue (SQS or Celery/RQ) only when F2 makes scans
  slow. Do NOT add Kafka.
```

### S3 or Cloudflare R2
```
Should we add it? Yes — on the hosting path.
Fit score: 7/10
Where it fits: Store generated report artifacts (findings.json/md, dynamic_findings.*),
  which today are written to local dirs (reports/, agentshield-output/). For a hosted API /
  GitHub App / Lambda, object storage is the right home; DB keeps metadata + the S3 key.
Where it does NOT fit: Local CLI use — the filesystem is fine and simpler.
Feature it enables: Durable, shareable report artifacts for the hosted product.
Architecture change: A storage interface (local FS vs S3/R2) behind report writers in
  reporting/.
Implementation difficulty: Low-Medium.
Resume/interview value: Medium (standard but correct).
Risk of looking forced: Low.
Final recommendation: Add with F3/F4 hosting. R2 if you want egress-free; S3 if all-AWS.
```

### OpenTelemetry
```
Should we add it? Yes — high value, low risk; part of F3.
Fit score: 7/10
Where it fits: Trace the scan pipeline end-to-end: spans around run_static_scan
  (services/scan_service.py), per-file parse+rules, evaluate_trace (policy/policy_engine.py),
  and especially the LLM HTTP calls in dynamic/llm_judge.py (capture latency, status, token
  usage, retries). This is exactly the "make llm_routing_rate / cost / latency real" need.
Where it does NOT fit: Nowhere problematic — keep it opt-in so the CLI stays quiet by default.
Feature it enables: Real latency/cost/error metrics; the numbers METRICS_AND_OUTCOMES.md
  currently marks "Not measured yet."
Architecture change: New observability/ module; instrument service + judge boundaries;
  export to a collector (or console exporter locally).
Implementation difficulty: Medium.
Resume/interview value: High — concrete, specific ("I traced an LLM scan pipeline and cut
  p95 by X via caching") rather than buzzword "observability."
Risk of looking forced: Low — directly addresses a documented gap.
Final recommendation: Adopt in F3. This is the single best "platform engineer" signal here.
```

### Prometheus / Grafana
```
Should we add it? Yes — IF hosted; pairs with OTel.
Fit score: 6/10
Where it fits: For the hosted API, export metrics (scan count, findings rate by category,
  p95 latency, LLM cost, error rate) and dashboard them. Complements OTel traces.
Where it does NOT fit: A local CLI doesn't need a Prometheus server.
Feature it enables: Operational dashboards + alerts for the service.
Architecture change: /metrics endpoint (prometheus_client) + scrape + Grafana.
Implementation difficulty: Medium.
Resume value: Medium-High.
Risk of looking forced: Low if hosted; High if bolted onto a local CLI.
Final recommendation: Add alongside F3 hosting, after OpenTelemetry.
```

### Terraform
```
Should we add it? Yes — once there's anything to deploy.
Fit score: 7/10
Where it fits: Codify the hosting stack (Lambda/API Gateway or ECS, S3 bucket, IAM,
  secrets, the OTel collector) as IaC. Strong, honest cloud/platform signal.
Where it does NOT fit: Before there's a deployment target — don't write Terraform for
  nothing.
Feature it enables: Reproducible, reviewable infrastructure.
Architecture change: infra/terraform/ with modules for the chosen compute + storage.
Implementation difficulty: Medium.
Resume/interview value: High — "infra as code for a serverless scan service" is concrete.
Risk of looking forced: Low once F3/F4 exist.
Final recommendation: Add in Phase 4 to provision the F3/F4/Lambda/S3 stack.
```

### GitHub Actions CI/CD
```
Should we add it? Already present — extend it.
Fit score: 9/10
Where it fits: ci.yml (ruff+pytest) and scan.yml (self-scan gate) already exist and are a
  strength. Extend: add pytest --cov gate, run npm run build + frontend tests (F7), run the
  F1 eval and publish precision/recall as an artifact, and (Phase 4) a deploy job via
  Terraform.
Where it does NOT fit: n/a — it's the right tool.
Feature it enables: Coverage gating, eval-in-CI, automated deploy.
Architecture change: Extend existing workflows.
Implementation difficulty: Low.
Resume/interview value: Medium-High (already a good story; make it better).
Risk of looking forced: None.
Final recommendation: Keep and extend. Add coverage + eval + frontend-build jobs first.
```

---

## Verdict matrix

| Tech | Add? | Fit | When |
|---|---|:--:|---|
| GitHub Actions (extend) | ✅ Yes | 9 | Now |
| OpenTelemetry | ✅ Yes | 7 | F3 |
| Terraform | ✅ Yes | 7 | Phase 4 |
| S3 / R2 | ✅ Yes | 7 | F3/F4 |
| AWS Lambda | ✅ Yes | 7 | Phase 4 |
| Redis | 🟡 Maybe | 6 | After F2 |
| Prometheus/Grafana | 🟡 Maybe | 6 | If hosted |
| LangGraph / orchestration | 🟡 Maybe | 6 | F11 only |
| Queue (SQS/Celery/RQ) | 🟡 Maybe | 6 | With F9 |
| LangChain | ❌ No | 3 | — (use small vector lib if ever) |
| DynamoDB | ❌ No | 3 | — (use Postgres) |
| Amazon EKS | ❌ No | 2 | — (Lambda/container instead) |
| Amazon SageMaker | ❌ No | 2 | F12 only, far future |
| Kafka | ❌ No | 2 | — (overkill) |
