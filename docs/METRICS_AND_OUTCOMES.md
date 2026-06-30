# AgentShield — Metrics & Outcomes

> Only real, source-backed numbers appear as measured. Everything unproven is marked
> **Not measured yet** — no invented figures. Sources: `reports/metrics.json`,
> `agentshield-output/phase7-final-expansion-pass/summary.json`, live `pytest` run on
> 2026-06-29, and direct source inspection.

---

## 1. Measured outcomes currently in the codebase

### Test suite (live run, 2026-06-29)
- **116 tests passed**, 0 failed, ~1.5s (`pytest -q`).
- Breakdown: `test_dynamic.py` 48, `test_metrics.py` 17, `test_rules.py` 12,
  `test_exit_codes.py` 8, `test_benchmark_runner.py` 5, `test_eval.py` 9,
  `test_web_api.py` 5, `test_discovery.py` 3,
  `test_benchmark_loader.py` 3, `test_mcp_parser.py` 3, `test_reporting.py` 3.

### Benchmark suite (`reports/metrics.json`)
- **9/9 cases passed → 100% pass rate.**
- `avg_scan_time_ms`: **0.11**; `p95_scan_time_ms`: **1.0**.
- Category coverage: TOOL_POISONING 2/2, DATA_EXFILTRATION_PATTERN 2/2,
  INDIRECT_PROMPT_INJECTION 2/2, TASK_DRIFT 2/2, UNSAFE_PERMISSIONS 1/1.
- ⚠️ **Caveat:** cases are **self-authored** alongside the rules — this measures
  internal consistency, not real-world accuracy.

### Static scan over fixtures (`reports/metrics.json`)
- `configs_scanned`: 2; `findings_total`: 6; `findings_high_or_critical`: 3;
  `overall_risk_score`: 54.

### Dynamic simulation (`reports/metrics.json`)
- `scenarios_run`: 5; `violations_total`: 25; all 5 categories covered;
  `max_severity_seen`: CRITICAL.
- ⚠️ **Caveat:** scenarios are scripted by the project (`dynamic/attack_generator.py`);
  this measures policy-engine behavior on known inputs.

### Rule inventory (`reports/metrics.json`)
- **11 rules** across 5 categories: EXF-001/002/003, OV-001/002, DRIFT-001/002,
  PERM-001/002/003, SP-001.

### Labeled evaluation corpus (`agentshield eval benchmarks/labeled`)
- Corpus size: **50 labeled artifacts**.
- Composition: 29 public Phase 7 artifacts, 9 existing benchmark cases, 10 authored
  challenge fixtures, 2 authored smoke fixtures.
- Hard negatives: **27**.
- Expected positive findings: **51**.
- Minimum category support: **10+ positives in every current category**.
- Current result: **51 TP / 2 FP / 0 FN**.
- Micro precision / recall / F1: **96.23% / 100% / 98.08%**.
- Macro precision / recall / F1: **96.92% / 100% / 98.33%**.
- Weighted precision / recall / F1: **96.69% / 100% / 98.20%**.
- Wilson 95% CI: precision **87.25%–98.96%**, recall **93.00%–100%**.
- Severity-weighted recall: **100%**.
- Evidence-span validation: **43/43 passed**.
- Known false positives: 2 low-severity `EXF-003` README URL-only cases
  (`mcp-servers/time.README.md`, `openai-agents/README.md`).
- ⚠️ **Caveat:** this is now a credible development benchmark, but still not a broad
  market-wide accuracy claim because part of the corpus is authored challenge data.

### Phase 7 real-world validation (`agentshield-output/phase7-final-expansion-pass/summary.json`)
- **29 public artifacts** scanned (MCP servers, agent examples, READMEs).
- **10 findings total:** EXF-003 ×5, EXF-001 ×1, EXF-002 ×1, PERM-001 ×1, PERM-003 ×2.
- By category: DATA_EXFILTRATION_PATTERN 7, UNSAFE_PERMISSIONS 3.
- Tuning progression on the 20-artifact set: **19 → 9 → 7 findings** after EXF-003 then
  PERM-003 context gates (i.e. measurable noise reduction).
- ⚠️ These are **counts on unlabeled artifacts** — they characterize noise volume, **not**
  precision/recall, because there's no ground-truth labeling of which findings are true.

### Structural "rates" (honest note)
`rules_only_rate=1.0`, `llm_routing_rate=0.0`, `avg_scan_cost_usd=0.0` in
`metrics.json` are **structural constants** (the default path makes no LLM calls), not
measured behavioral rates. Documented as such in the repo-root `DECISIONS.md`.

## 2. Performance metrics that SHOULD be tracked

| Metric | Now | How to measure |
|---|---|---|
| Per-file scan latency (p50/p95) | partial (benchmark avg/p95 on tiny inputs) | Time `run_static_scan` across a large real corpus; record distribution |
| Full-repo scan time vs repo size | **Not measured** | Scan repos of 10/100/1000 files; plot time vs file count |
| Memory under large input | **Not measured** | `tracemalloc`/`/usr/bin/time -v` on a big monorepo |
| LLM judge latency + cost per scenario | **Not measured** | Instrument `OpenAIJudge`/`ClaudeJudge` round-trip + token usage |
| API throughput / concurrency ceiling | **Not measured** | `locust`/`k6` against `/api/scan` |

## 3. Product metrics that SHOULD be tracked

| Metric | Now | How to measure |
|---|---|---|
| **Detection precision / recall / F1** | micro 96.23% / 100% / 98.08% on 50 labeled artifacts | Expand independent public corpus beyond authored challenges |
| False-positive rate in prose/docs | 2 known README URL-only false positives in labeled corpus | Add more benign docs/repos and track FP/1k lines |
| Findings per category in the wild | partial (29-artifact counts; source files now included in directory mode) | Expand corpus; track category distribution |
| CI gate trigger rate | **N/A (unreleased)** | Count `scan.yml` runs that fail on high/critical |
| Adoption (installs, scans, repos) | **N/A (unreleased)** | PyPI stats + opt-in privacy-respecting telemetry |

## 4. Engineering metrics that SHOULD be tracked

| Metric | Now | How to measure |
|---|---|---|
| Test count / pass rate | **116 / 100%** ✅ | `pytest` (already in CI) |
| Code coverage % | **Not measured** | `pytest --cov=agentshield`; gate in `ci.yml` |
| Frontend test coverage | **0% (no tests)** | Add Vitest + RTL; report coverage |
| Lint cleanliness | tracked ✅ | `ruff` in `ci.yml` |
| Build health (frontend) | green ✅ | `npm run build` (manual; add to CI) |
| Mean time to green CI | **Not measured** | GitHub Actions analytics |

## 5. Suggested benchmark tests to generate defensible metrics

1. **Labeled detection benchmark (highest value).** Curate ≥50 real MCP/agent artifacts;
   have a human label each finding true/false. Script precision/recall/F1. This is the
   one number that makes the product credible.
2. **Adversarial evasion benchmark.** Take known-true positives and paraphrase/obfuscate
   them (synonyms, spacing, encoding). Measure how many the substring rules still catch —
   this quantifies the paraphrase-evasion weakness honestly.
3. **Negative/clean corpus.** Scan a large set of benign configs/docs; measure false
   positives per 1,000 files (noise rate).
4. **Scale benchmark.** Scan synthetic repos at 10/100/1k/10k files; record time + memory.
5. **Judge value benchmark.** Run rule-based vs OpenAI vs Claude judges on the same
   dynamic set; measure dismissal precision (did the LLM dismiss only real false
   positives?) + latency + cost.
6. **Coverage gate.** Add `pytest --cov` with a minimum threshold in `ci.yml`.

> Until #1 exists, AgentShield can honestly claim **"11 rules, 5 categories, 103 passing
> tests, 100% on a 9-case self-authored benchmark, validated for noise on 29 public
> artifacts"** — and must **not** claim a precision/recall figure, because none is measured.

---

## 6. Strategy-aligned outcomes to track (added 2026-06-24)

> Tied to the top-3 build plan ([IMMEDIATE_BUILD_PLAN.md](./IMMEDIATE_BUILD_PLAN.md)) and the
> v2 architecture ([V2_ARCHITECTURE_PROPOSAL.md](./internal/V2_ARCHITECTURE_PROPOSAL.md)).
> Values are either measured below or explicitly marked **Not measured yet**. No numbers
> are invented.

### From Feature 1 (labeled validation harness)
| Outcome | Status | Test that produces it |
|---|---|---|
| Overall precision / recall / F1 | micro 96.23% / 100% / 98.08% on 50 labeled artifacts | `agentshield eval benchmarks/labeled` vs labels |
| Per-category P/R/F1 (TP/IPI/UP/EXF/TD) | At least 10 positives per current category | Same harness, grouped by category |
| False-positive rate per 1,000 lines of prose | **Not measured yet** | Run scorer over a benign docs corpus |
| Corpus size + independent-label provenance | 50 labeled artifacts; provenance in each label file | Count + document `benchmarks/labeled/**` |

### From Feature 2 (hybrid rules+semantic engine)
| Outcome | Status | Test that produces it |
|---|---|---|
| **Hybrid F1 − rules-only F1** (the headline lift) | **Not measured yet** | Run F1 harness in `--mode rules` then `--mode hybrid`, compare |
| Real `llm_routing_rate` (escalated ÷ candidates) | **Not measured yet** | Instrument triage in `services/scan_service.py`; replace hardcoded `0.0` in `metrics/aggregator.py:129` |
| Semantic-cache hit rate | **Not measured yet** | Count cache hits/misses in `detect/semantic.py` |
| Recall gain on paraphrased/obfuscated attacks | **Not measured yet** | Adversarial benchmark (F10): rules-only vs hybrid catch rate |
| LLM token cost + USD per scan | **Not measured yet** | Sum token usage from semantic-stage spans (F3 OTel) |

### From Feature 3 (productionized API)
| Outcome | Status | Test that produces it |
|---|---|---|
| p50 / p95 scan latency (rules vs hybrid) | **Not measured yet** | OTel spans around `run_scan`; aggregate from traces |
| Auth failure rate / unauthorized attempts | **Not measured yet** | Structured logs on the auth dependency |
| API error rate | **Not measured yet** | OTel/Prometheus on `web/app.py` |
| Container build + cold-start time | **Not measured yet** | Time `docker build` / first request |

### Additional recommended benchmark tests (extends §5)
7. **Routing-efficiency benchmark.** Measure what % of candidates the triage layer escalates
   to the LLM at a fixed F1 — proves the "cost-aware" claim with a number.
8. **Degradation test.** Force the semantic stage to fail mid-scan; assert rules-only
   fallback + `semantic_unavailable` flag, and record the result-completeness delta.
9. **Auth/security regression test.** Assert every `/api/*` route except `/api/health`
   rejects unauthenticated requests (turn it into a standing CI test).

> Discipline reminder: each feature lands only when its row above moves from **Not measured
> yet** to a real, reproducible number written into `metrics.json` and shown in CI. That is
> the difference between "I added a semantic detector" and "I improved F1 from X to Y."
