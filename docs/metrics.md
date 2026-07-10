# Project Metrics

Track only measured metrics here. Canonical sources:
[METRICS_AND_OUTCOMES.md](./METRICS_AND_OUTCOMES.md) (numbers + caveats) and the
generated [PROJECT_METRICS.md](./PROJECT_METRICS.md) (`agentshield metrics`).

## AgentShield (measured, 2026-07-09)

- attack_categories: 5
- distinct_rules: 11
- total_benchmark_cases: 9 (100% pass — self-authored smoke suite)
- labeled_eval_corpus: 50 artifacts (27 hard negatives)
- labeled_eval_micro_precision: 96.23%
- labeled_eval_micro_recall: 100%
- labeled_eval_micro_f1: 98.08%
- workflows_or_configs_scanned (fixtures): 2
- findings_total (fixtures): 6
- findings_high_or_critical (fixtures): 3
- avg_scan_time_ms (benchmark cases): ~0.1
- backend_tests: 136 passing
- frontend_tests: 12 passing
- llm_routing_rate: 0% (structural — LLM tier is flag-off; measured offline, not a net win)
- review_time_before_minutes / after_minutes: not measured
