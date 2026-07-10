# Benchmark Plan

> Status 2026-07-09: both phases below are done and superseded by the labeled eval
> corpus — `benchmarks/cases/` (9 YAML smoke cases, 100% pass, gated in CI) and
> `benchmarks/labeled/` (50 labeled artifacts; micro F1 98.08%, gated in CI at
> `--min-f1 0.95`). See [METRICS_AND_OUTCOMES.md](./METRICS_AND_OUTCOMES.md).
> Next: expand the public-only share of the labeled corpus; an adversarial
> paraphrase/obfuscation benchmark remains planned.

Phase 1 (done):
- define benchmark case format
- create category folders

Phase 2 (done, evolved):
- 9 smoke cases across 5 categories + 50-artifact labeled eval corpus with
  reproducible expected findings and per-category support
