# AgentShield Labeled Evaluation Corpus

This directory contains `*.labels.yaml` files consumed by:

```bash
python -m agentshield eval benchmarks/labeled
```

Each label file points at an artifact path relative to this directory. The corpus currently
contains **50 labeled artifacts** and mixes:

- small authored smoke-test fixtures (`clean-tool.json`, `tool-poisoning.json`)
- real public artifacts from `benchmarks/phase7_public_artifacts/`
- existing AgentShield benchmark cases from `benchmarks/cases/`
- authored challenge fixtures that fill coverage gaps across all five categories

Label rules:

- `true_positive: true` means the artifact context supports the category/rule finding.
- `expected_findings: []` means the artifact is a clean negative for the current static
  threat model.
- `case_type: hard_negative` marks benign or near-miss artifacts that should remain clean.
- Low-severity findings are still valid labels when the artifact should be reviewed, but
  notes must explain why the signal is plausible.
- `evidence_terms` validates that the finding evidence/title includes the expected marker.

Current benchmark shape:

- 50 labeled artifacts
- 27 hard negatives
- 51 expected positive findings
- at least 10 positives in every current category
- 43 evidence-span validations

Current measured result:

- micro precision / recall / F1: 96.23% / 100% / 98.08%
- macro precision / recall / F1: 96.92% / 100% / 98.33%
- weighted precision / recall / F1: 96.69% / 100% / 98.20%
- severity-weighted recall: 100%
- Wilson 95% CI: precision 87.25%-98.96%, recall 93.00%-100%

Two known false positives remain, both low-severity `EXF-003` README URL cases. Keep them
in the corpus; they make the benchmark more honest and give semantic detection something
specific to improve.
