# Phase 7 Second Pass Results

Data sources:
- static outputs: `agentshield-output/phase7-second-pass/scans/*/findings.json`
- static summary: `agentshield-output/phase7-second-pass/summary.json`
- first-pass baseline: `agentshield-output/phase7-first-pass/summary.json`
- LLM context run: `agentshield-output/phase7-second-pass/openai_judge_comparison.json`

## Scope

- First pass baseline: 7 artifacts
- Second pass set: 20 artifacts (13 new artifacts added)
- This is still a validation step. No rule tuning or prompt tuning was done.

## Second-Pass Static Summary

- Total findings: 19
- Categories:
  - `DATA_EXFILTRATION_PATTERN`: 16
  - `UNSAFE_PERMISSIONS`: 3
- Rule IDs:
  - `EXF-003`: 14
  - `PERM-003`: 2
  - `PERM-001`: 1
  - `EXF-001`: 1
  - `EXF-002`: 1

## Comparison vs First Pass

- First pass findings: 11
- Second pass findings: 19
- Delta: +8 findings

Rule deltas:
- `EXF-003`: +7
- `PERM-003`: +1
- `PERM-001`: no change
- `EXF-001`: no change
- `EXF-002`: no change

Interpretation: growth is concentrated in low-signal `EXF-003` and, to a smaller extent, `PERM-003`.

## Findings by Artifact Type

- `readme_docs` (6 artifacts): 12 findings
  - Noise-heavy: `EXF-003` (8), `PERM-003` (1)
  - Also contains the only `PERM-001`, `EXF-001`, `EXF-002` hits (from `mcp-servers/README.md`)
- `package_manifest` (4 artifacts): 4 findings
  - All `EXF-003` low-severity hits
- `pyproject_config` (4 artifacts): 1 finding
  - Mostly clean; one `EXF-003` hit (`openai-agents/pyproject.toml`)
- `config_json` (2 artifacts): 0 findings
  - Both settings JSON files were clean
- `prompt_definition_code` (1 artifact): 0 findings
- `tool_definition_code` (1 artifact): 0 findings
- `agent_example_code` (2 artifacts): 2 findings
  - `examples.mcp.filesystem_example.main.py`: `EXF-003` + `PERM-003`
  - `examples.tools.shell.py`: clean

## Likely Noise Candidates by Type

- `EXF-003` remains the dominant noise candidate.
  - Concentration: README/docs first, package manifests second.
- `PERM-003` appears lower-volume but still likely noisy.
  - Concentration: docs and one agent example file.
- Config-oriented artifacts (`config_json`, most `pyproject_config`) remain mostly clean.

## OpenAI Review Context (Used Sparingly)

The existing dynamic comparison was rerun to keep dismissal behavior in view while analyzing low-signal static findings:

- Raw: 25
- Confirmed: 21
- Dismissed: 4
- Dismiss rate: 16%
- Dismissals remained in low-signal IDs:
  - `POLSTA-DRIFT-002`
  - `POLSTA-EXF-003`

This supports the same conclusion as the first pass: OpenAI review helps trim low-signal findings, but does not change higher-signal detections in this test set.

## Second-Pass Conclusion

- `EXF-003` is still the main noise candidate, especially in docs and metadata-heavy artifacts.
- `PERM-003` remains a secondary noise candidate, mostly in docs/example contexts.
- Config files are mostly clean in this sample.
- Phase 7 should continue with a small additional curated set before any tuning decision.

## Follow-up

- A narrow tuning pass was run after this baseline.
- Results are recorded in `docs/phase7/tuning_pass_results.md`.
