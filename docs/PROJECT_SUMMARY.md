# AgentShield — Project Summary

AgentShield is a security evaluation framework for MCP-connected AI agents and tool-using workflows. It checks configs, manifests, and agent traces for known attack patterns and reports findings with severity, evidence, and recommendation.

## What it covers

Five attack categories, 11 rules:

| Category | Rules | Severity range |
|---|---|---|
| Tool Poisoning | `SP-001` | HIGH |
| Indirect Prompt Injection | `OV-001`, `OV-002` | HIGH / MEDIUM |
| Unsafe Permissions | `PERM-001`, `PERM-002`, `PERM-003` | HIGH → LOW |
| Data Exfiltration Patterns | `EXF-001`, `EXF-002`, `EXF-003` | CRITICAL → LOW |
| Task Drift | `DRIFT-001`, `DRIFT-002` | MEDIUM / LOW |

## What was built (phases 0–7)

| Phase | Deliverable |
|---|---|
| 0 | Project setup, architecture, threat model |
| 1 | Static scanner: parser, rules, severity scoring, JSON/Markdown reports, SQLite |
| 2 | Benchmark runner: YAML case definitions, pass/fail tracking, 9 cases |
| 3 | Dynamic simulation: 5 scripted attack scenarios, policy engine, trace capture |
| 4 | CI/CD: GitHub Actions workflows, PR comment, exit-code contract |
| 5 | Metrics: real aggregation from scan/benchmark/simulation data |
| 6 | LLM judge: optional OpenAI/Claude judge behind a clean interface, provenance-aware results |
| 7 | Real-world validation: 29 public artifacts, 2 tuning passes, rule set frozen |

## Validation outcome (Phase 7)

Scanned 29 real public artifacts from `modelcontextprotocol/servers`, `openai/openai-agents-python`, and `anthropics/claude-code`.

Final findings: 10 across 29 artifacts.

Tuning done:
- `EXF-003`: context gate added — URL markers now require outbound/exfiltration context words. Reduced noise from 14 to 4 findings on the 20-artifact set.
- `PERM-003`: context gate added — rule now requires permission/capability vocabulary to be present. Eliminated 2 README/prose false positives.

Stronger rules (`EXF-001`, `EXF-002`, `PERM-001`) were not changed. All 9 benchmark cases still pass. 98 tests pass.

## Key design decisions

- Default judge is `rule_based` — deterministic, no API dependency, works in CI
- LLM judge is opt-in (`--judge openai` or `--judge claude`) and fail-fast on API errors
- Raw policy violations are always preserved, separate from judge-reviewed results
- SQLite stores raw violation count, confirmed count, judge type, and per-violation status
- Exit code contract: 0 = clean, 1 = findings at/above threshold, 2 = invalid arguments

## Known limitations

- Pattern matching, not semantic understanding
- Dynamic scenarios are scripted; they don't replay real agent traces
- LLM judge dismisses by `policy_id` — multiple violations sharing an ID are all dismissed together
- Judge dismissal notes are not persisted to SQLite
- Claude happy-path (successful real dismissal run) has not been validated end-to-end

## Quick start

```bash
pip install -e .

# Static scan
agentshield scan benchmarks/fixtures --format both

# Benchmark
agentshield benchmark benchmarks/cases

# Dynamic simulation (default: rule-based judge)
agentshield simulate

# Dynamic simulation with OpenAI judge
agentshield simulate --judge openai --llm-api-key $OPENAI_API_KEY

# Metrics
agentshield metrics
```

## Test and lint

```bash
pytest --tb=short -q     # 98 tests
ruff check agentshield tests
```
