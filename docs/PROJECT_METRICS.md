# AgentShield — Project Metrics

*Generated: 2026-04-03T22:45:45.160140+00:00  |  Version: 0.1.0*

> All values are computed from real scan, benchmark, and simulation runs. No values are hardcoded or estimated.

## Coverage Summary

| Metric | Value |
| --- | --- |
| Attack categories covered | 5 |
| Categories | TOOL_POISONING, INDIRECT_PROMPT_INJECTION, UNSAFE_PERMISSIONS, DATA_EXFILTRATION_PATTERN, TASK_DRIFT |
| Total benchmark test cases | 9 |
| Benchmark pass rate | 100% |
| Dynamic simulation scenarios | 5 |
| Distinct rule IDs | 11 |

## Static Scan (sample fixtures)

| Metric | Value |
| --- | --- |
| Configs / workflows scanned | 2 |
| Total findings | 6 |
| High or critical findings | 3 |
| Overall risk score (0–100) | 54 |

## Benchmark Performance

| Metric | Value |
| --- | --- |
| Total cases | 9 |
| Passed | 9 |
| Failed | 0 |
| Pass rate | 100% |
| Avg scan time (ms) | 0.0 |
| P95 scan time (ms) | 0.0 |
| Avg scan time (s) | 0.0000 |
| P95 scan time (s) | 0.0000 |

### Category Breakdown

| Category | Total | Passed | Failed |
| --- | --- | --- | --- |
| DATA_EXFILTRATION_PATTERN | 2 | 2 | 0 |
| INDIRECT_PROMPT_INJECTION | 2 | 2 | 0 |
| TASK_DRIFT | 2 | 2 | 0 |
| TOOL_POISONING | 2 | 2 | 0 |
| UNSAFE_PERMISSIONS | 1 | 1 | 0 |

## Dynamic Simulation

| Metric | Value |
| --- | --- |
| Scenarios run | 5 |
| Total policy violations detected | 25 |
| Categories covered | DATA_EXFILTRATION_PATTERN, INDIRECT_PROMPT_INJECTION, TASK_DRIFT, TOOL_POISONING, UNSAFE_PERMISSIONS |
| Max severity seen | CRITICAL |

## Rule Coverage

| Metric | Value |
| --- | --- |
| Total distinct rule IDs | 11 |

| Category | Rule IDs |
| --- | --- |
| DATA_EXFILTRATION_PATTERN | EXF-001, EXF-002, EXF-003 |
| INDIRECT_PROMPT_INJECTION | OV-001, OV-002 |
| TASK_DRIFT | DRIFT-001, DRIFT-002 |
| TOOL_POISONING | SP-001 |
| UNSAFE_PERMISSIONS | PERM-001, PERM-002, PERM-003 |

### All Rules

| Rule ID | Category | Severity |
| --- | --- | --- |
| `DRIFT-001` | TASK_DRIFT | MEDIUM |
| `DRIFT-002` | TASK_DRIFT | LOW |
| `EXF-001` | DATA_EXFILTRATION_PATTERN | CRITICAL |
| `EXF-002` | DATA_EXFILTRATION_PATTERN | MEDIUM |
| `EXF-003` | DATA_EXFILTRATION_PATTERN | LOW |
| `OV-001` | INDIRECT_PROMPT_INJECTION | HIGH |
| `OV-002` | INDIRECT_PROMPT_INJECTION | MEDIUM |
| `PERM-001` | UNSAFE_PERMISSIONS | HIGH |
| `PERM-002` | UNSAFE_PERMISSIONS | MEDIUM |
| `PERM-003` | UNSAFE_PERMISSIONS | LOW |
| `SP-001` | TOOL_POISONING | HIGH |

## Cost and Routing

| Metric | Value |
| --- | --- |
| Rules-only detection rate | 100% |
| LLM routing rate | 0% |
| Avg scan cost (USD) | $0.00 |

> Rules-only rate is 100% because all detection is performed by deterministic rule checks. No LLM calls are made in Phase 1–4. The `BaseJudge` interface exists for a future LLM layer.

## Data Sources

| Metric group | Source |
| --- | --- |
| Scan metrics | `agentshield scan benchmarks/fixtures/` |
| Benchmark metrics | `agentshield benchmark benchmarks/cases/` |
| Dynamic metrics | `agentshield simulate --scenario all` |
| Rule coverage | Rule checkers called with maximal probe string |
| Cost / routing | Structural: no LLM calls in Phase 1–4 |
