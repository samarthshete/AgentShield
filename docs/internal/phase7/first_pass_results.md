# Phase 7 First Pass Results

Data sources:
- static scan outputs: `agentshield-output/phase7-first-pass/scans/*/findings.json`
- static summary: `agentshield-output/phase7-first-pass/summary.json`
- judge comparison: `agentshield-output/phase7-first-pass/openai_judge_comparison.json`

## Static Scan Summary (7 public artifacts)

- Total findings: 11
- Categories triggered:
  - `DATA_EXFILTRATION_PATTERN`: 9
  - `UNSAFE_PERMISSIONS`: 2
- Rule IDs triggered:
  - `EXF-003`: 7
  - `PERM-001`: 1
  - `PERM-003`: 1
  - `EXF-001`: 1
  - `EXF-002`: 1

Per artifact findings:
- `mcp_servers_readme`: 5
- `anthropic_claude_code_readme`: 3
- `openai_agents_readme`: 1
- `mcp_filesystem_pkg`: 1
- `mcp_memory_pkg`: 1
- `mcp_fetch_pyproject`: 0
- `mcp_git_pyproject`: 0

## Early Noise Signals

Likely noisy patterns from this first pass:
- `EXF-003` on plain documentation URLs (`http://`, `https://`) and transfer words (`curl`) in README content
- `PERM-003` in badge/link-rich README text with no actual runtime permission request

Potentially useful but needs more real samples:
- `PERM-001` in MCP server docs where filesystem/network capability text is present
- `EXF-001` / `EXF-002` in README prose mentioning terms like `api key` / `token` (could be real warning context, not malicious behavior)

## Where OpenAI Review Helps (Existing Judge Flow)

OpenAI review was run on the existing dynamic scenarios to evaluate dismissal behavior:
- Raw: 25
- Confirmed: 21
- Dismissed: 4
- Dismiss rate: 16%

Dismissals were limited to lower-signal IDs:
- `POLSTA-DRIFT-002` (TASK_DRIFT)
- `POLSTA-EXF-003` (DATA_EXFILTRATION_PATTERN)

This is directionally useful for trimming low-signal findings, but it does not remove the known coarse behavior:
- dismissal is by `policy_id`, so repeated IDs are dismissed as a group.

## First-Pass Conclusion

- Phase 7 first pass succeeded: real public artifacts were scanned and produced useful initial signal.
- Most observed noise is in low-severity transfer/URL matching (`EXF-003`) on documentation-heavy files.
- Next step should be to expand the public set before any rule or prompt tuning.
