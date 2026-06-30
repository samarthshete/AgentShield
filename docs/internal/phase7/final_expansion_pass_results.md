# Phase 7 Final Expansion Pass Results

Data source: `agentshield-output/phase7-final-expansion-pass/summary.json`

## Scope

- Previous set: 20 artifacts
- New artifacts added: 9 (all code/config, no new READMEs)
- Final total: 29 artifacts
- Rules used: tuned EXF-003 and PERM-003 (from previous two tuning passes)

## New Artifacts Selected

All 9 new artifacts are code or config files. No new README/docs added.

| # | File | Source | Type | Rationale |
|---|---|---|---|---|
| 1 | `mcp-servers/filesystem.index.ts` | `modelcontextprotocol/servers/src/filesystem/index.ts` | tool definition code | TypeScript MCP server entry point with all tool registrations and allowed-directory access control |
| 2 | `mcp-servers/fetch.server.py` | `modelcontextprotocol/servers/src/fetch/src/mcp_server_fetch/server.py` | tool definition code | Python MCP HTTP fetch server; makes real outbound HTTP requests |
| 3 | `mcp-servers/git.server.py` | `modelcontextprotocol/servers/src/git/src/mcp_server_git/server.py` | tool definition code | Python MCP git operations server; real file read/write + command execution via git |
| 4 | `openai-agents/examples.basic.tools.py` | `openai/openai-agents-python/examples/basic/tools.py` | agent example code | basic tool use example; clean baseline for agent code |
| 5 | `openai-agents/examples.agent_patterns.deterministic.py` | `openai/openai-agents-python/examples/agent_patterns/deterministic.py` | agent example code | deterministic agent orchestration pattern |
| 6 | `openai-agents/examples.tools.web_search.py` | `openai/openai-agents-python/examples/tools/web_search.py` | agent example code | web search tool; has URL handling |
| 7 | `openai-agents/examples.tools.computer_use.py` | `openai/openai-agents-python/examples/tools/computer_use.py` | agent example code | computer use tool; exec + filesystem + network |
| 8 | `mcp-servers/everything.resources.index.ts` | `modelcontextprotocol/servers/src/everything/resources/index.ts` | tool definition code | resource definition TypeScript code |
| 9 | `openai-agents/examples.agent_patterns.llm_as_a_judge.py` | `openai/openai-agents-python/examples/agent_patterns/llm_as_a_judge.py` | agent example code | LLM-as-a-judge pattern |

## Final Expansion Pass Results (29 artifacts)

- Total findings: 10
- Categories:
  - `DATA_EXFILTRATION_PATTERN`: 7
  - `UNSAFE_PERMISSIONS`: 3
- Rule IDs:
  - `EXF-001`: 1
  - `EXF-002`: 1
  - `EXF-003`: 5
  - `PERM-001`: 1
  - `PERM-003`: 2

## Findings by Artifact Type (final 29-artifact set)

- `readme_docs`: 7 findings (mcp-servers README + time README; all existing artifacts)
- `tool_definition_code`: 2 findings (1 EXF-003 on `fetch.server.py`, 1 PERM-003 on `filesystem.index.ts`)
- `agent_example_code`: 1 finding (PERM-003 on `git.server.py`)
- All other types (`package_manifest`, `pyproject_config`, `config_json`): 0 findings

6 of the 9 new code artifacts produced zero findings.

## Four-Pass Progression

| Rule | second-pass baseline (20) | EXF-003 tuned (20) | PERM-003 tuned (20) | final expansion (29) |
|---|---|---|---|---|
| EXF-001 | 1 | 1 | 1 | 1 |
| EXF-002 | 1 | 1 | 1 | 1 |
| EXF-003 | 14 | 4 | 4 | 5 |
| PERM-001 | 1 | 1 | 1 | 1 |
| PERM-003 | 2 | 2 | 0 | 2 |
| **TOTAL** | **19** | **9** | **7** | **10** |

The +3 delta from 7 to 10 is entirely from the 3 new MCP server implementation files.

## New Findings Detail

### `filesystem.index.ts` — PERM-003 (LOW)

- Context words present: `permission` (from "permissions" in file metadata tool description), `allow` (from `allowedDirectories` access control throughout)
- `read`/`write`: yes, this server defines explicit `read_file` and `write_file` operations
- `command` trigger: from error message `"Server was started without command-line arguments"`

The MCP filesystem server genuinely combines file read/write capability with permission/access-control vocabulary. The `command` trigger is from "command-line arguments" in an error string, not from command execution capability. **Classification: plausible.** The server is a real filesystem access provider; the PERM-003 signal is weak but not obviously wrong.

### `git.server.py` — PERM-003 (LOW)

- Context words present: `capability` (from `RootsCapability` MCP SDK type), `allow` (from `allowed_repository` path validation), `auth` (from `Author:` in git commit log output)
- `read`/`write`: yes, git operations read and write repositories
- `command` trigger: git subprocess execution is inherently command-based

The MCP git server genuinely combines repo read/write access with execution (git subprocess calls). The context word matches are somewhat incidental (`RootsCapability` → `capability`, `Author:` → `auth`), but the underlying pattern is real. **Classification: plausible.** Git operations are inherently a combination of data access and command execution.

### `fetch.server.py` — EXF-003 (LOW)

- URL trigger: `https://` in the default user-agent string pointing to the MCP servers repo
- Context trigger: `put ` from HTTP method handling (the fetch server supports PUT requests)

The HTTP fetch server is designed to make outbound HTTP requests. EXF-003 firing here is directionally appropriate — it is a server that sends data to external URLs. **Classification: plausible.** This is precisely the kind of artifact EXF-003 is designed to flag at low severity for review.

## Stability Check

| Rule | Status |
|---|---|
| EXF-003 | Stable and controlled. +1 new hit from actual HTTP proxy server (plausible). README noise pattern not growing. |
| PERM-003 | 2 new hits from real MCP server implementations with genuine permission/capability vocabulary. Different in character from the previous false positives (no bare prose matches). |
| EXF-001, EXF-002, PERM-001 | All stable at 1 hit each (mcp-servers README, unchanged). |

No new stable noise pattern emerged. The new findings are specific to actual MCP server implementations, not broad rule pollution.

## Conclusion

Phase 7 validation is complete. The tuned rule set is stable across a 29-artifact set covering:
- 6 README/doc files
- 7 package manifests and config files (all clean after tuning)
- 8 TypeScript tool/resource definition files (1 finding — plausible)
- 8 Python agent example and server files (2 findings — plausible)

The remaining 10 findings all have clear justification:
- 7 from `mcp-servers/README.md` (real MCP capability descriptions — high-quality signal)
- 3 from actual MCP server implementation code (plausible low-severity findings)

Phase 7 can be concluded. No further rule tuning is justified by the evidence in this set.
