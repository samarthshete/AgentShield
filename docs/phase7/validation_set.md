# Phase 7 Public Validation Set

Controlled public set used for Phase 7 validation.

- First pass: 7 artifacts
- Second pass expansion: 13 new artifacts
- Final expansion pass: 9 new artifacts
- Current total: 29 artifacts

## First Pass (7 artifacts)

1. `https://github.com/modelcontextprotocol/servers` → `README.md`
   - Type: README/docs
   - Why chosen: central MCP reference doc
   - Signal expected: permission and transfer-language noise in prose
2. `https://github.com/modelcontextprotocol/servers` → `src/filesystem/package.json`
   - Type: package manifest
   - Why chosen: real MCP metadata example
   - Signal expected: URL/transfer-token matches in metadata
3. `https://github.com/modelcontextprotocol/servers` → `src/memory/package.json`
   - Type: package manifest
   - Why chosen: second MCP manifest for balance
   - Signal expected: low-signal exfil pattern matches
4. `https://github.com/modelcontextprotocol/servers` → `src/fetch/pyproject.toml`
   - Type: pyproject config
   - Why chosen: Python config baseline from MCP ecosystem
   - Signal expected: low/no findings
5. `https://github.com/modelcontextprotocol/servers` → `src/git/pyproject.toml`
   - Type: pyproject config
   - Why chosen: second Python config baseline
   - Signal expected: low/no findings
6. `https://github.com/openai/openai-agents-python` → `README.md`
   - Type: README/docs
   - Why chosen: tool-using agent framework docs
   - Signal expected: low-signal transfer matches in usage text
7. `https://github.com/anthropics/claude-code` → `README.md`
   - Type: README/docs
   - Why chosen: second major agent framework docs
   - Signal expected: permission/exfil wording in documentation

## Second Pass Additions (13 artifacts)

1. `https://github.com/modelcontextprotocol/servers` → `src/everything/package.json`
   - Type: package manifest
   - Why chosen: high-capability MCP server manifest
   - Signal expected: metadata-driven exfil token matches
2. `https://github.com/modelcontextprotocol/servers` → `src/sequentialthinking/package.json`
   - Type: package manifest
   - Why chosen: second nontrivial MCP server manifest
   - Signal expected: low-signal URL/transfer terms
3. `https://github.com/modelcontextprotocol/servers` → `src/time/pyproject.toml`
   - Type: pyproject config
   - Why chosen: third MCP Python config
   - Signal expected: mostly clean config baseline
4. `https://github.com/modelcontextprotocol/servers` → `src/everything/README.md`
   - Type: README/docs
   - Why chosen: server-specific operational docs
   - Signal expected: docs-heavy EXF-003 behavior
5. `https://github.com/modelcontextprotocol/servers` → `src/sequentialthinking/README.md`
   - Type: README/docs
   - Why chosen: second server-specific docs sample
   - Signal expected: docs-heavy EXF-003 behavior
6. `https://github.com/modelcontextprotocol/servers` → `src/time/README.md`
   - Type: README/docs
   - Why chosen: Python MCP server docs
   - Signal expected: docs-heavy EXF-003 behavior
7. `https://github.com/modelcontextprotocol/servers` → `src/everything/prompts/index.ts`
   - Type: prompt definition code
   - Why chosen: concrete prompt registration code
   - Signal expected: whether prompt-definition source triggers scanner
8. `https://github.com/modelcontextprotocol/servers` → `src/everything/tools/index.ts`
   - Type: tool definition code
   - Why chosen: concrete tool registration code
   - Signal expected: whether tool-definition source triggers permission/exfil rules
9. `https://github.com/openai/openai-agents-python` → `pyproject.toml`
   - Type: pyproject config
   - Why chosen: non-MCP framework config baseline
   - Signal expected: mostly clean config baseline
10. `https://github.com/openai/openai-agents-python` → `examples/mcp/filesystem_example/main.py`
    - Type: agent example code
    - Why chosen: real tool-using MCP example
    - Signal expected: practical EXF/PERM low-signal matches from example text
11. `https://github.com/openai/openai-agents-python` → `examples/tools/shell.py`
    - Type: agent example code
    - Why chosen: explicit tool-use example
    - Signal expected: check whether tool examples trigger broad noise
12. `https://github.com/anthropics/claude-code` → `examples/settings/settings-strict.json`
    - Type: config JSON
    - Why chosen: real agent settings config
    - Signal expected: confirm whether config JSON remains mostly clean
13. `https://github.com/anthropics/claude-code` → `examples/settings/settings-lax.json`
    - Type: config JSON
    - Why chosen: second settings profile for contrast
    - Signal expected: confirm whether config JSON remains mostly clean

## Final Expansion Pass (9 artifacts)

All 9 new additions are code or config files. No new READMEs.

1. `https://github.com/modelcontextprotocol/servers` → `src/filesystem/index.ts`
   - Type: tool definition code
   - Why chosen: TypeScript MCP filesystem server — tool registrations and allowed-directory access control
   - Signal expected: PERM-003 (real read/write + permission vocabulary)
2. `https://github.com/modelcontextprotocol/servers` → `src/fetch/src/mcp_server_fetch/server.py`
   - Type: tool definition code
   - Why chosen: Python HTTP fetch server — makes real outbound HTTP requests
   - Signal expected: EXF-003 (URL + outbound HTTP context)
3. `https://github.com/modelcontextprotocol/servers` → `src/git/src/mcp_server_git/server.py`
   - Type: tool definition code
   - Why chosen: Python git operations server — real file read/write + command execution
   - Signal expected: PERM-003 (capability + allowed-repo path validation)
4. `https://github.com/openai/openai-agents-python` → `examples/basic/tools.py`
   - Type: agent example code
   - Why chosen: basic tool use example; clean code baseline
   - Signal expected: none or minimal
5. `https://github.com/openai/openai-agents-python` → `examples/agent_patterns/deterministic.py`
   - Type: agent example code
   - Why chosen: deterministic agent orchestration pattern
   - Signal expected: none or minimal
6. `https://github.com/openai/openai-agents-python` → `examples/tools/web_search.py`
   - Type: agent example code
   - Why chosen: web search tool with URL handling
   - Signal expected: none or EXF-003 if URL context triggers
7. `https://github.com/openai/openai-agents-python` → `examples/tools/computer_use.py`
   - Type: agent example code
   - Why chosen: computer use tool — exec + filesystem + network
   - Signal expected: PERM-003 if exec + filesystem vocabulary co-located
8. `https://github.com/modelcontextprotocol/servers` → `src/everything/resources/index.ts`
   - Type: tool definition code (resource definitions)
   - Why chosen: resource registration TypeScript code
   - Signal expected: none or minimal
9. `https://github.com/openai/openai-agents-python` → `examples/agent_patterns/llm_as_a_judge.py`
   - Type: agent example code
   - Why chosen: LLM-as-a-judge agent pattern
   - Signal expected: none or minimal

## Notes

- All artifacts are public and reproducible from repository URLs.
- The set stays intentionally small enough for manual inspection and per-file review.
- Phase 7 is complete at 29 artifacts.
