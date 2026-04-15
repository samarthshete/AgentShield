# Phase 7 Narrow Rule-Tuning Results (EXF-003)

This is the first targeted tuning pass in Phase 7. Scope was intentionally narrow:

- tuned only `EXF-003` logic
- no architecture changes
- no LLM judge changes
- no tuning of stronger exfiltration rules (`EXF-001`, `EXF-002`)
- no `PERM-003` changes in this pass

Data source:
- tuned run output: `agentshield-output/phase7-tuned-pass/summary.json`
- first-pass baseline: `agentshield-output/phase7-first-pass/summary.json`
- second-pass baseline: `agentshield-output/phase7-second-pass/summary.json`

## What Changed in EXF-003

Before tuning, `EXF-003` fired whenever these tokens appeared anywhere:
- `http://`
- `https://`
- `curl `
- `wget `

After tuning, `EXF-003` now requires context:
- URL markers (`http://`, `https://`) only fire when outbound/exfiltration context also appears (for example `send`, `upload`, `post`, `token`, `secret`, `authorization`).
- transfer command markers (`curl`, `wget`) only fire when transfer/exfiltration context appears (for example `--data`, `--upload-file`, `send`, `token`, `secret`).

This keeps low-signal URL-only docs/metadata from firing by default while preserving low-level exfil alerts when outbound intent is present.

## Before vs After (Second-Pass Baseline → Tuned 20-artifact set)

- Total findings: `19 -> 9` (delta `-10`)
- `EXF-003`: `14 -> 4` (delta `-10`)
- `EXF-001`: `1 -> 1` (no change)
- `EXF-002`: `1 -> 1` (no change)
- `PERM-001`: `1 -> 1` (no change)
- `PERM-003`: `2 -> 2` (no change)

Interpretation: reduction came entirely from `EXF-003` noise; higher-signal exfiltration and permission findings were preserved.

## First-Pass Baseline Comparison (7-artifact subset)

Using the same original 7 artifacts:
- Total findings: `11 -> 7` (delta `-4`)
- `EXF-003`: `7 -> 3` (delta `-4`)
- `EXF-001`, `EXF-002`, `PERM-001`, `PERM-003`: unchanged

## Artifact-Type Impact

Key shifts in tuned 20-artifact run:
- `package_manifest`: `4 findings -> 0`
- `pyproject_config`: `1 finding -> 0`
- `readme_docs`: `12 findings -> 8` (still highest concentration)
- `config_json`: stayed `0`

This matches the Phase 7 evidence: noise was concentrated in docs/metadata-heavy artifacts.

## What Remains Noisy

- `EXF-003` still appears in some README/docs files where outbound intent words and URLs coexist.
- `PERM-003` remains in:
  - `anthropic/README.md`
  - `openai-agents/examples.mcp.filesystem_example.main.py`

These `PERM-003` cases were left unchanged in this pass by design.

## Conclusion

The narrow EXF-003 tuning goal is met:
- obvious URL-only and metadata-only false positives were reduced substantially
- stronger exfiltration signals stayed intact
- config-like artifact coverage was not weakened

---

## PERM-003 Narrow Tuning Pass

This is the second targeted tuning pass in Phase 7. Scope is equally narrow:

- tuned only `PERM-003` logic
- no architecture changes
- no LLM judge changes
- `PERM-001` and `PERM-002` unchanged

Data source:
- tuned run output: `agentshield-output/phase7-perm003-tuned-pass/summary.json`

### What the evidence showed

Two `PERM-003` hits remained after the EXF-003 tuning pass:

| Artifact | False-positive reason |
|---|---|
| `anthropic/README.md` | `read` matched as substring of `README.md`; `command` matched `custom commands` prose |
| `openai-agents/examples.mcp.filesystem_example.main.py` | `read` from natural-language agent instructions; `command` from `"command": "npx"` launch parameter |

Neither file contained any permission/capability declaration vocabulary (`permission`, `capability`, `grant`, `allow`, `scope`, `storage`, `disk`, `privilege`, `authorized`, `credential`, `auth`). Both matches were incidental word coincidence, not co-located permission grants.

### What changed in PERM-003

Before tuning, `PERM-003` fired whenever:
- `read` or `write` appeared anywhere in the text
- AND `execute`, `shell`, or `command` appeared anywhere

After tuning, `PERM-003` requires a third condition: at least one permission/capability context word must also be present:

```
permission, capability, grant, allow, scope, storage, disk, privilege,
authorized, credential, auth
```

This ensures the rule fires on actual permission or capability declarations, not on README prose, agent instruction strings, or tool launch parameters.

### Before vs After (EXF-003 tuned baseline → PERM-003 tuned 20-artifact set)

- Total findings: `9 -> 7` (delta `-2`)
- `PERM-003`: `2 -> 0` (delta `-2`)
- `EXF-001`: `1 -> 1` (no change)
- `EXF-002`: `1 -> 1` (no change)
- `EXF-003`: `4 -> 4` (no change)
- `PERM-001`: `1 -> 1` (no change)

Full progression across all three passes:

| Rule | second-pass baseline | after EXF-003 tuning | after PERM-003 tuning |
|---|---|---|---|
| EXF-001 | 1 | 1 | 1 |
| EXF-002 | 1 | 1 | 1 |
| EXF-003 | 14 | 4 | 4 |
| PERM-001 | 1 | 1 | 1 |
| PERM-003 | 2 | 2 | 0 |
| **TOTAL** | **19** | **9** | **7** |

### PERM-003 probe updated

`agentshield/metrics/rule_registry.py` probe for PERM-003 was updated to include `permission` so the rule registry continues to discover PERM-003 correctly.

### Tests added

Five new tests in `tests/test_rules.py`:
- `test_perm_003_fires_on_permission_context` — real permission declaration still fires
- `test_perm_003_suppressed_in_readme_prose` — README substring + prose commands suppressed
- `test_perm_003_suppressed_in_natural_language_read_plus_npx_command` — agent instruction + npx launch param suppressed
- `test_perm_001_unchanged` — PERM-001 behavior confirmed unchanged
- `test_perm_002_unchanged` — PERM-002 behavior confirmed unchanged

### Conclusion

PERM-003 tuning goal is met:
- both false positives from the evidence review are suppressed
- higher-signal permission detections (`PERM-001`) are unchanged
- config-like artifact coverage is not weakened
- the rule still fires correctly on real permission declarations

Phase 7 rule tuning is now complete. Both noise candidates (`EXF-003` and `PERM-003`) have been addressed with narrow, test-backed context gates. The remaining 7 findings across the 20-artifact set all correspond to the `mcp-servers/README.md` artifact, which contains real MCP server capability declarations.
