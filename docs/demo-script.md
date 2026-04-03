# Demo Script

## Demo 1 — Static scan
1. Prepare a config with suspicious tool descriptions
2. Run:
   `agentshield scan ./sample-config --format both --output ./reports`
3. Open:
   - reports/findings.json
   - reports/findings.md

## Demo goal
Show that AgentShield can:
- parse a target
- apply rule packs
- score severity
- generate developer-friendly output
