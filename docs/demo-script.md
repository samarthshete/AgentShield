# Demo Script

## Demo 0 — Live console (no install)
1. Open https://agent-shield-topaz.vercel.app → Static Scan → **Paste config** mode.
2. Paste an agent/tool config with a suspicious tool description; run the scan.
3. Walk through the KPI stat tiles, severity-distribution bar, and per-finding
   evidence + recommendation rows.
4. Dashboard: show the labeled-eval hero (F1 / precision / recall + Wilson 95% CI)
   and its honest caveat.

## Demo 1 — Static scan (CLI)
1. Prepare a config with suspicious tool descriptions
2. Run:
   `agentshield scan ./sample-config --format both --output ./reports`
3. Open:
   - reports/findings.json
   - reports/findings.md

## Demo 2 — Measured accuracy
1. Run: `agentshield eval benchmarks/labeled`
2. Show micro precision/recall/F1 (96.23% / 100% / 98.08%) and the 2 known
   false positives — and that the same command gates CI at `--min-f1 0.95`.

## Demo goal
Show that AgentShield can:
- parse a target (server path or pasted content)
- apply rule packs + the semantic confirmer
- score severity
- generate developer-friendly output
- back its accuracy claims with a labeled, reproducible eval
