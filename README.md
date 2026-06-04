# AgentShield

AgentShield is a security evaluation framework for tool-using agent workflows. It scans configuration files and directories, detects risky patterns, runs deterministic attack simulations, and exposes both CLI and web interfaces for reviewing findings.

## Problem Solved

Tool-using agents can inherit risk from prompts, tool descriptions, resources, broad permissions, and unsafe automation paths. AgentShield makes those risks visible before a workflow is shipped or connected to sensitive systems.

## What It Detects

| Category | Example |
|---|---|
| `TOOL_POISONING` | Hidden imperative instructions inside tool descriptions |
| `INDIRECT_PROMPT_INJECTION` | Override or jailbreak phrases in resources or prompts |
| `UNSAFE_PERMISSIONS` | Broad filesystem or network access scopes |
| `DATA_EXFILTRATION_PATTERN` | API key forwarding or command patterns that send data externally |
| `TASK_DRIFT` | Context spoofing that redirects the original goal |

## Key Features

- Python CLI with `scan`, `benchmark`, `simulate`, and `version` commands.
- Static scanner for files or directories.
- Markdown and JSON report output.
- SQLite persistence for scan and simulation history.
- Deterministic benchmark cases stored as YAML.
- Dynamic simulation mode across the supported threat categories.
- FastAPI wrapper over the CLI/service logic.
- React/TypeScript web console for dashboard, static scan, dynamic simulation, benchmarks, metrics, and run history.
- GitHub Actions workflows for lint/test and security-scan reporting.

## Tech Stack

| Area | Technology |
|---|---|
| CLI | Python, Typer, Rich |
| Validation | Pydantic, PyYAML |
| API | FastAPI, Uvicorn |
| Persistence | SQLite |
| Frontend | React, TypeScript, Vite, Tailwind CSS |
| CI | GitHub Actions, ruff, pytest |

## Architecture

```text
CLI / Web UI
   |
   v
FastAPI service layer
   |
   +--> Scan orchestrator -> parser -> static rules -> severity scoring -> reports
   |
   +--> Benchmark runner -> scanner -> benchmark summary
   |
   +--> Attack generator -> runtime simulator -> policy engine -> dynamic reports
   |
   +--> SQLite persistence
```

## Project Structure

```text
AgentShield/
|-- agentshield/              # CLI, scanning, simulation, API modules
|-- benchmarks/cases/         # YAML benchmark cases
|-- tests/                    # pytest coverage
|-- web/                      # React/TypeScript console
|-- .github/workflows/        # CI and scan workflows
|-- pyproject.toml
`-- README.md
```

## Install And Run

Prerequisites:

- Python 3.11+
- Node.js 18+ for the web console

Install the CLI locally:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

Run a scan:

```bash
python -m agentshield scan ./my-agent-config --format both --output ./reports
```

Run dynamic simulations:

```bash
python -m agentshield simulate --scenario all --output ./reports
```

Run benchmark cases:

```bash
python -m agentshield benchmark benchmarks/cases --output ./reports
```

## Web API

Start the API wrapper:

```bash
uvicorn agentshield.web.app:app --reload
```

Base URL: `http://127.0.0.1:8000`

Implemented endpoints:

- `GET /api/health`
- `POST /api/scan`
- `POST /api/benchmark`
- `POST /api/simulate`
- `GET /api/metrics`
- `GET /api/history/scans`
- `GET /api/history/dynamic`
- `GET /api/runs/{id}`

## Web Console

```bash
cd web
npm install
npm run dev
```

Default URL: `http://127.0.0.1:5173`

Routes include dashboard, static scan, dynamic simulation, benchmarks, metrics, and run history.

## CI And Local Quality Checks

GitHub Actions runs linting and tests on pushes and pull requests.

Local equivalent:

```bash
pip install -e ".[dev]"
ruff check agentshield tests
pytest --tb=short -q
```

The scan workflow can run `agentshield scan` against the repository and upload report artifacts.

## Report Outputs

| File | Description |
|---|---|
| `findings.json` | Machine-readable static scan results |
| `findings.md` | Human-readable static report |
| `benchmark_results.json` | Benchmark suite summary |
| `dynamic_findings.json` | Dynamic simulation trace and violations |
| `dynamic_findings.md` | Human-readable dynamic report |
| `agentshield.db` | Local SQLite history database |

## Technical Decisions

- Keep core detection deterministic so findings are explainable and testable.
- Provide CLI-first workflows for CI and local security checks.
- Add a thin API layer rather than duplicating scanner logic.
- Use lightweight persistence so scans can be reviewed without external services.

## Future Improvements

- Add more rule categories and benchmark cases.
- Add authentication if the web API is deployed outside local development.
- Add richer trend views in the web console.
- Add SARIF export for code scanning integrations.

## License

MIT.
