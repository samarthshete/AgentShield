"""Typer CLI entrypoint for AgentShield."""
from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from agentshield.config import settings
from agentshield.reporting.json_report import build_scan_payload, write_json_report
from agentshield.reporting.markdown_report import write_markdown_report
from agentshield.reporting.severity import severity_rank
from agentshield.services.scan_service import run_static_scan
from agentshield.storage.sqlite_store import init_sqlite, persist_scan

app = typer.Typer(help="AgentShield security scanner")
console = Console()

_FAIL_ORDER = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


def _normalize_format(value: str) -> str:
    v = value.strip().lower()
    if v not in {"json", "markdown", "both"}:
        raise typer.BadParameter("format must be json, markdown, or both")
    return v


def _normalize_fail_on(value: str) -> str:
    v = value.strip().lower()
    if v not in _FAIL_ORDER:
        raise typer.BadParameter("fail-on must be info, low, medium, high, or critical")
    return v


def _should_fail(fail_on: str, max_severity_rank: int) -> bool:
    return max_severity_rank >= _FAIL_ORDER[fail_on]


# ── scan command ─────────────────────────────────────────────────────────────


@app.command("scan")
def scan_cmd(
    path: str = typer.Argument(..., help="Path to config or repository to scan"),
    format: str = typer.Option(
        "both",
        help="Output format: json, markdown, both",
        callback=lambda v: _normalize_format(v),
    ),
    output: str | None = typer.Option(
        None,
        help="Output directory for reports",
    ),
    fail_on: str = typer.Option(
        "high",
        help="Exit non-zero if any finding meets or exceeds this severity",
        callback=lambda v: _normalize_fail_on(v),
    ),
    db_path: str | None = typer.Option(
        None,
        help="SQLite database path",
    ),
    verbose: bool = typer.Option(False, help="Verbose logging"),
) -> None:
    """Run a static security scan."""
    target = Path(path)
    out_dir = Path(output or settings.agentshield_output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    db = Path(db_path or settings.agentshield_db_path)

    scan_run, findings, targets = run_static_scan(str(target))

    init_sqlite(db)
    persist_scan(db, scan_run, findings, targets)

    payload = build_scan_payload(scan_run, findings, targets)
    if format in {"json", "both"}:
        write_json_report(out_dir / "findings.json", payload)
    if format in {"markdown", "both"}:
        write_markdown_report(out_dir / "findings.md", scan_run, findings)

    max_rank = max((severity_rank(f.severity) for f in findings), default=0)
    if verbose:
        console.print(f"[dim]Scanned targets: {len(targets)}[/dim]")
        console.print(f"[dim]Findings: {len(findings)} (max severity rank {max_rank})[/dim]")

    console.print(
        f"[bold]Scan complete[/bold] — findings: {scan_run.findings_count}, "
        f"high/critical: {scan_run.high_or_critical_count}, "
        f"risk score: {scan_run.overall_risk_score}"
    )
    console.print(f"Reports: {out_dir.resolve()}")
    console.print(f"Database: {db.resolve()}")

    if findings and _should_fail(fail_on, max_rank):
        raise typer.Exit(code=1)


# ── benchmark command ────────────────────────────────────────────────────────


@app.command("benchmark")
def benchmark_cmd(
    suite_dir: str = typer.Argument(..., help="Directory containing benchmark .yaml case files"),
    output: str | None = typer.Option(
        None,
        help="Output directory for benchmark results",
    ),
    verbose: bool = typer.Option(False, help="Print per-case detail"),
) -> None:
    """Run a benchmark suite against the static scanner."""
    from agentshield.benchmarks.runner import run_benchmark

    suite_path = Path(suite_dir)
    if not suite_path.is_dir():
        console.print(f"[red]Not a directory: {suite_path}[/red]")
        raise typer.Exit(code=2)

    summary = run_benchmark(suite_path)

    # per-case table
    table = Table(title="Benchmark Results")
    table.add_column("Case", style="cyan")
    table.add_column("Category")
    table.add_column("Findings", justify="right")
    table.add_column("Max Severity")
    table.add_column("Result")

    for r in summary.results:
        status = "[green]PASS[/green]" if r.passed else "[red]FAIL[/red]"
        table.add_row(
            r.case_id,
            r.category,
            str(r.findings_count),
            r.max_severity or "-",
            status,
        )

    console.print(table)

    if verbose:
        for r in summary.results:
            if r.failure_reasons:
                console.print(f"  [red]{r.case_id}[/red]: {'; '.join(r.failure_reasons)}")

    # summary line
    console.print(
        f"\n[bold]Total:[/bold] {summary.total_cases}  "
        f"[green]Passed:[/green] {summary.passed}  "
        f"[red]Failed:[/red] {summary.failed}  "
        f"Pass rate: {summary.pass_rate:.0%}  "
        f"Avg scan: {summary.avg_scan_time_ms:.1f} ms"
    )

    # category breakdown
    if summary.category_breakdown:
        console.print("\n[bold]Category breakdown:[/bold]")
        for cat, bd in sorted(summary.category_breakdown.items()):
            console.print(f"  {cat}: {bd.passed}/{bd.total} passed")

    # write outputs
    out_dir = Path(output or settings.agentshield_output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    json_path = out_dir / "benchmark_results.json"
    json_path.write_text(
        json.dumps(summary.model_dump(), indent=2),
        encoding="utf-8",
    )
    console.print(f"\nResults: {json_path.resolve()}")

    if summary.failed > 0:
        raise typer.Exit(code=1)


# ── simulate command ─────────────────────────────────────────────────────────


@app.command("simulate")
def simulate_cmd(
    scenario: str = typer.Option(
        "all",
        help=(
            "Scenario to run: 'all', or a specific ID such as "
            "'DYN-TP-001', 'DYN-IPI-001', 'DYN-EXF-001'"
        ),
    ),
    output: str | None = typer.Option(
        None,
        help="Output directory for dynamic reports",
    ),
    db_path: str | None = typer.Option(
        None,
        help="SQLite database path",
    ),
    judge: str = typer.Option(
        "rule_based",
        help="Judge to apply to policy violations: rule_based, openai, or claude",
    ),
    llm_api_key: str | None = typer.Option(
        None,
        help="API key for the LLM judge",
    ),
    llm_model: str = typer.Option(
        "",
        help="Model name for LLM judge (provider default used if not specified)",
    ),
    verbose: bool = typer.Option(False, help="Print per-violation detail"),
) -> None:
    """Run dynamic attack simulations and report policy violations."""
    import uuid
    from datetime import datetime, timezone

    from rich.table import Table

    from agentshield.dynamic.attack_generator import get_scenario, list_scenarios
    from agentshield.dynamic.llm_judge import ClaudeJudgeError, OpenAIJudgeError, get_judge
    from agentshield.dynamic.report import write_dynamic_json, write_dynamic_markdown
    from agentshield.dynamic.runtime_simulator import simulate
    from agentshield.models.dynamic import DynamicScanResult
    from agentshield.policy.policy_engine import evaluate_trace
    from agentshield.reporting.severity import severity_rank
    from agentshield.storage.sqlite_store import init_sqlite, persist_dynamic_scan

    out_dir = Path(output or settings.agentshield_output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    db = Path(db_path or settings.agentshield_db_path)
    init_sqlite(db)

    _judge_key = llm_api_key
    if _judge_key is None:
        normalized_judge = judge.strip().lower()
        if normalized_judge == "openai":
            _judge_key = settings.openai_api_key
        else:
            _judge_key = settings.claude_api_key

    try:
        judge_impl = get_judge(judge, api_key=_judge_key, model=llm_model)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc

    if scenario.lower() == "all":
        payloads = list_scenarios()
    else:
        try:
            payloads = [get_scenario(scenario.upper())]
        except KeyError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(code=2) from exc

    results: list[DynamicScanResult] = []
    ran_at = datetime.now(timezone.utc).isoformat()

    for payload in payloads:
        trace = simulate(payload)
        raw_violations = evaluate_trace(trace)
        try:
            verdict = judge_impl.evaluate(trace, raw_violations)
        except (ClaudeJudgeError, OpenAIJudgeError) as exc:
            console.print(
                f"[red]LLM judge failed for scenario {payload.scenario_id}: {exc}[/red]"
            )
            raise typer.Exit(code=2) from exc
        confirmed = verdict.confirmed_violations

        max_sev = (
            max((v.severity for v in confirmed), key=lambda s: severity_rank(s))
            if confirmed
            else None
        )

        result = DynamicScanResult(
            scenario_id=payload.scenario_id,
            scenario_name=payload.scenario_name,
            category=payload.category,
            violations=confirmed,
            raw_violations=list(raw_violations),
            dismissed_violations=verdict.dismissed_violations,
            trace=trace,
            violation_count=len(confirmed),
            max_severity=max_sev,
            passed_clean=len(confirmed) == 0,
            judge_type=verdict.judge_type,
            judge_model=getattr(judge_impl, "model", None),
        )
        results.append(result)
        persist_dynamic_scan(db, uuid.uuid4().hex, result, ran_at)

    # print summary table
    table = Table(title="Dynamic Simulation Results")
    table.add_column("Scenario", style="cyan")
    table.add_column("Category")
    table.add_column("Violations", justify="right")
    table.add_column("Max Severity")
    table.add_column("Clean?")

    for r in results:
        clean = "[green]Yes[/green]" if r.passed_clean else "[red]No[/red]"
        table.add_row(
            r.scenario_id,
            r.category,
            str(r.violation_count),
            r.max_severity or "-",
            clean,
        )

    console.print(table)

    if verbose:
        for r in results:
            if r.violations:
                console.print(f"\n[bold]{r.scenario_id}[/bold] violations:")
                for v in r.violations:
                    step_note = f" [step {v.step_seq}]" if v.step_seq is not None else ""
                    console.print(
                        f"  [{v.severity}] {v.policy_id}{step_note}: {v.title}"
                    )

    write_dynamic_json(out_dir / "dynamic_findings.json", results)
    write_dynamic_markdown(out_dir / "dynamic_findings.md", results)

    console.print(f"\nReports: {out_dir.resolve()}")
    console.print(f"Database: {db.resolve()}")

    dirty = sum(1 for r in results if not r.passed_clean)
    if dirty:
        raise typer.Exit(code=1)


# ── metrics command ──────────────────────────────────────────────────────────


@app.command("metrics")
def metrics_cmd(
    fixtures: str = typer.Option(
        "benchmarks/fixtures",
        help="Path to config fixtures for the static scan",
    ),
    cases: str = typer.Option(
        "benchmarks/cases",
        help="Directory containing benchmark YAML cases",
    ),
    output: str | None = typer.Option(
        None,
        help="Output directory for metrics.json (default: agentshield-output)",
    ),
    docs_output: str = typer.Option(
        "docs",
        help="Directory where PROJECT_METRICS.md is written",
    ),
) -> None:
    """Generate project metrics from scan, benchmark, and simulation data."""
    from agentshield.metrics.aggregator import run_all_and_aggregate
    from agentshield.metrics.report_writer import write_markdown

    fixtures_path = Path(fixtures)
    cases_path = Path(cases)
    out_dir = Path(output or settings.agentshield_output_dir)
    docs_dir = Path(docs_output)

    for p, name in [(fixtures_path, "fixtures"), (cases_path, "cases")]:
        if not p.exists():
            console.print(f"[red]Path not found ({name}): {p}[/red]")
            raise typer.Exit(code=2)

    console.print("[dim]Running benchmark, scan, and dynamic simulation...[/dim]")
    metrics = run_all_and_aggregate(fixtures_path, cases_path)

    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "metrics.json"
    json_path.write_text(json.dumps(metrics.model_dump(), indent=2), encoding="utf-8")

    md_path = docs_dir / "PROJECT_METRICS.md"
    write_markdown(md_path, metrics)
    (out_dir / "PROJECT_METRICS.md").write_text(md_path.read_text(encoding="utf-8"), encoding="utf-8")

    console.print(
        f"[bold]Metrics generated[/bold] — "
        f"cases: {metrics.total_test_cases}, "
        f"pass rate: {metrics.benchmark.pass_rate:.0%}, "
        f"findings: {metrics.findings_total}, "
        f"rules: {metrics.rule_coverage.total_rules}"
    )
    console.print(f"JSON : {json_path.resolve()}")
    console.print(f"Docs : {md_path.resolve()}")


# ── version command ──────────────────────────────────────────────────────────


@app.command("version")
def version_cmd() -> None:
    """Print AgentShield version."""
    from agentshield import __version__

    console.print(__version__)


if __name__ == "__main__":
    app()
