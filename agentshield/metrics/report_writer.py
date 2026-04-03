from __future__ import annotations

from pathlib import Path

from agentshield.models.metrics import ProjectMetrics


def _table(headers: tuple[str, str], rows: list[tuple[str, str]]) -> list[str]:
    lines = [
        f"| {headers[0]} | {headers[1]} |",
        "| --- | --- |",
    ]
    for label, value in rows:
        lines.append(f"| {label} | {value} |")
    lines.append("")
    return lines


def render_markdown(m: ProjectMetrics) -> str:
    lines: list[str] = []

    def heading(level: int, text: str) -> None:
        lines.append(f"{'#' * level} {text}")
        lines.append("")

    heading(1, "AgentShield — Project Metrics")
    lines.append(f"*Generated: {m.generated_at}  |  Version: {m.agentshield_version}*")
    lines.append("")
    lines.append(
        "> All values are computed from real scan, benchmark, and simulation runs. "
        "No values are hardcoded or estimated."
    )
    lines.append("")

    heading(2, "Coverage Summary")
    lines += _table(("Metric", "Value"), [
        ("Attack categories covered", str(len(m.attack_categories))),
        ("Categories", ", ".join(m.attack_categories)),
        ("Total benchmark test cases", str(m.total_test_cases)),
        ("Benchmark pass rate", f"{m.benchmark.pass_rate:.0%}"),
        ("Dynamic simulation scenarios", str(m.dynamic.scenarios_run)),
        ("Distinct rule IDs", str(m.rule_coverage.total_rules)),
    ])

    heading(2, "Static Scan (sample fixtures)")
    lines += _table(("Metric", "Value"), [
        ("Configs / workflows scanned", str(m.scan.configs_scanned)),
        ("Total findings", str(m.scan.findings_total)),
        ("High or critical findings", str(m.scan.findings_high_or_critical)),
        ("Overall risk score (0–100)", str(m.scan.overall_risk_score)),
    ])

    heading(2, "Benchmark Performance")
    lines += _table(("Metric", "Value"), [
        ("Total cases", str(m.benchmark.total_cases)),
        ("Passed", str(m.benchmark.passed)),
        ("Failed", str(m.benchmark.failed)),
        ("Pass rate", f"{m.benchmark.pass_rate:.0%}"),
        ("Avg scan time (ms)", f"{m.benchmark.avg_scan_time_ms:.1f}"),
        ("P95 scan time (ms)", f"{m.benchmark.p95_scan_time_ms:.1f}"),
        ("Avg scan time (s)", f"{m.avg_scan_time_seconds:.4f}"),
        ("P95 scan time (s)", f"{m.p95_scan_time_seconds:.4f}"),
    ])

    heading(3, "Category Breakdown")
    if m.benchmark.category_breakdown:
        lines.append("| Category | Total | Passed | Failed |")
        lines.append("| --- | --- | --- | --- |")
        for cat, bd in sorted(m.benchmark.category_breakdown.items()):
            lines.append(f"| {cat} | {bd['total']} | {bd['passed']} | {bd['failed']} |")
        lines.append("")
    else:
        lines.append("No category breakdown available.")
        lines.append("")

    heading(2, "Dynamic Simulation")
    lines += _table(("Metric", "Value"), [
        ("Scenarios run", str(m.dynamic.scenarios_run)),
        ("Total policy violations detected", str(m.dynamic.violations_total)),
        ("Categories covered", ", ".join(m.dynamic.categories_covered) or "none"),
        ("Max severity seen", m.dynamic.max_severity_seen or "none"),
    ])

    heading(2, "Rule Coverage")
    lines += _table(("Metric", "Value"), [
        ("Total distinct rule IDs", str(m.rule_coverage.total_rules)),
    ])

    if m.rule_coverage.rules_by_category:
        lines += _table(("Category", "Rule IDs"), [
            (cat, ", ".join(ids))
            for cat, ids in sorted(m.rule_coverage.rules_by_category.items())
        ])

    if m.rule_coverage.all_rules:
        heading(3, "All Rules")
        lines.append("| Rule ID | Category | Severity |")
        lines.append("| --- | --- | --- |")
        for rule in m.rule_coverage.all_rules:
            lines.append(f"| `{rule.rule_id}` | {rule.category} | {rule.severity} |")
        lines.append("")

    heading(2, "Cost and Routing")
    lines += _table(("Metric", "Value"), [
        ("Rules-only detection rate", f"{m.rules_only_rate:.0%}"),
        ("LLM routing rate", f"{m.llm_routing_rate:.0%}"),
        ("Avg scan cost (USD)", f"${m.avg_scan_cost_usd:.2f}"),
    ])
    lines.append(
        "> Rules-only rate is 100% because all detection is performed by deterministic "
        "rule checks. No LLM calls are made in Phase 1–4. The `BaseJudge` interface "
        "exists for a future LLM layer."
    )
    lines.append("")

    heading(2, "Data Sources")
    lines += _table(("Metric group", "Source"), [
        ("Scan metrics", "`agentshield scan benchmarks/fixtures/`"),
        ("Benchmark metrics", "`agentshield benchmark benchmarks/cases/`"),
        ("Dynamic metrics", "`agentshield simulate --scenario all`"),
        ("Rule coverage", "Rule checkers called with maximal probe string"),
        ("Cost / routing", "Structural: no LLM calls in Phase 1–4"),
    ])

    return "\n".join(lines)


def write_markdown(path: Path, metrics: ProjectMetrics) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_markdown(metrics), encoding="utf-8")
