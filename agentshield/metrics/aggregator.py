from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from agentshield import __version__
from agentshield.dynamic.attack_generator import list_scenarios
from agentshield.dynamic.runtime_simulator import simulate
from agentshield.metrics.rule_registry import build_rule_coverage
from agentshield.models.benchmark import BenchmarkSummary
from agentshield.models.dynamic import DynamicScanResult
from agentshield.models.finding import Finding
from agentshield.models.metrics import (
    BenchmarkMetrics,
    DynamicMetrics,
    ProjectMetrics,
    ScanMetrics,
)
from agentshield.models.scan import ScanRun
from agentshield.models.target import ScannedTarget
from agentshield.policy.policy_engine import evaluate_trace
from agentshield.reporting.severity import severity_rank

_ATTACK_CATEGORIES = [
    "TOOL_POISONING",
    "INDIRECT_PROMPT_INJECTION",
    "UNSAFE_PERMISSIONS",
    "DATA_EXFILTRATION_PATTERN",
    "TASK_DRIFT",
]


def _p95(values: list[int | float]) -> float:
    if not values:
        return 0.0
    sorted_v = sorted(values)
    idx = min(int(len(sorted_v) * 0.95), len(sorted_v) - 1)
    return float(sorted_v[idx])


def aggregate_scan(
    scan_run: ScanRun,
    findings: list[Finding],
    targets: list[ScannedTarget],
) -> ScanMetrics:
    return ScanMetrics(
        configs_scanned=len(targets),
        findings_total=len(findings),
        findings_high_or_critical=scan_run.high_or_critical_count or 0,
        overall_risk_score=scan_run.overall_risk_score or 0,
    )


def aggregate_benchmark(summary: BenchmarkSummary) -> BenchmarkMetrics:
    times = [r.scan_time_ms for r in summary.results]
    return BenchmarkMetrics(
        total_cases=summary.total_cases,
        passed=summary.passed,
        failed=summary.failed,
        pass_rate=summary.pass_rate,
        avg_scan_time_ms=summary.avg_scan_time_ms,
        p95_scan_time_ms=_p95(times),
        category_breakdown={
            cat: {"total": bd.total, "passed": bd.passed, "failed": bd.failed}
            for cat, bd in summary.category_breakdown.items()
        },
    )


def aggregate_dynamic(results: list[DynamicScanResult]) -> DynamicMetrics:
    severities = [v.severity for r in results for v in r.violations]
    return DynamicMetrics(
        scenarios_run=len(results),
        violations_total=sum(r.violation_count for r in results),
        categories_covered=sorted({r.category for r in results}),
        max_severity_seen=(
            max(severities, key=lambda s: severity_rank(s)) if severities else None
        ),
    )


def _run_dynamic_scenarios() -> list[DynamicScanResult]:
    results: list[DynamicScanResult] = []
    for payload in list_scenarios():
        trace = simulate(payload)
        violations = evaluate_trace(trace)
        max_sev = (
            max((v.severity for v in violations), key=lambda s: severity_rank(s))
            if violations
            else None
        )
        results.append(DynamicScanResult(
            scenario_id=payload.scenario_id,
            scenario_name=payload.scenario_name,
            category=payload.category,
            violations=violations,
            trace=trace,
            violation_count=len(violations),
            max_severity=max_sev,
            passed_clean=len(violations) == 0,
        ))
    return results


def build_project_metrics(
    scan_run: ScanRun,
    findings: list[Finding],
    targets: list[ScannedTarget],
    benchmark_summary: BenchmarkSummary,
    dynamic_results: list[DynamicScanResult],
) -> ProjectMetrics:
    scan_m = aggregate_scan(scan_run, findings, targets)
    bench_m = aggregate_benchmark(benchmark_summary)
    dyn_m = aggregate_dynamic(dynamic_results)

    return ProjectMetrics(
        generated_at=datetime.now(timezone.utc).isoformat(),
        agentshield_version=__version__,
        attack_categories=_ATTACK_CATEGORIES,
        total_test_cases=bench_m.total_cases,
        scan=scan_m,
        benchmark=bench_m,
        dynamic=dyn_m,
        rule_coverage=build_rule_coverage(),
        rules_only_rate=1.0,
        llm_routing_rate=0.0,
        avg_scan_cost_usd=0.0,
        workflows_or_configs_scanned=scan_m.configs_scanned,
        findings_total=scan_m.findings_total,
        findings_high_or_critical=scan_m.findings_high_or_critical,
        avg_scan_time_seconds=round(bench_m.avg_scan_time_ms / 1000, 4),
        p95_scan_time_seconds=round(bench_m.p95_scan_time_ms / 1000, 4),
    )


def run_all_and_aggregate(
    fixtures_path: Path,
    benchmark_cases_dir: Path,
) -> ProjectMetrics:
    from agentshield.benchmarks.runner import run_benchmark
    from agentshield.services.scan_service import run_static_scan

    benchmark_summary = run_benchmark(benchmark_cases_dir)
    scan_run, findings, targets = run_static_scan(str(fixtures_path))
    dynamic_results = _run_dynamic_scenarios()

    return build_project_metrics(
        scan_run=scan_run,
        findings=findings,
        targets=targets,
        benchmark_summary=benchmark_summary,
        dynamic_results=dynamic_results,
    )
