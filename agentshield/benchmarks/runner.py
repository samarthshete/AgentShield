from __future__ import annotations

import tempfile
from pathlib import Path

from agentshield.benchmarks.loader import load_suite
from agentshield.models.benchmark import (
    BenchmarkCase,
    BenchmarkCaseResult,
    BenchmarkSummary,
    CategoryBreakdown,
)
from agentshield.reporting.severity import severity_rank
from agentshield.services.scan_service import run_static_scan


def _evaluate_case(case: BenchmarkCase) -> BenchmarkCaseResult:
    ext = case.input.format if case.input.format.startswith(".") else f".{case.input.format}"
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=ext, delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(case.input.content)
        tmp.flush()
        tmp_path = tmp.name

    scan_run, findings, _targets = run_static_scan(tmp_path)
    Path(tmp_path).unlink(missing_ok=True)

    found_categories = sorted({f.category for f in findings})
    found_rule_ids = sorted({f.rule_id for f in findings if f.rule_id})
    max_sev = max((severity_rank(f.severity) for f in findings), default=0)
    max_sev_label = next(
        (f.severity.upper() for f in findings if severity_rank(f.severity) == max_sev),
        None,
    ) if findings else None

    failures: list[str] = []
    exp = case.expect

    if len(findings) < exp.min_findings:
        failures.append(f"expected >= {exp.min_findings} findings, got {len(findings)}")

    if exp.categories:
        missing = set(exp.categories) - {f.category for f in findings}
        if missing:
            failures.append(f"missing categories: {sorted(missing)}")

    if exp.min_severity:
        required_rank = severity_rank(exp.min_severity)
        if max_sev < required_rank:
            failures.append(
                f"expected severity >= {exp.min_severity}, got {max_sev_label or 'none'}"
            )

    if exp.rule_ids:
        missing_rules = set(exp.rule_ids) - {f.rule_id for f in findings if f.rule_id}
        if missing_rules:
            failures.append(f"missing rule_ids: {sorted(missing_rules)}")

    return BenchmarkCaseResult(
        case_id=case.id,
        case_name=case.name,
        category=case.category,
        passed=len(failures) == 0,
        findings_count=len(findings),
        matched_categories=found_categories,
        matched_rule_ids=found_rule_ids,
        max_severity=max_sev_label,
        scan_time_ms=scan_run.duration_ms or 0,
        failure_reasons=failures,
    )


def run_benchmark(suite_dir: Path) -> BenchmarkSummary:
    cases = load_suite(suite_dir)
    results: list[BenchmarkCaseResult] = []
    for case in cases:
        results.append(_evaluate_case(case))

    passed = sum(1 for r in results if r.passed)
    failed = len(results) - passed
    total = len(results)

    breakdown: dict[str, CategoryBreakdown] = {}
    for r in results:
        cat = r.category
        if cat not in breakdown:
            breakdown[cat] = CategoryBreakdown()
        breakdown[cat].total += 1
        if r.passed:
            breakdown[cat].passed += 1
        else:
            breakdown[cat].failed += 1

    avg_ms = sum(r.scan_time_ms for r in results) / total if total else 0.0

    return BenchmarkSummary(
        total_cases=total,
        passed=passed,
        failed=failed,
        pass_rate=round(passed / total, 4) if total else 0.0,
        category_breakdown=breakdown,
        avg_scan_time_ms=round(avg_ms, 2),
        results=results,
    )
