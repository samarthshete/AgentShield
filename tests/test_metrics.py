from __future__ import annotations

import uuid

from agentshield.metrics.aggregator import (
    _p95,
    aggregate_benchmark,
    aggregate_dynamic,
    aggregate_scan,
)
from agentshield.metrics.report_writer import render_markdown
from agentshield.metrics.rule_registry import build_rule_coverage, collect_rules
from agentshield.models.benchmark import (
    BenchmarkCaseResult,
    BenchmarkSummary,
    CategoryBreakdown,
)
from agentshield.models.dynamic import DynamicScanResult, PolicyViolation, SimTrace
from agentshield.models.finding import Finding
from agentshield.models.metrics import (
    BenchmarkMetrics,
    DynamicMetrics,
    ProjectMetrics,
    RuleCoverageMetrics,
    ScanMetrics,
)
from agentshield.models.scan import ScanRun
from agentshield.models.target import ScannedTarget

_EXPECTED_RULE_IDS = {
    "SP-001",
    "OV-001",
    "OV-002",
    "PERM-001",
    "PERM-002",
    "PERM-003",
    "EXF-001",
    "EXF-002",
    "EXF-003",
    "DRIFT-001",
    "DRIFT-002",
}


def test_collect_rules_finds_all_expected_ids() -> None:
    found = {r.rule_id for r in collect_rules()}
    assert _EXPECTED_RULE_IDS <= found, f"Missing: {_EXPECTED_RULE_IDS - found}"


def test_rule_coverage_total() -> None:
    assert build_rule_coverage().total_rules >= len(_EXPECTED_RULE_IDS)


def test_rule_coverage_categories() -> None:
    expected = {
        "TOOL_POISONING",
        "INDIRECT_PROMPT_INJECTION",
        "UNSAFE_PERMISSIONS",
        "DATA_EXFILTRATION_PATTERN",
        "TASK_DRIFT",
    }
    assert expected <= set(build_rule_coverage().rules_by_category.keys())


def test_rule_coverage_by_category_nonempty() -> None:
    for cat, ids in build_rule_coverage().rules_by_category.items():
        assert len(ids) > 0, f"Category {cat} has no rules"


def test_p95_empty() -> None:
    assert _p95([]) == 0.0


def test_p95_single() -> None:
    assert _p95([42]) == 42.0


def test_p95_ten_values() -> None:
    assert _p95(list(range(1, 11))) == 10.0


def test_p95_uniform() -> None:
    assert _p95([5, 5, 5, 5]) == 5.0


def _make_scan_run(**kwargs) -> ScanRun:
    defaults = dict(
        id=uuid.uuid4().hex,
        target_path="/tmp/test",
        mode="static",
        started_at="2026-01-01T00:00:00",
        findings_count=0,
        high_or_critical_count=0,
        overall_risk_score=0,
    )
    defaults.update(kwargs)
    return ScanRun(**defaults)


def _make_finding(severity: str = "HIGH", category: str = "TOOL_POISONING") -> Finding:
    return Finding(
        id=uuid.uuid4().hex,
        scan_run_id=uuid.uuid4().hex,
        category=category,
        severity=severity,
        title="Test finding",
        rule_id="SP-001",
    )


def _make_target() -> ScannedTarget:
    return ScannedTarget(
        id=uuid.uuid4().hex,
        scan_run_id=uuid.uuid4().hex,
        target_name="config.json",
        target_path="/tmp/config.json",
        target_kind="file",
    )


def test_aggregate_scan_counts_targets() -> None:
    sr = _make_scan_run(
        findings_count=2,
        high_or_critical_count=1,
        overall_risk_score=12,
    )
    findings = [_make_finding("HIGH"), _make_finding("LOW")]
    targets = [_make_target(), _make_target()]
    m = aggregate_scan(sr, findings, targets)
    assert m.configs_scanned == 2
    assert m.findings_total == 2
    assert m.findings_high_or_critical == 1
    assert m.overall_risk_score == 12


def _make_benchmark_summary(times: list[int]) -> BenchmarkSummary:
    results = [
        BenchmarkCaseResult(
            case_id=f"B-{i}",
            case_name=f"Case {i}",
            category="TOOL_POISONING",
            passed=True,
            scan_time_ms=t,
        )
        for i, t in enumerate(times)
    ]
    return BenchmarkSummary(
        total_cases=len(results),
        passed=len(results),
        failed=0,
        pass_rate=1.0,
        category_breakdown={
            "TOOL_POISONING": CategoryBreakdown(
                total=len(results),
                passed=len(results),
            )
        },
        avg_scan_time_ms=sum(times) / len(times) if times else 0.0,
        results=results,
    )


def test_aggregate_benchmark_pass_rate() -> None:
    m = aggregate_benchmark(_make_benchmark_summary([10, 20, 30]))
    assert m.pass_rate == 1.0
    assert m.total_cases == 3


def test_aggregate_benchmark_p95() -> None:
    m = aggregate_benchmark(
        _make_benchmark_summary([10, 20, 30, 40, 50, 60, 70, 80, 90, 100])
    )
    assert m.p95_scan_time_ms == 100.0


def test_aggregate_benchmark_category_breakdown() -> None:
    summary = _make_benchmark_summary([5, 10])
    assert "TOOL_POISONING" in aggregate_benchmark(summary).category_breakdown


def _make_dynamic_result(violations: int = 2, category: str = "TOOL_POISONING") -> DynamicScanResult:
    viols = [
        PolicyViolation(
            policy_id=f"POLDYN-00{i}",
            category=category,
            severity="HIGH",
            title="Test violation",
            evidence="test evidence",
        )
        for i in range(violations)
    ]
    trace = SimTrace(
        scenario_id="DYN-TEST",
        scenario_name="Test",
        category=category,
        steps=[],
    )
    return DynamicScanResult(
        scenario_id="DYN-TEST",
        scenario_name="Test",
        category=category,
        violations=viols,
        trace=trace,
        violation_count=violations,
        max_severity="HIGH" if violations else None,
        passed_clean=violations == 0,
    )


def test_aggregate_dynamic_counts() -> None:
    results = [
        _make_dynamic_result(2, "TOOL_POISONING"),
        _make_dynamic_result(1, "TASK_DRIFT"),
    ]
    m = aggregate_dynamic(results)
    assert m.scenarios_run == 2
    assert m.violations_total == 3
    assert "TOOL_POISONING" in m.categories_covered
    assert "TASK_DRIFT" in m.categories_covered
    assert m.max_severity_seen == "HIGH"


def test_aggregate_dynamic_clean() -> None:
    m = aggregate_dynamic([_make_dynamic_result(0)])
    assert m.violations_total == 0
    assert m.max_severity_seen is None


def _make_minimal_metrics() -> ProjectMetrics:
    return ProjectMetrics(
        generated_at="2026-01-01T00:00:00+00:00",
        agentshield_version="0.1.0",
        attack_categories=["TOOL_POISONING", "TASK_DRIFT"],
        total_test_cases=5,
        scan=ScanMetrics(
            configs_scanned=2,
            findings_total=4,
            findings_high_or_critical=2,
        ),
        benchmark=BenchmarkMetrics(
            total_cases=5,
            passed=5,
            pass_rate=1.0,
            avg_scan_time_ms=12.3,
            p95_scan_time_ms=20.0,
        ),
        dynamic=DynamicMetrics(
            scenarios_run=3,
            violations_total=7,
            categories_covered=["TOOL_POISONING"],
        ),
        rule_coverage=RuleCoverageMetrics(total_rules=11),
        rules_only_rate=1.0,
        llm_routing_rate=0.0,
        avg_scan_cost_usd=0.0,
        workflows_or_configs_scanned=2,
        findings_total=4,
        findings_high_or_critical=2,
        avg_scan_time_seconds=0.0123,
        p95_scan_time_seconds=0.02,
    )


def test_render_markdown_contains_headings() -> None:
    md = render_markdown(_make_minimal_metrics())
    for heading in [
        "# AgentShield",
        "## Coverage Summary",
        "## Static Scan",
        "## Benchmark Performance",
        "## Dynamic Simulation",
        "## Rule Coverage",
        "## Cost and Routing",
        "## Data Sources",
    ]:
        assert heading in md, f"Missing heading: {heading}"


def test_render_markdown_contains_values() -> None:
    md = render_markdown(_make_minimal_metrics())
    assert "100%" in md
    assert "$0.00" in md
    assert "0.0123" in md
    assert "0.1.0" in md
