from __future__ import annotations

from pathlib import Path

from agentshield.web.app import (
    get_dynamic_history,
    get_metrics,
    get_scan_history,
    health,
    run_benchmark,
    run_scan,
    run_simulation,
)
from agentshield.web.schemas import BenchmarkRequest, ScanRequest, SimulateRequest


def test_health_endpoint_payload() -> None:
    payload = health()
    assert payload["status"] == "ok"
    assert payload["service"] == "agentshield-web"
    assert "timestamp" in payload


def test_scan_endpoint_runs(tmp_path: Path) -> None:
    db_path = tmp_path / "scan.db"
    out_dir = tmp_path / "scan-output"
    response = run_scan(
        ScanRequest(
            path="benchmarks/fixtures",
            format="json",
            output_dir=str(out_dir),
            db_path=str(db_path),
            persist=True,
        )
    )
    assert response.scan_run.findings_count >= 0
    assert "json" in response.reports
    history = get_scan_history(limit=10, db_path=str(db_path))
    assert len(history.runs) >= 1


def test_benchmark_endpoint_runs(tmp_path: Path) -> None:
    out_dir = tmp_path / "benchmark-output"
    response = run_benchmark(
        BenchmarkRequest(
            suite_dir="benchmarks/cases",
            output_dir=str(out_dir),
        )
    )
    assert response.summary.total_cases > 0
    assert response.report_path.endswith("benchmark_results.json")


def test_simulate_endpoint_runs(tmp_path: Path) -> None:
    db_path = tmp_path / "simulate.db"
    out_dir = tmp_path / "simulate-output"
    response = run_simulation(
        SimulateRequest(
            scenario="DYN-TP-001",
            output_dir=str(out_dir),
            db_path=str(db_path),
            persist=True,
            judge="rule_based",
        )
    )
    assert response.total_scenarios == 1
    assert "json" in response.reports
    history = get_dynamic_history(limit=10, db_path=str(db_path))
    assert len(history.runs) >= 1


def test_metrics_endpoint_runs() -> None:
    response = get_metrics(fixtures="benchmarks/fixtures", cases="benchmarks/cases")
    assert response.metrics.total_test_cases > 0
    assert response.metrics.findings_total >= 0

