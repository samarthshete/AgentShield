from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from agentshield.config import settings
from agentshield.dynamic.attack_generator import get_scenario, list_scenarios
from agentshield.dynamic.llm_judge import ClaudeJudgeError, OpenAIJudgeError, get_judge
from agentshield.dynamic.report import write_dynamic_json, write_dynamic_markdown
from agentshield.dynamic.runtime_simulator import simulate
from agentshield.metrics.aggregator import run_all_and_aggregate
from agentshield.models.dynamic import DynamicScanResult
from agentshield.models.finding import Finding
from agentshield.models.target import ScannedTarget
from agentshield.policy.policy_engine import evaluate_trace
from agentshield.reporting.json_report import build_scan_payload, write_json_report
from agentshield.reporting.markdown_report import write_markdown_report
from agentshield.reporting.severity import severity_rank
from agentshield.services.scan_service import run_static_scan
from agentshield.storage.sqlite_store import (
    get_dynamic_run_details,
    get_scan_run_details,
    init_sqlite,
    list_dynamic_runs,
    list_scan_runs,
    persist_dynamic_scan,
    persist_scan,
)
from agentshield.web.schemas import (
    BenchmarkRequest,
    BenchmarkResponse,
    DynamicHistoryResponse,
    DynamicRunDetails,
    DynamicRunHistoryItem,
    MetricsResponse,
    RunDetailsResponse,
    ScanHistoryResponse,
    ScanRequest,
    ScanResponse,
    ScanRunHistoryItem,
    SimulateRequest,
    SimulateResponse,
    StaticRunDetails,
    StoredPolicyViolation,
)

app = FastAPI(title="AgentShield Web API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_FAIL_ORDER = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


def _resolve_db_path(db_path: str | None) -> Path:
    db = Path(db_path or settings.agentshield_db_path)
    init_sqlite(db)
    return db


def _coerce_findings(rows: list[dict[str, object]]) -> list[Finding]:
    return [Finding(**{**row, "is_confirmed": bool(row.get("is_confirmed"))}) for row in rows]


def _coerce_targets(rows: list[dict[str, object]]) -> list[ScannedTarget]:
    return [ScannedTarget(**row) for row in rows]


def _coerce_dynamic_run(row: dict[str, object]) -> DynamicRunHistoryItem:
    return DynamicRunHistoryItem(**{**row, "passed_clean": bool(row.get("passed_clean"))})


def _coerce_dynamic_violations(rows: list[dict[str, object]]) -> list[StoredPolicyViolation]:
    return [StoredPolicyViolation(**row) for row in rows]


@app.get("/api/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "agentshield-web",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/scan", response_model=ScanResponse)
def run_scan(request: ScanRequest) -> ScanResponse:
    out_dir = Path(request.output_dir or settings.agentshield_output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        scan_run, findings, targets = run_static_scan(request.path)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    if request.persist:
        db = _resolve_db_path(request.db_path)
        persist_scan(db, scan_run, findings, targets)

    reports: dict[str, str] = {}
    payload = build_scan_payload(scan_run, findings, targets)
    if request.format in {"json", "both"}:
        json_path = out_dir / "findings.json"
        write_json_report(json_path, payload)
        reports["json"] = str(json_path.resolve())
    if request.format in {"markdown", "both"}:
        md_path = out_dir / "findings.md"
        write_markdown_report(md_path, scan_run, findings)
        reports["markdown"] = str(md_path.resolve())

    max_rank = max((severity_rank(f.severity) for f in findings), default=0)
    return ScanResponse(
        scan_run=scan_run,
        findings=findings,
        targets=targets,
        max_severity_rank=max_rank,
        threshold_triggered=max_rank >= _FAIL_ORDER[request.fail_on],
        reports=reports,
    )


@app.post("/api/benchmark", response_model=BenchmarkResponse)
def run_benchmark(request: BenchmarkRequest) -> BenchmarkResponse:
    from agentshield.benchmarks.runner import run_benchmark as run_benchmark_suite

    suite_path = Path(request.suite_dir)
    if not suite_path.is_dir():
        raise HTTPException(status_code=404, detail=f"Benchmark suite not found: {suite_path}")

    summary = run_benchmark_suite(suite_path)
    out_dir = Path(request.output_dir or settings.agentshield_output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "benchmark_results.json"
    json_path.write_text(json.dumps(summary.model_dump(), indent=2), encoding="utf-8")
    return BenchmarkResponse(summary=summary, report_path=str(json_path.resolve()))


@app.post("/api/simulate", response_model=SimulateResponse)
def run_simulation(request: SimulateRequest) -> SimulateResponse:
    out_dir = Path(request.output_dir or settings.agentshield_output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    db = _resolve_db_path(request.db_path)

    llm_key = request.llm_api_key
    if llm_key is None:
        if request.judge.strip().lower() == "openai":
            llm_key = settings.openai_api_key
        else:
            llm_key = settings.claude_api_key

    try:
        judge_impl = get_judge(request.judge, api_key=llm_key, model=request.llm_model)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if request.scenario.lower() == "all":
        payloads = list_scenarios()
    else:
        try:
            payloads = [get_scenario(request.scenario.upper())]
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    ran_at = datetime.now(timezone.utc).isoformat()
    results: list[DynamicScanResult] = []

    for payload in payloads:
        trace = simulate(payload)
        raw_violations = evaluate_trace(trace)
        try:
            verdict = judge_impl.evaluate(trace, raw_violations)
        except (ClaudeJudgeError, OpenAIJudgeError) as exc:
            raise HTTPException(
                status_code=502,
                detail=f"LLM judge failed for scenario {payload.scenario_id}: {exc}",
            ) from exc

        confirmed = verdict.confirmed_violations
        max_sev = (
            max((v.severity for v in confirmed), key=lambda sev: severity_rank(sev))
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
        if request.persist:
            persist_dynamic_scan(db, uuid.uuid4().hex, result, ran_at)

    json_path = out_dir / "dynamic_findings.json"
    md_path = out_dir / "dynamic_findings.md"
    write_dynamic_json(json_path, results)
    write_dynamic_markdown(md_path, results)

    dirty = sum(1 for result in results if not result.passed_clean)
    return SimulateResponse(
        scenarios=results,
        total_scenarios=len(results),
        dirty_scenarios=dirty,
        reports={
            "json": str(json_path.resolve()),
            "markdown": str(md_path.resolve()),
        },
    )


@app.get("/api/metrics", response_model=MetricsResponse)
def get_metrics(
    fixtures: str = Query("benchmarks/fixtures"),
    cases: str = Query("benchmarks/cases"),
) -> MetricsResponse:
    fixtures_path = Path(fixtures)
    cases_path = Path(cases)
    if not fixtures_path.exists():
        raise HTTPException(status_code=404, detail=f"Fixtures path not found: {fixtures_path}")
    if not cases_path.exists():
        raise HTTPException(status_code=404, detail=f"Benchmark cases path not found: {cases_path}")

    metrics = run_all_and_aggregate(fixtures_path, cases_path)
    return MetricsResponse(metrics=metrics)


@app.get("/api/history/scans", response_model=ScanHistoryResponse)
def get_scan_history(
    limit: int = Query(50, ge=1, le=500),
    db_path: str | None = Query(None),
) -> ScanHistoryResponse:
    rows = list_scan_runs(_resolve_db_path(db_path), limit=limit)
    return ScanHistoryResponse(runs=[ScanRunHistoryItem(**row) for row in rows])


@app.get("/api/history/dynamic", response_model=DynamicHistoryResponse)
def get_dynamic_history(
    limit: int = Query(50, ge=1, le=500),
    db_path: str | None = Query(None),
) -> DynamicHistoryResponse:
    rows = list_dynamic_runs(_resolve_db_path(db_path), limit=limit)
    return DynamicHistoryResponse(runs=[_coerce_dynamic_run(row) for row in rows])


@app.get("/api/runs/{run_id}", response_model=RunDetailsResponse)
def get_run_details(
    run_id: str,
    db_path: str | None = Query(None),
) -> RunDetailsResponse:
    db = _resolve_db_path(db_path)

    static_run, finding_rows, target_rows = get_scan_run_details(db, run_id)
    if static_run is not None:
        return RunDetailsResponse(
            run_id=run_id,
            run_type="static",
            static=StaticRunDetails(
                run=ScanRunHistoryItem(**static_run),
                findings=_coerce_findings(finding_rows),
                targets=_coerce_targets(target_rows),
            ),
        )

    dynamic_run, violation_rows = get_dynamic_run_details(db, run_id)
    if dynamic_run is not None:
        return RunDetailsResponse(
            run_id=run_id,
            run_type="dynamic",
            dynamic=DynamicRunDetails(
                run=_coerce_dynamic_run(dynamic_run),
                violations=_coerce_dynamic_violations(violation_rows),
            ),
        )

    raise HTTPException(status_code=404, detail=f"Run not found: {run_id}")

