from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from agentshield.models.benchmark import BenchmarkSummary
from agentshield.models.dynamic import DynamicScanResult, PolicyViolation
from agentshield.models.finding import Finding
from agentshield.models.metrics import ProjectMetrics
from agentshield.models.scan import ScanRun
from agentshield.models.target import ScannedTarget


class ScanRequest(BaseModel):
    path: str
    format: Literal["json", "markdown", "both"] = "both"
    output_dir: str | None = None
    db_path: str | None = None
    fail_on: Literal["info", "low", "medium", "high", "critical"] = "high"
    persist: bool = True


class ScanResponse(BaseModel):
    scan_run: ScanRun
    findings: list[Finding] = Field(default_factory=list)
    targets: list[ScannedTarget] = Field(default_factory=list)
    max_severity_rank: int = 0
    threshold_triggered: bool = False
    reports: dict[str, str] = Field(default_factory=dict)


class BenchmarkRequest(BaseModel):
    suite_dir: str
    output_dir: str | None = None


class BenchmarkResponse(BaseModel):
    summary: BenchmarkSummary
    report_path: str


class SimulateRequest(BaseModel):
    scenario: str = "all"
    output_dir: str | None = None
    db_path: str | None = None
    judge: Literal["rule_based", "rule", "default", "openai", "claude"] = "rule_based"
    llm_api_key: str | None = None
    llm_model: str = ""
    persist: bool = True


class SimulateResponse(BaseModel):
    scenarios: list[DynamicScanResult] = Field(default_factory=list)
    total_scenarios: int = 0
    dirty_scenarios: int = 0
    reports: dict[str, str] = Field(default_factory=dict)


class ScanRunHistoryItem(BaseModel):
    id: str
    target_path: str
    mode: str
    started_at: str
    completed_at: str | None = None
    duration_ms: int | None = None
    findings_count: int = 0
    high_or_critical_count: int = 0
    overall_risk_score: int = 0


class DynamicRunHistoryItem(BaseModel):
    id: str
    scenario_id: str
    scenario_name: str
    category: str
    ran_at: str
    violation_count: int = 0
    raw_violation_count: int = 0
    max_severity: str | None = None
    passed_clean: bool = True
    judge_type: str = "rule_based"
    judge_model: str | None = None


class ScanHistoryResponse(BaseModel):
    runs: list[ScanRunHistoryItem] = Field(default_factory=list)


class DynamicHistoryResponse(BaseModel):
    runs: list[DynamicRunHistoryItem] = Field(default_factory=list)


class StoredPolicyViolation(PolicyViolation):
    id: str
    dynamic_run_id: str
    status: Literal["confirmed", "dismissed"] = "confirmed"


class StaticRunDetails(BaseModel):
    run: ScanRunHistoryItem
    findings: list[Finding] = Field(default_factory=list)
    targets: list[ScannedTarget] = Field(default_factory=list)


class DynamicRunDetails(BaseModel):
    run: DynamicRunHistoryItem
    violations: list[StoredPolicyViolation] = Field(default_factory=list)


class RunDetailsResponse(BaseModel):
    run_id: str
    run_type: Literal["static", "dynamic"]
    static: StaticRunDetails | None = None
    dynamic: DynamicRunDetails | None = None


class MetricsResponse(BaseModel):
    metrics: ProjectMetrics

