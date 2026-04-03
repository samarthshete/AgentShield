from __future__ import annotations

from pydantic import BaseModel, Field


class RuleInfo(BaseModel):
    rule_id: str
    category: str
    severity: str


class ScanMetrics(BaseModel):
    configs_scanned: int = 0
    findings_total: int = 0
    findings_high_or_critical: int = 0
    overall_risk_score: int = 0


class BenchmarkMetrics(BaseModel):
    total_cases: int = 0
    passed: int = 0
    failed: int = 0
    pass_rate: float = 0.0
    avg_scan_time_ms: float = 0.0
    p95_scan_time_ms: float = 0.0
    category_breakdown: dict[str, dict[str, int]] = Field(default_factory=dict)


class DynamicMetrics(BaseModel):
    scenarios_run: int = 0
    violations_total: int = 0
    categories_covered: list[str] = Field(default_factory=list)
    max_severity_seen: str | None = None


class RuleCoverageMetrics(BaseModel):
    total_rules: int = 0
    rules_by_category: dict[str, list[str]] = Field(default_factory=dict)
    all_rules: list[RuleInfo] = Field(default_factory=list)


class ProjectMetrics(BaseModel):
    generated_at: str
    agentshield_version: str

    attack_categories: list[str] = Field(default_factory=list)
    total_test_cases: int = 0

    scan: ScanMetrics = Field(default_factory=ScanMetrics)
    benchmark: BenchmarkMetrics = Field(default_factory=BenchmarkMetrics)
    dynamic: DynamicMetrics = Field(default_factory=DynamicMetrics)
    rule_coverage: RuleCoverageMetrics = Field(default_factory=RuleCoverageMetrics)

    # Structural: no LLM calls exist in Phase 1–5
    rules_only_rate: float = 1.0
    llm_routing_rate: float = 0.0
    avg_scan_cost_usd: float = 0.0

    # Top-level mirrors of sub-object fields for flat access / resume export
    workflows_or_configs_scanned: int = 0
    findings_total: int = 0
    findings_high_or_critical: int = 0
    avg_scan_time_seconds: float = 0.0
    p95_scan_time_seconds: float = 0.0
