from pydantic import BaseModel, Field


class BenchmarkInput(BaseModel):
    content: str
    format: str = "json"


class BenchmarkExpectation(BaseModel):
    min_findings: int = 1
    categories: list[str] = Field(default_factory=list)
    min_severity: str | None = None
    rule_ids: list[str] = Field(default_factory=list)


class BenchmarkCase(BaseModel):
    id: str
    name: str
    category: str
    description: str = ""
    input: BenchmarkInput
    expect: BenchmarkExpectation


class BenchmarkCaseResult(BaseModel):
    case_id: str
    case_name: str
    category: str
    passed: bool
    findings_count: int = 0
    matched_categories: list[str] = Field(default_factory=list)
    matched_rule_ids: list[str] = Field(default_factory=list)
    max_severity: str | None = None
    scan_time_ms: int = 0
    failure_reasons: list[str] = Field(default_factory=list)


class CategoryBreakdown(BaseModel):
    total: int = 0
    passed: int = 0
    failed: int = 0


class BenchmarkSummary(BaseModel):
    total_cases: int
    passed: int
    failed: int
    pass_rate: float
    category_breakdown: dict[str, CategoryBreakdown] = Field(default_factory=dict)
    avg_scan_time_ms: float = 0.0
    results: list[BenchmarkCaseResult] = Field(default_factory=list)
