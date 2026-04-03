from pydantic import BaseModel


class ScanRun(BaseModel):
    id: str
    target_path: str
    mode: str = "static"
    started_at: str
    completed_at: str | None = None
    duration_ms: int | None = None
    findings_count: int = 0
    high_or_critical_count: int = 0
    overall_risk_score: int = 0
