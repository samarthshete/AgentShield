from pydantic import BaseModel

class RuleResult(BaseModel):
    rule_id: str
    category: str
    severity: str
    title: str
    evidence: str | None = None
    recommendation: str | None = None
