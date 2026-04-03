from pydantic import BaseModel, Field


class Finding(BaseModel):
    id: str
    category: str
    severity: str
    title: str
    evidence: str | None = None
    affected_component: str | None = None
    recommendation: str | None = None
    rule_id: str | None = None
    is_confirmed: bool = Field(default=False, description="Static Phase 1 findings default to unconfirmed.")
