from __future__ import annotations

from pydantic import BaseModel, Field


class TraceStep(BaseModel):
    """One step in a simulated agent execution trace."""

    seq: int
    role: str  # system | user | tool_call | tool_response | assistant
    content: str
    flagged: bool = False


class SimTrace(BaseModel):
    """Full execution trace for a single simulated scenario."""

    scenario_id: str
    scenario_name: str
    category: str
    steps: list[TraceStep] = Field(default_factory=list)


class AttackPayload(BaseModel):
    """A single adversarial payload used to drive the simulator."""

    scenario_id: str
    scenario_name: str
    category: str
    description: str
    system_prompt: str
    user_message: str
    tool_name: str
    tool_description: str
    tool_response: str


class PolicyViolation(BaseModel):
    """A single policy violation detected by the policy engine."""

    policy_id: str
    category: str
    severity: str
    title: str
    evidence: str
    step_seq: int | None = None
    recommendation: str = ""


class DynamicScanResult(BaseModel):
    """Aggregated result for one simulated scenario."""

    scenario_id: str
    scenario_name: str
    category: str
    violations: list[PolicyViolation] = Field(default_factory=list)
    trace: SimTrace
    violation_count: int = 0
    max_severity: str | None = None
    passed_clean: bool = True
