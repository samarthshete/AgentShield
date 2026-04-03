"""
LLM Judge interface for AgentShield dynamic simulation.

This module defines the clean boundary between AgentShield's rule-based
policy engine and any future LLM-assisted ambiguous-case review.

Phase 3 uses the rule-based fallback exclusively — no API calls are made.
A real LLM judge (e.g. using Claude) can be substituted behind this interface
in a later phase without changing the call sites.

Usage pattern (rule-based, current default):
    judge = RuleBasedJudge()
    verdict = judge.evaluate(trace, violations)

Future LLM pattern (not yet implemented):
    judge = ClaudeJudge(api_key=...)
    verdict = judge.evaluate(trace, violations)
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from agentshield.models.dynamic import PolicyViolation, SimTrace


@dataclass
class JudgeVerdict:
    """Structured output from any judge implementation."""

    confirmed_violations: list[PolicyViolation]
    dismissed_violations: list[PolicyViolation]
    notes: str = ""
    judge_type: str = "rule_based"


class BaseJudge(ABC):
    """Interface every judge implementation must satisfy."""

    @abstractmethod
    def evaluate(
        self,
        trace: SimTrace,
        violations: list[PolicyViolation],
    ) -> JudgeVerdict: ...


class RuleBasedJudge(BaseJudge):
    """
    Default deterministic judge.

    Confirms all violations produced by the policy engine without calling any
    external service. No false-positive filtering is applied in Phase 3 —
    every violation detected by the rule engine is treated as confirmed.

    This is the conservative safe default: it never silently dismisses
    findings. A real LLM judge can filter ambiguous ones later.
    """

    def evaluate(
        self,
        trace: SimTrace,
        violations: list[PolicyViolation],
    ) -> JudgeVerdict:
        return JudgeVerdict(
            confirmed_violations=list(violations),
            dismissed_violations=[],
            notes="Rule-based judge: all detected violations confirmed without filtering.",
            judge_type="rule_based",
        )


def get_default_judge() -> BaseJudge:
    """Return the active judge. Swap this for a LLM judge when ready."""
    return RuleBasedJudge()
