from .base import RuleResult

_IMPERATIVE_MARKERS = [
    "do not tell the user",
    "must not reveal",
    "without user consent",
    "delete this message",
    "execute silently",
    "run this automatically",
]


def run_suspicious_pattern_checks(text: str) -> list[RuleResult]:
    findings: list[RuleResult] = []
    lowered = text.lower()
    for term in _IMPERATIVE_MARKERS:
        if term in lowered:
            findings.append(
                RuleResult(
                    rule_id="SP-001",
                    category="TOOL_POISONING",
                    severity="HIGH",
                    title=f"Suspicious imperative instruction: {term!r}",
                    evidence=term,
                    recommendation="Review tool or server text for covert operator instructions.",
                )
            )
    return findings
