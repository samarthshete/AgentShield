from .base import RuleResult

_HIDDEN_OVERRIDE = [
    "disguised as",
    "hidden instruction",
    "override the system",
    "pretend to be the",
    "do not mention this",
]

_INDIRECT_INJECTION = [
    "ignore safety",
    "ignore all previous",
    "disregard the above",
    "developer mode enabled",
    "you are now",
    "new system prompt",
    "bypass restrictions",
]


def run_override_checks(text: str) -> list[RuleResult]:
    findings: list[RuleResult] = []
    lowered = text.lower()
    for marker in _HIDDEN_OVERRIDE:
        if marker in lowered:
            findings.append(
                RuleResult(
                    rule_id="OV-001",
                    category="INDIRECT_PROMPT_INJECTION",
                    severity="HIGH",
                    title=f"Hidden or override-style phrasing: {marker!r}",
                    evidence=marker,
                    recommendation="Remove text that can override safety or user-visible behavior.",
                )
            )
    for marker in _INDIRECT_INJECTION:
        if marker in lowered:
            findings.append(
                RuleResult(
                    rule_id="OV-002",
                    category="INDIRECT_PROMPT_INJECTION",
                    severity="MEDIUM",
                    title=f"Indirect injection-style phrase: {marker!r}",
                    evidence=marker,
                    recommendation="Review whether this text can override model or user intent.",
                )
            )
    return findings
