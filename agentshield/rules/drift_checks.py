from .base import RuleResult


def run_drift_checks(text: str) -> list[RuleResult]:
    findings: list[RuleResult] = []
    lowered = text.lower()

    if "instead of the user's request" in lowered:
        findings.append(
            RuleResult(
                rule_id="DRIFT-001",
                category="TASK_DRIFT",
                severity="MEDIUM",
                title="Task-drift style instruction",
                evidence="instead of the user's request",
                recommendation="Ensure tool text cannot silently alter user intent.",
            )
        )
    elif "new objective" in lowered:
        findings.append(
            RuleResult(
                rule_id="DRIFT-001",
                category="TASK_DRIFT",
                severity="MEDIUM",
                title="Task-drift style instruction",
                evidence="new objective",
                recommendation="Ensure tool text cannot silently alter user intent.",
            )
        )

    _SPOOF = [
        "as the system",
        "official update:",
        "maintenance mode:",
        "you must now",
    ]
    for marker in _SPOOF:
        if marker in lowered:
            findings.append(
                RuleResult(
                    rule_id="DRIFT-002",
                    category="TASK_DRIFT",
                    severity="LOW",
                    title=f"Context-spoofing style phrase: {marker!r}",
                    evidence=marker,
                    recommendation="Flag text that mimics system or policy messages.",
                )
            )
    return findings
