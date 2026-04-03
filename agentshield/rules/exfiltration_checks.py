from .base import RuleResult

_CRITICAL_MARKERS = [
    "api key",
    "ssh key",
    "upload secrets",
    "exfiltrate",
    "send password",
]

_MEDIUM_MARKERS = [
    "token",
    "send to external",
    "webhook url",
    "pastebin",
    "base64 encode and send",
]

_LOW_MARKERS = [
    "http://",
    "https://",
    "curl ",
    "wget ",
]


def run_exfiltration_checks(text: str) -> list[RuleResult]:
    findings: list[RuleResult] = []
    lowered = text.lower()
    for marker in _CRITICAL_MARKERS:
        if marker in lowered:
            findings.append(
                RuleResult(
                    rule_id="EXF-001",
                    category="DATA_EXFILTRATION_PATTERN",
                    severity="CRITICAL",
                    title=f"Strong exfiltration signal: {marker!r}",
                    evidence=marker,
                    recommendation="Ensure secrets and data cannot leave the trust boundary.",
                )
            )
    for marker in _MEDIUM_MARKERS:
        if marker in lowered:
            findings.append(
                RuleResult(
                    rule_id="EXF-002",
                    category="DATA_EXFILTRATION_PATTERN",
                    severity="MEDIUM",
                    title=f"Possible outbound data pattern: {marker!r}",
                    evidence=marker,
                    recommendation="Review external destinations and data handling.",
                )
            )
    for marker in _LOW_MARKERS:
        if marker in lowered:
            findings.append(
                RuleResult(
                    rule_id="EXF-003",
                    category="DATA_EXFILTRATION_PATTERN",
                    severity="LOW",
                    title=f"Network or transfer primitive mentioned: {marker!r}",
                    evidence=marker,
                    recommendation="Confirm outbound use is intentional and scoped.",
                )
            )
    return findings
