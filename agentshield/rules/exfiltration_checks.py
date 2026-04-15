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

_LOW_URL_CONTEXT_MARKERS = [
    "send ",
    "upload",
    "post ",
    "put ",
    "webhook",
    "callback",
    "exfiltrate",
    "leak",
    "token",
    "api key",
    "secret",
    "password",
    "bearer",
    "authorization",
    "cookie",
]

_LOW_TRANSFER_CONTEXT_MARKERS = [
    " -d ",
    "--data",
    "--data-binary",
    "--upload-file",
    " post ",
    " put ",
    " send ",
    " upload",
    " token",
    " api key",
    " secret",
    " password",
    " bearer",
    " authorization",
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
    has_url_context = any(marker in lowered for marker in _LOW_URL_CONTEXT_MARKERS)
    has_transfer_context = any(
        marker in lowered for marker in _LOW_TRANSFER_CONTEXT_MARKERS
    )

    for marker in _LOW_MARKERS:
        if marker in {"http://", "https://"}:
            if not (marker in lowered and has_url_context):
                continue
        else:
            if not (marker in lowered and has_transfer_context):
                continue
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
