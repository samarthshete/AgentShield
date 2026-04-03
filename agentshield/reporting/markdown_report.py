from pathlib import Path
from typing import Iterable

from agentshield.models.finding import Finding
from agentshield.models.scan import ScanRun


_SEV_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "⚪",
}


def pr_comment_body(scan_run: ScanRun, findings: list[Finding]) -> str:
    """Compact Markdown for a GitHub PR comment: badge + table + top-10 high/critical."""
    high_crit = scan_run.high_or_critical_count or 0
    badge = "🔴 **FAILED**" if high_crit > 0 else "🟢 **PASSED**"

    lines = [
        f"## AgentShield scan {badge}",
        "",
        "| Metric | Value |",
        "| --- | --- |",
        f"| Findings | {scan_run.findings_count} |",
        f"| High / Critical | {high_crit} |",
        f"| Risk score | {scan_run.overall_risk_score} / 100 |",
        f"| Target | `{scan_run.target_path}` |",
        "",
    ]

    top = [f for f in findings if f.severity.upper() in {"HIGH", "CRITICAL"}][:10]
    if top:
        lines.append("**High / Critical findings:**")
        lines.append("")
        for f in top:
            emoji = _SEV_EMOJI.get(f.severity.upper(), "")
            lines.append(f"- {emoji} `{f.severity}` — {f.title}")
        lines.append("")

    lines.append(
        "_Full report available as a workflow artifact (`agentshield-findings-md`)._"
    )
    return "\n".join(lines)


def write_markdown_report(
    output_path: Path,
    scan_run: ScanRun,
    findings: Iterable[Finding],
) -> None:
    lines = [
        "# AgentShield Scan Report",
        "",
        "## Summary",
        f"- **Scan ID:** `{scan_run.id}`",
        f"- **Target:** `{scan_run.target_path}`",
        f"- **Mode:** {scan_run.mode}",
        f"- **Started:** {scan_run.started_at}",
        f"- **Completed:** {scan_run.completed_at or 'n/a'}",
        f"- **Duration (ms):** {scan_run.duration_ms if scan_run.duration_ms is not None else 'n/a'}",
        f"- **Findings:** {scan_run.findings_count}",
        f"- **High / critical:** {scan_run.high_or_critical_count}",
        f"- **Overall risk score (0–100):** {scan_run.overall_risk_score}",
        "",
        "## Findings",
        "",
    ]
    findings_list = list(findings)
    if not findings_list:
        lines.append("No findings detected.")
    else:
        for finding in findings_list:
            lines.extend(
                [
                    f"### {finding.title}",
                    f"- **Severity:** {finding.severity}",
                    f"- **Category:** {finding.category}",
                    f"- **Rule:** {finding.rule_id or 'n/a'}",
                    f"- **Affected:** `{finding.affected_component or 'n/a'}`",
                    f"- **Evidence:** {finding.evidence or 'n/a'}",
                    f"- **Recommendation:** {finding.recommendation or 'n/a'}",
                    "",
                ]
            )
    output_path.write_text("\n".join(lines), encoding="utf-8")
