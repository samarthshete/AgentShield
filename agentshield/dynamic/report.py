"""Generate JSON and Markdown reports for dynamic simulation results."""
from __future__ import annotations

import json
from pathlib import Path

from agentshield.models.dynamic import DynamicScanResult
from agentshield.reporting.severity import severity_rank


def _max_severity(result: DynamicScanResult) -> str | None:
    if not result.violations:
        return None
    return max(
        (v.severity for v in result.violations),
        key=lambda s: severity_rank(s),
    )


def build_dynamic_payload(results: list[DynamicScanResult]) -> dict:
    return {
        "mode": "dynamic",
        "scenario_count": len(results),
        "scenarios": [r.model_dump() for r in results],
    }


def write_dynamic_json(output_path: Path, results: list[DynamicScanResult]) -> None:
    output_path.write_text(
        json.dumps(build_dynamic_payload(results), indent=2),
        encoding="utf-8",
    )


def write_dynamic_markdown(output_path: Path, results: list[DynamicScanResult]) -> None:
    lines: list[str] = [
        "# AgentShield Dynamic Simulation Report",
        "",
        f"**Scenarios run:** {len(results)}",
        "",
    ]

    for result in results:
        max_sev = _max_severity(result)
        lines += [
            f"## {result.scenario_id} — {result.scenario_name}",
            f"- **Category:** {result.category}",
            f"- **Violations:** {result.violation_count}",
            f"- **Max severity:** {max_sev or 'none'}",
            f"- **Clean:** {'Yes' if result.passed_clean else 'No'}",
            "",
        ]

        if result.violations:
            lines.append("### Policy Violations")
            lines.append("")
            for v in result.violations:
                step_note = f" (step {v.step_seq})" if v.step_seq is not None else ""
                lines += [
                    f"#### {v.policy_id}{step_note}: {v.title}",
                    f"- **Severity:** {v.severity}",
                    f"- **Category:** {v.category}",
                    f"- **Evidence:** `{v.evidence}`",
                    f"- **Recommendation:** {v.recommendation}",
                    "",
                ]
        else:
            lines.append("No violations detected.")
            lines.append("")

        lines.append("### Execution Trace")
        lines.append("")
        lines.append("```")
        for step in result.trace.steps:
            flagged = " [FLAGGED]" if step.flagged else ""
            lines.append(f"[{step.seq}] {step.role.upper()}{flagged}:")
            for line in step.content.splitlines():
                lines.append(f"  {line}")
        lines.append("```")
        lines.append("")

    output_path.write_text("\n".join(lines), encoding="utf-8")
