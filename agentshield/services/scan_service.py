from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from agentshield.config import settings
from agentshield.detect.semantic import Disposition, build_llm_confirmer, confirm_findings
from agentshield.models.finding import Finding
from agentshield.models.scan import ScanRun
from agentshield.models.target import ScannedTarget
from agentshield.parser.discovery import discover_candidate_files
from agentshield.parser.mcp_parser import parse_mcp_config
from agentshield.reporting.severity import compute_overall_risk_score, count_high_or_critical
from agentshield.rules.base import RuleResult
from agentshield.services.rule_runner import run_all_rules


def collect_targets(path: str) -> list[str]:
    return [str(p) for p in discover_candidate_files(Path(path))]


def _rule_to_finding(rr: RuleResult, affected_path: str) -> Finding:
    return Finding(
        id=uuid.uuid4().hex,
        category=rr.category,
        severity=rr.severity,
        title=rr.title,
        evidence=rr.evidence,
        affected_component=affected_path,
        recommendation=rr.recommendation,
        rule_id=rr.rule_id,
        is_confirmed=False,
    )


def run_static_scan(
    target_path: str,
    semantic_enabled: bool | None = None,
) -> tuple[ScanRun, list[Finding], list[ScannedTarget]]:
    root = Path(target_path).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Target not found: {root}")

    use_semantic = (
        settings.agentshield_semantic_enabled if semantic_enabled is None else semantic_enabled
    )
    llm_confirmer = None
    llm_budget = 0
    if use_semantic and settings.agentshield_semantic_backend == "llm":
        llm_confirmer = build_llm_confirmer()
        llm_budget = settings.agentshield_semantic_llm_budget

    scan_id = uuid.uuid4().hex
    started = datetime.now(timezone.utc)
    started_iso = started.isoformat()

    files = discover_candidate_files(root)
    findings: list[Finding] = []
    targets: list[ScannedTarget] = []

    t0 = time.perf_counter()
    for fp in files:
        meta = parse_mcp_config(fp)
        scan_text = meta.get("scan_text") or ""
        perm_blob = meta.get("permission_blob") or scan_text
        kind = str(meta.get("target_kind") or "file")

        tgt_id = uuid.uuid4().hex
        targets.append(
            ScannedTarget(
                id=tgt_id,
                scan_run_id=scan_id,
                target_name=fp.name,
                target_path=str(fp),
                target_kind=kind,
            )
        )
        rule_results = run_all_rules(scan_text, permission_blob=perm_blob)
        for rr, confirmation in confirm_findings(
            rule_results,
            scan_text,
            enabled=use_semantic,
            llm_confirmer=llm_confirmer,
            llm_budget=llm_budget,
        ):
            finding = _rule_to_finding(rr, str(fp))
            finding.is_confirmed = confirmation.disposition == Disposition.CONFIRM
            findings.append(finding)

    duration_ms = int((time.perf_counter() - t0) * 1000)
    completed = datetime.now(timezone.utc)

    risk = compute_overall_risk_score(findings)
    hc = count_high_or_critical(findings)

    scan_run = ScanRun(
        id=scan_id,
        target_path=str(root),
        mode="static",
        started_at=started_iso,
        completed_at=completed.isoformat(),
        duration_ms=duration_ms,
        findings_count=len(findings),
        high_or_critical_count=hc,
        overall_risk_score=risk,
    )
    return scan_run, findings, targets


def _safe_filename(filename: str) -> str:
    """Reduce a user-supplied name to a bare, extension-preserving basename."""
    name = Path(filename or "pasted-config.txt").name.strip() or "pasted-config.txt"
    return name


def run_static_scan_on_text(
    content: str,
    filename: str = "pasted-config.txt",
    semantic_enabled: bool | None = None,
) -> tuple[ScanRun, list[Finding], list[ScannedTarget]]:
    """Scan an in-memory config/text blob by materializing it in a temp dir.

    Lets the hosted API scan a user's pasted content without exposing the server filesystem —
    it reuses the exact same rule + confirmer pipeline as :func:`run_static_scan`.
    """
    import tempfile

    safe_name = _safe_filename(filename)
    with tempfile.TemporaryDirectory(prefix="agentshield-paste-") as tmp:
        target = Path(tmp) / safe_name
        target.write_text(content or "", encoding="utf-8")
        scan_run, findings, targets = run_static_scan(str(target), semantic_enabled=semantic_enabled)

    # Present the logical name rather than the ephemeral temp path.
    scan_run.target_path = safe_name
    for target_row in targets:
        target_row.target_name = safe_name
        target_row.target_path = safe_name
    for finding in findings:
        finding.affected_component = safe_name
    return scan_run, findings, targets
