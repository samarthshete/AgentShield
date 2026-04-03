from agentshield.models.finding import Finding
from agentshield.models.scan import ScanRun
from agentshield.models.target import ScannedTarget
from agentshield.reporting.json_report import build_scan_payload
from agentshield.reporting.severity import compute_overall_risk_score, severity_rank


def test_build_scan_payload_shape() -> None:
    scan = ScanRun(
        id="s1",
        target_path="/tmp",
        mode="static",
        started_at="2025-01-01T00:00:00+00:00",
        completed_at="2025-01-01T00:00:01+00:00",
        duration_ms=1,
        findings_count=1,
        high_or_critical_count=1,
        overall_risk_score=12,
    )
    f = Finding(
        id="f1",
        category="TOOL_POISONING",
        severity="HIGH",
        title="t",
        rule_id="SP-001",
    )
    t = ScannedTarget(
        id="t1",
        scan_run_id="s1",
        target_name="x.json",
        target_path="/tmp/x.json",
        target_kind="json",
    )
    payload = build_scan_payload(scan, [f], [t])
    assert payload["scan_run"]["id"] == "s1"
    assert len(payload["findings"]) == 1
    assert payload["findings"][0]["severity"] == "HIGH"


def test_severity_rank_order() -> None:
    assert severity_rank("CRITICAL") > severity_rank("LOW")


def test_risk_score_cap() -> None:
    findings = [
        Finding(
            id=str(i),
            category="X",
            severity="CRITICAL",
            title="t",
        )
        for i in range(20)
    ]
    assert compute_overall_risk_score(findings) == 100
