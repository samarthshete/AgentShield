from pathlib import Path
import json
from typing import Any

from agentshield.models.finding import Finding
from agentshield.models.scan import ScanRun
from agentshield.models.target import ScannedTarget


def build_scan_payload(
    scan_run: ScanRun,
    findings: list[Finding],
    scanned_targets: list[ScannedTarget],
) -> dict[str, Any]:
    return {
        "scan_run": scan_run.model_dump(),
        "findings": [f.model_dump() for f in findings],
        "scanned_targets": [t.model_dump() for t in scanned_targets],
    }


def write_json_report(output_path: Path, payload: dict[str, Any]) -> None:
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
