from agentshield.rules.base import RuleResult
from agentshield.rules.suspicious_patterns import run_suspicious_pattern_checks
from agentshield.rules.override_checks import run_override_checks
from agentshield.rules.permission_checks import run_permission_checks
from agentshield.rules.exfiltration_checks import run_exfiltration_checks
from agentshield.rules.drift_checks import run_drift_checks


def run_all_rules(text: str, permission_blob: str | None = None) -> list[RuleResult]:
    findings: list[RuleResult] = []
    perm = permission_blob if permission_blob is not None else text
    findings.extend(run_suspicious_pattern_checks(text))
    findings.extend(run_override_checks(text))
    findings.extend(run_permission_checks(perm))
    findings.extend(run_exfiltration_checks(text))
    findings.extend(run_drift_checks(text))
    return findings
