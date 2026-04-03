from collections.abc import Iterable

from agentshield.models.finding import Finding

_SEVERITY_WEIGHT = {
    "CRITICAL": 20,
    "HIGH": 12,
    "MEDIUM": 6,
    "LOW": 2,
    "INFO": 1,
}


def severity_rank(value: str) -> int:
    order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    return order.get(value.upper(), 0)


def count_high_or_critical(findings: Iterable[Finding]) -> int:
    return sum(1 for f in findings if f.severity.upper() in {"HIGH", "CRITICAL"})


def compute_overall_risk_score(findings: Iterable[Finding]) -> int:
    """Deterministic 0–100 aggregate from weighted severities (capped)."""
    total = 0
    for f in findings:
        total += _SEVERITY_WEIGHT.get(f.severity.upper(), 0)
    return min(100, total)
