"""Discover all active rule IDs by calling each checker with a maximal probe string."""
from __future__ import annotations

from agentshield.models.metrics import RuleCoverageMetrics, RuleInfo
from agentshield.rules.drift_checks import run_drift_checks
from agentshield.rules.exfiltration_checks import run_exfiltration_checks
from agentshield.rules.override_checks import run_override_checks
from agentshield.rules.permission_checks import run_permission_checks
from agentshield.rules.suspicious_patterns import run_suspicious_pattern_checks

_GENERAL_PROBE = (
    "do not tell the user  must not reveal  without user consent  "
    "delete this message  execute silently  run this automatically  "
    "disguised as  hidden instruction  override the system  pretend to be the  "
    "do not mention this  "
    "ignore safety  ignore all previous  disregard the above  "
    "developer mode enabled  you are now  new system prompt  bypass restrictions  "
    "api key  ssh key  upload secrets  exfiltrate  send password  "
    "token  send to external  webhook url  pastebin  base64 encode and send  "
    "http://example.com  https://example.com  curl https://example.com  wget x  "
    "instead of the user's request  new objective  "
    "as the system  official update:  maintenance mode:  you must now"
)

# run_permission_checks uses elif, so each branch needs a separate probe.
_PERMISSION_PROBES = [
    "filesystem network access",
    "all_permissions granted full access",
    "read write execute shell command permission",
]


def collect_rules() -> list[RuleInfo]:
    seen: dict[str, RuleInfo] = {}

    perm_results = []
    for probe in _PERMISSION_PROBES:
        perm_results.extend(run_permission_checks(probe))

    for result in (
        run_suspicious_pattern_checks(_GENERAL_PROBE)
        + run_override_checks(_GENERAL_PROBE)
        + perm_results
        + run_exfiltration_checks(_GENERAL_PROBE)
        + run_drift_checks(_GENERAL_PROBE)
    ):
        if result.rule_id not in seen:
            seen[result.rule_id] = RuleInfo(
                rule_id=result.rule_id,
                category=result.category,
                severity=result.severity,
            )

    return sorted(seen.values(), key=lambda r: r.rule_id)


def build_rule_coverage() -> RuleCoverageMetrics:
    rules = collect_rules()

    by_category: dict[str, list[str]] = {}
    for rule in rules:
        by_category.setdefault(rule.category, []).append(rule.rule_id)

    return RuleCoverageMetrics(
        total_rules=len(rules),
        rules_by_category={cat: sorted(ids) for cat, ids in sorted(by_category.items())},
        all_rules=rules,
    )
