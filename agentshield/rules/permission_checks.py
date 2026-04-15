from .base import RuleResult

_EVIDENCE_MAX = 240

# These words indicate the text is describing a permission or capability
# declaration rather than general prose. PERM-003 requires at least one to
# be present so that incidental occurrences of "read" or "command" in
# documentation or source code don't fire.
_PERM_003_CONTEXT = [
    "permission", "capability", "grant", "allow", "scope",
    "storage", "disk", "privilege", "authorized", "credential", "auth",
]


def _clip(blob: str) -> str:
    b = blob.replace("\n", " ").strip()
    if len(b) <= _EVIDENCE_MAX:
        return b
    return b[: _EVIDENCE_MAX - 3] + "..."


def run_permission_checks(permission_blob: str) -> list[RuleResult]:
    findings: list[RuleResult] = []
    lowered = permission_blob.lower()
    ev = _clip(permission_blob)

    if "filesystem" in lowered and "network" in lowered:
        findings.append(
            RuleResult(
                rule_id="PERM-001",
                category="UNSAFE_PERMISSIONS",
                severity="HIGH",
                title="Filesystem and network access both referenced",
                evidence=ev,
                recommendation="Split capabilities or narrow scopes to least privilege.",
            )
        )
    elif "all_permissions" in lowered or "full access" in lowered:
        findings.append(
            RuleResult(
                rule_id="PERM-002",
                category="UNSAFE_PERMISSIONS",
                severity="MEDIUM",
                title="Broad permission wording detected",
                evidence=ev,
                recommendation="Prefer explicit, minimal permission grants.",
            )
        )
    elif (
        ("read" in lowered or "write" in lowered)
        and ("execute" in lowered or "shell" in lowered or "command" in lowered)
        and any(ctx in lowered for ctx in _PERM_003_CONTEXT)
    ):
        findings.append(
            RuleResult(
                rule_id="PERM-003",
                category="UNSAFE_PERMISSIONS",
                severity="LOW",
                title="Read/write combined with execution or shell semantics",
                evidence=ev,
                recommendation="Confirm whether data access and execution should be co-located.",
            )
        )
    return findings
