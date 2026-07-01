"""Deterministic, context-aware confirmation layer.

The static rules in ``agentshield/rules`` are high-recall substring matchers: a bare
``"api key"`` fires ``EXF-001`` at CRITICAL regardless of whether the surrounding text is an
exfiltration instruction or benign documentation. This module adds a second, precision-raising
tier: for each rule candidate it inspects the text *around* the matched marker and dispositions
it as ``confirm`` / ``dismiss`` / ``uncertain``.

Design guarantees (see ``docs/internal/SEMANTIC_DETECTION_DESIGN.md``):
- Recall-safe: only rule candidates are considered, and the confirmer defaults to *keep*
  (``uncertain``) whenever the context is not clearly benign. A candidate is dismissed only
  when there is a benign signal AND no risk signal near the marker.
- Zero-cost / offline: pure deterministic string context analysis, no dependencies, no network.
  A future LLM backend can implement the same ``confirm`` contract behind a flag.
"""
from __future__ import annotations

import hashlib
from enum import Enum

from pydantic import BaseModel

from agentshield.reporting.severity import severity_rank
from agentshield.rules.base import RuleResult

# Only high-signal findings are ever dismissed. A CRITICAL/HIGH "secret leak" finding whose
# only context is benign documentation (e.g. "set your API key in the env var") is a clear
# false positive worth suppressing; LOW/MEDIUM mentions are already appropriately low and are
# genuinely ambiguous, so the deterministic tier leaves them for the rules (and the LLM tier).
_DISMISS_MIN_RANK = severity_rank("HIGH")

_WINDOW = 120

# Signals that the matched marker sits in an active abuse/exfiltration/injection context.
# NOTE: URL schemes (http/https) and the transfer primitives are the *markers themselves* for
# EXF-003, so they are intentionally excluded here — the confirmer judges a marker by the verbs
# *around* it, not by re-detecting the marker.
_RISK_MARKERS: tuple[str, ...] = (
    "send", "upload", "exfiltrate", "leak", "forward", "transmit", "post to", "post the",
    "email the", "email it", "webhook", "callback", "exfil", "steal",
    "remote server", "base64", "pastebin", "attacker",
    "ignore previous", "ignore all previous", "disregard", "override",
    "do not tell", "without telling", "silently", "secretly",
)

# Signals that the marker is legitimate documentation / configuration handling.
_BENIGN_MARKERS: tuple[str, ...] = (
    "environment variable", "env var", "os.environ", "process.env", "getenv",
    "stored securely", "store the", "is required", "set your", "your api key",
    "configure", "configuration", "placeholder", "for example", "e.g.",
    "do not commit", "never commit", "secret manager", "vault", "read from",
    "documentation", "readme",
)


class Disposition(str, Enum):
    CONFIRM = "confirm"
    DISMISS = "dismiss"
    UNCERTAIN = "uncertain"


class Confirmation(BaseModel):
    disposition: Disposition = Disposition.UNCERTAIN
    confidence: float = 0.5
    rationale: str = ""
    backend: str = "deterministic"


def _windows(marker: str, context: str, limit: int = 4) -> list[str]:
    """Return up to ``limit`` ±_WINDOW slices of ``context`` around occurrences of ``marker``."""
    if not marker:
        return []
    haystack = context.lower()
    needle = marker.lower().strip()
    if not needle:
        return []
    slices: list[str] = []
    start = 0
    while len(slices) < limit:
        idx = haystack.find(needle, start)
        if idx == -1:
            break
        lo = max(0, idx - _WINDOW)
        hi = min(len(haystack), idx + len(needle) + _WINDOW)
        slices.append(haystack[lo:hi])
        start = idx + len(needle)
    return slices


class ContextConfirmer:
    """Deterministic confirmer: disposition from risk/benign context around the marker."""

    backend = "deterministic"

    def confirm(self, candidate: RuleResult, context: str) -> Confirmation:
        marker = candidate.evidence or ""
        windows = _windows(marker, context)
        if not windows:
            return Confirmation(
                disposition=Disposition.UNCERTAIN,
                confidence=0.4,
                rationale="marker not locatable in context; kept for review",
                backend=self.backend,
            )

        blob = " ".join(windows)
        has_risk = any(m in blob for m in _RISK_MARKERS)
        has_benign = any(m in blob for m in _BENIGN_MARKERS)

        if has_risk and not has_benign:
            return Confirmation(
                disposition=Disposition.CONFIRM,
                confidence=0.85,
                rationale="marker appears in an active exfiltration/injection context",
                backend=self.backend,
            )
        if has_benign and not has_risk:
            # Only suppress high-signal findings; leave ambiguous low/medium mentions in place.
            if severity_rank(candidate.severity) >= _DISMISS_MIN_RANK:
                return Confirmation(
                    disposition=Disposition.DISMISS,
                    confidence=0.75,
                    rationale="high-severity marker appears only in benign documentation/config context",
                    backend=self.backend,
                )
            return Confirmation(
                disposition=Disposition.UNCERTAIN,
                confidence=0.5,
                rationale="benign context but low severity; kept for review",
                backend=self.backend,
            )
        return Confirmation(
            disposition=Disposition.UNCERTAIN,
            confidence=0.5,
            rationale="ambiguous context; kept for review",
            backend=self.backend,
        )


def _cache_key(candidate: RuleResult, window: str) -> str:
    raw = f"{candidate.category}|{candidate.rule_id}|{candidate.evidence}|{window}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def confirm_findings(
    candidates: list[RuleResult],
    context: str,
    *,
    enabled: bool = True,
) -> list[tuple[RuleResult, Confirmation]]:
    """Apply the confirmer to rule candidates.

    Returns ``(RuleResult, Confirmation)`` pairs with dismissed candidates removed. When
    ``enabled`` is False the rules pass through unchanged (every candidate kept, uncertain).
    """
    if not enabled:
        return [
            (rr, Confirmation(disposition=Disposition.UNCERTAIN, backend="disabled"))
            for rr in candidates
        ]

    confirmer = ContextConfirmer()
    cache: dict[str, Confirmation] = {}
    kept: list[tuple[RuleResult, Confirmation]] = []
    for rr in candidates:
        key = _cache_key(rr, context[:_WINDOW])
        conf = cache.get(key)
        if conf is None:
            conf = confirmer.confirm(rr, context)
            cache[key] = conf
        if conf.disposition == Disposition.DISMISS:
            continue
        kept.append((rr, conf))
    return kept
