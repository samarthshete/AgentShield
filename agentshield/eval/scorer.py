from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field

from agentshield.models.finding import Finding
from agentshield.reporting.severity import severity_rank
from agentshield.services.scan_service import run_static_scan

_ATTACK_CATEGORIES = (
    "TOOL_POISONING",
    "INDIRECT_PROMPT_INJECTION",
    "UNSAFE_PERMISSIONS",
    "DATA_EXFILTRATION_PATTERN",
    "TASK_DRIFT",
)
_WILSON_Z_95 = 1.959963984540054


class ExpectedFindingLabel(BaseModel):
    category: str
    rule_id: str | None = None
    true_positive: bool = True
    severity: str = "MEDIUM"
    evidence_terms: list[str] = Field(default_factory=list)
    note: str = ""


class LabeledArtifact(BaseModel):
    artifact: str
    case_type: Literal["positive", "hard_negative", "negative"] | None = None
    expected_findings: list[ExpectedFindingLabel] = Field(default_factory=list)
    provenance: str = ""
    notes: str = ""


class WilsonInterval(BaseModel):
    lower: float = 0.0
    upper: float = 0.0
    confidence: float = 0.95


class EvalCategoryMetrics(BaseModel):
    category: str
    support: int = 0
    predicted: int = 0
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    precision: float = 0.0
    precision_ci: WilsonInterval = Field(default_factory=WilsonInterval)
    recall: float = 0.0
    recall_ci: WilsonInterval = Field(default_factory=WilsonInterval)
    f1: float = 0.0
    severity_weighted_recall: float = 0.0


class EvalArtifactResult(BaseModel):
    artifact: str
    labels_path: str
    case_type: str
    findings_count: int
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    precision_ci: WilsonInterval = Field(default_factory=WilsonInterval)
    recall: float
    recall_ci: WilsonInterval = Field(default_factory=WilsonInterval)
    f1: float
    severity_weighted_recall: float = 0.0
    matched_labels: list[ExpectedFindingLabel] = Field(default_factory=list)
    missed_labels: list[ExpectedFindingLabel] = Field(default_factory=list)
    false_positive_findings: list[Finding] = Field(default_factory=list)
    evidence_expectations: int = 0
    evidence_validated: int = 0
    evidence_validation_failures: list[ExpectedFindingLabel] = Field(default_factory=list)


class EvalSummary(BaseModel):
    total_artifacts: int = 0
    positive_artifacts: int = 0
    hard_negative_artifacts: int = 0
    negative_artifacts: int = 0
    total_expected_findings: int = 0
    total_findings: int = 0
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    precision: float = 0.0
    precision_ci: WilsonInterval = Field(default_factory=WilsonInterval)
    recall: float = 0.0
    recall_ci: WilsonInterval = Field(default_factory=WilsonInterval)
    f1: float = 0.0
    micro_precision: float = 0.0
    micro_recall: float = 0.0
    micro_f1: float = 0.0
    macro_precision: float = 0.0
    macro_recall: float = 0.0
    macro_f1: float = 0.0
    weighted_precision: float = 0.0
    weighted_recall: float = 0.0
    weighted_f1: float = 0.0
    severity_weighted_recall: float = 0.0
    evidence_expectations: int = 0
    evidence_validated: int = 0
    evidence_validation_failures: int = 0
    category_breakdown: dict[str, EvalCategoryMetrics] = Field(default_factory=dict)
    results: list[EvalArtifactResult] = Field(default_factory=list)


def _round(value: float) -> float:
    return round(value, 4)


def _wilson_interval(successes: int, trials: int, z: float = _WILSON_Z_95) -> WilsonInterval:
    if trials <= 0:
        return WilsonInterval()
    p_hat = successes / trials
    denominator = 1 + (z * z / trials)
    center = (p_hat + (z * z / (2 * trials))) / denominator
    half_width = (
        z
        * ((p_hat * (1 - p_hat) / trials) + (z * z / (4 * trials * trials))) ** 0.5
        / denominator
    )
    return WilsonInterval(
        lower=_round(max(0.0, center - half_width)),
        upper=_round(min(1.0, center + half_width)),
    )


def _score(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
    return _round(precision), _round(recall), _round(f1)


def _severity_weight(label: ExpectedFindingLabel) -> int:
    return max(severity_rank(label.severity), 1)


def _severity_weighted_recall(
    matched_labels: list[ExpectedFindingLabel],
    expected_labels: list[ExpectedFindingLabel],
) -> float:
    denominator = sum(_severity_weight(label) for label in expected_labels)
    if denominator <= 0:
        return 0.0
    numerator = sum(_severity_weight(label) for label in matched_labels)
    return _round(numerator / denominator)


def load_labeled_artifact(path: Path) -> LabeledArtifact:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return LabeledArtifact(**raw)


def load_label_suite(directory: Path) -> list[tuple[Path, LabeledArtifact]]:
    if not directory.is_dir():
        raise FileNotFoundError(f"Labeled eval directory not found: {directory}")

    labels: list[tuple[Path, LabeledArtifact]] = []
    for path in sorted(directory.glob("*.labels.yaml")):
        labels.append((path, load_labeled_artifact(path)))
    for path in sorted(directory.glob("*.labels.yml")):
        labels.append((path, load_labeled_artifact(path)))
    return labels


def _label_matches_finding(label: ExpectedFindingLabel, finding: Finding) -> bool:
    if label.category != finding.category:
        return False
    return label.rule_id is None or label.rule_id == finding.rule_id


def _evidence_matches(label: ExpectedFindingLabel, finding: Finding) -> bool:
    if not label.evidence_terms:
        return True
    haystack = " ".join(
        part
        for part in (finding.evidence, finding.title, finding.recommendation)
        if part
    ).lower()
    return all(term.lower() in haystack for term in label.evidence_terms)


def _case_type(label: LabeledArtifact) -> str:
    if label.case_type:
        return label.case_type
    if any(item.true_positive for item in label.expected_findings):
        return "positive"
    return "negative"


def _score_artifact(labels_path: Path, label: LabeledArtifact) -> EvalArtifactResult:
    artifact_path = (labels_path.parent / label.artifact).resolve()
    _scan_run, findings, _targets = run_static_scan(str(artifact_path))

    expected_true = [item for item in label.expected_findings if item.true_positive]
    matched_label_indexes: set[int] = set()
    matched_labels: list[ExpectedFindingLabel] = []
    false_positive_findings: list[Finding] = []
    evidence_validation_failures: list[ExpectedFindingLabel] = []
    true_positives = 0

    for finding in findings:
        match_index = next(
            (
                idx
                for idx, expected in enumerate(expected_true)
                if idx not in matched_label_indexes
                and _label_matches_finding(expected, finding)
                and _evidence_matches(expected, finding)
            ),
            None,
        )
        if match_index is None:
            evidence_failure = next(
                (
                    expected
                    for idx, expected in enumerate(expected_true)
                    if idx not in matched_label_indexes
                    and _label_matches_finding(expected, finding)
                    and expected.evidence_terms
                ),
                None,
            )
            if evidence_failure is not None:
                evidence_validation_failures.append(evidence_failure)
            false_positive_findings.append(finding)
            continue
        matched_label_indexes.add(match_index)
        matched_labels.append(expected_true[match_index])
        true_positives += 1

    missed_labels = [
        expected for idx, expected in enumerate(expected_true) if idx not in matched_label_indexes
    ]
    false_positives = len(false_positive_findings)
    false_negatives = len(missed_labels)
    precision, recall, f1 = _score(true_positives, false_positives, false_negatives)
    evidence_expectations = sum(1 for expected in expected_true if expected.evidence_terms)
    evidence_validated = sum(1 for expected in matched_labels if expected.evidence_terms)

    return EvalArtifactResult(
        artifact=str(artifact_path),
        labels_path=str(labels_path),
        case_type=_case_type(label),
        findings_count=len(findings),
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
        precision=precision,
        precision_ci=_wilson_interval(true_positives, true_positives + false_positives),
        recall=recall,
        recall_ci=_wilson_interval(true_positives, true_positives + false_negatives),
        f1=f1,
        severity_weighted_recall=_severity_weighted_recall(matched_labels, expected_true),
        matched_labels=matched_labels,
        missed_labels=missed_labels,
        false_positive_findings=false_positive_findings,
        evidence_expectations=evidence_expectations,
        evidence_validated=evidence_validated,
        evidence_validation_failures=evidence_validation_failures,
    )


def _build_category_breakdown(results: list[EvalArtifactResult]) -> dict[str, EvalCategoryMetrics]:
    by_category: dict[str, EvalCategoryMetrics] = {
        category: EvalCategoryMetrics(category=category)
        for category in _ATTACK_CATEGORIES
    }

    for result in results:
        for matched in result.matched_labels:
            metric = by_category.setdefault(matched.category, EvalCategoryMetrics(category=matched.category))
            metric.true_positives += 1
            metric.support += 1
            metric.predicted += 1
        for missed in result.missed_labels:
            metric = by_category.setdefault(missed.category, EvalCategoryMetrics(category=missed.category))
            metric.false_negatives += 1
            metric.support += 1
        for finding in result.false_positive_findings:
            metric = by_category.setdefault(finding.category, EvalCategoryMetrics(category=finding.category))
            metric.false_positives += 1
            metric.predicted += 1

    for metric in by_category.values():
        metric.precision, metric.recall, metric.f1 = _score(
            metric.true_positives,
            metric.false_positives,
            metric.false_negatives,
        )
        metric.precision_ci = _wilson_interval(
            metric.true_positives,
            metric.true_positives + metric.false_positives,
        )
        metric.recall_ci = _wilson_interval(
            metric.true_positives,
            metric.true_positives + metric.false_negatives,
        )
        matched_labels = [
            label for result in results for label in result.matched_labels
            if label.category == metric.category
        ]
        expected_labels = [
            label for result in results for label in result.matched_labels + result.missed_labels
            if label.category == metric.category
        ]
        metric.severity_weighted_recall = _severity_weighted_recall(matched_labels, expected_labels)

    return dict(sorted(by_category.items()))


def _mean(values: list[float]) -> float:
    return _round(sum(values) / len(values)) if values else 0.0


def _weighted_mean(category_metrics: list[EvalCategoryMetrics], field: str) -> float:
    total_support = sum(metric.support for metric in category_metrics)
    if total_support <= 0:
        return 0.0
    return _round(
        sum(getattr(metric, field) * metric.support for metric in category_metrics)
        / total_support
    )


def run_labeled_eval(directory: Path) -> EvalSummary:
    labeled_artifacts = load_label_suite(directory)
    results = [_score_artifact(path, label) for path, label in labeled_artifacts]

    tp = sum(result.true_positives for result in results)
    fp = sum(result.false_positives for result in results)
    fn = sum(result.false_negatives for result in results)
    precision, recall, f1 = _score(tp, fp, fn)
    category_breakdown = _build_category_breakdown(results)
    category_metrics = list(category_breakdown.values())
    expected_labels = [
        label for result in results for label in result.matched_labels + result.missed_labels
    ]
    matched_labels = [label for result in results for label in result.matched_labels]

    return EvalSummary(
        total_artifacts=len(results),
        positive_artifacts=sum(1 for result in results if result.case_type == "positive"),
        hard_negative_artifacts=sum(1 for result in results if result.case_type == "hard_negative"),
        negative_artifacts=sum(1 for result in results if result.case_type == "negative"),
        total_expected_findings=len(expected_labels),
        total_findings=sum(result.findings_count for result in results),
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        precision=precision,
        precision_ci=_wilson_interval(tp, tp + fp),
        recall=recall,
        recall_ci=_wilson_interval(tp, tp + fn),
        f1=f1,
        micro_precision=precision,
        micro_recall=recall,
        micro_f1=f1,
        macro_precision=_mean([metric.precision for metric in category_metrics]),
        macro_recall=_mean([metric.recall for metric in category_metrics]),
        macro_f1=_mean([metric.f1 for metric in category_metrics]),
        weighted_precision=_weighted_mean(category_metrics, "precision"),
        weighted_recall=_weighted_mean(category_metrics, "recall"),
        weighted_f1=_weighted_mean(category_metrics, "f1"),
        severity_weighted_recall=_severity_weighted_recall(matched_labels, expected_labels),
        evidence_expectations=sum(result.evidence_expectations for result in results),
        evidence_validated=sum(result.evidence_validated for result in results),
        evidence_validation_failures=sum(
            len(result.evidence_validation_failures) for result in results
        ),
        category_breakdown=category_breakdown,
        results=results,
    )
