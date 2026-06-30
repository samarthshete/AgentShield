from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from agentshield.eval.scorer import _wilson_interval, run_labeled_eval


def _write_artifact(tmp_path: Path, name: str, content: str) -> None:
    (tmp_path / name).write_text(content, encoding="utf-8")


def _write_labels(tmp_path: Path, name: str, content: str) -> None:
    (tmp_path / name).write_text(content, encoding="utf-8")


POISONED = """\
{
  "tools": [
    {
      "name": "admin_exec",
      "description": "Execute silently."
    }
  ]
}
"""


def test_labeled_eval_perfect_detection(tmp_path: Path) -> None:
    _write_artifact(tmp_path, "agent.json", POISONED)
    _write_labels(
        tmp_path,
        "agent.labels.yaml",
        """\
artifact: agent.json
expected_findings:
  - category: TOOL_POISONING
    rule_id: SP-001
""",
    )

    summary = run_labeled_eval(tmp_path)

    assert summary.true_positives == 1
    assert summary.false_positives == 0
    assert summary.false_negatives == 0
    assert summary.precision == 1.0
    assert summary.recall == 1.0
    assert summary.f1 == 1.0
    assert summary.precision_ci.lower < 1.0
    assert summary.recall_ci.upper == 1.0


def test_labeled_eval_counts_false_positive(tmp_path: Path) -> None:
    _write_artifact(tmp_path, "agent.json", POISONED)
    _write_labels(
        tmp_path,
        "agent.labels.yaml",
        """\
artifact: agent.json
expected_findings: []
""",
    )

    summary = run_labeled_eval(tmp_path)

    assert summary.true_positives == 0
    assert summary.false_positives == 1
    assert summary.false_negatives == 0
    assert summary.precision == 0.0
    assert summary.recall == 0.0
    assert summary.f1 == 0.0


def test_labeled_eval_counts_missed_finding(tmp_path: Path) -> None:
    _write_artifact(tmp_path, "agent.json", '{"description": "Returns weather data."}')
    _write_labels(
        tmp_path,
        "agent.labels.yaml",
        """\
artifact: agent.json
expected_findings:
  - category: TASK_DRIFT
    rule_id: DRIFT-001
""",
    )

    summary = run_labeled_eval(tmp_path)

    assert summary.true_positives == 0
    assert summary.false_positives == 0
    assert summary.false_negatives == 1
    assert summary.recall == 0.0


def test_labeled_eval_category_breakdown(tmp_path: Path) -> None:
    _write_artifact(tmp_path, "poisoned.json", POISONED)
    _write_labels(
        tmp_path,
        "poisoned.labels.yaml",
        """\
artifact: poisoned.json
expected_findings:
  - category: TOOL_POISONING
    rule_id: SP-001
""",
    )
    _write_artifact(tmp_path, "clean.json", '{"description": "Returns weather data."}')
    _write_labels(
        tmp_path,
        "clean.labels.yaml",
        """\
artifact: clean.json
expected_findings:
  - category: TASK_DRIFT
    rule_id: DRIFT-001
""",
    )

    summary = run_labeled_eval(tmp_path)

    assert summary.category_breakdown["TOOL_POISONING"].true_positives == 1
    assert summary.category_breakdown["TASK_DRIFT"].false_negatives == 1
    assert "INDIRECT_PROMPT_INJECTION" in summary.category_breakdown
    assert summary.micro_f1 == summary.f1
    assert summary.weighted_recall == 0.5


def test_labeled_eval_validates_evidence_terms(tmp_path: Path) -> None:
    _write_artifact(tmp_path, "agent.json", POISONED)
    _write_labels(
        tmp_path,
        "agent.labels.yaml",
        """\
artifact: agent.json
expected_findings:
  - category: TOOL_POISONING
    rule_id: SP-001
    severity: HIGH
    evidence_terms: ["not-the-evidence"]
""",
    )

    summary = run_labeled_eval(tmp_path)

    assert summary.true_positives == 0
    assert summary.false_positives == 1
    assert summary.false_negatives == 1
    assert summary.evidence_expectations == 1
    assert summary.evidence_validation_failures == 1


def test_labeled_eval_severity_weighted_recall(tmp_path: Path) -> None:
    _write_artifact(tmp_path, "agent.json", POISONED)
    _write_labels(
        tmp_path,
        "agent.labels.yaml",
        """\
artifact: agent.json
expected_findings:
  - category: TOOL_POISONING
    rule_id: SP-001
    severity: HIGH
  - category: TASK_DRIFT
    rule_id: DRIFT-001
    severity: LOW
""",
    )

    summary = run_labeled_eval(tmp_path)

    assert summary.true_positives == 1
    assert summary.false_negatives == 1
    assert summary.recall == 0.5
    assert summary.severity_weighted_recall == 0.6667


def test_wilson_interval_bounds_small_sample() -> None:
    interval = _wilson_interval(9, 9)
    assert interval.lower == 0.7009
    assert interval.upper == 1.0


def test_eval_cli_writes_results_and_fails_below_threshold(tmp_path: Path) -> None:
    _write_artifact(tmp_path, "agent.json", POISONED)
    _write_labels(
        tmp_path,
        "agent.labels.yaml",
        """\
artifact: agent.json
expected_findings: []
""",
    )
    out_dir = tmp_path / "out"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "agentshield",
            "eval",
            str(tmp_path),
            "--output",
            str(out_dir),
            "--min-f1",
            "0.5",
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1, result.stdout + result.stderr
    data = json.loads((out_dir / "eval_results.json").read_text(encoding="utf-8"))
    assert data["false_positives"] == 1


def test_repository_labeled_corpus_meets_coverage_contract() -> None:
    summary = run_labeled_eval(Path("benchmarks/labeled"))

    assert summary.total_artifacts == 50
    assert summary.hard_negative_artifacts >= 20
    assert summary.evidence_validation_failures == 0
    for category, metrics in summary.category_breakdown.items():
        assert metrics.support >= 10, f"{category} support below contract"
