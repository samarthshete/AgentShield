"""Tests for dynamic simulation: attack generator, simulator, policy engine."""
import pytest

from agentshield.dynamic.attack_generator import (
    get_scenario,
    get_scenarios_for_category,
    list_scenarios,
)
from agentshield.dynamic.runtime_simulator import simulate
from agentshield.policy.policy_engine import evaluate_trace


# ── attack generator ──────────────────────────────────────────────────────────


def test_list_scenarios_returns_all_five() -> None:
    scenarios = list_scenarios()
    ids = {s.scenario_id for s in scenarios}
    assert "DYN-UP-001" in ids
    assert "DYN-TD-001" in ids
    assert "DYN-TP-001" in ids
    assert "DYN-IPI-001" in ids
    assert "DYN-EXF-001" in ids


def test_get_scenario_by_id() -> None:
    s = get_scenario("DYN-TP-001")
    assert s.category == "TOOL_POISONING"


def test_get_scenario_unknown_raises() -> None:
    with pytest.raises(KeyError):
        get_scenario("DYN-DOES-NOT-EXIST")


def test_get_scenarios_for_category() -> None:
    matches = get_scenarios_for_category("TOOL_POISONING")
    assert len(matches) >= 1
    assert all(m.category == "TOOL_POISONING" for m in matches)


def test_all_five_categories_covered() -> None:
    all_cats = {s.category for s in list_scenarios()}
    expected = {
        "TOOL_POISONING",
        "INDIRECT_PROMPT_INJECTION",
        "DATA_EXFILTRATION_PATTERN",
        "UNSAFE_PERMISSIONS",
        "TASK_DRIFT",
    }
    assert all_cats == expected


# ── runtime simulator ─────────────────────────────────────────────────────────


def test_simulate_produces_five_steps() -> None:
    payload = get_scenario("DYN-TP-001")
    trace = simulate(payload)
    assert len(trace.steps) == 5


def test_simulate_step_roles() -> None:
    payload = get_scenario("DYN-IPI-001")
    trace = simulate(payload)
    roles = [s.role for s in trace.steps]
    assert roles == ["system", "user", "tool_call", "tool_response", "assistant"]


def test_simulate_tool_response_contains_payload() -> None:
    payload = get_scenario("DYN-IPI-001")
    trace = simulate(payload)
    tool_resp = next(s for s in trace.steps if s.role == "tool_response")
    assert "ignore all previous" in tool_resp.content.lower()


def test_simulate_preserves_scenario_metadata() -> None:
    payload = get_scenario("DYN-EXF-001")
    trace = simulate(payload)
    assert trace.scenario_id == "DYN-EXF-001"
    assert trace.category == "DATA_EXFILTRATION_PATTERN"


# ── policy engine ─────────────────────────────────────────────────────────────


def test_tool_poisoning_trace_has_violations() -> None:
    trace = simulate(get_scenario("DYN-TP-001"))
    violations = evaluate_trace(trace)
    assert len(violations) > 0


def test_injection_trace_detects_injection() -> None:
    trace = simulate(get_scenario("DYN-IPI-001"))
    violations = evaluate_trace(trace)
    cats = {v.category for v in violations}
    assert "INDIRECT_PROMPT_INJECTION" in cats


def test_exfiltration_trace_detects_critical() -> None:
    trace = simulate(get_scenario("DYN-EXF-001"))
    violations = evaluate_trace(trace)
    severities = {v.severity for v in violations}
    assert "CRITICAL" in severities


def test_policy_violations_have_evidence() -> None:
    trace = simulate(get_scenario("DYN-IPI-001"))
    violations = evaluate_trace(trace)
    for v in violations:
        assert v.evidence, f"Violation {v.policy_id} has empty evidence"


def test_injection_step_seq_recorded() -> None:
    trace = simulate(get_scenario("DYN-IPI-001"))
    violations = evaluate_trace(trace)
    dynamic_violations = [v for v in violations if v.step_seq is not None]
    assert len(dynamic_violations) > 0


def test_unsafe_permissions_trace_has_violations() -> None:
    trace = simulate(get_scenario("DYN-UP-001"))
    violations = evaluate_trace(trace)
    cats = {v.category for v in violations}
    assert "UNSAFE_PERMISSIONS" in cats


def test_unsafe_permissions_detects_privilege_escalation() -> None:
    trace = simulate(get_scenario("DYN-UP-001"))
    violations = evaluate_trace(trace)
    poldyn = [v for v in violations if v.policy_id.startswith("POLDYN-007")]
    assert len(poldyn) > 0, "Expected POLDYN-007 privilege escalation violation"


def test_task_drift_trace_has_violations() -> None:
    trace = simulate(get_scenario("DYN-TD-001"))
    violations = evaluate_trace(trace)
    cats = {v.category for v in violations}
    assert "TASK_DRIFT" in cats


def test_task_drift_detects_redirect_in_tool_response() -> None:
    trace = simulate(get_scenario("DYN-TD-001"))
    violations = evaluate_trace(trace)
    poldyn = [v for v in violations if v.policy_id.startswith("POLDYN-008")]
    assert len(poldyn) > 0, "Expected POLDYN-008 task-drift violation"
    step_violations = [v for v in poldyn if v.step_seq is not None]
    assert len(step_violations) > 0, "POLDYN-008 should have step attribution"


def test_no_violations_on_clean_trace() -> None:
    from agentshield.models.dynamic import SimTrace, TraceStep

    clean_trace = SimTrace(
        scenario_id="CLEAN",
        scenario_name="clean",
        category="TOOL_POISONING",
        steps=[
            TraceStep(seq=1, role="system", content="You are a helpful assistant."),
            TraceStep(seq=2, role="user", content="What is the weather today?"),
            TraceStep(seq=3, role="tool_call", content='{"tool": "weather", "args": {}}'),
            TraceStep(seq=4, role="tool_response", content="It is 22 degrees and sunny."),
            TraceStep(seq=5, role="assistant", content="The weather today is 22 degrees and sunny."),
        ],
    )
    violations = evaluate_trace(clean_trace)
    assert len(violations) == 0


# ── llm_judge interface ───────────────────────────────────────────────────────


def test_rule_based_judge_confirms_all_violations() -> None:
    from agentshield.dynamic.llm_judge import RuleBasedJudge

    trace = simulate(get_scenario("DYN-TP-001"))
    violations = evaluate_trace(trace)

    judge = RuleBasedJudge()
    verdict = judge.evaluate(trace, violations)

    assert verdict.judge_type == "rule_based"
    assert len(verdict.confirmed_violations) == len(violations)
    assert len(verdict.dismissed_violations) == 0


def test_rule_based_judge_empty_violations() -> None:
    from agentshield.models.dynamic import SimTrace, TraceStep

    from agentshield.dynamic.llm_judge import RuleBasedJudge

    clean_trace = SimTrace(
        scenario_id="CLEAN",
        scenario_name="clean",
        category="TOOL_POISONING",
        steps=[
            TraceStep(seq=1, role="system", content="You are a helpful assistant."),
            TraceStep(seq=2, role="user", content="Hello"),
            TraceStep(seq=3, role="assistant", content="Hi there!"),
        ],
    )
    judge = RuleBasedJudge()
    verdict = judge.evaluate(clean_trace, [])

    assert len(verdict.confirmed_violations) == 0
    assert verdict.notes != ""


def test_get_default_judge_returns_base_judge() -> None:
    from agentshield.dynamic.llm_judge import BaseJudge, get_default_judge

    judge = get_default_judge()
    assert isinstance(judge, BaseJudge)


def test_get_judge_rule_based_aliases() -> None:
    from agentshield.dynamic.llm_judge import RuleBasedJudge, get_judge

    assert isinstance(get_judge("rule_based"), RuleBasedJudge)
    assert isinstance(get_judge("rule"), RuleBasedJudge)
    assert isinstance(get_judge("default"), RuleBasedJudge)


def test_get_judge_claude_requires_api_key() -> None:
    from agentshield.dynamic.llm_judge import get_judge

    with pytest.raises(ValueError):
        get_judge("claude", api_key="")


def test_claude_judge_splits_confirmed_and_dismissed() -> None:
    from unittest.mock import patch

    from agentshield.dynamic.llm_judge import ClaudeJudge

    trace = simulate(get_scenario("DYN-TP-001"))
    violations = evaluate_trace(trace)
    assert len(violations) >= 2
    dismiss_id = violations[0].policy_id

    judge = ClaudeJudge(api_key="test-key")
    with patch.object(
        ClaudeJudge,
        "_call_claude",
        return_value={"dismiss_policy_ids": [dismiss_id], "notes": "dismissed one"},
    ):
        verdict = judge.evaluate(trace, violations)

    assert verdict.judge_type == "claude"
    assert len(verdict.dismissed_violations) >= 1
    assert all(v.policy_id == dismiss_id for v in verdict.dismissed_violations)
    assert all(v.policy_id != dismiss_id for v in verdict.confirmed_violations)


def test_claude_judge_empty_violations_short_circuit() -> None:
    from agentshield.dynamic.llm_judge import ClaudeJudge
    from agentshield.models.dynamic import SimTrace, TraceStep

    trace = SimTrace(
        scenario_id="CLEAN",
        scenario_name="clean",
        category="TOOL_POISONING",
        steps=[TraceStep(seq=1, role="assistant", content="ok")],
    )
    verdict = ClaudeJudge(api_key="test-key").evaluate(trace, [])
    assert verdict.judge_type == "claude"
    assert verdict.confirmed_violations == []
    assert verdict.dismissed_violations == []


def test_claude_judge_timeout_handling() -> None:
    from unittest.mock import patch
    from urllib.error import URLError

    from agentshield.dynamic.llm_judge import ClaudeJudge, ClaudeJudgeError

    trace = simulate(get_scenario("DYN-TP-001"))
    violations = evaluate_trace(trace)
    judge = ClaudeJudge(api_key="test-key")

    with patch("agentshield.dynamic.llm_judge.urlopen", side_effect=URLError("timed out")):
        with pytest.raises(ClaudeJudgeError, match="timed out"):
            judge.evaluate(trace, violations)


def test_claude_judge_non_200_response_handling() -> None:
    from io import BytesIO
    from unittest.mock import patch
    from urllib.error import HTTPError

    from agentshield.dynamic.llm_judge import ClaudeJudge, ClaudeJudgeError

    trace = simulate(get_scenario("DYN-TP-001"))
    violations = evaluate_trace(trace)
    judge = ClaudeJudge(api_key="test-key")

    err = HTTPError(
        url="https://api.anthropic.com/v1/messages",
        code=500,
        msg="Internal Server Error",
        hdrs=None,
        fp=BytesIO(b"server exploded"),
    )
    with patch("agentshield.dynamic.llm_judge.urlopen", side_effect=err):
        with pytest.raises(ClaudeJudgeError, match="HTTP 500"):
            judge.evaluate(trace, violations)


def test_claude_judge_malformed_api_json_handling() -> None:
    from unittest.mock import patch

    from agentshield.dynamic.llm_judge import ClaudeJudge, ClaudeJudgeError

    class FakeResponse:
        def __enter__(self) -> "FakeResponse":
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

        def read(self) -> bytes:
            return b"not-json"

    trace = simulate(get_scenario("DYN-TP-001"))
    violations = evaluate_trace(trace)
    judge = ClaudeJudge(api_key="test-key")

    with patch("agentshield.dynamic.llm_judge.urlopen", return_value=FakeResponse()):
        with pytest.raises(ClaudeJudgeError, match="malformed JSON"):
            judge.evaluate(trace, violations)


def test_claude_judge_missing_content_blocks_handling() -> None:
    from unittest.mock import patch

    from agentshield.dynamic.llm_judge import ClaudeJudge, ClaudeJudgeError

    class FakeResponse:
        def __enter__(self) -> "FakeResponse":
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

        def read(self) -> bytes:
            return b'{"id":"msg_1","type":"message"}'

    trace = simulate(get_scenario("DYN-TP-001"))
    violations = evaluate_trace(trace)
    judge = ClaudeJudge(api_key="test-key")

    with patch("agentshield.dynamic.llm_judge.urlopen", return_value=FakeResponse()):
        with pytest.raises(ClaudeJudgeError, match="text block"):
            judge.evaluate(trace, violations)


def test_claude_judge_empty_model_output_handling() -> None:
    from unittest.mock import patch

    from agentshield.dynamic.llm_judge import ClaudeJudge, ClaudeJudgeError

    class FakeResponse:
        def __enter__(self) -> "FakeResponse":
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

        def read(self) -> bytes:
            return b'{"content":[{"type":"text","text":"   "}]}'

    trace = simulate(get_scenario("DYN-TP-001"))
    violations = evaluate_trace(trace)
    judge = ClaudeJudge(api_key="test-key")

    with patch("agentshield.dynamic.llm_judge.urlopen", return_value=FakeResponse()):
        with pytest.raises(ClaudeJudgeError, match="empty text output"):
            judge.evaluate(trace, violations)


def test_claude_judge_invalid_decision_parse_handling() -> None:
    from unittest.mock import patch

    from agentshield.dynamic.llm_judge import ClaudeJudge, ClaudeJudgeError

    class FakeResponse:
        def __enter__(self) -> "FakeResponse":
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

        def read(self) -> bytes:
            return b'{"content":[{"type":"text","text":"not-json"}]}'

    trace = simulate(get_scenario("DYN-TP-001"))
    violations = evaluate_trace(trace)
    judge = ClaudeJudge(api_key="test-key")

    with patch("agentshield.dynamic.llm_judge.urlopen", return_value=FakeResponse()):
        with pytest.raises(ClaudeJudgeError, match="not valid JSON"):
            judge.evaluate(trace, violations)


def test_claude_judge_missing_required_decision_field() -> None:
    from unittest.mock import patch

    from agentshield.dynamic.llm_judge import ClaudeJudge, ClaudeJudgeError

    class FakeResponse:
        def __enter__(self) -> "FakeResponse":
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

        def read(self) -> bytes:
            return b'{"content":[{"type":"text","text":"{\\"notes\\": \\"x\\"}"}]}'

    trace = simulate(get_scenario("DYN-TP-001"))
    violations = evaluate_trace(trace)
    judge = ClaudeJudge(api_key="test-key")

    with patch("agentshield.dynamic.llm_judge.urlopen", return_value=FakeResponse()):
        with pytest.raises(ClaudeJudgeError, match="dismiss_policy_ids"):
            judge.evaluate(trace, violations)


# ── result provenance and raw/confirmed/dismissed separation ─────────────────


def test_rule_based_result_preserves_raw_violations() -> None:
    from agentshield.dynamic.llm_judge import RuleBasedJudge
    from agentshield.models.dynamic import DynamicScanResult

    trace = simulate(get_scenario("DYN-TP-001"))
    raw = evaluate_trace(trace)
    verdict = RuleBasedJudge().evaluate(trace, raw)

    result = DynamicScanResult(
        scenario_id="DYN-TP-001",
        scenario_name="test",
        category="TOOL_POISONING",
        violations=verdict.confirmed_violations,
        raw_violations=list(raw),
        dismissed_violations=verdict.dismissed_violations,
        trace=trace,
        violation_count=len(verdict.confirmed_violations),
        judge_type=verdict.judge_type,
    )
    assert len(result.raw_violations) == len(raw)
    assert len(result.violations) == len(raw)
    assert len(result.dismissed_violations) == 0
    assert result.judge_type == "rule_based"
    assert result.judge_model is None


def test_claude_result_preserves_raw_and_tracks_dismissed() -> None:
    from unittest.mock import patch

    from agentshield.dynamic.llm_judge import ClaudeJudge
    from agentshield.models.dynamic import DynamicScanResult

    trace = simulate(get_scenario("DYN-TP-001"))
    raw = evaluate_trace(trace)
    assert len(raw) >= 2
    dismiss_id = raw[0].policy_id

    judge = ClaudeJudge(api_key="test-key", model="claude-3-5-haiku-latest")
    with patch.object(
        ClaudeJudge,
        "_call_claude",
        return_value={"dismiss_policy_ids": [dismiss_id], "notes": "test"},
    ):
        verdict = judge.evaluate(trace, raw)

    result = DynamicScanResult(
        scenario_id="DYN-TP-001",
        scenario_name="test",
        category="TOOL_POISONING",
        violations=verdict.confirmed_violations,
        raw_violations=list(raw),
        dismissed_violations=verdict.dismissed_violations,
        trace=trace,
        violation_count=len(verdict.confirmed_violations),
        judge_type=verdict.judge_type,
        judge_model=judge.model,
    )
    assert len(result.raw_violations) == len(raw)
    assert len(result.violations) < len(raw)
    assert len(result.dismissed_violations) >= 1
    assert result.judge_type == "claude"
    assert result.judge_model == "claude-3-5-haiku-latest"
    assert len(result.violations) + len(result.dismissed_violations) == len(result.raw_violations)


def test_dynamic_report_includes_judge_metadata() -> None:
    from agentshield.dynamic.report import write_dynamic_markdown
    from agentshield.models.dynamic import DynamicScanResult, SimTrace, TraceStep

    result = DynamicScanResult(
        scenario_id="T-001",
        scenario_name="Test",
        category="TOOL_POISONING",
        violations=[],
        raw_violations=[],
        dismissed_violations=[],
        trace=SimTrace(
            scenario_id="T-001",
            scenario_name="Test",
            category="TOOL_POISONING",
            steps=[TraceStep(seq=1, role="assistant", content="ok")],
        ),
        judge_type="claude",
        judge_model="claude-3-5-haiku-latest",
    )
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "report.md"
        write_dynamic_markdown(out, [result])
        md = out.read_text()

    assert "Judge:" in md
    assert "claude" in md
    assert "claude-3-5-haiku-latest" in md
    assert "Raw violations" in md
    assert "Confirmed violations" in md


def test_dynamic_report_shows_dismissed_section() -> None:
    from agentshield.dynamic.report import write_dynamic_markdown
    from agentshield.models.dynamic import (
        DynamicScanResult,
        PolicyViolation,
        SimTrace,
        TraceStep,
    )

    dismissed = PolicyViolation(
        policy_id="POLDYN-999",
        category="TOOL_POISONING",
        severity="MEDIUM",
        title="False positive",
        evidence="benign",
    )
    result = DynamicScanResult(
        scenario_id="T-002",
        scenario_name="Test dismissed",
        category="TOOL_POISONING",
        violations=[],
        raw_violations=[dismissed],
        dismissed_violations=[dismissed],
        trace=SimTrace(
            scenario_id="T-002",
            scenario_name="Test dismissed",
            category="TOOL_POISONING",
            steps=[TraceStep(seq=1, role="assistant", content="ok")],
        ),
        judge_type="claude",
        judge_model="claude-3-5-haiku-latest",
    )
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "report.md"
        write_dynamic_markdown(out, [result])
        md = out.read_text()

    assert "### Dismissed Violations" in md
    assert "POLDYN-999" in md


def test_dynamic_json_includes_provenance_fields() -> None:
    from agentshield.dynamic.report import build_dynamic_payload
    from agentshield.models.dynamic import (
        DynamicScanResult,
        PolicyViolation,
        SimTrace,
        TraceStep,
    )

    v = PolicyViolation(
        policy_id="P-001",
        category="TOOL_POISONING",
        severity="HIGH",
        title="Test",
        evidence="test",
    )
    result = DynamicScanResult(
        scenario_id="T-003",
        scenario_name="Test JSON",
        category="TOOL_POISONING",
        violations=[v],
        raw_violations=[v],
        dismissed_violations=[],
        trace=SimTrace(
            scenario_id="T-003",
            scenario_name="Test JSON",
            category="TOOL_POISONING",
            steps=[TraceStep(seq=1, role="assistant", content="ok")],
        ),
        violation_count=1,
        judge_type="rule_based",
    )
    payload = build_dynamic_payload([result])
    scenario = payload["scenarios"][0]
    assert "raw_violations" in scenario
    assert "dismissed_violations" in scenario
    assert "judge_type" in scenario
    assert scenario["judge_type"] == "rule_based"


# ── OpenAIJudge tests ─────────────────────────────────────────────────────────


def test_get_judge_openai_requires_api_key() -> None:
    from agentshield.dynamic.llm_judge import get_judge

    with pytest.raises(ValueError):
        get_judge("openai", api_key="")


def test_openai_judge_splits_confirmed_and_dismissed() -> None:
    from unittest.mock import patch

    from agentshield.dynamic.llm_judge import OpenAIJudge

    trace = simulate(get_scenario("DYN-TP-001"))
    violations = evaluate_trace(trace)
    assert len(violations) >= 2
    dismiss_id = violations[0].policy_id

    judge = OpenAIJudge(api_key="test-key")
    with patch.object(
        OpenAIJudge,
        "_call_openai",
        return_value={"dismiss_policy_ids": [dismiss_id], "notes": "dismissed one"},
    ):
        verdict = judge.evaluate(trace, violations)

    assert verdict.judge_type == "openai"
    assert len(verdict.dismissed_violations) >= 1
    assert all(v.policy_id == dismiss_id for v in verdict.dismissed_violations)
    assert all(v.policy_id != dismiss_id for v in verdict.confirmed_violations)


def test_openai_judge_empty_violations_short_circuit() -> None:
    from agentshield.dynamic.llm_judge import OpenAIJudge
    from agentshield.models.dynamic import SimTrace, TraceStep

    trace = SimTrace(
        scenario_id="CLEAN",
        scenario_name="clean",
        category="TOOL_POISONING",
        steps=[TraceStep(seq=1, role="assistant", content="ok")],
    )
    verdict = OpenAIJudge(api_key="test-key").evaluate(trace, [])
    assert verdict.judge_type == "openai"
    assert verdict.confirmed_violations == []
    assert verdict.dismissed_violations == []


def test_openai_judge_timeout_handling() -> None:
    from unittest.mock import patch
    from urllib.error import URLError

    from agentshield.dynamic.llm_judge import OpenAIJudge, OpenAIJudgeError

    trace = simulate(get_scenario("DYN-TP-001"))
    violations = evaluate_trace(trace)
    judge = OpenAIJudge(api_key="test-key")

    with patch("agentshield.dynamic.llm_judge.urlopen", side_effect=URLError("timed out")):
        with pytest.raises(OpenAIJudgeError, match="timed out"):
            judge.evaluate(trace, violations)


def test_openai_judge_non_200_response_handling() -> None:
    from io import BytesIO
    from unittest.mock import patch
    from urllib.error import HTTPError

    from agentshield.dynamic.llm_judge import OpenAIJudge, OpenAIJudgeError

    trace = simulate(get_scenario("DYN-TP-001"))
    violations = evaluate_trace(trace)
    judge = OpenAIJudge(api_key="test-key")

    err = HTTPError(
        url="https://api.openai.com/v1/chat/completions",
        code=429,
        msg="Too Many Requests",
        hdrs=None,
        fp=BytesIO(b"rate limited"),
    )
    with patch("agentshield.dynamic.llm_judge.urlopen", side_effect=err):
        with pytest.raises(OpenAIJudgeError, match="HTTP 429"):
            judge.evaluate(trace, violations)


def test_openai_judge_malformed_api_json_handling() -> None:
    from unittest.mock import patch

    from agentshield.dynamic.llm_judge import OpenAIJudge, OpenAIJudgeError

    class FakeResponse:
        def __enter__(self) -> "FakeResponse":
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

        def read(self) -> bytes:
            return b"not-json"

    trace = simulate(get_scenario("DYN-TP-001"))
    violations = evaluate_trace(trace)
    judge = OpenAIJudge(api_key="test-key")

    with patch("agentshield.dynamic.llm_judge.urlopen", return_value=FakeResponse()):
        with pytest.raises(OpenAIJudgeError, match="malformed JSON"):
            judge.evaluate(trace, violations)


def test_openai_judge_empty_model_output_handling() -> None:
    from unittest.mock import patch

    from agentshield.dynamic.llm_judge import OpenAIJudge, OpenAIJudgeError

    class FakeResponse:
        def __enter__(self) -> "FakeResponse":
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

        def read(self) -> bytes:
            return b'{"choices":[{"message":{"role":"assistant","content":"   "}}]}'

    trace = simulate(get_scenario("DYN-TP-001"))
    violations = evaluate_trace(trace)
    judge = OpenAIJudge(api_key="test-key")

    with patch("agentshield.dynamic.llm_judge.urlopen", return_value=FakeResponse()):
        with pytest.raises(OpenAIJudgeError, match="empty text output"):
            judge.evaluate(trace, violations)


def test_openai_judge_missing_choices_handling() -> None:
    from unittest.mock import patch

    from agentshield.dynamic.llm_judge import OpenAIJudge, OpenAIJudgeError

    class FakeResponse:
        def __enter__(self) -> "FakeResponse":
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

        def read(self) -> bytes:
            return b'{"id":"chatcmpl-1","object":"chat.completion"}'

    trace = simulate(get_scenario("DYN-TP-001"))
    violations = evaluate_trace(trace)
    judge = OpenAIJudge(api_key="test-key")

    with patch("agentshield.dynamic.llm_judge.urlopen", return_value=FakeResponse()):
        with pytest.raises(OpenAIJudgeError, match="choices"):
            judge.evaluate(trace, violations)


def test_openai_judge_invalid_decision_parse_handling() -> None:
    from unittest.mock import patch

    from agentshield.dynamic.llm_judge import OpenAIJudge, OpenAIJudgeError

    class FakeResponse:
        def __enter__(self) -> "FakeResponse":
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

        def read(self) -> bytes:
            return b'{"choices":[{"message":{"role":"assistant","content":"not-json"}}]}'

    trace = simulate(get_scenario("DYN-TP-001"))
    violations = evaluate_trace(trace)
    judge = OpenAIJudge(api_key="test-key")

    with patch("agentshield.dynamic.llm_judge.urlopen", return_value=FakeResponse()):
        with pytest.raises(OpenAIJudgeError, match="not valid JSON"):
            judge.evaluate(trace, violations)


def test_openai_judge_missing_required_decision_field() -> None:
    from unittest.mock import patch

    from agentshield.dynamic.llm_judge import OpenAIJudge, OpenAIJudgeError

    class FakeResponse:
        def __enter__(self) -> "FakeResponse":
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

        def read(self) -> bytes:
            payload = b'{"choices":[{"message":{"role":"assistant","content":"{\\"notes\\": \\"x\\"}"}}]}'
            return payload

    trace = simulate(get_scenario("DYN-TP-001"))
    violations = evaluate_trace(trace)
    judge = OpenAIJudge(api_key="test-key")

    with patch("agentshield.dynamic.llm_judge.urlopen", return_value=FakeResponse()):
        with pytest.raises(OpenAIJudgeError, match="dismiss_policy_ids"):
            judge.evaluate(trace, violations)
