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
