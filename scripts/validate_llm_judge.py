#!/usr/bin/env python3
"""Compare rule-based and LLM judge outputs on real simulate runs.

Usage:
    python scripts/validate_llm_judge.py --api-key sk-...
    python scripts/validate_llm_judge.py --api-key sk-... --judge claude --scenario DYN-TP-001
    python scripts/validate_llm_judge.py --api-key sk-... --output /tmp/comparison.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_repo_root = Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from agentshield.dynamic.attack_generator import get_scenario, list_scenarios  # noqa: E402
from agentshield.dynamic.llm_judge import ClaudeJudgeError, OpenAIJudgeError, get_judge  # noqa: E402
from agentshield.dynamic.runtime_simulator import simulate  # noqa: E402
from agentshield.models.dynamic import DynamicScanResult  # noqa: E402
from agentshield.policy.policy_engine import evaluate_trace  # noqa: E402
from agentshield.reporting.severity import severity_rank  # noqa: E402


def _run_scenario(payload, judge_name: str, api_key: str | None, model: str) -> DynamicScanResult:
    judge_impl = get_judge(judge_name, api_key=api_key, model=model)
    trace = simulate(payload)
    raw_violations = evaluate_trace(trace)
    verdict = judge_impl.evaluate(trace, raw_violations)
    confirmed = verdict.confirmed_violations
    max_sev = (
        max((v.severity for v in confirmed), key=lambda s: severity_rank(s))
        if confirmed
        else None
    )
    return DynamicScanResult(
        scenario_id=payload.scenario_id,
        scenario_name=payload.scenario_name,
        category=payload.category,
        violations=confirmed,
        raw_violations=list(raw_violations),
        dismissed_violations=verdict.dismissed_violations,
        trace=trace,
        violation_count=len(confirmed),
        max_severity=max_sev,
        passed_clean=len(confirmed) == 0,
        judge_type=verdict.judge_type,
        judge_model=getattr(judge_impl, "model", None),
    )


def _print_comparison(rule_result: DynamicScanResult, llm_result: DynamicScanResult) -> None:
    raw = len(rule_result.raw_violations)
    rule_confirmed = len(rule_result.violations)
    llm_confirmed = len(llm_result.violations)
    llm_dismissed = len(llm_result.dismissed_violations)
    judge_label = llm_result.judge_type

    changed = rule_confirmed != llm_confirmed
    marker = "  <<< CHANGED" if changed else ""
    print(f"\n{'=' * 60}")
    print(f"  {rule_result.scenario_id}  ({rule_result.category})")
    print(f"{'=' * 60}")
    print(f"  raw violations (policy engine) : {raw}")
    print(f"  rule_based confirmed           : {rule_confirmed}{marker}")
    print(f"  {judge_label} confirmed        : {llm_confirmed}{marker}")
    print(f"  {judge_label} dismissed        : {llm_dismissed}")
    print(f"  {judge_label} model            : {llm_result.judge_model}")

    if llm_dismissed:
        print("  dismissed policy IDs:")
        for v in llm_result.dismissed_violations:
            print(f"    - {v.policy_id} | {v.severity} | {v.title}")

    if changed:
        confirmed_ids = {v.policy_id for v in llm_result.violations}
        for v in rule_result.violations:
            if v.policy_id not in confirmed_ids:
                print(f"  NOTE: {v.policy_id} confirmed by rule_based but dismissed by {judge_label}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate LLM judge against rule-based baseline")
    parser.add_argument("--judge", default="openai", choices=["openai", "claude"],
                        help="LLM provider to validate (default: openai)")
    parser.add_argument("--api-key", help="API key for the selected provider")
    parser.add_argument("--scenario", default="all", help="Scenario ID or 'all'")
    parser.add_argument("--model", default="", help="Model override (provider default used if not specified)")
    parser.add_argument("--output", help="Write JSON comparison to this file")
    args = parser.parse_args()

    api_key = args.api_key
    if not api_key:
        try:
            from agentshield.config import settings
            api_key = (
                settings.openai_api_key if args.judge == "openai" else settings.claude_api_key
            ) or None
        except Exception:
            pass

    if not api_key:
        key_var = "OPENAI_API_KEY" if args.judge == "openai" else "CLAUDE_API_KEY"
        print(f"Error: no API key provided. Use --api-key or set {key_var} in .env", file=sys.stderr)
        return 2

    if args.scenario.lower() == "all":
        payloads = list_scenarios()
    else:
        try:
            payloads = [get_scenario(args.scenario.upper())]
        except KeyError:
            print(f"Error: unknown scenario '{args.scenario}'", file=sys.stderr)
            return 2

    print(f"Judge    : {args.judge}")
    print(f"Model    : {args.model or '(provider default)'}")
    print(f"Scenarios: {len(payloads)}\n")

    _error_cls = OpenAIJudgeError if args.judge == "openai" else ClaudeJudgeError
    comparisons = []
    any_changed = False

    for payload in payloads:
        print(f"[rule_based] {payload.scenario_id} ...")
        rule_result = _run_scenario(payload, "rule_based", api_key=None, model=args.model)

        print(f"[{args.judge:<10}] {payload.scenario_id} ...")
        try:
            llm_result = _run_scenario(payload, args.judge, api_key=api_key, model=args.model)
        except _error_cls as exc:
            print(f"ERROR: {args.judge} judge failed for {payload.scenario_id}: {exc}", file=sys.stderr)
            return 2

        _print_comparison(rule_result, llm_result)

        dismissed_count = len(llm_result.dismissed_violations)
        comparison = {
            "scenario_id": payload.scenario_id,
            "category": payload.category,
            "judge": args.judge,
            "model": llm_result.judge_model,
            "raw_count": len(rule_result.raw_violations),
            "rule_based_confirmed": len(rule_result.violations),
            "llm_confirmed": len(llm_result.violations),
            "llm_dismissed": dismissed_count,
            "llm_dismissed_ids": [v.policy_id for v in llm_result.dismissed_violations],
        }
        comparisons.append(comparison)
        if comparison["rule_based_confirmed"] != comparison["llm_confirmed"]:
            any_changed = True

    print(f"\n{'=' * 60}")
    print("SUMMARY")
    print(f"{'=' * 60}")
    print(f"  Scenarios run   : {len(payloads)}")
    print(f"  Any dismissals  : {'YES' if any_changed else 'no'}")
    total_raw = sum(c["raw_count"] for c in comparisons)
    total_dismissed = sum(c["llm_dismissed"] for c in comparisons)
    print(f"  Total raw       : {total_raw}")
    print(f"  Total dismissed : {total_dismissed}")
    if total_raw:
        print(f"  Dismiss rate    : {total_dismissed / total_raw:.0%}")
    else:
        print("  Dismiss rate    : n/a")

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps({"comparisons": comparisons}, indent=2), encoding="utf-8")
        print(f"\nJSON written: {out.resolve()}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
