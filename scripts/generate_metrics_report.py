#!/usr/bin/env python3
"""Generate docs/PROJECT_METRICS.md and metrics.json from live scan/benchmark/simulation data."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_repo_root = Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from agentshield.metrics.aggregator import run_all_and_aggregate  # noqa: E402
from agentshield.metrics.report_writer import write_markdown  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate AgentShield project metrics report")
    parser.add_argument("--fixtures", default="benchmarks/fixtures", help="Config fixtures path")
    parser.add_argument("--cases", default="benchmarks/cases", help="Benchmark YAML cases dir")
    parser.add_argument("--output", default="agentshield-reports", help="Output dir for metrics.json")
    parser.add_argument("--docs-output", default="docs", help="Dir for PROJECT_METRICS.md")
    args = parser.parse_args()

    fixtures = Path(args.fixtures)
    cases = Path(args.cases)
    out_dir = Path(args.output)
    docs_dir = Path(args.docs_output)

    for p, name in [(fixtures, "--fixtures"), (cases, "--cases")]:
        if not p.exists():
            print(f"Error: {name} path does not exist: {p}", file=sys.stderr)
            return 2

    print("Running benchmark, scan, and dynamic simulations ...")
    metrics = run_all_and_aggregate(fixtures, cases)

    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "metrics.json"
    json_path.write_text(json.dumps(metrics.model_dump(), indent=2), encoding="utf-8")
    print(f"Written: {json_path.resolve()}")

    md_path = docs_dir / "PROJECT_METRICS.md"
    write_markdown(md_path, metrics)
    print(f"Written: {md_path.resolve()}")

    (out_dir / "PROJECT_METRICS.md").write_text(md_path.read_text(encoding="utf-8"), encoding="utf-8")

    sep = "─" * 60
    m = metrics
    print(f"""
{sep}
AgentShield metrics  (v{m.agentshield_version})
{sep}
  Attack categories         : {len(m.attack_categories)}
  Total benchmark cases     : {m.total_test_cases}
  Benchmark pass rate       : {m.benchmark.pass_rate:.0%}
  Configs scanned           : {m.workflows_or_configs_scanned}
  Findings total            : {m.findings_total}
  High / critical findings  : {m.findings_high_or_critical}
  Avg scan time             : {m.avg_scan_time_seconds:.4f} s
  P95 scan time             : {m.p95_scan_time_seconds:.4f} s
  Dynamic scenarios run     : {m.dynamic.scenarios_run}
  Dynamic violations found  : {m.dynamic.violations_total}
  Distinct rule IDs         : {m.rule_coverage.total_rules}
  Rules-only rate           : {m.rules_only_rate:.0%}
  LLM routing rate          : {m.llm_routing_rate:.0%}
  Avg scan cost (USD)       : ${m.avg_scan_cost_usd:.2f}
{sep}""")

    return 0


if __name__ == "__main__":
    sys.exit(main())
