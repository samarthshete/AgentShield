from __future__ import annotations

from pathlib import Path

import yaml

from agentshield.models.benchmark import BenchmarkCase


def load_case(path: Path) -> BenchmarkCase:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    return BenchmarkCase(**raw)


def load_suite(directory: Path) -> list[BenchmarkCase]:
    if not directory.is_dir():
        raise FileNotFoundError(f"Benchmark directory not found: {directory}")
    cases: list[BenchmarkCase] = []
    for p in sorted(directory.glob("*.yaml")):
        cases.append(load_case(p))
    for p in sorted(directory.glob("*.yml")):
        if p.with_suffix(".yaml") not in {c.with_suffix(".yaml") for c in directory.glob("*.yaml")}:
            cases.append(load_case(p))
    return cases
