from pathlib import Path

_SKIP_DIR_NAMES = frozenset(
    {
        ".git",
        "node_modules",
        "venv",
        ".venv",
        "__pycache__",
        ".tox",
        "dist",
        "build",
        ".mypy_cache",
        ".ruff_cache",
    }
)

_DISCOVERABLE_SUFFIXES = frozenset(
    {
        ".json",
        ".yaml",
        ".yml",
        ".toml",
        ".md",
        ".txt",
        ".py",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs",
    }
)


def _is_skipped(path: Path) -> bool:
    return any(part in _SKIP_DIR_NAMES for part in path.parts)


def discover_candidate_files(root: Path) -> list[Path]:
    """Discover scan-friendly config, prose, and source files under a path."""
    if root.is_file():
        return [root]
    results: list[Path] = []
    for p in root.rglob("*"):
        if _is_skipped(p):
            continue
        if p.is_file() and p.suffix.lower() in _DISCOVERABLE_SUFFIXES:
            results.append(p)
    return sorted(set(results))
