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


def _is_skipped(path: Path) -> bool:
    return any(part in _SKIP_DIR_NAMES for part in path.parts)


def discover_candidate_files(root: Path) -> list[Path]:
    """Discover JSON/YAML/TOML/Markdown files under a path (single file returns itself)."""
    if root.is_file():
        return [root]
    patterns = ("*.json", "*.yaml", "*.yml", "*.toml", "*.md")
    results: list[Path] = []
    for pattern in patterns:
        for p in root.rglob(pattern):
            if _is_skipped(p):
                continue
            results.append(p)
    return sorted(set(results))
