from __future__ import annotations

from pathlib import Path

from agentshield.parser.discovery import discover_candidate_files


def test_discovery_includes_config_docs_and_source_files(tmp_path: Path) -> None:
    expected_names = {
        "config.json",
        "manifest.yaml",
        "settings.toml",
        "README.md",
        "server.py",
        "tools.ts",
        "widget.tsx",
        "script.js",
    }
    for name in expected_names:
        (tmp_path / name).write_text("safe text", encoding="utf-8")
    (tmp_path / "image.png").write_text("not scanned", encoding="utf-8")

    discovered = {path.name for path in discover_candidate_files(tmp_path)}

    assert expected_names <= discovered
    assert "image.png" not in discovered


def test_discovery_skips_vendor_and_build_dirs(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "tool.ts").write_text("safe text", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "bundle.js").write_text("safe text", encoding="utf-8")

    discovered = {path.relative_to(tmp_path).as_posix() for path in discover_candidate_files(tmp_path)}

    assert "src/tool.ts" in discovered
    assert "node_modules/package.json" not in discovered
    assert "dist/bundle.js" not in discovered


def test_discovery_returns_single_file_even_for_unknown_suffix(tmp_path: Path) -> None:
    target = tmp_path / "custom.unknown"
    target.write_text("safe text", encoding="utf-8")

    assert discover_candidate_files(target) == [target]
