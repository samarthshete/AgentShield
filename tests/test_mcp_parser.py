from pathlib import Path

from agentshield.parser.mcp_parser import extract_normalized_surface, parse_mcp_config


def test_parse_json_extracts_tools_and_builds_scan_text(tmp_path: Path) -> None:
    path = tmp_path / "cfg.json"
    path.write_text(
        '{"tools":[{"name":"alpha","description":"Beta desc"}],"mcpServers":{"x":{"env":{"API":"1"}}}}',
        encoding="utf-8",
    )
    meta = parse_mcp_config(path)
    assert meta["target_kind"] == "json"
    assert len(meta["tools"]) == 1
    assert "alpha" in meta["tools"][0]
    assert "Beta" in meta["scan_text"]


def test_extract_surface_nested_tools() -> None:
    data = {
        "mcpServers": {
            "a": {
                "tools": [{"name": "t1", "description": "d1"}],
            }
        }
    }
    surface = extract_normalized_surface(data)
    assert len(surface.tools) == 1
    assert "t1" in surface.tools[0]


def test_parse_toml_permissions(tmp_path: Path) -> None:
    path = tmp_path / "p.toml"
    path.write_text(
        '[capabilities]\nscopes = ["filesystem", "network"]\n',
        encoding="utf-8",
    )
    meta = parse_mcp_config(path)
    assert meta["target_kind"] == "toml"
    assert "filesystem" in meta["permission_blob"].lower()
