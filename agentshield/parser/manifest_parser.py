"""Entry point for manifest-style paths; same parsing as MCP configs in Phase 1."""
from pathlib import Path
from typing import Any

from agentshield.parser.mcp_parser import extract_normalized_surface, parse_mcp_config

__all__ = ["extract_normalized_surface", "parse_manifest", "parse_mcp_config"]


def parse_manifest(path: Path) -> dict[str, Any]:
    return parse_mcp_config(path)
