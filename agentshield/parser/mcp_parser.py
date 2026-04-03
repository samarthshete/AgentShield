"""Load MCP-style and generic config files into text for static rules."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from agentshield.models.mcp_surface import NormalizedMcpSurface

_JSON_LIKE = {".json"}
_YAML_LIKE = {".yaml", ".yml"}
_TOML_LIKE = {".toml"}
_TEXT_LIKE = {".md", ".txt"}


def _flatten_strings(obj: Any, out: list[str], min_len: int = 2) -> None:
    if isinstance(obj, str):
        if len(obj.strip()) >= min_len:
            out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _flatten_strings(v, out, min_len)
    elif isinstance(obj, list):
        for item in obj:
            _flatten_strings(item, out, min_len)


def _permission_subtree(obj: Any) -> str | None:
    if not isinstance(obj, dict):
        return None
    for candidate in ("permissions", "permission", "capabilities", "scopes", "authorization"):
        for k in obj:
            if k.lower() == candidate:
                try:
                    return json.dumps(obj[k], sort_keys=True)
                except (TypeError, ValueError):
                    return str(obj[k])
    return None


def _walk_permission_strings(obj: Any, parts: list[str]) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            lk = k.lower()
            if any(x in lk for x in ("permission", "capabilit", "scope", "filesystem", "network")):
                try:
                    parts.append(json.dumps({k: v}, sort_keys=True))
                except (TypeError, ValueError):
                    parts.append(f"{k}: {v!s}")
            _walk_permission_strings(v, parts)
    elif isinstance(obj, list):
        for item in obj:
            _walk_permission_strings(item, parts)


def aggregated_text_from_data(data: Any) -> tuple[str, str]:
    flat: list[str] = []
    _flatten_strings(data, flat)
    full = "\n".join(flat)

    perm_parts: list[str] = []
    _walk_permission_strings(data, perm_parts)
    subtree = _permission_subtree(data)
    if subtree:
        perm_parts.insert(0, subtree)
    perm_blob = "\n".join(perm_parts) if perm_parts else full
    return full, perm_blob


def _tool_entry_as_text(item: Any) -> str | None:
    if isinstance(item, str) and item.strip():
        return item.strip()
    if not isinstance(item, dict):
        return None
    name = item.get("name", "")
    desc = item.get("description", "")
    if isinstance(name, str) and isinstance(desc, str):
        return f"{name} {desc}".strip() or None
    if isinstance(name, str) and name.strip():
        return name.strip()
    return None


def _resource_entry_as_text(item: Any) -> str | None:
    if isinstance(item, str) and item.strip():
        return item.strip()
    if isinstance(item, dict):
        uri = item.get("uri", item.get("url", ""))
        name = item.get("name", "")
        bits = [str(x) for x in (name, uri) if x]
        return " ".join(bits).strip() or None
    return None


def _prompt_entry_as_text(item: Any) -> str | None:
    if isinstance(item, str) and item.strip():
        return item.strip()
    if isinstance(item, dict):
        name = item.get("name", "")
        body = item.get("text", item.get("content", item.get("description", "")))
        if isinstance(name, str) and isinstance(body, str):
            return f"{name} {body}".strip() or None
        if isinstance(body, str) and body.strip():
            return body.strip()
    return None


def extract_normalized_surface(data: Any) -> NormalizedMcpSurface:
    surface = NormalizedMcpSurface()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            tools_list = node.get("tools") or node.get("toolDefinitions")
            if isinstance(tools_list, list):
                for item in tools_list:
                    t = _tool_entry_as_text(item)
                    if t:
                        surface.tools.append(t)

            res_list = node.get("resources")
            if isinstance(res_list, list):
                for item in res_list:
                    r = _resource_entry_as_text(item)
                    if r:
                        surface.resources.append(r)

            pr_list = node.get("prompts")
            if isinstance(pr_list, list):
                for item in pr_list:
                    p = _prompt_entry_as_text(item)
                    if p:
                        surface.prompts.append(p)

            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(data)
    return surface


def parse_mcp_config(path: Path) -> dict[str, Any]:
    suffix = path.suffix.lower()
    raw = path.read_text(encoding="utf-8", errors="replace")

    data: Any = None
    target_kind = "text"
    if suffix in _JSON_LIKE:
        target_kind = "json"
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            data = None
    elif suffix in _YAML_LIKE:
        target_kind = "yaml"
        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError:
            data = None
    elif suffix in _TOML_LIKE:
        target_kind = "toml"
        try:
            import tomllib

            data = tomllib.loads(raw)
        except tomllib.TOMLDecodeError:
            data = None
    elif suffix in _TEXT_LIKE:
        target_kind = "markdown" if suffix == ".md" else "text"

    surface = NormalizedMcpSurface()
    if data is None:
        scan_text = raw
        perm_blob = raw
    else:
        surface = extract_normalized_surface(data)
        scan_text, perm_blob = aggregated_text_from_data(data)
        extra = surface.labeled_text()
        if extra:
            scan_text = f"{scan_text}\n{extra}".strip()

    return {
        "path": str(path),
        "target_kind": target_kind,
        "tools": surface.tools,
        "prompts": surface.prompts,
        "resources": surface.resources,
        "scan_text": scan_text,
        "permission_blob": perm_blob,
    }
