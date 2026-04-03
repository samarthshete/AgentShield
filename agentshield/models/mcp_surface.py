from pydantic import BaseModel, Field


class NormalizedMcpSurface(BaseModel):
    """Flattened tool, resource, and prompt strings from a parsed config tree."""

    tools: list[str] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=list)
    prompts: list[str] = Field(default_factory=list)

    def labeled_text(self) -> str:
        lines: list[str] = []
        for t in self.tools:
            lines.append(f"[tool] {t}")
        for r in self.resources:
            lines.append(f"[resource] {r}")
        for p in self.prompts:
            lines.append(f"[prompt] {p}")
        return "\n".join(lines)
