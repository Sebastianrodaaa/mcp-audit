"""Plain data the scanner works on: what a server exposes, and what was found in it."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITIES = ["info", "low", "medium", "high", "critical"]


def sev_rank(s: str) -> int:
    return SEVERITIES.index(s)


@dataclass
class Server:
    """One MCP server's advertised surface, as raw JSON dicts from tools/list, prompts/list and resources/list."""

    name: str
    transport: str = "file"
    source: str = ""
    instructions: str = ""
    tools: list[dict[str, Any]] = field(default_factory=list)
    prompts: list[dict[str, Any]] = field(default_factory=list)
    resources: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""

    def items(self):
        """Yield (kind, name, definition) for everything the client would show the model."""
        if self.instructions:
            yield "instructions", "(server)", {"instructions": self.instructions}
        for kind, group in (("tool", self.tools), ("prompt", self.prompts), ("resource", self.resources)):
            for d in group:
                key = d.get("uri") if kind == "resource" else None  # resource names need not be unique, URIs are
                yield kind, str(key or d.get("name") or d.get("uri") or "?"), d


@dataclass
class Finding:
    rule: str
    severity: str
    server: str
    kind: str
    item: str
    message: str
    evidence: str = ""
    field: str = "description"

    def to_dict(self):
        return asdict(self)


@dataclass
class Report:
    servers: list[Server]
    findings: list[Finding]

    def worst(self) -> str | None:
        return max((f.severity for f in self.findings), key=sev_rank, default=None)

    def item_score(self, server: str, item: str) -> int:
        return max((sev_rank(f.severity) for f in self.findings if f.server == server and f.item == item), default=-1)
