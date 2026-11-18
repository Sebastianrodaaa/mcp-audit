"""Terminal, Markdown and JSON views of a scan."""
from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict

from .model import Finding, Server, sev_rank

COLOR = {"critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[2m"}
RESET, DIM, BOLD, GREEN = "\033[0m", "\033[2m", "\033[1m", "\033[32m"


def _c(code: str, s: str, on: bool) -> str:
    return f"{code}{s}{RESET}" if on else s


def text(servers: list[Server], findings: list[Finding], threshold: str = "low", color: bool | None = None) -> str:
    if color is None:
        color = bool(os.environ.get("FORCE_COLOR")) or (sys.stdout.isatty() and not os.environ.get("NO_COLOR"))
    on = color
    shown = [f for f in findings if sev_rank(f.severity) >= sev_rank(threshold)]
    lines = []
    for s in servers:
        counts = f"{s.transport} · {len(s.tools)} tools · {len(s.prompts)} prompts · {len(s.resources)} resources"
        head = f"{s.name}  {_c(DIM, counts, on)}"
        if s.error:
            lines.append(_c(BOLD, "✗ ", on) + f"{s.name}  could not connect: {s.error}")
            continue
        mine = [f for f in shown if f.server == s.name]
        lines.append((_c(GREEN, "✓ ", on) if not mine else _c(COLOR[max((f.severity for f in mine), key=sev_rank)], "! ", on)) + head)
        for f in mine:
            tag = _c(COLOR[f.severity], f"{f.severity.upper():<8}", on)
            lines.append(f"  {tag} {f.rule}  {f.kind} {_c(BOLD, f.item, on)}: {f.message}")
            if f.evidence:
                ev = f.evidence if len(f.evidence) <= 150 else f.evidence[:149] + "…"
                lines.append(_c(DIM, f"           ↳ {ev}", on))
    counts = {s: sum(f.severity == s for f in shown) for s in ("critical", "high", "medium", "low", "info")}
    summary = ", ".join(f"{n} {s}" for s, n in counts.items() if n) or "no findings"
    items = sum(1 for s in servers for _ in s.items())
    lines.append("")
    lines.append(f"{len(servers)} server(s), {items} definitions scanned: {summary}")
    return "\n".join(lines)


def as_json(servers: list[Server], findings: list[Finding]) -> str:
    return json.dumps({"servers": [asdict(s) for s in servers], "findings": [f.to_dict() for f in findings]}, indent=2, ensure_ascii=False)


def markdown(servers: list[Server], findings: list[Finding]) -> str:
    out = ["| Severity | Rule | Server | Item | Finding |", "|---|---|---|---|---|"]
    for f in findings:
        msg = f.message.replace("|", "\\|")
        out.append(f"| {f.severity} | {f.rule} | {f.server} | `{f.item}` | {msg} |")
    if not findings:
        out.append("| - | - | - | - | no findings |")
    return "\n".join(out)
