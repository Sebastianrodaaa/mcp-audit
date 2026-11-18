"""Pin every definition by hash in a lockfile; a later scan reports anything that changed (rug-pulls)."""
from __future__ import annotations

import difflib
import hashlib
import json
from pathlib import Path

from .model import Finding, Server

VERSION = 1


def canonical(defn: dict) -> str:
    return json.dumps(defn, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def digest(defn: dict) -> str:
    return "sha256:" + hashlib.sha256(canonical(defn).encode()).hexdigest()


def snapshot(servers: list[Server]) -> dict:
    out = {"version": VERSION, "servers": {}}
    for s in servers:
        if s.error:
            continue
        out["servers"][s.name] = {f"{k}:{n}": {"hash": digest(d), "definition": d} for k, n, d in s.items()}
    return out


def write(path: str | Path, servers: list[Server], previous: dict | None = None) -> dict:
    lock = snapshot(servers)
    if previous:  # keep servers that were not part of this run
        for name, entries in previous.get("servers", {}).items():
            lock["servers"].setdefault(name, entries)
    Path(path).write_text(json.dumps(lock, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    return lock


def load(path: str | Path) -> dict | None:
    p = Path(path)
    return json.loads(p.read_text()) if p.exists() else None


def _diff(a: dict, b: dict) -> str:
    lines = difflib.unified_diff(json.dumps(a, indent=1, sort_keys=True).splitlines(), json.dumps(b, indent=1, sort_keys=True).splitlines(), lineterm="", n=0)
    return " | ".join(ln for ln in lines if ln[:1] in "+-" and not ln.startswith(("+++", "---")))[:400]


def compare(lock: dict, servers: list[Server]) -> list[Finding]:
    out = []
    for s in servers:
        pinned = lock.get("servers", {}).get(s.name)
        if pinned is None or s.error:
            continue
        current = {f"{k}:{n}": d for k, n, d in s.items()}
        for key, d in current.items():
            kind, name = key.split(":", 1)
            if key not in pinned:
                out.append(Finding("MA012", "medium", s.name, kind, name, "New definition that is not in the lockfile", "", "definition"))
            elif pinned[key]["hash"] != digest(d):
                out.append(Finding("MA012", "high", s.name, kind, name, f"Definition changed since pinned ({pinned[key]['hash'][:19]}… → {digest(d)[:19]}…)",
                                   _diff(pinned[key].get("definition", {}), d), "definition"))
        for key in pinned.keys() - current.keys():
            kind, name = key.split(":", 1)
            out.append(Finding("MA012", "low", s.name, kind, name, "Pinned definition is gone", "", "definition"))
    return out
