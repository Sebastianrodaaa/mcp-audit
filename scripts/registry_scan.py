"""Measurement scan: every remote (HTTP/SSE) server in the official MCP Registry that answers without credentials.

    python scripts/registry_scan.py --limit 200      # writes results/registry/{inventory.json.gz,findings.json,meta.json}
    python scripts/registry_scan.py --rescan         # re-run the rules on the saved inventory, no network

Only metadata is requested (initialize + tools/prompts/resources list). No tool is ever called. Servers that need
auth, time out, or error are recorded as unreachable and not retried.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import sys
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mcp_audit.collect import connect  # noqa: E402
from mcp_audit.model import Server  # noqa: E402
from mcp_audit.rules import scan  # noqa: E402

API = "https://registry.modelcontextprotocol.io/v0/servers"
OUT = Path("results/registry")


def registry(max_pages: int = 1000):
    seen, cursor = {}, None
    for _ in range(max_pages):
        q = {"limit": 100, "version": "latest"} | ({"cursor": cursor} if cursor else {})
        with urllib.request.urlopen(f"{API}?{urllib.parse.urlencode(q)}", timeout=30) as r:
            d = json.loads(r.read())
        for item in d["servers"]:
            s = item["server"]
            seen[s["name"]] = s
        cursor = d.get("metadata", {}).get("nextCursor")
        if not cursor:
            break
    return list(seen.values())


def candidates(servers):
    out = []
    for s in servers:
        for rem in s.get("remotes") or []:
            url = rem.get("url", "")
            if "{" in url or any(h.get("isRequired") for h in rem.get("headers") or []):
                continue
            if rem.get("type") in ("streamable-http", "sse") and url.startswith("https://"):
                out.append({"name": s["name"], "url": url, "type": "sse" if rem["type"] == "sse" else "http", "description": s.get("description", "")})
                break
    return sorted(out, key=lambda c: c["name"])


def load_inventory() -> list[Server]:
    with gzip.open(OUT / "inventory.json.gz", "rt", encoding="utf-8") as fh:
        data = json.load(fh)
    return [Server(**{k: v for k, v in s.items() if k in Server.__dataclass_fields__}) for s in data["servers"]]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=200, help="stop after this many servers answered")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--seed", default="mcp-audit-17", help="order in which candidates are probed")
    ap.add_argument("--rescan", action="store_true", help="only re-run the rules on results/registry/inventory.json.gz")
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    if a.rescan:
        reached = load_inventory()
        findings = scan(reached)
        (OUT / "findings.json").write_text(json.dumps([f.to_dict() for f in findings], ensure_ascii=False) + "\n")
        print(f"rescanned {len(reached)} servers, {len(findings)} findings")
        return
    listed = registry()
    cands = sorted(candidates(listed), key=lambda c: hashlib.sha256(f"{a.seed}:{c['name']}".encode()).hexdigest())
    print(f"registry: {len(listed)} servers, {len(cands)} remote without required headers", file=sys.stderr)

    def probe(c):
        return connect(c["name"], {"url": c["url"], "type": c["type"]}, c["url"], timeout=20)

    reached: list[Server] = []
    failed, probed, batch = [], 0, a.workers * 4
    with ThreadPoolExecutor(a.workers) as pool:
        while len(reached) < a.limit and probed < len(cands):
            chunk = cands[probed: probed + batch]
            probed += len(chunk)
            for c, s in zip(chunk, pool.map(probe, chunk)):
                if s.error or not (s.tools or s.prompts or s.resources):
                    failed.append({"name": c["name"], "url": c["url"], "error": s.error or "empty inventory"})
                elif len(reached) < a.limit:
                    reached.append(s)
            print(f"  probed {probed}, answered {len(reached)}", file=sys.stderr)
    with gzip.open(OUT / "inventory.json.gz", "wt", encoding="utf-8") as fh:
        json.dump({"servers": [asdict(s) for s in reached]}, fh, ensure_ascii=False)
    (OUT / "unreachable.json").write_text(json.dumps(failed, indent=1))
    findings = scan(reached)
    (OUT / "findings.json").write_text(json.dumps([f.to_dict() for f in findings], ensure_ascii=False) + "\n")
    (OUT / "meta.json").write_text(json.dumps({"listed": len(listed), "candidates": len(cands), "probed": probed, "answered": len(reached),
                                               "seed": a.seed}, indent=1))
    print(f"scanned {len(reached)} servers, {sum(len(s.tools) for s in reached)} tools, {len(findings)} findings; {len(failed)} unreachable")


if __name__ == "__main__":
    main()
