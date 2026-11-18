"""Second stage for the registry scan: ask the LLM judge about every definition the static rules flagged high or worse.

    python scripts/registry_judge.py --model qwen2.5:3b     # reads results/registry/{inventory.json.gz,findings.json}
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from registry_scan import load_inventory  # noqa: E402

from mcp_audit.judge import classify  # noqa: E402
from mcp_audit.model import sev_rank  # noqa: E402

OUT = Path("results/registry")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="qwen2.5:3b")
    a = ap.parse_args()
    servers = {s.name: s for s in load_inventory()}
    flagged = sorted({(f["server"], f["kind"], f["item"]) for f in json.loads((OUT / "findings.json").read_text())
                      if sev_rank(f["severity"]) >= sev_rank("high")})
    cache = OUT / f"judge_{a.model.replace(':', '-')}.jsonl"
    done = {tuple(d["key"]) for d in map(json.loads, cache.open())} if cache.exists() else set()
    with cache.open("a") as fh:
        for key in flagged:
            if key in done:
                continue
            srv, kind, item = key
            defn = next(d for k, n, d in servers[srv].items() if k == kind and n == item)
            v = classify(defn, a.model)
            fh.write(json.dumps({"key": key, "poisoned": v["poisoned"], "rule": v.get("rule"), "reason": str(v.get("reason", ""))[:200]}) + "\n")
            fh.flush()
    rows = [json.loads(line) for line in cache.open()]
    kept = {r["key"][0] for r in rows if r["poisoned"]}
    print(f"{len(rows)} flagged definitions judged, {sum(r['poisoned'] for r in rows)} confirmed, on {len(kept)} servers")


if __name__ == "__main__":
    main()
