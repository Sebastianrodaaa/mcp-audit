"""Build data/mcptox.jsonl from the MCPTox benchmark at a pinned commit.

Positives are the 485 poisoned tool descriptions in pure_tool.json. Negatives are the 353 real tool
definitions of the same 45 servers, parsed from each server's clean system prompt. Servers are split
into dev and test halves by a seeded hash, so rules and the judge rubric are tuned on dev servers only.
"""
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

REPO = "https://github.com/zhiqiangwang4/MCPTox-Benchmark"
COMMIT = "630121b3275f74cc72d000a7a056e4d3c68648ef"
SEED = "mcp-audit-17"
SRC = Path(".cache/MCPTox-Benchmark")
OUT = Path("data/mcptox.jsonl")


def fetch():
    if not (SRC / "pure_tool.json").exists():
        SRC.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", "-q", str(SRC)], check=True)
        subprocess.run(["git", "-C", str(SRC), "fetch", "-q", "--depth", "1", REPO, COMMIT], check=True)
        subprocess.run(["git", "-C", str(SRC), "checkout", "-q", "--detach", "FETCH_HEAD"], check=True)


def split(server):
    return "dev" if int(hashlib.sha256(f"{SEED}:{server}".encode()).hexdigest(), 16) % 2 == 0 else "test"


def parse_clean(prompt):
    body = prompt.split("Choose the appropriate tool")[0]
    tools = []
    for block in re.split(r"\n\s*\nTool: ", "\n\n" + body)[1:]:
        name, _, rest = block.partition("\nDescription: ")
        desc, _, args = rest.partition("\nArguments:")
        props, required = {}, []
        for line in args.strip().splitlines():
            m = re.match(r"- ([^:]+):\s*(.*)", line.strip())
            if not m:
                continue
            arg, text = m.groups()
            if text.endswith("(required)"):
                required.append(arg)
                text = text[: -len("(required)")].strip()
            props[arg] = {"type": "string"} if text == "No description" else {"type": "string", "description": text}
        tools.append({"name": name.strip(), "description": desc.strip(),
                      "inputSchema": {"type": "object", "properties": props, "required": required}})
    return tools


def main():
    fetch()
    pure = json.loads((SRC / "pure_tool.json").read_text())
    servers = json.loads((SRC / "response_all.json").read_text())["servers"]
    rows, seen = [], set()
    for name, s in servers.items():
        for t in parse_clean(s["clean_system_promot"]):
            rows.append({"id": f"clean/{name}/{t['name']}", "server": name, "split": split(name), "label": 0,
                         "paradigm": None, "risk": None, "tool": t})
    for group in pure:
        for key, v in group.items():
            text = v["tool_content"].strip()
            if (v["server_name"], text) in seen:
                continue
            seen.add((v["server_name"], text))
            rows.append({"id": f"poisoned/{key}", "server": v["server_name"], "split": split(v["server_name"]), "label": 1,
                         "paradigm": v["paradigm"], "risk": v["security risk"],
                         "tool": {"name": v["tool_name"], "description": text,
                                  "inputSchema": {"type": "object", "properties": {}, "required": []}}})
    OUT.parent.mkdir(exist_ok=True)
    with OUT.open("w") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    by = {(r["split"], r["label"]): 0 for r in rows}
    for r in rows:
        by[(r["split"], r["label"])] += 1
    print(f"wrote {len(rows)} rows to {OUT}: " + ", ".join(f"{k[0]}/{'poisoned' if k[1] else 'clean'}={v}" for k, v in sorted(by.items())))


if __name__ == "__main__":
    sys.exit(main())
