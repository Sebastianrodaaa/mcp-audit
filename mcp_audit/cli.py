"""mcp-audit command line."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, collect, pin, render
from .model import SEVERITIES, sev_rank
from .rules import RULES, scan

EPILOG = """examples:
  mcp-audit scan                                   # every MCP client config found on this machine
  mcp-audit scan ~/.cursor/mcp.json --lock mcp-audit.lock
  mcp-audit scan --stdio -- npx -y @modelcontextprotocol/server-filesystem /tmp
  mcp-audit scan https://example.com/mcp --format sarif -o mcp-audit.sarif
  mcp-audit pin mcp.json                          # write the lockfile, later scans flag rug-pulls
  mcp-audit proxy -- python server.py             # strip poisoned tools live
"""


def _target_args(p):
    p.add_argument("target", nargs="?", help="MCP client config (mcp.json, claude_desktop_config.json), a saved tools/list JSON, or an http(s) URL")
    p.add_argument("--stdio", action="store_true", help="launch a stdio server: everything after `--` is the command")
    p.add_argument("--transport", choices=["http", "sse"], help="force the transport for a URL target")
    p.add_argument("-H", "--header", action="append", default=[], help="HTTP header for URL targets, e.g. 'Authorization: Bearer …'")
    p.add_argument("--server", action="append", help="only these server names from a config")
    p.add_argument("--name", help="name to give a stdio or URL server")
    p.add_argument("--timeout", type=float, default=30.0, help="seconds per server (default 30)")


def _servers(a):
    command = a.command
    headers = dict(h.split(":", 1) for h in a.header)
    headers = {k.strip(): v.strip() for k, v in headers.items()}
    if command or a.target:
        return collect.collect(a.target or "", command, a.transport, headers, a.timeout, a.server, a.name)
    found = collect.discover()
    if not found:
        sys.exit("mcp-audit: no target given and no MCP client config found (try `mcp-audit scan mcp.json`)")
    servers = []
    for path in found:
        print(f"mcp-audit: reading {path}", file=sys.stderr)
        servers += collect.collect(path, timeout=a.timeout, only=a.server)
    return servers


def cmd_scan(a) -> int:
    servers = _servers(a)
    findings = scan(servers, a.max_params)
    lock = pin.load(a.lock) if a.lock else None
    if lock:
        findings += pin.compare(lock, servers)
    if a.judge:
        from .judge import judge
        findings += judge(servers, a.model)
    findings.sort(key=lambda f: (-sev_rank(f.severity), f.server, f.item, f.rule))
    if a.lock and (a.update_lock or lock is None):
        pin.write(a.lock, servers, lock)
        print(f"mcp-audit: pinned {sum(1 for s in servers for _ in s.items())} definitions to {a.lock}", file=sys.stderr)
    if a.dump:
        Path(a.dump).write_text(render.as_json(servers, []))
    if a.format == "sarif":
        from .sarif import to_sarif
        out = json.dumps(to_sarif([f for f in findings if sev_rank(f.severity) >= sev_rank(a.min_severity)], a.artifact or a.target or "mcp.json"), indent=2)
    elif a.format == "json":
        out = render.as_json(servers, [f for f in findings if sev_rank(f.severity) >= sev_rank(a.min_severity)])
    elif a.format == "markdown":
        out = render.markdown(servers, [f for f in findings if sev_rank(f.severity) >= sev_rank(a.min_severity)])
    else:
        out = render.text(servers, findings, a.min_severity)
    if a.output:
        Path(a.output).write_text(out + "\n")
        if a.format != "text":
            print(render.text(servers, findings, a.min_severity))
    else:
        print(out)
    worst = max((sev_rank(f.severity) for f in findings), default=-1)
    if a.fail_on != "never" and worst >= sev_rank(a.fail_on):
        return 1
    return 2 if any(s.error for s in servers) and a.strict else 0


def cmd_pin(a) -> int:
    servers = _servers(a)
    pin.write(a.lock, servers, pin.load(a.lock))
    for s in servers:
        print(f"{'✗' if s.error else '✓'} {s.name}: " + (s.error or f"{sum(1 for _ in s.items())} definitions pinned"))
    print(f"wrote {a.lock}")
    return 2 if any(s.error for s in servers) else 0


def cmd_proxy(a) -> int:
    from .proxy import run
    command = a.command
    if not command:
        sys.exit("mcp-audit proxy: give the server command after --")
    return run(command, a.name or collect.guess_name(command), a.threshold, a.lock)


def cmd_rules(a) -> int:
    for r in RULES.values():
        print(f"{r.id}  {r.name:<28} {r.summary}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="mcp-audit", description="Find tool poisoning and rug-pulls in MCP servers.", epilog=EPILOG,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=f"mcp-audit {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="list every tool, prompt and resource and check them")
    _target_args(s)
    s.add_argument("--format", choices=["text", "json", "sarif", "markdown"], default="text")
    s.add_argument("-o", "--output", help="write the report here (text summary still goes to stdout)")
    s.add_argument("--artifact", help="file path SARIF results point at (default: the target)")
    s.add_argument("--lock", help="lockfile: written on first run, compared on later runs")
    s.add_argument("--update-lock", action="store_true", help="accept the current definitions into the lockfile")
    s.add_argument("--judge", action="store_true", help="also ask a local model (Ollama) to classify each definition")
    s.add_argument("--model", default="qwen2.5:3b", help="Ollama model for --judge")
    s.add_argument("--min-severity", choices=SEVERITIES, default="low", help="hide findings below this")
    s.add_argument("--fail-on", choices=SEVERITIES + ["never"], default="high", help="exit 1 at or above this severity (default high)")
    s.add_argument("--max-params", type=int, default=20)
    s.add_argument("--dump", help="save the collected inventory as JSON (scannable offline later)")
    s.add_argument("--strict", action="store_true", help="exit 2 if any server could not be reached")
    s.set_defaults(fn=cmd_scan)

    p = sub.add_parser("pin", help="write a lockfile of definition hashes")
    _target_args(p)
    p.add_argument("--lock", default="mcp-audit.lock")
    p.set_defaults(fn=cmd_pin)

    x = sub.add_parser("proxy", help="run a stdio server behind a filter that drops poisoned definitions")
    x.add_argument("--threshold", choices=SEVERITIES, default="high")
    x.add_argument("--lock", help="also drop definitions that changed against this lockfile")
    x.add_argument("--name", help="server name used in the lockfile")
    x.set_defaults(fn=cmd_proxy)

    r = sub.add_parser("rules", help="list the checks")
    r.set_defaults(fn=cmd_rules)

    argv = list(sys.argv[1:] if argv is None else argv)
    command = []
    if "--" in argv:
        i = argv.index("--")
        argv, command = argv[:i], argv[i + 1:]
    a = ap.parse_args(argv)
    a.command = command
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
