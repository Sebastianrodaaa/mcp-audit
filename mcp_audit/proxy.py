"""A stdio proxy between an MCP client and a server that strips poisoned definitions before the model sees them.

The client launches `mcp-audit proxy -- <server command>` instead of the server. Requests pass through
untouched; `tools/list`, `prompts/list` and `resources/list` responses are scanned, and anything at or
above the threshold (or changed against a lockfile) is dropped. Calls to a dropped tool get an error.
"""
from __future__ import annotations

import json
import subprocess
import sys
import threading

from . import pin
from .model import sev_rank
from .rules import scan_definition

LISTS = {"tools/list": ("tools", "tool"), "prompts/list": ("prompts", "prompt"), "resources/list": ("resources", "resource")}


class Filter:
    def __init__(self, name: str, threshold: str = "high", lock: dict | None = None, log=sys.stderr):
        self.name, self.threshold, self.lock, self.log = name, threshold, lock, log
        self.pending: dict = {}
        self.blocked: set[str] = set()
        self.known_tools: set[str] = set()

    def _say(self, msg: str):
        print(f"[mcp-audit] {msg}", file=self.log, flush=True)

    def from_client(self, msg: dict) -> tuple[dict | None, dict | None]:
        """Returns (message to forward to the server, reply to send straight back to the client)."""
        if msg.get("method") in (*LISTS, "initialize") and "id" in msg:
            self.pending[msg["id"]] = msg["method"]
        if msg.get("method") == "tools/call" and msg.get("params", {}).get("name") in self.blocked:
            name = msg["params"]["name"]
            self._say(f"blocked call to quarantined tool {name}")
            return None, {"jsonrpc": "2.0", "id": msg.get("id"), "error": {"code": -32001, "message": f"mcp-audit: tool '{name}' was quarantined as poisoned"}}
        return msg, None

    def _initialize(self, msg: dict) -> dict:
        text = msg["result"].get("instructions") or ""
        if not text:
            return msg
        d = {"instructions": text}
        hits = [f for f in scan_definition(self.name, "instructions", "(server)", d, self.known_tools) if sev_rank(f.severity) >= sev_rank(self.threshold)]
        ref = (self.lock or {}).get("servers", {}).get(self.name, {}).get("instructions:(server)")
        if hits or (ref is not None and ref["hash"] != pin.digest(d)):
            self._say("stripped server instructions: " + (", ".join(sorted({f"{f.rule} {f.message}" for f in hits}))[:200] or "changed since pinned"))
            msg["result"].pop("instructions", None)
        return msg

    def from_server(self, msg: dict) -> dict:
        method = self.pending.pop(msg.get("id"), None) if "id" in msg else None
        if not method or "result" not in msg:
            return msg
        if method == "initialize":
            return self._initialize(msg)
        key, kind = LISTS[method]
        defs = msg["result"].get(key) or []
        if kind == "tool":
            self.known_tools |= {d.get("name", "") for d in defs}
        pinned = (self.lock or {}).get("servers", {}).get(self.name, {})
        keep = []
        for d in defs:
            uri = d.get("uri") if kind == "resource" else None  # same keys as Server.items and the lockfile
            name = str(uri or d.get("name") or d.get("uri") or "?")
            found = scan_definition(self.name, kind, name, d, self.known_tools, local_names=self.known_tools)
            hits = [f for f in found if sev_rank(f.severity) >= sev_rank(self.threshold)]
            ref = pinned.get(f"{kind}:{name}")
            changed = ref is not None and ref["hash"] != pin.digest(d)
            if hits or changed:
                why = "definition changed since pinned" if changed else ", ".join(sorted({f"{f.rule} {f.message}" for f in hits}))[:200]
                self._say(f"quarantined {kind} {name}: {why}")
                if kind == "tool":
                    self.blocked.add(name)
                continue
            keep.append(d)
        msg["result"][key] = keep
        return msg


def _pump(src, dst, handle, back=None):
    for line in src:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            dst.write(line + "\n"); dst.flush()
            continue
        out = handle(msg)
        fwd, reply = out if isinstance(out, tuple) else (out, None)
        if fwd is not None:
            dst.write(json.dumps(fwd) + "\n"); dst.flush()
        if reply is not None and back is not None:
            back.write(json.dumps(reply) + "\n"); back.flush()


def run(command: list[str], name: str, threshold: str = "high", lock_path: str | None = None) -> int:
    lock = pin.load(lock_path) if lock_path else None
    flt = Filter(name, threshold, lock)
    proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
    out_lock = threading.Lock()

    class Locked:
        def __init__(self, f): self.f = f
        def write(self, s):
            with out_lock: self.f.write(s)
        def flush(self): self.f.flush()

    client_out = Locked(sys.stdout)

    def client_side():
        try:
            _pump(sys.stdin, proc.stdin, flt.from_client, client_out)
        except (BrokenPipeError, ValueError, OSError):
            pass
        finally:
            try:
                proc.stdin.close()
            except OSError:
                pass

    threading.Thread(target=client_side, daemon=True).start()
    _pump(proc.stdout, client_out, flt.from_server)  # returns when the server closes its stdout
    code = proc.wait()
    sys.stdout.flush()
    return code

