"""Turn a target into Servers: a live MCP server (stdio, SSE, streamable HTTP), a client config file, or a JSON dump."""
from __future__ import annotations

import json
import os
import shlex
from pathlib import Path

import anyio

try:
    BaseExceptionGroup
except NameError:  # Python 3.10
    from exceptiongroup import BaseExceptionGroup

from .model import Server

CONFIG_KEYS = ("mcpServers", "servers", "mcp_servers")


def _dump(objs) -> list[dict]:
    return [o.model_dump(mode="json", by_alias=True, exclude_none=True) for o in objs]


async def _paged(fn):
    out, cursor = [], None
    while True:
        from mcp.types import PaginatedRequestParams
        res = await fn(params=PaginatedRequestParams(cursor=cursor) if cursor else None)
        out += list(getattr(res, "tools", None) or getattr(res, "prompts", None) or getattr(res, "resources", None) or [])
        cursor = getattr(res, "next_cursor", None) or getattr(res, "nextCursor", None)
        if not cursor:
            return out


async def _session_inventory(read, write, server: Server) -> Server:
    from mcp import ClientSession

    async with ClientSession(read, write) as session:
        init = await session.initialize()
        server.instructions = getattr(init, "instructions", None) or ""
        caps = init.capabilities
        if getattr(caps, "tools", None) is not None:
            server.tools = _dump(await _paged(session.list_tools))
        if getattr(caps, "prompts", None) is not None:
            server.prompts = _dump(await _paged(session.list_prompts))
        if getattr(caps, "resources", None) is not None:
            server.resources = _dump(await _paged(session.list_resources))
    return server


async def _connect(server: Server, spec: dict, timeout: float) -> Server:
    with anyio.fail_after(timeout):
        if "command" in spec:
            from mcp.client.stdio import StdioServerParameters, stdio_client

            env = {**os.environ, **(spec.get("env") or {})}
            params = StdioServerParameters(command=spec["command"], args=spec.get("args", []), env=env, cwd=spec.get("cwd"))
            with open(os.devnull, "w") as errlog:
                async with stdio_client(params, errlog=errlog) as (read, write):
                    return await _session_inventory(read, write, server)
        url = spec["url"]
        forced = spec.get("type") or spec.get("transport")
        if forced == "sse" or (forced is None and url.rstrip("/").endswith("/sse")):
            from mcp.client.sse import sse_client

            async with sse_client(url, headers=spec.get("headers")) as (read, write):
                return await _session_inventory(read, write, server)
        from mcp.client.streamable_http import streamable_http_client
        from mcp.shared._httpx_utils import create_mcp_http_client

        async with create_mcp_http_client(headers=spec.get("headers") or None) as client:
            async with streamable_http_client(url, http_client=client) as streams:
                return await _session_inventory(streams[0], streams[1], server)


def connect(name: str, spec: dict, source: str = "", timeout: float = 30.0) -> Server:
    transport = "stdio" if "command" in spec else ("sse" if spec.get("type") == "sse" or str(spec.get("url", "")).rstrip("/").endswith("/sse") else "http")
    server = Server(name=name, transport=transport, source=source)
    try:
        return anyio.run(_connect, server, spec, timeout)
    except BaseException as e:  # a dead server is a result, not a crash
        if isinstance(e, KeyboardInterrupt):
            raise
        while isinstance(e, BaseExceptionGroup) and e.exceptions:
            e = e.exceptions[0]
        server.error = f"{type(e).__name__}: {e}"[:300] or type(e).__name__
        return server


def from_json(data, source: str, timeout: float, only: list[str] | None = None) -> list[Server]:
    for key in CONFIG_KEYS:
        if isinstance(data, dict) and isinstance(data.get(key), dict):
            return [connect(n, spec, source, timeout) for n, spec in data[key].items()
                    if (not only or n in only) and not spec.get("disabled")]
    if isinstance(data, dict) and isinstance(data.get("servers"), list):  # a saved inventory from --dump
        return [Server(**{k: v for k, v in s.items() if k in Server.__dataclass_fields__}) for s in data["servers"]]
    if isinstance(data, dict) and "result" in data:
        data = data["result"]
    if isinstance(data, dict) and any(k in data for k in ("tools", "prompts", "resources")):
        return [Server(name=data.get("name") or Path(source).stem, source=source, instructions=data.get("instructions", ""),
                       tools=data.get("tools", []), prompts=data.get("prompts", []), resources=data.get("resources", []))]
    if isinstance(data, list):
        return [Server(name=Path(source).stem, source=source, tools=data)]
    raise ValueError(f"{source}: not an MCP client config, a tools/list result or a saved inventory")


def guess_name(command: list[str]) -> str:
    for a in command[1:]:
        if not a.startswith("-") and ("/" in a or "." in a or a.startswith("@")):
            return Path(a.split("@")[0] if not a.startswith("@") else a).stem or a
    return Path(command[-1] if len(command) > 1 else command[0]).name


CANDIDATES = ["mcp.json", ".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", "~/.cursor/mcp.json", "~/.codeium/windsurf/mcp_config.json",
              "~/.config/Claude/claude_desktop_config.json", "~/Library/Application Support/Claude/claude_desktop_config.json"]


def discover() -> list[str]:
    return [str(Path(c).expanduser()) for c in CANDIDATES if Path(c).expanduser().is_file()]


def collect(target: str, command: list[str] | None = None, transport: str | None = None, headers: dict | None = None,
            timeout: float = 30.0, only: list[str] | None = None, name: str | None = None) -> list[Server]:
    if command:
        return [connect(name or guess_name(command), {"command": command[0], "args": command[1:]}, shlex.join(command), timeout)]
    if target.startswith(("http://", "https://")):
        spec = {"url": target, "headers": headers or {}}
        if transport:
            spec["type"] = transport
        return [connect(name or target, spec, target, timeout)]
    path = Path(target).expanduser()
    return from_json(json.loads(path.read_text()), str(path), timeout, only)
