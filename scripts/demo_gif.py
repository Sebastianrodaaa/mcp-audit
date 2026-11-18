"""Demo GIF from real runs: every line of output is captured from mcp-audit against examples/poisoned_server.py."""
import json
import os
import re
import subprocess
import sys
import tempfile

from PIL import Image, ImageDraw, ImageFont

W, H, PAD, LH, COLS = 1100, 640, 22, 17, 118
MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
F, FB = ImageFont.truetype(MONO, 13), ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf", 13)
SHADE = {"1;97;41": (0, 255, True), "1;31": (255, None, True), "33": (225, None, False), "36": (165, None, False), "2": (110, None, False),
         "1": (255, None, True), "32": (200, None, False)}
PY = sys.executable
DEMO = "examples/poisoned_server.py"
LOCK = os.path.join(tempfile.mkdtemp(), "mcp-audit.lock")


def run(cmd, env=None, stdin=None):
    e = {**os.environ, "FORCE_COLOR": "1", **(env or {})}
    r = subprocess.run(cmd, env=e, capture_output=True, text=True, input=stdin)
    return (r.stdout + r.stderr).rstrip("\n").splitlines()


def spans(line):
    """ANSI line -> [(text, fg, bg, bold)]"""
    out, fg, bg, bold = [], 215, None, False
    for part in re.split(r"(\033\[[0-9;]*m)", line):
        m = re.fullmatch(r"\033\[([0-9;]*)m", part)
        if m:
            code = m.group(1)
            fg, bg, bold = SHADE.get(code, (215, None, False)) if code not in ("", "0") else (215, None, False)
        elif part:
            out.append((part, fg, bg, bold))
    return out


def wrap(line):
    plain = re.sub(r"\033\[[0-9;]*m", "", line)
    if len(plain) <= COLS:
        return [line]
    return [line[: COLS + (len(line) - len(plain))]]  # clip, long evidence lines only


class Term:
    def __init__(self):
        self.lines, self.frames, self.durs = [], [], []

    def draw(self, cursor=False):
        im = Image.new("L", (W, H), 0)
        d = ImageDraw.Draw(im)
        d.rectangle([0, 0, W, 30], fill=18)
        for i, x in enumerate((18, 38, 58)):
            d.ellipse([x - 5, 10, x + 5, 20], outline=90)
        d.text((W // 2, 15), "mcp-audit · real run against examples/poisoned_server.py", font=F, fill=120, anchor="mm")
        rows = (H - 44 - PAD) // LH
        view = self.lines[-rows:]
        y = 42
        for ln in view:
            x = PAD
            for text, fg, bg, bold in spans(ln):
                w = d.textlength(text, font=F)
                if bg is not None:
                    d.rectangle([x - 1, y - 1, x + w + 1, y + LH - 3], fill=235)
                d.text((x, y), text, font=FB if bold else F, fill=fg)
                x += w
            y += LH
        if cursor:
            x = PAD + d.textlength(re.sub(r"\033\[[0-9;]*m", "", view[-1] if view else ""), font=F)
            d.rectangle([x + 1, y - LH, x + 8, y - 3], fill=230)
        return im

    def snap(self, ms, cursor=False):
        self.frames.append(self.draw(cursor)); self.durs.append(ms)

    def type(self, cmd, comment=None):
        if comment:
            self.lines.append(f"\033[2m# {comment}\033[0m")
        self.lines.append("\033[1m$\033[0m ")
        for i in range(0, len(cmd), 3):
            self.lines[-1] = "\033[1m$\033[0m " + cmd[: i + 3]
            self.snap(90, True)
        self.snap(1200, True)

    def out(self, lines, per=320, hold=5000):
        for ln in lines:
            self.lines += wrap(ln)
            self.snap(per)
        self.lines.append("")
        self.snap(int(hold * 1.6))

    def clear(self):
        self.lines = []


t = Term()
t.type("mcp-audit rules", "0. thirteen checks over what the client hands the model; nothing is executed")
t.out(run([PY, "-m", "mcp_audit", "rules"]), per=200, hold=8000)
t.clear()
t.type("mcp-audit scan --stdio -- python examples/poisoned_server.py", "1. scan a server before the agent loads it")
t.out(run([PY, "-m", "mcp_audit", "scan", "--name", "weather-tools", "--stdio", "--", PY, DEMO]), hold=14000)
t.clear()
t.type("MCP_DEMO_CLEAN=1 mcp-audit pin --lock mcp-audit.lock --stdio -- python examples/poisoned_server.py", "2. a clean release: pin every definition by hash")
t.out(run([PY, "-m", "mcp_audit", "pin", "--lock", LOCK, "--name", "weather-tools", "--stdio", "--", PY, DEMO], {"MCP_DEMO_CLEAN": "1"}), hold=4000)
t.type("MCP_DEMO_CLEAN=1 MCP_DEMO_STAGE=2 mcp-audit scan --lock mcp-audit.lock --stdio -- python examples/poisoned_server.py",
       "3. the server ships an update: same tool name, new instructions")
t.out(run([PY, "-m", "mcp_audit", "scan", "--lock", LOCK, "--name", "weather-tools", "--stdio", "--", PY, DEMO],
          {"MCP_DEMO_CLEAN": "1", "MCP_DEMO_STAGE": "2"}), hold=14000)
t.clear()
init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "demo", "version": "0"}}}
msgs = [init, {"jsonrpc": "2.0", "method": "notifications/initialized"}, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "add", "arguments": {"a": 2, "b": 3}}}]
t.type("mcp-audit proxy -- python examples/poisoned_server.py", "4. or sit between client and server and quarantine live")
p = subprocess.Popen([PY, "-m", "mcp_audit", "proxy", "--", PY, DEMO], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
replies = {}
for m in msgs:
    p.stdin.write(json.dumps(m) + "\n"); p.stdin.flush()
    if "id" in m:
        r = json.loads(p.stdout.readline()); replies[r["id"]] = r
p.stdin.close(); p.wait()
logs = [f"\033[33m{ln}\033[0m" for ln in p.stderr.read().splitlines() if ln.startswith("[mcp-audit]")]
names = [x["name"] for x in replies[2]["result"]["tools"]]
t.out(logs + ["", "\033[2m→ tools/list the client receives:\033[0m " + ", ".join(names),
              "\033[2m→ tools/call add:\033[0m " + replies[3]["error"]["message"]], hold=12000)
t.type("mcp-audit scan mcp.json --format sarif -o mcp-audit.sarif   # CI: findings land in code scanning", "5. in CI")
sarif = os.path.join(tempfile.mkdtemp(), "out.sarif")
t.out(run([PY, "-m", "mcp_audit", "scan", "examples/poisoned-inventory.json", "--format", "sarif", "-o", sarif, "--min-severity", "high"])[-1:]
      + [f"\033[2m{len(json.load(open(sarif))['runs'][0]['results'])} SARIF results written · exit code 1 fails the job\033[0m"], hold=9000)
print(f"{len(t.frames)} frames, {sum(t.durs) / 1000:.0f}s")
t.frames[0].save("docs/screenshots/demo.gif", save_all=True, append_images=t.frames[1:], duration=t.durs, loop=0, optimize=True)
