"""Bundle results/ into app/data.js for the static dashboard (app/index.html), then screenshot it to docs/screenshots/hero.png."""
import gzip
import json
import shutil
import subprocess
from pathlib import Path

R = Path("results")


def load(p):
    p = R / p
    return json.loads(p.read_text()) if p.exists() else None


def registry():
    inv = R / "registry/inventory.json.gz"
    if not inv.exists():
        return {"meta": None, "findings": [], "servers": []}
    with gzip.open(inv, "rt", encoding="utf-8") as fh:
        servers = json.load(fh)["servers"]
    keep = ("server", "severity", "rule")  # the dashboard only aggregates
    return {"meta": load("registry/meta.json"), "findings": [{k: f[k] for k in keep} for f in load("registry/findings.json") or []],
            "servers": [{"name": s["name"], "tools": len(s["tools"]), "prompts": len(s["prompts"]), "resources": len(s["resources"])} for s in servers]}


data = {"metrics": load("metrics.json"), "judge": [m for m in (load("metrics_judge3b.json"), load("metrics_judge15b.json")) if m],
        "registry": registry(),
        "demo": json.loads(Path("examples/demo-findings.json").read_text()) if Path("examples/demo-findings.json").exists() else None}
Path("app/data.js").write_text("window.DATA = " + json.dumps(data, ensure_ascii=False) + ";\n")
chrome = shutil.which("google-chrome") or shutil.which("chromium") or shutil.which("chromium-browser")
if chrome:
    subprocess.run([chrome, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--window-size=1440,900", "--force-device-scale-factor=1",
                    f"--screenshot={Path('docs/screenshots/hero.png').resolve()}", f"file://{Path('app/index.html').resolve()}"],
                   check=True, capture_output=True)
    print("wrote docs/screenshots/hero.png")
