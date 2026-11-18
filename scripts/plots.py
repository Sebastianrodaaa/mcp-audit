"""Black-and-white plots from results/ into docs/screenshots/, and the README results table between markers."""
import collections
import json
import re
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

plt.rcParams.update({"figure.facecolor": "black", "axes.facecolor": "black", "savefig.facecolor": "black", "text.color": "#ddd",
                     "axes.labelcolor": "#bbb", "axes.edgecolor": "#444", "xtick.color": "#999", "ytick.color": "#999",
                     "font.family": "monospace", "font.size": 10, "axes.grid": True, "axes.axisbelow": True, "grid.color": "#1c1c1c", "legend.frameon": False})
SHADES = ["#ffffff", "#9a9a9a", "#555555", "#2e2e2e"]


def load(p):
    return json.loads(Path(p).read_text()) if Path(p).exists() else None


def save(fig, name):
    fig.tight_layout()
    fig.savefig(f"docs/screenshots/{name}.png", dpi=110)
    plt.close(fig)


M = load("results/metrics.json")
J = [m for m in (load("results/metrics_judge3b.json"), load("results/metrics_judge15b.json")) if m]
systems = dict(M["systems"])
if J:
    systems[f"mcp-audit static ({J[0]['judge_sample']}-tool sample)"] = J[0]["systems"]["mcp-audit static"]
for m in J:
    systems.update({k: v for k, v in m["systems"].items() if "judge" in k})

# 1. precision / recall / F1 on the held-out servers
names = [n for n in systems if "test" in systems[n]]
fig, ax = plt.subplots(figsize=(9, 0.55 * len(names) + 1.2))
h = 0.26
for i, metric in enumerate(["precision", "recall", "f1"]):
    vals = [systems[n]["test"][metric] for n in names]
    ys = [y + (i - 1) * h for y in range(len(names))]
    ax.barh(ys, vals, h, color=SHADES[i], edgecolor="#ddd", lw=0.6, label=metric)
    for y, v in zip(ys, vals):
        ax.text(v + 0.01, y, f"{v:.2f}", va="center", fontsize=7, color="#aaa")
ax.set_yticks(range(len(names)), names, fontsize=8)
ax.invert_yaxis()
bt = M["dataset"]["by_split"]["test"]
ax.set(xlim=(0, 1.12), title=f"MCPTox held-out servers · {bt['poisoned']} poisoned / {bt['clean']} clean tools")
ax.legend(loc="lower right", ncol=3, fontsize=8)
save(fig, "results")

# 2. recall by attack paradigm and the severity threshold sweep
fig, (a1, a2) = plt.subplots(1, 2, figsize=(9, 3.6))
PARADIGM = {"Template-1": "explicit trigger\nfunction hijack", "Template-2": "implicit trigger\nfunction hijack",
            "Template-3": "implicit trigger\nparameter tamper"}
rp = {PARADIGM.get(k, k): v for k, v in M["recall_by_paradigm"]["test"].items()}
a1.barh(list(rp), list(rp.values()), color="white", edgecolor="#ddd")
for i, v in enumerate(rp.values()):
    a1.text(v - 0.02, i, f"{v:.3f}", va="center", ha="right", color="black", fontsize=9)
a1.set(xlim=(0, 1), title="static recall by MCPTox paradigm (test)")
th = M["static_by_threshold"]["test"]
a2.plot(list(th), [v["precision"] for v in th.values()], "o-", color="white", label="precision")
a2.plot(list(th), [v["recall"] for v in th.values()], "s--", color="#888", label="recall")
a2.set(ylim=(0, 1.05), title="flag at severity ≥ …", xlabel="threshold")
a2.legend(loc="lower left")
save(fig, "paradigms")

# 3. which rules fire on poisoned tools
rh = M["rule_hits_poisoned"]["test"]
fig, ax = plt.subplots(figsize=(9, 3.2))
ax.bar(list(rh), list(rh.values()), color="white", edgecolor="#ddd")
ax.set(title="rules firing on poisoned test tools (one tool can trip several)", ylabel="tools")
save(fig, "rules")

# 4. registry measurement
R = load("results/registry/findings.json")
inv = None
if Path("results/registry/inventory.json.gz").exists():
    import gzip
    with gzip.open("results/registry/inventory.json.gz", "rt", encoding="utf-8") as fh:
        inv = json.load(fh)
meta = load("results/registry/meta.json")
if R is not None and inv:
    from mcp_audit.model import sev_rank
    worst = {}
    for f in R:
        worst[f["server"]] = max(worst.get(f["server"], -1), sev_rank(f["severity"]))
    n = len(inv["servers"])
    levels = ["critical", "high", "medium", "low"]
    counts = [sum(1 for v in worst.values() if v == sev_rank(s)) for s in levels]
    clean = n - sum(counts)
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(9, 3.6))
    a1.barh(["none"] + levels[::-1], [clean] + counts[::-1], color=["#2e2e2e", "#555", "#9a9a9a", "#ddd", "white"], edgecolor="#ddd")
    for i, v in enumerate([clean] + counts[::-1]):
        a1.text(v + 1, i, str(v), va="center", fontsize=9)
    a1.set(title=f"{n} public servers · worst finding", xlabel="servers")
    by_rule = collections.Counter()
    for f in R:
        if sev_rank(f["severity"]) >= sev_rank("medium"):
            by_rule[f["rule"]] += 1
    rules_sorted = by_rule.most_common()
    a2.bar([r for r, _ in rules_sorted], [c for _, c in rules_sorted], color="white", edgecolor="#ddd")
    a2.set(title="medium+ findings by rule", ylabel="definitions")
    save(fig, "registry")

# README table
rows = ["| system | dev P | dev R | test P | test R | test F1 | test FPR |", "|---|---|---|---|---|---|---|"]
for n, by in systems.items():
    d, t = by.get("dev", {}), by["test"]
    dev = f"{d['precision']:.3f} | {d['recall']:.3f}" if d else "– | –"
    rows.append(f"| {n} | {dev} | {t['precision']:.3f} | {t['recall']:.3f} | {t['f1']:.3f} | {t['fpr']:.3f} |")
readme = Path("README.md")
if readme.exists() and "<!-- results -->" in readme.read_text():
    txt = re.sub(r"<!-- results -->.*?<!-- /results -->", "<!-- results -->\n" + "\n".join(rows) + "\n<!-- /results -->", readme.read_text(), flags=re.S)
    readme.write_text(txt)
print("\n".join(rows))
