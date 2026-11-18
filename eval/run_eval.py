"""Score mcp-audit on the MCPTox split.

    python eval/build_mcptox.py           # writes data/mcptox.jsonl (pinned commit, seeded split)
    python eval/run_eval.py               # static rules + keyword baseline, both splits
    python eval/run_eval.py --judge qwen2.5:3b --split test   # adds the LLM judge (cached in results/)

Rules were developed on the dev servers only; test servers were held out and scored once.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mcp_audit.model import sev_rank  # noqa: E402
from mcp_audit.rules import scan_definition  # noqa: E402

DATA = Path("data/mcptox.jsonl")
RESULTS = Path("results")
KEYWORDS = re.compile(r"<important>|ignore (?:all |previous )|~/\.ssh|id_rsa|password|do not tell|system prompt", re.I)


def load():
    rows = [json.loads(line) for line in DATA.open()]
    names = collections.defaultdict(set)
    for r in rows:
        if r["label"] == 0:
            names[r["server"]].add(r["tool"]["name"])
    return rows, names


def metrics(pairs):
    tp = sum(1 for y, p in pairs if y and p); fp = sum(1 for y, p in pairs if not y and p)
    fn = sum(1 for y, p in pairs if y and not p); tn = sum(1 for y, p in pairs if not y and not p)
    pr = tp / (tp + fp) if tp + fp else 0.0; rc = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * pr * rc / (pr + rc) if pr + rc else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": round(pr, 4), "recall": round(rc, 4), "f1": round(f1, 4),
            "fpr": round(fp / (fp + tn), 4) if fp + tn else 0.0}


def static_preds(rows, names, threshold="medium"):
    out = {}
    for r in rows:
        t = r["tool"]
        ctx = names[r["server"]] | {t["name"]}
        f = scan_definition(r["server"], "tool", t["name"], t, ctx, local_names=ctx)
        out[r["id"]] = {"pred": any(sev_rank(x.severity) >= sev_rank(threshold) for x in f),
                        "rules": sorted({x.rule for x in f if sev_rank(x.severity) >= sev_rank(threshold)}),
                        "score": max((sev_rank(x.severity) for x in f), default=-1)}
    return out


def judge_preds(rows, model):
    from mcp_audit.judge import classify
    RESULTS.mkdir(exist_ok=True)
    cache = RESULTS / f"judge_{model.replace(':', '-').replace('/', '-')}.jsonl"
    done = {}
    if cache.exists():
        for line in cache.open():
            d = json.loads(line); done[d["id"]] = d
    with cache.open("a") as fh:
        for i, r in enumerate(rows):
            if r["id"] in done:
                continue
            t0 = time.time()
            v = classify(r["tool"], model)
            d = {"id": r["id"], "pred": v["poisoned"], "rule": v.get("rule"), "reason": str(v.get("reason", ""))[:200], "secs": round(time.time() - t0, 2)}
            done[r["id"]] = d
            fh.write(json.dumps(d) + "\n"); fh.flush()
            if i % 25 == 0:
                print(f"  judge {model}: {len(done)}/{len(rows)}", file=sys.stderr)
    return done


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", choices=["dev", "test", "all"], default="all")
    ap.add_argument("--judge", action="append", default=[], help="Ollama model(s) to score as LLM judge")
    ap.add_argument("--judge-sample", type=int, default=0, help="score the judge on a seeded, label-balanced sample of this size")
    ap.add_argument("--out", default="results/metrics.json")
    a = ap.parse_args()
    rows, names = load()
    splits = ["dev", "test"] if a.split == "all" else [a.split]
    st = static_preds(rows, names)
    by_split = {s: {"clean": sum(1 for r in rows if r["split"] == s and not r["label"]),
                    "poisoned": sum(1 for r in rows if r["split"] == s and r["label"])} for s in ("dev", "test")}
    report = {"dataset": {"rows": len(rows), "servers": len({r["server"] for r in rows}), "by_split": by_split}, "systems": {}}
    pool = [r for r in rows if r["split"] in splits]
    if a.judge and a.judge_sample:
        key = lambda r: hashlib.sha256(f"mcp-audit-17:{r['id']}".encode()).hexdigest()  # noqa: E731
        pool = [r for lab in (0, 1) for r in sorted((r for r in pool if r["label"] == lab), key=key)[: a.judge_sample // 2]]
        report["judge_sample"] = len(pool)
    judged = {m: judge_preds(pool, m) for m in a.judge}
    for s in splits:
        sub = [r for r in pool if r["split"] == s] if a.judge else [r for r in rows if r["split"] == s]
        systems = {
            "keyword baseline": [(r["label"], bool(KEYWORDS.search(json.dumps(r["tool"])))) for r in sub],
            "mcp-audit static": [(r["label"], st[r["id"]]["pred"]) for r in sub],
        }
        for m, j in judged.items():
            systems[f"LLM judge ({m})"] = [(r["label"], j[r["id"]]["pred"]) for r in sub]
            systems[f"static OR judge ({m})"] = [(r["label"], st[r["id"]]["pred"] or j[r["id"]]["pred"]) for r in sub]
            systems[f"static AND judge ({m})"] = [(r["label"], st[r["id"]]["pred"] and j[r["id"]]["pred"]) for r in sub]
        for name, pairs in systems.items():
            report["systems"].setdefault(name, {})[s] = metrics(pairs)
        groups = collections.defaultdict(list)
        for r in sub:
            if r["label"]:
                groups[r["paradigm"]].append((1, st[r["id"]]["pred"]))
        report.setdefault("recall_by_paradigm", {})[s] = {k: metrics(v)["recall"] for k, v in sorted(groups.items())}
        rule_counts = collections.Counter(rule for r in sub if r["label"] for rule in st[r["id"]]["rules"])
        report.setdefault("rule_hits_poisoned", {})[s] = dict(rule_counts.most_common())
        thr = {}
        for t in ("low", "medium", "high", "critical"):
            thr[t] = metrics([(r["label"], st[r["id"]]["score"] >= sev_rank(t)) for r in sub])
        report.setdefault("static_by_threshold", {})[s] = thr
    Path(a.out).parent.mkdir(exist_ok=True)
    Path(a.out).write_text(json.dumps(report, indent=2) + "\n")
    preds = RESULTS / "static_predictions.jsonl"
    with preds.open("w") as fh:
        for r in rows:
            fh.write(json.dumps({"id": r["id"], "split": r["split"], "label": r["label"], **st[r["id"]]}) + "\n")
    w = max(len(n) for n in report["systems"])
    print(f"{'system':<{w}}  split  precision  recall    F1   FPR")
    for n, by in report["systems"].items():
        for s, m in by.items():
            print(f"{n:<{w}}  {s:<5}  {m['precision']:>9.3f}  {m['recall']:>6.3f}  {m['f1']:.3f}  {m['fpr']:.3f}")


if __name__ == "__main__":
    main()
