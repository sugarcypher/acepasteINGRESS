#!/usr/bin/env python3
"""HIB report: detection rate and false-positive rate with Wilson 95% intervals, overall and by technique,
carrier and payload source, for any number of verdict files.

  python3 bench/hib/score/report.py --split public [--data bench/hib/data] \
      --defense "Ingress 0.10.0=results/ingress-0.10.0-public.jsonl" --defense "regex=results/regex-public.jsonl" ...

A verdict file is JSON Lines with at least {"id": ..., "flagged": true|false}. An item with no verdict counts as not
flagged and is reported as missing. Writes results/report-<split>.md and results/summary-<split>.json.
"""
import argparse, json, math, os
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def wilson(k, n, z=1.959963984540054):
    if n == 0: return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))

def fmt(k, n):
    if n == 0: return "n/a"
    lo, hi = wilson(k, n)
    return f"{100 * k / n:.1f}% ({k}/{n}; {100 * lo:.1f}-{100 * hi:.1f})"

def cell(k, n):
    return {"k": k, "n": n, "rate": (k / n if n else None), "wilson95": list(wilson(k, n)) if n else None}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", required=True)
    ap.add_argument("--data", default=os.path.join(ROOT, "data"))
    ap.add_argument("--defense", action="append", required=True, help="NAME=verdicts.jsonl")
    a = ap.parse_args()
    rows = [json.loads(l) for l in open(os.path.join(a.data, a.split, "manifest.jsonl"), encoding="utf-8")]
    defs = []
    for d in a.defense:
        name, path = d.split("=", 1)
        path = path if os.path.isabs(path) else os.path.join(ROOT, path)
        v = {}
        for l in open(path, encoding="utf-8"):
            if l.strip():
                x = json.loads(l); v[x["id"]] = x
        defs.append((name, v))
    summary = {"split": a.split, "items": len(rows), "attack": sum(r["label"] == "attack" for r in rows),
               "benign": sum(r["label"] == "benign" for r in rows), "defenses": {}}
    md = [f"# HIB results, split `{a.split}`", "", f"{summary['items']} items: {summary['attack']} attack, {summary['benign']} benign. "
          "Detection = attack items flagged; FP = benign items flagged. Cells: rate (k/n; Wilson 95% interval, %).", ""]
    groups = [("technique", "technique"), ("carrier", "carrier"), ("payload source", "payload_source")]
    for name, v in defs:
        D = {"missing": sum(r["id"] not in v for r in rows)}
        tiers = defaultdict(int)
        for r in rows:
            if r["id"] in v: tiers[str(v[r["id"]].get("tier", "-"))] += 1
        D["tiers"] = dict(tiers)
        f = lambda r: bool(v.get(r["id"], {}).get("flagged"))
        atk = [r for r in rows if r["label"] == "attack"]; ben = [r for r in rows if r["label"] == "benign"]
        D["overall"] = {"detection": cell(sum(map(f, atk)), len(atk)), "fp": cell(sum(map(f, ben)), len(ben))}
        # hidden-only: drop the visible control and visible-but-obfuscated techniques
        hid = [r for r in atk if r["human_visible"] not in ("yes", "obfuscated")]
        D["overall"]["detection_hidden_only"] = cell(sum(map(f, hid)), len(hid))
        for gname, key in groups:
            g = defaultdict(lambda: [0, 0, 0, 0])
            for r in rows:
                k = r.get(key) or "-"
                if key == "payload_source" and r["label"] != "attack": continue
                i = 0 if r["label"] == "attack" else 2
                g[k][i] += f(r); g[k][i + 1] += 1
            D[gname] = {k: {"detection": cell(x[0], x[1]), "fp": cell(x[2], x[3])} for k, x in sorted(g.items())}
        summary["defenses"][name] = D
    # markdown: overall table, then per group with one column per defense
    md += ["## Overall", "", "| defense | detection (all attacks) | detection (hidden payloads only) | false positives |", "|---|---|---|---|"]
    for name, _ in defs:
        o = summary["defenses"][name]["overall"]
        md.append(f"| {name} | {fmt(o['detection']['k'], o['detection']['n'])} | {fmt(o['detection_hidden_only']['k'], o['detection_hidden_only']['n'])} | {fmt(o['fp']['k'], o['fp']['n'])} |")
    md.append("")
    for gname, _ in groups:
        md += [f"## By {gname}", "", "| " + gname + " | " + " | ".join(f"{n}: detection | {n}: FP" if gname != "payload source" else f"{n}: detection" for n, _ in defs) + " |",
               "|---|" + "|".join(["---|---"] * len(defs) if gname != "payload source" else ["---"] * len(defs)) + "|"]
        keys = list(summary["defenses"][defs[0][0]][gname].keys())
        for k in keys:
            cells = []
            for n, _ in defs:
                c = summary["defenses"][n][gname][k]
                cells.append(fmt(c["detection"]["k"], c["detection"]["n"]))
                if gname != "payload source": cells.append(fmt(c["fp"]["k"], c["fp"]["n"]))
            md.append(f"| {k} | " + " | ".join(cells) + " |")
        md.append("")
    md += ["## Verdict tiers", ""] + [f"- {n}: " + ", ".join(f"{t} {c}" for t, c in sorted(summary['defenses'][n]['tiers'].items())) + f"; missing {summary['defenses'][n]['missing']}" for n, _ in defs] + [""]
    os.makedirs(os.path.join(ROOT, "results"), exist_ok=True)
    open(os.path.join(ROOT, "results", f"report-{a.split}.md"), "w").write("\n".join(md))
    json.dump(summary, open(os.path.join(ROOT, "results", f"summary-{a.split}.json"), "w"), indent=1)
    print("\n".join(md[:12]))

if __name__ == "__main__":
    main()
