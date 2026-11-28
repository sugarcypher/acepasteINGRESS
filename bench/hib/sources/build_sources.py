#!/usr/bin/env python3
"""Build bench/hib/sources/upstream_payloads.json from the upstream benchmark files.

Payload text comes from two independent, MIT-licensed benchmarks (see ../NOTICE.md):
  * BIPIA (microsoft/BIPIA): benchmark/text_attack_test.json and benchmark/code_attack_test.json
  * InjecAgent (uiuc-kang-lab/InjecAgent): data/test_cases_{dh,ds}_base.json, unique "Attacker Instruction"
    strings, plus InjecAgent's own "enhanced" prefix (taken from data/test_cases_dh_enhanced.json).

  python3 build_sources.py <raw-dir>

<raw-dir> holds the upstream files under these names (same names as tools/eval-0.10.0 on branch eval/0.10.0):
  bipia_text_attack_test.json, bipia_code_attack_test.json,
  injecagent_test_cases_dh_base.json, injecagent_test_cases_ds_base.json, injecagent_test_cases_dh_enhanced.json
Their sha256 are written into the output so anyone can check they built from the same upstream bytes.
Nothing from AcePaste Ingress's own corpus is used.
"""
import hashlib, json, os, sys

raw = sys.argv[1]
here = os.path.dirname(os.path.abspath(__file__))
def sha(p): return hashlib.sha256(open(p, "rb").read()).hexdigest()
files = {
    "bipia_text_attack_test.json": "https://github.com/microsoft/BIPIA/blob/main/benchmark/text_attack_test.json",
    "bipia_code_attack_test.json": "https://github.com/microsoft/BIPIA/blob/main/benchmark/code_attack_test.json",
    "injecagent_test_cases_dh_base.json": "https://github.com/uiuc-kang-lab/InjecAgent/blob/main/data/test_cases_dh_base.json",
    "injecagent_test_cases_ds_base.json": "https://github.com/uiuc-kang-lab/InjecAgent/blob/main/data/test_cases_ds_base.json",
    "injecagent_test_cases_dh_enhanced.json": "https://github.com/uiuc-kang-lab/InjecAgent/blob/main/data/test_cases_dh_enhanced.json",
}
payloads = []
for cat, items in json.load(open(f"{raw}/bipia_text_attack_test.json")).items():
    for i, t in enumerate(items):
        payloads.append({"source": "bipia_text", "upstream_category": cat, "text": t})
for cat, items in json.load(open(f"{raw}/bipia_code_attack_test.json")).items():
    for i, t in enumerate(items):
        payloads.append({"source": "bipia_code", "upstream_category": cat, "text": t})
seen = set()
for f, kind in (("dh_base", "direct_harm"), ("ds_base", "data_stealing")):
    for r in json.load(open(f"{raw}/injecagent_test_cases_{f}.json")):
        t = r["Attacker Instruction"]
        if t in seen: continue
        seen.add(t)
        payloads.append({"source": "injecagent", "upstream_category": kind, "text": t})

# InjecAgent's enhanced setting prefixes the attacker instruction with a fixed string; read it from the upstream file
enh = json.load(open(f"{raw}/injecagent_test_cases_dh_enhanced.json"))[0]
resp, instr = enh["Tool Response"], enh["Attacker Instruction"]
end = resp.index(instr)
start = resp.rindex("IMPORTANT", 0, end)
prefix = resp[start:end]
assert prefix.startswith("IMPORTANT!!!"), "unexpected InjecAgent enhanced format"

out = {
    "about": "Attack instructions from BIPIA (MIT, Copyright (c) Microsoft Corporation) and InjecAgent (MIT, Copyright (c) 2023 Qiusi Zhan). Built by build_sources.py; see NOTICE.md.",
    "upstream": [{"file": f, "url": u, "sha256": sha(f"{raw}/{f}")} for f, u in files.items()],
    "injecagent_enhanced_prefix": prefix,
    "payloads": payloads,
}
json.dump(out, open(os.path.join(here, "upstream_payloads.json"), "w"), ensure_ascii=False, indent=1)
from collections import Counter
print(Counter(p["source"] for p in payloads), "enhanced prefix:", repr(prefix))
