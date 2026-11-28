#!/usr/bin/env python3
"""Build PINT-format JSON Lines sets from BIPIA (microsoft/BIPIA, MIT) and InjecAgent
(uiuc-kang-lab/InjecAgent, MIT) for scoring with Ingress's text scan. Prints counts only.

  python3 build-indirect-sets.py <raw-dir> <out-dir>

BIPIA: every test context as-is (benign), and every context x every test attack inserted with
BIPIA's own insert_start / insert_end ("\n".join). insert_middle needs NLTK's Punkt splitter and is
not built here. Text attacks go into email and table contexts; code attacks into code contexts,
as in BIPIA. The bare attack strings are also emitted as their own set.
InjecAgent: the "Tool Response" of every test case (dh/ds x base/enhanced) is an attack. The 17 user
cases' tool-response templates with the <Attacker Instruction> placeholder replaced by an empty
string are a small benign control of the same JSON scaffolding (constructed here, not part of InjecAgent).
"""
import json, sys, os

raw, out = sys.argv[1], sys.argv[2]
os.makedirs(out, exist_ok=True)

def jl(p): return [json.loads(l) for l in open(p, encoding="utf-8") if l.strip()]
def write(name, rows, source):
    with open(os.path.join(out, name), "w", encoding="utf-8") as f:
        for r in rows: f.write(json.dumps({**r, "source": source}, ensure_ascii=False) + "\n")
    pos = sum(1 for r in rows if r["label"])
    print(f"{name:34} {len(rows):6} rows  {pos} attacks / {len(rows)-pos} benign")

def flat(d): return [a for v in d.values() for a in v]
text_atk = flat(json.load(open(f"{raw}/bipia_text_attack_test.json")))
code_atk = flat(json.load(open(f"{raw}/bipia_code_attack_test.json")))

def ctx_of(task, r):
    if task == "code":
        # BIPIA code task context: the retrieved answer text (list or str)
        c = r["context"]
        return "\n".join(c) if isinstance(c, list) else str(c)
    return str(r["context"])

for task, atks in (("email", text_atk), ("table", text_atk), ("code", code_atk)):
    ctxs = [ctx_of(task, r) for r in jl(f"{raw}/bipia_{task}_test.jsonl")]
    rows = [{"text": c, "label": False, "category": f"bipia_{task}_benign"} for c in ctxs]
    for c in ctxs:
        for a in atks:
            rows.append({"text": "\n".join([a, c]), "label": True, "category": f"bipia_{task}_attack_start"})
            rows.append({"text": "\n".join([c, a]), "label": True, "category": f"bipia_{task}_attack_end"})
    write(f"bipia-{task}.jsonl", rows, f"microsoft/BIPIA benchmark/{task}/test.jsonl x {'text' if task!='code' else 'code'}_attack_test.json")

write("bipia-attack-strings.jsonl",
      [{"text": a, "label": True, "category": "bipia_text_attack_bare"} for a in text_atk] +
      [{"text": a, "label": True, "category": "bipia_code_attack_bare"} for a in code_atk],
      "microsoft/BIPIA text_attack_test.json + code_attack_test.json (bare)")

rows = []
for f in ("dh_base", "dh_enhanced", "ds_base", "ds_enhanced"):
    for r in json.load(open(f"{raw}/injecagent_test_cases_{f}.json")):
        rows.append({"text": r["Tool Response"], "label": True, "category": f"injecagent_{f}"})
for u in jl(f"{raw}/injecagent_user_cases.jsonl"):
    rows.append({"text": u["Tool Response Template"].replace("<Attacker Instruction>", ""), "label": False, "category": "injecagent_scaffold_control"})
write("injecagent.jsonl", rows, "uiuc-kang-lab/InjecAgent data/test_cases_*.json Tool Response; control = user_cases templates, placeholder emptied")

uniq = sorted({r["Attacker Instruction"] for f in ("dh_base", "ds_base") for r in json.load(open(f"{raw}/injecagent_test_cases_{f}.json"))})
write("injecagent-attacker-instructions.jsonl", [{"text": a, "label": True, "category": "injecagent_instruction_bare"} for a in uniq],
      "uiuc-kang-lab/InjecAgent unique Attacker Instruction strings (bare)")
