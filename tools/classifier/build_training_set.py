#!/usr/bin/env python3
"""
Build the training set for the Ingress classifier from public, licensed data.

    python tools/classifier/build_training_set.py <out-dir> --exclude <eval-dir> [--exclude <eval-dir> ...]

Writes <out-dir>/train.jsonl with {"text", "label", "source"} per line, and prints counts only (never text:
half of this data is attacks).

What keeps the scores honest:
  - Every text in the --exclude folders (the PINT-style sets and both email samples) is removed by exact match
    after whitespace and case folding.
  - LLMail-Inject is a competition: teams resubmitted near-copies of their own attacks. Exact matching would let
    those through, so every TEAM with a message in an excluded email sample is removed from training entirely.
  - Only the training splits of sets whose test splits are used for scoring are read.

Sources (license): microsoft/llmail-inject-challenge (MIT), reshabhs/SPML_Chatbot_Prompt_Injection (MIT),
rikka-snow/prompt-injection-multilingual train (MIT), deepset/prompt-injections train (Apache-2.0),
jackhhao/jailbreak-classification train (Apache-2.0), Lakera/gandalf_ignore_instructions train (MIT),
corbt/enron-emails (public record), OpenAssistant/oasst1 (Apache-2.0), databricks/databricks-dolly-15k (CC BY-SA 3.0).
"""
import argparse
import glob
import hashlib
import json
import os
import random
import re
import sys
import time
import urllib.request

import pandas as pd

HF = "https://huggingface.co/datasets/{repo}/resolve/refs%2Fconvert%2Fparquet/{config}/{split}/{n:04d}.parquet"


def fetch(repo, split, n=0, config="default", cache="."):
    path = os.path.join(cache, f"{repo.replace('/', '__')}__{config}__{split}__{n:04d}.parquet")
    if not os.path.exists(path):
        url = HF.format(repo=repo, config=config, split=split, n=n)
        for attempt in range(5):
            try:
                req = urllib.request.Request(url, headers={"user-agent": "acepaste-ingress-train"})
                with urllib.request.urlopen(req, timeout=300) as r, open(path + ".part", "wb") as f:
                    while chunk := r.read(1 << 20):
                        f.write(chunk)
                os.replace(path + ".part", path)
                break
            except Exception as e:  # noqa: BLE001
                if attempt == 4:
                    raise RuntimeError(f"{url}: {e}") from e
                time.sleep(5 * (attempt + 1))
    return pd.read_parquet(path)


# stand-in addresses of every shape, so neither a name nor an ending becomes the tell
TRAIN_ADDRESSES = ["billing@northwind-supplies.example", "j.ortega@lakeshorepartners.com", "accounts@fabrikam.com", "desk@harbor-office.org", "m.chen@riverbend-group.net", "it-help@tailspintoys.com", "records@alpine-ledger.co.uk", "team@quartzline.io", "noreply@bluefern-mail.example", "p.novak@meridian-works.de", "archive@stonebridge-data.example.org", "ops@cedarandpine.com", "sara.k@contoso.com", "office@litware.net", "h.tanaka@proseware.jp", "info@wingtiptoys.fr"]
TRAIN_WORDS = ["acknowledged", "received", "done", "approved", "ok", "verified", "complete", "noted", "accepted", "ready", "sent", "understood"]


def deartifact(text, rng):
    """
    LLMail-Inject was a game with one goal: get the assistant to send the word "confirmation" to
    contact@contact.com. A model trained on it as is learns the address and the word, not the attack.
    Each message gets its own stand-in address, and usually its own stand-in word.
    """
    addr = rng.choice(TRAIN_ADDRESSES)
    text = re.sub(r"contact\s*(?:@|\[at\]|\(at\)| at )\s*contact\s*(?:\.|\[dot\]|\(dot\)| dot )\s*com", addr, text, flags=re.I)
    if rng.random() < 0.8:
        word = rng.choice(TRAIN_WORDS)
        text = re.sub(r"\bconfirmation\b", word, text, flags=re.I)
    return text


def norm(t):
    return re.sub(r"\s+", " ", str(t or "")).strip().lower()


def h(t):
    return hashlib.sha1(norm(t).encode("utf-8", "replace")).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--exclude", action="append", default=[])
    ap.add_argument("--benign", action="append", default=[], help="a JSON Lines file whose rows with label false are added as benign text (a development half of a public set: ordinary text messages)")
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    cache = os.path.join(a.out, "cache")
    os.makedirs(cache, exist_ok=True)
    rng = random.Random(a.seed)

    # ---- everything used for scoring ----
    held = set()
    held_email_bodies = set()
    for d in a.exclude:
        for f in glob.glob(os.path.join(d, "*.jsonl")):
            with open(f, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if not line.strip():
                        continue
                    r = json.loads(line)
                    for k in ("text", "body", "raw"):
                        if isinstance(r.get(k), str) and r[k].strip():
                            held.add(h(r[k]))
                    if isinstance(r.get("body"), str):
                        held.add(h((r.get("subject") or "") + "\n" + r["body"]))
                        if r.get("label") is True:
                            held_email_bodies.add(h(r["body"]))
    print(f"held-out texts to exclude: {len(held)} ({len(held_email_bodies)} attack emails)")

    rows = []

    def add(texts, label, source, cap=None):
        seen, kept = set(), []
        for t in texts:
            if not isinstance(t, str):
                continue
            t = t.strip()
            if len(t) < 12:
                continue
            k = h(t)
            if k in held or k in seen:
                continue
            seen.add(k)
            kept.append(t[:6000])
        if cap and len(kept) > cap:
            kept = rng.sample(kept, cap)
        rows.extend({"text": t, "label": label, "source": source} for t in kept)
        print(f"  {source:<34} {'attack' if label else 'benign':<7} {len(kept):>6}")

    # ---- attacks ----
    for phase, files in (("Phase1", 3), ("Phase2", 1)):
        df = pd.concat([fetch("microsoft/llmail-inject-challenge", phase, n, cache=cache) for n in range(files)], ignore_index=True)
        df["bh"] = df["body"].map(h)
        banned_teams = set(df.loc[df["bh"].isin(held_email_bodies), "team_id"])
        keep = df[~df["team_id"].isin(banned_teams)]
        print(f"llmail {phase}: {len(df)} rows, {df['team_id'].nunique()} teams; {len(banned_teams)} teams are in the scoring samples and are left out; {len(keep)} rows remain")
        # at most 40 messages per team, so a few prolific teams do not become the whole class
        keep = keep.groupby("team_id", group_keys=False).apply(lambda g: g.sample(min(len(g), 40), random_state=a.seed))
        add((deartifact((s or "") + "\n" + (b or ""), rng) for s, b in zip(keep["subject"], keep["body"])), True, f"llmail-inject {phase}", cap=9000)

    spml = fetch("reshabhs/SPML_Chatbot_Prompt_Injection", "train", cache=cache)
    add(spml.loc[spml["Prompt injection"] == 1, "User Prompt"], True, "SPML", cap=8000)
    add(spml.loc[spml["Prompt injection"] == 0, "User Prompt"], False, "SPML", cap=4000)

    rk = fetch("rikka-snow/prompt-injection-multilingual", "train", cache=cache)
    add(rk.loc[rk["label"] == 1, "text"], True, "multilingual (train)")
    add(rk.loc[rk["label"] == 0, "text"], False, "multilingual (train)")

    ds = fetch("deepset/prompt-injections", "train", cache=cache)
    add(ds.loc[ds["label"] == 1, "text"], True, "deepset (train)")
    add(ds.loc[ds["label"] == 0, "text"], False, "deepset (train)")

    jb = fetch("jackhhao/jailbreak-classification", "train", cache=cache)
    add(jb.loc[jb["type"] == "jailbreak", "prompt"], True, "jailbreak-classification (train)")
    add(jb.loc[jb["type"] != "jailbreak", "prompt"], False, "jailbreak-classification (train)")

    gd = fetch("Lakera/gandalf_ignore_instructions", "train", cache=cache)
    add(gd["text"], True, "gandalf (train)")

    # ---- benign ----
    en = pd.concat([fetch("corbt/enron-emails", "train", n, cache=cache) for n in range(3)], ignore_index=True)
    en = en.sample(40000, random_state=a.seed)
    add(((s or "") + "\n" + (b or "") for s, b in zip(en["subject"], en["body"])), False, "enron", cap=12000)

    oa = fetch("OpenAssistant/oasst1", "train", cache=cache)
    oa = oa[(oa["deleted"] == False) & (oa["review_result"] != False)]  # noqa: E712
    add(oa.loc[oa["role"] == "prompter", "text"], False, "oasst1 (what people ask)", cap=9000)
    add(oa.loc[oa["role"] == "assistant", "text"], False, "oasst1 (explanatory prose)", cap=9000)

    dl = fetch("databricks/databricks-dolly-15k", "train", cache=cache)
    add(dl["instruction"], False, "dolly (instructions)", cap=3000)
    add(dl.loc[dl["context"].str.len() > 200, "context"], False, "dolly (reference passages)", cap=3000)

    # generated hard negatives (tools/classifier/hard_negatives.py), when present beside the output
    hn = os.path.join(a.out, "hard-negatives.jsonl")
    if os.path.exists(hn):
        with open(hn, encoding="utf-8") as fh:
            gen = [json.loads(line) for line in fh if line.strip()]
        for src in sorted({r["source"] for r in gen}):
            add((r["text"] for r in gen if r["source"] == src), False, src)
    else:
        print("  (no hard-negatives.jsonl beside the output: run hard_negatives.py first to include them)")

    # ordinary text from a channel the other sources do not cover (0.9.19: text messages; the model had never
    # seen how people text, and rated one ordinary message in a hundred as an attack)
    for f in a.benign:
        with open(f, encoding="utf-8", errors="replace") as fh:
            extra = [json.loads(line) for line in fh if line.strip()]
        add((r.get("text") for r in extra if r.get("label") is False), False, os.path.basename(os.path.dirname(f)) + "/" + os.path.basename(f))

    rng.shuffle(rows)
    out = os.path.join(a.out, "train.jsonl")
    with open(out, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    pos = sum(1 for r in rows if r["label"])
    print(f"\n{out}: {len(rows)} rows, {pos} attacks, {len(rows) - pos} benign")


if __name__ == "__main__":
    sys.exit(main())
