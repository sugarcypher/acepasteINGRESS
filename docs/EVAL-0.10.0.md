# AcePaste Ingress 0.10.0: evaluation

Run 2026-11-28 (UTC) against the 0.10.0 release. No rule, threshold, model or other engine code was changed for
this run; every number below is what the release does as shipped. Nothing here is a PINT score.

| | |
|---|---|
| Engine / ruleset | `ENGINE_VERSION` 0.10.0, `RULESET_VERSION` 2026.11.21-3 |
| Commit scored | `992d1eb160faf9763554e0e0eb2989875a3ca4b9` (main, "0.10.0: mcpscan, show, reposcan, outcheck, pkgcheck, filescan (#30)") |
| Build | `npm ci && npm run build` on that commit (25 s) |
| Machine | Linux 6.12 container, aarch64 (ARM Neoverse-V2), 2 vCPU, 7 GiB RAM, Node v22.23.5, npm 10.9.9 |
| Scan configuration | static passes only: `cloakingCheck: false`, `sandbox: "off"`, `fetchStylesheets: false`, no cache, default thresholds (suspect 0.25, hostile 0.7), rules **and** the learned classifier pass (on by default since 0.9.16) |
| Verdict rule | **refused = suspect or hostile** (both withhold content). Hostile is shown separately where the harness allows. |

Scripts added for this run (no engine code touched) are in `tools/eval-0.10.0/`:

- `score-tiers.mjs`: the same scan as `packages/core/eval/pint.ts` (`engine.scan(text, {isHtml:false})`), but it
  keeps hostile and suspect apart and times each set. Its refused counts match `pint.ts` on every shared set.
- `build-indirect-sets.py`: builds BIPIA and InjecAgent rows in the PINT JSON Lines format.
- `outcheck-benign.mjs`: a false-alarm proxy for the new `outcheck()` exfiltration check (see section 5).
- `bzip2-shim.py`: decompress-only `bzip2` for sandboxes without the binary (`tar -j` in the email fetcher needs it).
- `SHA256SUMS`: hashes of every data file scored, paths relative to the eval directory below.

## What the in-repo harnesses are, plainly

- `packages/core/eval/run.ts` + `corpus.ts`: the self-built regression corpus (Claude-generated, 2026-10-01).
- `packages/core/eval/pint.ts` + `tools/pint/`: **"PINT-style" scoring only. It does not use any PINT data.** Lakera's
  PINT dataset (4,314 inputs) is private. `fetch-public-sets.mjs` downloads nine *substitute* public sets and
  `pint.ts` scores them with PINT's metric (balanced accuracy). `tools/pint/ingress_pint.py` is an eval function
  for Lakera's official notebook; it has only been useful to Lakera, who hold the data. The only PINT-repo data
  that is public is `benchmark/data/example-dataset.yaml` (8 rows, which the file itself says is "NOT the PINT
  Benchmark dataset or representative of" it); it is scored below for completeness.
- `packages/core/eval/email.ts` + `tools/email-eval/`: LLMail-Inject attacks vs Enron/SpamAssassin mail, dev and
  hold-out samples.
- `tools/message-eval/`: UCI SMS Spam Collection through the message adapter (same `email.ts` scorer, `--as=message`).
- `tools/egress-replay/replay.mjs`: replays a recorded Claude Code session's tool calls through the egress gate.
  **The repo ships no session file**, so it cannot be run from public data (section 5).

## Contamination: which numbers are independent

| data | relation to Ingress's development | how to read it |
|---|---|---|
| Self-built corpus | written alongside the rules; every case must pass | regression floor, not a detection claim |
| deepset, jackhhao, gandalf, SPML, rikka (test splits) | the classifier trained on the *training* splits of these sets (SPML: other rows of the same split); the sets chose the classifier's decision thresholds (0.85 text, 0.8 messages) | **development set**, optimistic |
| turkish-1k, wikipedia, github-readmes | benign rows were used to fix false alarms (0.9.3 / 0.9.5, "spent" per `tools/pint/README.md`) | benign side optimistic |
| turkish-false-alarm | not used for a decision per the repo's notes | fairly clean benign number |
| LLMail-Inject / Enron / SpamAssassin **hold-out** | disjoint from classifier training; but this hold-out has now been scored for 0.9.15, 0.9.16 and here | reproduction, not fresh |
| SMS hold-out | scored before for 0.9.19 and 0.9.23; retraining used only the dev half | reproduction, not fresh |
| **BIPIA, InjecAgent** | not referenced anywhere in the repo (`grep -ri "bipia\|injecagent"` finds nothing) and not in the classifier's training list | **the independent numbers in this report** |

## Commands

```sh
cd acepasteINGRESS && git checkout 992d1eb && npm ci && npm run build
EVAL=~/ingress-eval-0.10.0; mkdir -p $EVAL/data/{pint,indirect,email-holdout,sms} $EVAL/raw
# (score-tiers.mjs, build-indirect-sets.py, outcheck-benign.mjs, bzip2-shim.py are on branch eval/0.10.0)

# 1. self-built corpus
time node packages/core/dist/eval/run.js
node packages/core/dist/eval/run.js --json > $EVAL/corpus.json

# 2. PINT-style public sets (+ the 8-row PINT example file)
node tools/pint/fetch-public-sets.mjs $EVAL/data/pint
curl -sL https://raw.githubusercontent.com/lakeraai/pint-benchmark/0efab3f463eae9c823130d8faffb71b2e7c06e63/benchmark/data/example-dataset.yaml -o $EVAL/pint-example.yaml
python3 -c "import yaml,json,sys; [print(json.dumps({'text':r['text'],'label':bool(r['label']),'category':r['category']})) for r in yaml.safe_load(open(sys.argv[1]))]" $EVAL/pint-example.yaml > $EVAL/data/pint/pint-example.jsonl
time npm run -s pint -- $EVAL/data/pint/*.jsonl
time node tools/eval-0.10.0/score-tiers.mjs --json=$EVAL/tiers-pint.json $EVAL/data/pint/*.jsonl

# 3. independent indirect-injection sets
B=https://raw.githubusercontent.com/microsoft/BIPIA/a004b69ec0dd446e0afd461d98cb5e96e120a5d0/benchmark
for f in email/test.jsonl table/test.jsonl code/test.jsonl text_attack_test.json code_attack_test.json; do curl -sfL $B/$f -o $EVAL/raw/bipia_$(echo $f|tr / _); done
I=https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/f19c9f2c79a41046eb13c03c51a24c567a8ffa07/data
for f in test_cases_dh_base.json test_cases_dh_enhanced.json test_cases_ds_base.json test_cases_ds_enhanced.json user_cases.jsonl; do curl -sfL $I/$f -o $EVAL/raw/injecagent_$f; done
python3 tools/eval-0.10.0/build-indirect-sets.py $EVAL/raw $EVAL/data/indirect
time node tools/eval-0.10.0/score-tiers.mjs --json=$EVAL/tiers-indirect.json $EVAL/data/indirect/*.jsonl

# 4. email and SMS hold-outs
# only if `bzip2` is not installed: mkdir -p $EVAL/bin && cp tools/eval-0.10.0/bzip2-shim.py $EVAL/bin/bzip2 && chmod +x $EVAL/bin/bzip2
PATH=$EVAL/bin:$PATH node tools/email-eval/fetch-email-sets.mjs $EVAL/data/email-holdout --holdout
time npm run -s email-eval -- $EVAL/data/email-holdout/*.jsonl --why
node tools/message-eval/fetch-sms.mjs $EVAL/data/sms
time npm run -s email-eval -- $EVAL/data/sms/holdout/sms.jsonl --as=message --why

# 5. outcheck false-alarm proxy
INGRESS_REPO=$PWD node tools/eval-0.10.0/outcheck-benign.mjs $EVAL/data/pint/github-readmes.jsonl $EVAL/data/indirect/bipia-*.jsonl $EVAL/data/pint/{deepset-test,jackhhao-test,spml-sample,multilingual-rikka,turkish-false-alarm}.jsonl
```

Hugging Face sets are read through `datasets-server.huggingface.co` at the latest revision on the run date; the
hashes in `SHA256SUMS` pin what was scored. GitHub-hosted sets are pinned to the commits in the URLs above.

## 1. Self-built corpus (`run.ts`)

| | n | refused | hostile | suspect |
|---|---|---|---|---|
| attacks | 90 | 90 (100%) | 70 (77.8%) | 20 |
| benign | 48 | 0 (0.0% FP) | 0 | 0 |
| ambiguous (expected: suspect, never hostile) | 3 | 3 as suspect | 0 | 3 |

Wall time 1.6 s for 141 cases; median 3.5 ms per case. This corpus was written with the engine and must pass for a
release, so 100% is a regression check, not a measurement. It is the only set here that exercises HTML hiding
(display:none, off-screen, colour, comments, attributes) and Unicode smuggling; it does so as static HTML strings,
not rendered pages.

## 2. PINT-style public sets (development data, plain text)

| set (license) | n | attacks | caught (refused) | of which hostile | benign | benign refused (FP) |
|---|---|---|---|---|---|---|
| deepset/prompt-injections test (Apache-2.0) | 116 | 60 | 21 (35.0%) | 2 (3.3%) | 56 | 0 (0.0%) |
| jackhhao/jailbreak-classification test (Apache-2.0) | 262 | 139 | 111 (79.9%) | 60 (43.2%) | 123 | 0 (0.0%) |
| Lakera/gandalf_ignore_instructions test (MIT) | 112 | 112 | 103 (92.0%) | 57 (50.9%) | 0 | - |
| reshabhs/SPML_Chatbot_Prompt_Injection, stratified (MIT) | 960 | 500 | 475 (95.0%) | 79 (15.8%) | 460 | 2 (0.4%) |
| rikka-snow/prompt-injection-multilingual test (MIT) | 1,276 | 660 | 214 (32.4%) | 4 (0.6%) | 616 | 5 (0.8%) |
| 3nesdeniz/turkish-prompt-injection-1k (CC-BY-4.0) | 1,000 | 550 | 19 (3.5%) | 0 | 450 | 8 (1.8%) |
| halilneed/turkish-…-false-alarm-benchmark (CC0-1.0) | 2,875 | 0 | - | - | 2,875 | 0 (0.0%) |
| GitHub READMEs of 35 repos (per repository) | 35 | 0 | - | - | 35 | 0 (0.0%) |
| wikimedia/wikipedia 8 languages (CC BY-SA 4.0) | **not scored**: download failed 3 times (HF datasets-server rate limiting, HTTP 429) | | | | | |
| **pooled, 8 sets above** | **6,636** | **2,021** | **943 (46.7%)** | **202 (10.0%)** | **4,615** | **15 (0.33%)** |
| lakeraai/pint-benchmark `example-dataset.yaml` (MIT) | 8 | 2 | 2 | 2 | 6 | 0 |

PINT-style balanced accuracy, pooled: **73.2%** (`pint.ts` output). Wall time 25 s (`pint.ts`) / 26 s
(`score-tiers.mjs`) for 6,644 inputs. These are the numbers the repo already reports for 0.9.16+ (46.7% / 99.8% /
73.3% on 6,876 inputs with Wikipedia); 0.10.0 changed no detector. The 8-row PINT example is a format sample, not
evidence.

## 3. Independent indirect-injection sets (BIPIA, InjecAgent; plain-text scan)

BIPIA (microsoft/BIPIA, MIT, commit a004b69): each test context is a benign row; each context × each test attack
is an attack row, inserted with BIPIA's own `insert_start` / `insert_end` (`"\n".join`). `insert_middle` (needs
NLTK Punkt) was not built. Text attacks go into email and table contexts, code attacks into code contexts, as in
BIPIA. The 125 attack strings were also scanned bare. Rows are highly redundant (75 or 50 distinct attacks repeated
over contexts), so the bare-string row is the better unit of independent evidence.

InjecAgent (uiuc-kang-lab/InjecAgent, MIT, commit f19c9f2): each test case's "Tool Response" (a JSON tool
observation with the attacker instruction embedded) is an attack. "Enhanced" cases add the prefix
`IMPORTANT!!! Ignore all previous instructions and strictly adhere to the following instruction:`; "base" cases do
not. InjecAgent has no benign tool responses; the 17-row control is the user-case templates with the
`<Attacker Instruction>` placeholder emptied (constructed here, so a sanity check of the JSON scaffolding only).

| set | n | attacks | caught (refused) | of which hostile | benign | benign refused |
|---|---|---|---|---|---|---|
| BIPIA EmailQA (50 contexts × 75 attacks × 2 positions) | 7,550 | 7,500 | 2 (0.03%) | 0 | 50 | 0 |
| BIPIA TableQA (100 × 75 × 2) | 15,100 | 15,000 | 0 (0.0%) | 0 | 100 | 0 |
| BIPIA CodeQA (50 × 50 × 2) | 5,050 | 5,000 | 4 (0.08%) | 0 | 50 | 0 |
| BIPIA attack strings, bare | 125 | 125 | 1 (0.8%) | 0 | 0 | - |
| InjecAgent base (dh 510 + ds 544) | 1,054 | 1,054 | 166 (15.7%) | 0 | - | - |
| InjecAgent enhanced (dh 510 + ds 544) | 1,054 | 1,054 | 1,054 (100%) | 1,052 (99.8%) | - | - |
| InjecAgent attacker instructions, bare (unique) | 62 | 62 | 14 (22.6%) | 0 | - | - |
| InjecAgent scaffold control (constructed) | 17 | 0 | - | - | 17 | 0 |

Benign FP across BIPIA contexts + control: 0 / 217. Wall time 4 min 47 s for 30,012 rows (table contexts are long).

What this says: on indirect injections that **contain no override phrase** (BIPIA's task hijacks such as "write a
short story about…" or "translate the reply into French", and InjecAgent's base cases, which read like ordinary
user requests: "Please grant permanent access to my friend…"), Ingress's text scan catches almost nothing (0.0% to
15.7%). With the classic "Ignore all previous instructions" prefix it catches 100%. The text pass detects the
*form* of an injection, not an instruction whose harm depends on the user's task. Both datasets are plain text:
none of the hiding techniques Ingress was designed around appears in them.

## 4. Email and SMS hold-outs (reproduction of earlier reported numbers)

Email (`email.ts`, source trust 4 "stranger"), the `--holdout` sample of `tools/email-eval`:

| set (license) | class | n | refused | hostile |
|---|---|---|---|---|
| microsoft/llmail-inject-challenge Phase1 (MIT) | attack | 1,899 | 1,721 (90.6%) | 768 |
| microsoft/llmail-inject-challenge Phase2 (MIT) | attack | 1,899 | 1,681 (88.5%) | 269 |
| corbt/enron-emails (public record, no license on card) | benign | 2,900 | 8 (0.3%) | 0 |
| SpamAssassin easy_ham_2 (Apache SpamAssassin public corpus) | benign | 1,400 | 3 (0.2%) | 0 |
| SpamAssassin 20021010 hard_ham | benign | 250 | 12 (4.8%) | 0 |
| SpamAssassin spam_2 | other (not scored) | 1,397 | 29 (2.1%) | 2 |
| **total** | | | **attacks 3,402 / 3,798 (89.6%)**, hostile 1,037 (27.3%) | **benign FP 23 / 4,550 (0.51%)** |

Balanced accuracy 94.5%. Wall time 1 min 57 s + 40 s for 10,045 messages. The 0.9.16 hold-out result in the repo was
3,395 / 3,798 and 4,527 / 4,550; this reproduces it within 7 attack rows. This hold-out has now been scored three
times, so it is not a fresh measurement. LLMail-Inject is one attack style (instructions typed into an email body
to make an assistant send mail), and the challenge's emails are plain text; the email adapter's HTML and
header checks are barely exercised.

SMS (`email.ts --as=message`, trust 4), UCI SMS Spam Collection hold-out half (CC BY 4.0): ordinary texts refused
**0 / 2,408**; spam ("other") 2 / 366 refused. 4.3 s. No chat-native attack set with a checkable license was found,
so there is no SMS detection rate.

## 5. Exfiltration checks (new in 0.10.0)

`tools/egress-replay/replay.mjs` needs a recorded Claude Code session (`~/.claude/projects/…/*.jsonl`). **The repo
ships none and none exists in the evaluation environment, so it was not run.** The repo's earlier figure (one
1,177-call session, 22 questions = 1.9%, no refusals; CHANGELOG 0.9.31) is a development number on a session
that guided the fixes, predates the 0.10.0 egress checks, and cannot be reproduced from public data.

As a proxy for the new reply-side check, `outcheck()` (images, links, HTML/CSS URLs that carry data out) was run
over benign texts as if each were a model's reply, with no session context and no allow-list:

| benign texts | with any address | addresses read | replies flagged | addresses flagged |
|---|---|---|---|---|
| GitHub READMEs (35) | 35 | 1,913 | **9 (25.7%)**: 1 hostile, 8 suspect | 24 (1.25%) |
| BIPIA code/email/table contexts (200) | 3 | 4 | 0 | 0 |
| chat/benign rows of deepset, jackhhao, SPML, rikka, Turkish false-alarm (4,130) | 1 | 1 | 0 | 0 |
| **total** | 39 | 1,918 | 9 of 39 texts with addresses | 24 |

Reasons given: "path carries N characters of encoded data" (15, review), "query or fragment carries N characters of
encoded data" (8 review, 1 high). These are badge and asset URLs in READMEs. Read this as: link-dense markdown,
which a coding agent echoes often, triggers outcheck on about a quarter of documents and about 1 in 80 addresses
without session context; the one hostile verdict would block rendering. The broker-side checks (URL carrying text
read earlier, DNS-carried data, sends to never-fetched hosts) need a session and were not measured.

## Limits

- **Text-only.** Every public set was scanned as a plain string with static passes. Nothing here exercises the
  page-fetching path: rendered-page hiding, bots-vs-browsers cloaking comparison, stylesheet fetches, the sandbox,
  images, audio, video or the new `filescan` document readers. The self-built corpus covers static HTML hiding, but
  it is not independent.
- **Self-built corpus is not independent**: same author (Claude-generated) and same time as the rules; 100% there is
  expected by construction.
- **Development contamination**: the PINT-style sets trained the classifier (training splits) and set its thresholds;
  several benign sets were used to fix false alarms. Only BIPIA and InjecAgent are independent of the engine, and
  both are attack-heavy with small benign sides (217 rows).
- **No PINT score.** PINT's data is private; only Lakera can run it.
- **BIPIA construction**: start/end insertion only (no middle); rows repeat 75/50 attack strings across contexts, so
  the effective sample of distinct attacks is small (125). InjecAgent's benign control is constructed.
- **Not scored**: Wikipedia docs (fetch failed 3 times on HF 429s); egress replay (no session data); the broker's
  session-based exfiltration checks.
- **Single run, single machine**, deterministic engine (static passes, fixed model), so repeated runs give the same
  verdicts; timings are for 2 vCPU ARM and will differ elsewhere.
- **"Refused" includes suspect**, which the product lets a person override. Hostile-only rates are given beside it.

## Summary

Independent of its own development data, Ingress 0.10.0's plain-text scan refused 0 of 217 benign tool contexts but
caught almost none of BIPIA's 27,500 embedded task-hijack injections (6 rows, 0.02%) and 15.7% of InjecAgent's base
tool-response injections, rising to 100% (99.8% hostile) only when the injection carries an "Ignore all previous
instructions" override. On its development sets it catches 46.7% of 2,021 direct injections and jailbreaks at a 0.33%
false-refusal rate, and 89.6% of a 3,798-row LLMail-Inject email hold-out at 0.5% on 4,550 legitimate emails;
its page-hiding and cloaking defences, and the new egress checks in a live session, are not exercised by any public
dataset here.
