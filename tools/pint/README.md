# Scoring Ingress the PINT way

[Lakera's PINT Benchmark](https://github.com/lakeraai/pint-benchmark) scores a prompt-injection detector by
**balanced accuracy**: the mean of its accuracy on attacks and its accuracy on benign inputs. The PINT dataset
(4,314 inputs, about 94% benign: chats, public documents, hard negatives) is private. Only Lakera can produce a
PINT score: request the dataset for research at `support@lakera.ai`, or ask `opensource@lakera.ai` to verify a
result. A number from any other data is not a PINT score.

What is here:

| file | what it does |
|---|---|
| `ingress_pint.py` | `evaluate_ingress(prompt) -> bool` for the official PINT notebook, through the local HTTP service |
| `fetch-public-sets.mjs` | downloads public, licensed sets in the PINT format (JSON Lines); prints counts, never text |
| `../../packages/core/eval/pint.ts` | the same balanced-accuracy score on those sets (`npm run pint -- <files>`) |

```sh
node tools/pint/fetch-public-sets.mjs ~/ingress-eval-data
npm run build && npm run pint -- ~/ingress-eval-data/*.jsonl
```

Rules for an honest number: none of these sets may be used to write or tune a rule. When a rule change is
measured on them, say so, and treat that set as spent for that purpose.

## Public sets (none used to tune Ingress)

| set | inputs | license |
|---|---|---|
| deepset/prompt-injections, test | 116 (60 attacks) | Apache-2.0 |
| jackhhao/jailbreak-classification, test | 262 (139 jailbreaks) | Apache-2.0 |
| Lakera/gandalf_ignore_instructions, test | 112 attacks | MIT |
| reshabhs/SPML_Chatbot_Prompt_Injection, stratified | 960 (500 attacks) | MIT |
| wikimedia/wikipedia 20231101, 30 articles each in en de fr ja ko zh fa ar | 240 benign | CC BY-SA 4.0 |
| halilneed/turkish-prompt-injection-false-alarm-benchmark | 2,875 benign | CC0-1.0 |
| 3nesdeniz/turkish-prompt-injection-1k, all splits | 1,000 (550 attacks) | CC-BY-4.0 |
| rikka-snow/prompt-injection-multilingual, test (vi en zh fr de hi it ja pt es th) | 1,276 (660 attacks) | MIT |
| GitHub READMEs of 35 well-known repositories | 35 benign | per repository |

Spent sets (a rule was changed after seeing results on them; say so whenever they are quoted): wikipedia-docs for the
adversarial-suffix and bidi-isolate mechanisms (0.9.3); turkish-1k benign rows for `extract.tr` and github-readmes for
the documentation-grade cap (0.9.5). No attack row of any set was looked at or used to write a rule.

## Results (2026-11-18, static passes, plain text)

| | 0.9.2 | 0.9.3 |
|---|---|---|
| attacks caught | 200 / 811 (24.7%) | 200 / 811 (24.7%) |
| benign passed | 878 / 879 | 879 / 879 |
| **balanced accuracy** | **62.3%** | **62.3%** |

With the multilingual, Turkish and README sets added (6,876 inputs):

| | 0.9.4 | 0.9.5 |
|---|---|---|
| Turkish attacks caught (550) | 8 | 18 |
| multilingual attacks caught (660) | 9 | 10 |
| READMEs passed (35) | 27 | 35 |
| Turkish false-alarm set passed (2,875) | 2,874 | 2,874 |
| attacks caught, all sets | 217 / 2,021 (10.7%) | 228 / 2,021 (11.3%) |
| benign passed, all sets | 4,841 / 4,855 | 4,849 / 4,855 |
| **balanced accuracy** | **55.2%** | **55.6%** |

For comparison only (different data): Lakera Guard scores 95.2% on PINT, AWS Bedrock Guardrails and Azure Prompt
Shield about 89%, the best open classifiers about 79%.

What the numbers say: Ingress's rules are precise (no benign input refused, in eight languages) and catch about a
quarter of plain-English direct injections and jailbreaks. Ingress was built to gate indirect content (pages, tool
results, documents) where hidden text, cloaking and character tricks are the signal; PINT-style sets are mostly
visible, direct, paraphrased attacks, which regular expressions do not generalize to. The 0.9.3 additions
(disguised text, suffixes, fake markers, image exfiltration) do not appear in these sets, so they do not move the
score. Closing the gap to the PINT leaders needs a learned classifier pass, not more patterns.

The non-English sets say the same louder: 0.9.5 has instruction rules in 30-odd languages and scripts and still catches
about 3% of Turkish and multilingual attacks, because real attacks are paraphrases, not the canonical "ignore all
previous instructions" in translation. False alarms stay near zero (6 of 4,855 benign inputs).

## With the learned pass (0.9.16)

0.9.16 adds a small classifier beside the rules (`packages/core/src/classifier.ts`, trained by `tools/classifier`).
Same 6,876 inputs:

| | 0.9.15, rules only | 0.9.16, rules and classifier |
|---|---|---|
| English injections caught (672) | 21.0% | 89.1% |
| jailbreaks caught (139) | 39.6% | 80.6% |
| multilingual attacks caught (660) | 1.5% | 32.6% |
| Turkish attacks caught (550) | 3.3% | 3.3% |
| attacks caught, all sets (2,021) | 11.1% | 46.7% |
| benign passed, all sets (4,855) | 99.9% | 99.8% |
| **balanced accuracy** | **55.5%** | **73.3%** |

How to read this honestly:

- The classifier never trained on a row of these sets: every text here was removed from its training data by
  exact match, and it used only the *training* splits of the sets whose test splits are scored.
- These sets did choose two numbers: the lines at which the classifier may decide for plain text (0.85) and for
  messages (0.8). So they are a development set for this release, not a hold-out. The email hold-out in
  `tools/email-eval` is the clean number.
- Two sets are close to the training data: SPML (other rows of the same set were trained on) and the multilingual
  set (its training split was). English injections at 89% lean on SPML; the deepset and jailbreak sets, which
  have no such overlap, are the fairer read.
- Turkish did not move, because no Turkish attack was in the training data. A bag-of-words model does not carry
  what it learned in one language to another. That needs a multilingual embedding model, which is not built.
- Still not a PINT score: only Lakera can produce one.
