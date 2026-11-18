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

## Results (2026-11-18, static passes, plain text)

| | 0.9.2 | 0.9.3 |
|---|---|---|
| attacks caught | 200 / 811 (24.7%) | 200 / 811 (24.7%) |
| benign passed | 878 / 879 | 879 / 879 |
| **balanced accuracy** | **62.3%** | **62.3%** |

For comparison only (different data): Lakera Guard scores 95.2% on PINT, AWS Bedrock Guardrails and Azure Prompt
Shield about 89%, the best open classifiers about 79%.

What the numbers say: Ingress's rules are precise (no benign input refused, in eight languages) and catch about a
quarter of plain-English direct injections and jailbreaks. Ingress was built to gate indirect content (pages, tool
results, documents) where hidden text, cloaking and character tricks are the signal; PINT-style sets are mostly
visible, direct, paraphrased attacks, which regular expressions do not generalize to. The 0.9.3 additions
(disguised text, suffixes, fake markers, image exfiltration) do not appear in these sets, so they do not move the
score. Closing the gap to the PINT leaders needs a learned classifier pass, not more patterns.
