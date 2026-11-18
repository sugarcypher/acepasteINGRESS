# Scoring Ingress on email

| file | what it does |
|---|---|
| `fetch-email-sets.mjs` | downloads public email sets as JSON Lines; prints counts, never text |
| `../../packages/core/eval/email.ts` | scans every message as email and prints counts (`npm run email-eval -- <files>`) |

```sh
node tools/email-eval/fetch-email-sets.mjs ~/ingress-email-dev              # the development sample
node tools/email-eval/fetch-email-sets.mjs ~/ingress-email-holdout --holdout   # a disjoint sample: score it once
npm run build && npm run email-eval -- ~/ingress-email-holdout/*.jsonl
npm run email-eval -- ~/ingress-email-dev/*.jsonl --why                      # which finding kinds refused benign mail
```

Rules for an honest number: no rule is written from an attack message, and nobody reads them. The development
sample may guide a threshold (by counts and finding kinds only); a number is reported from the hold-out
sample, scored once for a release.

## Sets

| set | what it is | license |
|---|---|---|
| microsoft/llmail-inject-challenge, Phase1 and Phase2 | attack emails submitted to a live email assistant in Microsoft's 2024-25 challenge; every row is an attempt | MIT |
| corbt/enron-emails | ordinary business mail, 2000-2002 | public record; no license stated on the dataset card |
| SpamAssassin public corpus: easy ham, hard ham | legitimate mail as received, HTML and newsletters included (hard ham is legitimate mail that looks like spam) | public corpus, Apache SpamAssassin project |
| SpamAssassin public corpus: spam | unwanted mail. Not an attack on an assistant, so it is scored as neither class | same |

Each sample takes evenly spaced pages of the Hugging Face sets and one SpamAssassin archive per folder; the
hold-out takes the pages halfway between and different archives.

## Results, 0.9.15 (2026-11-18, rules only, source trust 4 "stranger")

Hold-out sample, scored once, never used for a decision:

| set | class | messages | refused | rate |
|---|---|---|---|---|
| LLMail-Inject Phase1 | attack | 1,899 | 883 | 46.5% |
| LLMail-Inject Phase2 | attack | 1,899 | 336 | 17.7% |
| Enron | benign | 2,900 | 5 | 0.2% |
| SpamAssassin easy ham | benign | 1,400 | 3 | 0.2% |
| SpamAssassin hard ham | benign | 250 | 12 | 4.8% |
| SpamAssassin spam | other | 1,397 | 25 | 1.8% |

**Attacks caught 1,219 of 3,798 (32.1%); legitimate mail passed 4,530 of 4,550 (99.6%); balanced accuracy 65.8%.**

Development sample (two settings were chosen on it: the reply-to mismatch weight, and the jailbreak-suffix
check counting only beside other evidence in messages): attacks caught 1,424 of 3,956 (36.0%), legitimate mail
passed 5,738 of 5,750 (99.8%), balanced accuracy 67.9%.

What the numbers say: the adapter adds almost no false alarms on ordinary mail and catches about a third of
attacks written to get past an email assistant's defences. Those attacks are visible, reworded instructions
in the body, which is where rules are weakest; Phase 2 of the challenge, run against stronger defences, is
caught half as often as Phase 1. The structure checks this adapter adds (hidden HTML, a plain part that
differs, sender spoofing) barely appear in this data, because the challenge's emails were plain text typed
into a form. Closing the gap is the classifier's job (roadmap Phase 0). Newsletter-style mail is the
false-alarm risk: about 4% of "hard ham" is refused, mostly for imperative marketing copy.
