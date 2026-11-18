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

## Results, 0.9.16 (2026-11-18, rules and the learned pass, source trust 4)

The same hold-out sample, scored once for this release:

| set | class | messages | refused | rate |
|---|---|---|---|---|
| LLMail-Inject Phase1 | attack | 1,899 | 1,718 | 90.5% |
| LLMail-Inject Phase2 | attack | 1,899 | 1,677 | 88.3% |
| Enron | benign | 2,900 | 8 | 0.3% |
| SpamAssassin easy ham | benign | 1,400 | 3 | 0.2% |
| SpamAssassin hard ham | benign | 250 | 12 | 4.8% |
| SpamAssassin spam | other | 1,397 | 30 | 2.1% |

**Attacks caught 3,395 of 3,798 (89.4%); legitimate mail passed 4,527 of 4,550 (99.5%); balanced accuracy 94.4%**
(0.9.15, rules only: 32.1%, 99.6%, 65.8%). Development sample: 89.3%, 99.8%, 94.6%.

What keeps this number honest, and what limits it:

- The hold-out was not used to choose anything. The classifier's training data excludes every message in both
  samples, and excludes every challenge team that has a message in either sample, because teams resubmitted
  near-copies of their own attacks.
- LLMail-Inject was a game with one goal: get the assistant to send a fixed word to a fixed address. The first
  model trained on it scored 95%, and 72% once that address and word were masked: it had learned the goal.
  Training now gives each attack its own stand-in address and word, and the masked and unmasked scores agree
  (91% for the classifier alone). `tools/classifier/train.py --mask-goal` repeats the check.
- It is still one style of attack: instructions typed into a form to make an assistant send mail. Attacks that
  ask for something else, or arrive as HTML, are not measured here.
- The first model also rated ordinary email furniture as attack-like (an unsubscribe footer scored 0.94),
  because the benign mail it trained on is from 2001. Generated present-day email text was added to training
  (`tools/classifier/hard_negatives.py`); that footer now scores 0.003.
