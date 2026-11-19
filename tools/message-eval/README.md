# Message scoring

How the message adapter does on real text messages, and on attack text arriving as a message.

```sh
node tools/message-eval/fetch-sms.mjs ~/ingress-messages          # dev/ and holdout/ halves of the UCI SMS Spam Collection
npm run build
npm run email-eval -- ~/ingress-messages/dev/sms.jsonl --as=message --why
```

`--as=message` reads every row as a text message from an unknown number at stranger trust (4): the strictest
reading. It also accepts the email sets from `tools/email-eval`, sending each email's body as a text, which
checks that the same attack words are judged alike in a chat. Counts only are printed.

## Sets

| set | what | licence | role |
|---|---|---|---|
| UCI SMS Spam Collection, ordinary messages | 4,827 real texts between people | CC BY 4.0 | benign |
| UCI SMS Spam Collection, spam | 747 advertising and scam texts aimed at people | CC BY 4.0 | "other": not attacks on an assistant |
| LLMail-Inject bodies, sent as texts | attack emails from `tools/email-eval` | MIT | attacks |
| Enron bodies, sent as texts | ordinary business mail | public record | benign (an artificial reading: long mail as a text from a stranger) |

## Results (2026-11-18, engine 0.9.19, trust 4)

Hold-out halves, scored once after the rules were fixed:

| set | class | messages | refused | rate |
|---|---|---|---|---|
| ordinary text messages | benign | 2,408 | 3 | 0.1% |
| Enron bodies as texts | benign | 2,900 | 4 | 0.1% |
| LLMail-Inject Phase 1 as texts | attack | 1,899 | 1,587 | 83.6% |
| LLMail-Inject Phase 2 as texts | attack | 1,899 | 1,481 | 78.0% |
| spam texts | other | 366 | 2 | 0.5% |

**Attacks caught 3,068 of 3,798 (80.8%); benign passed 5,301 of 5,308 (99.9%); balanced accuracy 90.3%.**
Development halves: 81.0%, 99.9%, 90.4%.

**With the retrained classifier (0.9.23, 2026-11-19),** the same hold-out rows: ordinary texts refused 0 of
2,408; Enron bodies as texts 4 of 2,900; Phase 1 caught 1,592 (83.8%), Phase 2 1,476 (77.7%); spam texts 2 of
366. Attacks caught 3,068 of 3,798 (80.8%); benign passed 5,304 of 5,308 (99.9%); balanced accuracy 90.4%.
This is a second scoring of the hold-out, so it is a comparison with the table above, not a fresh
measurement. The retraining used ordinary texts from the development half only (2,198 of them).

## How it got there (development halves)

| step | ordinary texts refused | why |
|---|---|---|
| first cut | 25 of 2,419 (1.0%) | 20 by the classifier, which had never seen how people text ("call me now", "send me the address"); 5 by the scam-shape check |
| short-text mode: under 15 words the classifier alone does not decide; under 40 it needs 0.9 | 8 (0.3%) | |
| scam shape only on short messages; a stranger asking for a code must also press or claim an institution | 3 (0.1%) | before the length limit, Enron bodies read as texts tripped the scam-shape check 236 times in 3,000 |

## What the numbers do not say

- **The attack rows are email attacks sent as texts,** not attacks written for chat. The email hold-out they
  come from was scored once as email for 0.9.16 (89.4%); scoring the same texts through the message path is a
  second use of them, and says how much short-text mode costs (about 9 points), not how chat-native attacks fare.
- **Spam is not caught, and is not the target.** This corpus's spam is mostly premium-rate numbers and
  advertising from the 2000s with no link tricks. The scam-shape check is about links that hide their
  destination and requests for codes; it is tested on constructed cases (`test/messages.test.ts`), not measured
  on a present-day smishing corpus. None was found with a licence that could be checked.
- **The classifier was retrained afterwards, in 0.9.23.** The table above is the model that shipped with
  0.9.19, which had never seen a text message; short-text mode was the measure that made it usable. The
  retrained model (`tools/classifier/build_training_set.py --benign`) is installed from 0.9.23, and short-text
  mode stays on beside it. Its numbers are in the paragraph under the table.
- **Trust is per scan.** Every message here was read as from a stranger. A known contact (trust 2) gets the
  same rules with the default thresholds.
