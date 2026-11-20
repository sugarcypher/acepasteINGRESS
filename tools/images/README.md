# Image false-alarm check

How often does the image gate refuse an ordinary picture? These tools download ordinary images from Wikimedia
Commons and scan them. Every one is benign, so every refusal is a false alarm to explain.

```sh
npm run build && ingress vision build
node tools/images/fetch-commons.mjs ~/ingress-images 16            # <dir>/dev and <dir>/holdout, alternating
node tools/images/fetch-commons.mjs ~/ingress-images 8 --second    # <dir>/holdout2, other categories
node tools/images/score-images.mjs ~/ingress-images/dev            # prints verdicts and finding kinds, never text
```

The images are for local measurement and are not redistributed here (licences vary per file; all are free
licences, listed on each file's Commons page). Commons rate-limits downloads, so a run fetches fewer files
than it asks for; what was fetched is what was scored.

## What was scored, and how the sets were used

| set | images | used for |
|---|---|---|
| `dev` | 95: photographs, posters, maps, charts, logos, QR codes, book covers, newspapers, comics, handwriting, advertisements, signs | choosing the comparison rule and thresholds |
| `holdout` | 95, the same categories | scored once, then **spent**: its two false alarms were diagnosed and fixed, so it is development data from then on |
| `holdout2` | 89, other categories: office-suite screenshots, timetables, banknotes, warning signs, billboards, magazine covers, sheet music, blackboards, typewritten documents, receipts, tickets, pie charts, organisation charts | scored once after the last change; nothing was changed afterwards |

## Results (2026-11-18, engine 0.9.18, Apple Silicon)

| step | set | clean | refused | why |
|---|---|---|---|---|
| first cut | dev | 69 of 95 | 26 suspect | every image with dense text: the resizing check compared each unsmoothed resize only with the smoothed resize of the same size, and small print reads differently at every size |
| compare with every honest view | dev | 93 of 95 | 2 suspect | recognition noise two kernels agreed on, read at half confidence |
| full-confidence lines only | dev | 95 of 95 | 0 | |
| the same rules | holdout, scored once | **93 of 95** | 2 suspect, 0 hostile | a newspaper scan (recognised text mixed alphabets, counted as lookalike letters); a dense screenshot (digits misread as scraps like "1CU", with full confidence) |
| lookalike checks not applied to recognised text; a message must be words, not scraps | dev, holdout | 95 of 95, 95 of 95 | 0 | both sets are development data by now |
| the final rules | **holdout2, scored once** | **87 of 89** | 2 suspect, 0 hostile | a page of sheet music (the resizing check); a typewritten document (the classifier rated its visible text) |

**The number to quote: 87 of 89 ordinary images pass (97.8%), none rated hostile.** With the spent hold-out's
first score (93 of 95), the two honest measurements agree: about 2 in 100 ordinary images are wrongly held as
suspect. Nothing was changed after `holdout2` was scored, so its two false alarms are still there:

- Sheet music: lines read only after an unsmoothed resize, with full confidence, that pass the "is it words"
  test. Staff lines and lyrics alias badly. Not diagnosed further, to keep the set unspent.
- A typewritten document: nothing hidden. The classifier rated the page's own visible text as resembling an
  attack. Text recognised in a picture is judged as plain text of unknown kind, the classifier's less cautious
  setting; a scanned letter is closer to a document.

About 4 seconds per image (3.7 to 5.7 across the sets). One image of 89 could not be decoded by the helper and
was reported as not read.

What this does and does not say: it measures false alarms on ordinary pictures, with honest accounting of
which sets guided the rules. It does not measure how many real image attacks are caught: no public set of
image-injection attacks was scored (see `docs/IMAGES.md`). The self-test pictures show the mechanisms work on
constructed cases.

## Screens: interface elements drawn into a page (2026-11-20, engine 0.9.27)

Does the check for a browser window or a system dialog drawn into a page (`packages/core/src/screen.ts`) fire
on ordinary screens?

```sh
node tools/images/fetch-screens.mjs ~/ingress-screens                     # ScreenSpot-v2, 1.3 GB
node tools/images/score-screens.mjs ~/ingress-screens --half=dev
node tools/images/score-screens.mjs ~/ingress-screens --half=holdout --read-only   # read ahead, score nothing
node tools/images/score-screens.mjs ~/ingress-screens --half=holdout
```

The set is ScreenSpot-v2 (OS-Copilot/ScreenSpot-v2 on Hugging Face, Apache-2.0): 755 screenshots of real web
pages, desktop applications and phone screens. A hash of each file name decides its half, before anything is
read. Every picture is scored three ways: as given; declared a capture of a page's content area (the worst
case: desktop and phone screens are not, so real windows in them count against the rule); and declared a
capture of a page on an unrelated site.

| half | screens | drawn browser window found | drawn system dialog found | verdicts changed by declaring a viewport capture |
|---|---|---|---|---|
| development | 386 (web 123, desktop 115, phone 136, other 12) | 0 | 0 | 0 |
| **hold-out, scored once** | **361** (web 125, desktop 112, phone 111, other 13) | **0** | **0** | **0** |

The check never fired on the development half, so its rules and weights were left as first written, and the
hold-out half was scored once. None in 361 puts the false-alarm rate on screens like these under about 1 in
100. It says nothing about how many real drawn windows would be caught: no set of such pages was scored, and
the one positive case is the picture the helper draws (`ingress vision selftest`). Eight development pictures
were not read in the time allowed while other measurements were running, and are not in the 386.

The same run is also a first look at the picture gate as a whole on screenshots, a kind of picture the
Commons sets had few of. No picture rule was changed for it: **744 of 747 screens clean, 3 suspect (all in
the development half), none hostile.** The three were not diagnosed.
