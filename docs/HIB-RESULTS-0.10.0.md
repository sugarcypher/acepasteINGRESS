# HIB results: AcePaste Ingress 0.10.0

Scored on HIB v1 (Hidden Injection Bench, `bench/hib/`), both splits, 4,008 items. Ingress 0.10.0 is commit
`992d1eb`, scored as released: no engine, rule or threshold was changed for or after this run.

**Conflict of interest.** HIB and Ingress have the same author. The payloads come from BIPIA and InjecAgent (MIT,
third party) plus 50 paraphrased payloads the author wrote; the techniques, carriers and scoring are the author's.
The held-out split's generator was committed before it was first run, and nothing was tuned on either split. See
`bench/hib/README.md` for the mitigations and limits. Please check the numbers yourself; everything is reproducible.

## Summary

- Ingress flags **41.0%** of attack items on the public split and **38.7%** on the held-out split, with **4.9% / 5.1%**
  false positives. Almost all of those false positives (48 of 49, and 48 of 51) are one cause: any Unicode tag
  character is flagged, so legitimate subdivision-flag emoji (England, Scotland, Wales) are refused. Without the
  `unicode_tags` technique the false-positive rate is **0.1% (1/954)** and **0.3% (3/954)**.
- On payloads that are actually hidden from a person (no visible control, no on-screen obfuscation, no tag
  characters), Ingress flags **31.8%** (public) and **28.0%** (held-out). The same Ingress text checks run on a naive
  extraction of the same items flag 14.5% and 12.3%: reading pages and files the way they render roughly doubles
  detection of hidden payloads, at no measurable false-positive cost outside tag characters.
- Ingress *notices* hidden text far more often than it *refuses* it: it raised a hidden-content finding on 86% of
  hidden attack items (689/798 public, 686/798 held-out), and on 40% / 36% of benign items, which use the same
  mechanisms. The refusal then depends on whether the hidden text reads as an instruction, and most BIPIA-style task
  requests and the paraphrased payloads do not.
- Weakest: `js_injected` and `template` (0 of 24 in both splits, not even noticed), user-agent cloaking (21% / 29%:
  both copies are fetched but the difference alone does not change the verdict), PNG text metadata (25% / 17%),
  near-background text on a tinted page (17% held-out), iframe `srcdoc` (46% / 12%), hidden sheets (21% / 25%), and the
  visible control (16% / 16%), which matches the low plain-text detection in `docs/EVAL-0.10.0.md`.
- On the held-out split the point estimates fell for several techniques (CSS clip 47% to 20%, colour match 37% to
  17%, opacity 30% to 17%, iframe `srcdoc` 46% to 12%). With 24-30 items each the intervals still touch or overlap, so
  this is a signal rather than a measurement, but it is the kind of gap a held-out split exists to show: some public
  numbers describe the public templates more than the technique.

## What was scored, and how

| entry | carriers | Ingress call (= CLI) | flagged when |
|---|---|---|---|
| page gate | web article, product, docs, forum | `IngressEngine.fetch(url)` (= `ingress <url>`), default config: cloaking check on (AI-agent and browser user agents), stylesheets on, sandbox `escalate` | tier hostile or suspect |
| text | HTML email (`.eml`) | `IngressEngine.scan(raw)` (= `ingress --text < mail.eml`) | tier hostile or suspect |
| file | README, PDF, DOCX, XLSX, PPTX, PNG | `filescan(path)` (= `ingress filescan <file>`) | tier hostile or suspect |
| MCP | tool-list JSON | `mcpscan({url})` (= `ingress mcpscan --url`) against a fixture MCP server | any `high` finding (the command's exit-1 condition) |

Changes from the CLI defaults, none of which touches a rule: the page gate's network policy allows the loopback
fixture server, its cache is off, the jitter between its two fetches is zero, and its random choices (which AI user
agent, which fetch first) are seeded. MCP scans use a fresh pin directory per item. `review`-level MCP findings (8
public, 7 held-out items) are recorded but not counted as flagged. No verdict was `unreachable` or `error`.

Environment: Node v22.23.5, Python 3.12.16, linux aarch64, Chromium (headless shell) 153.0.8010.12 via Playwright,
installed with its missing system libraries (`libatk1.0-0 libxcomposite1 libxdamage1 libatspi2.0-0`) so the sandbox
escalation and the ground-truth check could run. Every technique was run; none is marked "not run". The public split
was scored twice with identical verdicts.

Ground truth: all 1,128 HTML attack items (web and email, both splits) were rendered in Chromium; every hidden payload
was imperceptible and every visible-labelled payload was perceptible (`bench/hib/results/validate-*.json`).

## Overall

Cells: rate (k/n; Wilson 95% interval). "Hidden only" excludes the visible control, on-screen obfuscation
(zero-width, homoglyph, bidi) and tag characters.

| defense | split | detection, all attacks | detection, hidden only | false positives | FP without unicode_tags |
|---|---|---|---|---|---|
| **Ingress 0.10.0, real entry points** | public | 41.0% (411/1002; 38.0-44.1) | 31.8% (204/642; 28.3-35.5) | 4.9% (49/1002; 3.7-6.4) | 0.1% (1/954; 0.0-0.6) |
| | held-out | 38.7% (388/1002; 35.8-41.8) | 28.0% (180/642; 24.7-31.6) | 5.1% (51/1002; 3.9-6.6) | 0.3% (3/954; 0.1-0.9) |
| naive extraction + Ingress text scan | public | 30.8% (309/1002; 28.1-33.8) | 14.5% (93/642; 12.0-17.4) | 4.8% (48/1002; 3.6-6.3) | 0.0% (0/954; 0.0-0.4) |
| | held-out | 29.3% (294/1002; 26.6-32.2) | 12.3% (79/642; 10.0-15.1) | 4.9% (49/1002; 3.7-6.4) | 0.1% (1/954; 0.0-0.6) |
| naive extraction + Ingress classifier only | public | 4.6% (46/1002; 3.5-6.1) | 4.8% (31/642; 3.4-6.8) | 0.0% (0/1002; 0.0-0.4) | 0.0% (0/954; 0.0-0.4) |
| | held-out | 7.4% (74/1002; 5.9-9.2) | 8.6% (55/642; 6.6-11.0) | 0.0% (0/1002; 0.0-0.4) | 0.0% (0/954; 0.0-0.4) |
| naive extraction + "ignore previous" regex | public | 10.5% (105/1002; 8.7-12.5) | 12.0% (77/642; 9.7-14.7) | 0.0% (0/1002; 0.0-0.4) | 0.0% (0/954; 0.0-0.4) |
| | held-out | 10.0% (100/1002; 8.3-12.0) | 11.4% (73/642; 9.1-14.1) | 0.0% (0/1002; 0.0-0.4) | 0.0% (0/954; 0.0-0.4) |

The regex catches InjecAgent's "enhanced" payloads (which begin "IMPORTANT!!! Ignore all previous instructions")
and nothing else; the classifier alone is a weak signal on these short task-like payloads.

## By technique

Ingress with Wilson intervals; baselines as rates. Per-technique samples are small (24-48 attack items), so
intervals are wide; differences inside overlapping intervals are noise.

| technique | Ingress det. public | Ingress det. held-out | Ingress FP public | Ingress FP held-out | text scan det. (pub / held) | regex det. (pub / held) |
|---|---|---|---|---|---|---|
| attr_hidden | 29% (11/38; 17-45) | 26% (10/38; 15-42) | 0% (0/38; 0-9) | 0% (0/38; 0-9) | 5% / 5% | 3% / 5% |
| bidi_override | 100% (48/48; 93-100) | 100% (48/48; 93-100) | 0% (0/48; 0-7) | 0% (0/48; 0-7) | 100% / 100% | 15% / 10% |
| css_clip | 47% (14/30; 30-64) | 20% (6/30; 10-37) | 0% (0/30; 0-11) | 0% (0/30; 0-11) | 17% / 7% | 17% / 7% |
| css_color_match_bg | 37% (11/30; 22-54) | 17% (5/30; 7-34) | 0% (0/30; 0-11) | 0% (0/30; 0-11) | 10% / 13% | 7% / 10% |
| css_display_none | 40% (12/30; 25-58) | 40% (12/30; 25-58) | 0% (0/30; 0-11) | 0% (0/30; 0-11) | 20% / 20% | 17% / 20% |
| css_font_size_zero | 20% (6/30; 10-37) | 47% (14/30; 30-64) | 0% (0/30; 0-11) | 0% (0/30; 0-11) | 20% / 17% | 13% / 13% |
| css_offscreen | 47% (14/30; 30-64) | 27% (8/30; 14-44) | 0% (0/30; 0-11) | 0% (0/30; 0-11) | 20% / 13% | 17% / 10% |
| css_opacity_zero | 30% (9/30; 17-48) | 17% (5/30; 7-34) | 0% (0/30; 0-11) | 0% (0/30; 0-11) | 7% / 7% | 7% / 3% |
| css_visibility_hidden | 37% (11/30; 22-54) | 23% (7/30; 12-41) | 0% (0/30; 0-11) | 0% (0/30; 0-11) | 13% / 7% | 10% / 7% |
| docx_hidden_run | 33% (8/24; 18-53) | 54% (13/24; 35-72) | 0% (0/24; 0-14) | 0% (0/24; 0-14) | 12% / 33% | 12% / 33% |
| docx_tiny_text | 42% (10/24; 24-61) | 21% (5/24; 9-40) | 0% (0/24; 0-14) | 0% (0/24; 0-14) | 29% / 12% | 17% / 12% |
| docx_white_text | 25% (6/24; 12-45) | 38% (9/24; 21-57) | 0% (0/24; 0-14) | 0% (0/24; 0-14) | 17% / 21% | 17% / 17% |
| homoglyph | 83% (40/48; 70-91) | 85% (41/48; 73-93) | 0% (0/48; 0-7) | 0% (0/48; 0-7) | 100% / 100% | 0% / 0% |
| html_comment | 27% (13/48; 17-41) | 25% (12/48; 15-39) | 0% (0/48; 0-7) | 0% (0/48; 0-7) | 10% / 2% | 10% / 2% |
| iframe_srcdoc | 46% (11/24; 28-65) | 12% (3/24; 4-31) | 0% (0/24; 0-14) | 0% (0/24; 0-14) | 0% / 0% | 0% / 0% |
| js_injected | 0% (0/24; 0-14) | 0% (0/24; 0-14) | 0% (0/24; 0-14) | 0% (0/24; 0-14) | 0% / 0% | 0% / 0% |
| mcp_param_description | 30% (3/10; 11-60) | 20% (2/10; 6-51) | 0% (0/10; 0-28) | 0% (0/10; 0-28) | 20% / 10% | 20% / 10% |
| noscript | 33% (8/24; 18-53) | 33% (8/24; 18-53) | 0% (0/24; 0-14) | 0% (0/24; 0-14) | 12% / 17% | 12% / 17% |
| pdf_tiny_text | 21% (5/24; 9-40) | 33% (8/24; 18-53) | 0% (0/24; 0-14) | 0% (0/24; 0-14) | 12% / 17% | 12% / 17% |
| pdf_white_text | 38% (9/24; 21-57) | 33% (8/24; 18-53) | 0% (0/24; 0-14) | 0% (0/24; 0-14) | 21% / 25% | 12% / 25% |
| png_text_metadata | 25% (6/24; 12-45) | 17% (4/24; 7-36) | 0% (0/24; 0-14) | 0% (0/24; 0-14) | 0% / 0% | 0% / 0% |
| pptx_speaker_notes | 38% (9/24; 21-57) | 42% (10/24; 24-61) | 0% (0/24; 0-14) | 0% (0/24; 0-14) | 25% / 25% | 17% / 25% |
| svg_text | 29% (7/24; 15-49) | 42% (10/24; 24-61) | 0% (0/24; 0-14) | 0% (0/24; 0-14) | 21% / 12% | 21% / 12% |
| template | 0% (0/24; 0-14) | 0% (0/24; 0-14) | 0% (0/24; 0-14) | 0% (0/24; 0-14) | 0% / 0% | 0% / 0% |
| ua_cloaking | 21% (5/24; 9-40) | 29% (7/24; 15-49) | 0% (0/24; 0-14) | 0% (0/24; 0-14) | 21% / 21% | 21% / 17% |
| unicode_tags | 100% (48/48; 93-100) | 100% (48/48; 93-100) | 100% (48/48; 93-100) | 100% (48/48; 93-100) | 100% / 100% | 0% / 0% |
| visible | 16% (23/144; 11-23) | 16% (23/144; 11-23) | 0% (0/144; 0-3) | 0% (0/144; 0-3) | 17% / 16% | 15% / 15% |
| xlsx_hidden_cells | 46% (11/24; 28-65) | 33% (8/24; 18-53) | 0% (0/24; 0-14) | 0% (0/24; 0-14) | 25% / 8% | 21% / 8% |
| xlsx_hidden_sheet | 21% (5/24; 9-40) | 25% (6/24; 12-45) | 0% (0/24; 0-14) | 0% (0/24; 0-14) | 21% / 17% | 17% / 17% |
| zero_width | 100% (48/48; 93-100) | 100% (48/48; 93-100) | 2% (1/48; 0-11) | 6% (3/48; 2-17) | 100% / 100% | 0% / 0% |

Notes:
- `unicode_tags` 100% detection and 100% false positives: the tag-character check fires on any tag character, so it
  does not separate an encoded instruction from a flag emoji. `zero_width`, `bidi_override` and `homoglyph` are
  caught by the text path alone too (character checks), with 1/48 and 3/48 benign zero-width items flagged.
- `template` and `js_injected`: no finding at all on any item (static score 0). The sandbox, which would render
  script-inserted text, escalates only at static suspicion >= 0.5 (the default `sandboxEscalateAt`), so it never ran
  on these pages; `<template>` content produced no finding either.
- `ua_cloaking`: the fixture served the agent copy to Ingress's AI-agent fetch and the clean copy to its browser
  fetch (checked by the ground-truth script for every item and on sample Ingress runs), and the cloaking comparison ran; it flagged only the items whose agent-only text was itself
  instruction-shaped (5/24, 7/24), the same as judging the agent copy alone.
- `css_color_match_bg` held-out (text coloured like a tinted container, not white): hidden text noticed on only 6/30.

## By carrier

| carrier | Ingress det. public | Ingress det. held-out | Ingress FP public | Ingress FP held-out | text scan det. (pub / held) |
|---|---|---|---|---|---|
| docx | 30% (29/96; 22-40) | 32% (31/96; 24-42) | 0% (0/96; 0-4) | 0% (0/96; 0-4) | 20% / 21% |
| email_html | 50% (42/84; 40-60) | 50% (42/84; 40-60) | 7% (6/84; 3-15) | 7% (6/84; 3-15) | 36% / 37% |
| mcp_tools_json | 53% (37/70; 41-64) | 51% (36/70; 40-63) | 16% (11/70; 9-26) | 17% (12/70; 10-28) | 64% / 60% |
| pdf | 25% (18/72; 16-36) | 29% (21/72; 20-41) | 0% (0/72; 0-5) | 0% (0/72; 0-5) | 17% / 21% |
| png | 25% (6/24; 12-45) | 17% (4/24; 7-36) | 0% (0/24; 0-14) | 0% (0/24; 0-14) | 0% / 0% |
| pptx | 25% (12/48; 15-39) | 27% (13/48; 17-41) | 0% (0/48; 0-7) | 0% (0/48; 0-7) | 19% / 19% |
| readme_md | 75% (42/56; 62-84) | 68% (38/56; 55-79) | 14% (8/56; 7-26) | 16% (9/56; 9-28) | 71% / 66% |
| web_article | 42% (50/120; 33-51) | 43% (52/120; 35-52) | 5% (6/120; 2-10) | 5% (6/120; 2-10) | 31% / 29% |
| web_docs | 38% (45/120; 29-46) | 39% (47/120; 31-48) | 5% (6/120; 2-10) | 5% (6/120; 2-10) | 25% / 28% |
| web_forum | 44% (53/120; 36-53) | 33% (40/120; 26-42) | 5% (6/120; 2-10) | 5% (6/120; 2-10) | 27% / 24% |
| web_product | 47% (56/120; 38-56) | 39% (47/120; 31-48) | 5% (6/120; 2-10) | 5% (6/120; 2-10) | 32% / 28% |
| xlsx | 29% (21/72; 20-41) | 24% (17/72; 15-35) | 0% (0/72; 0-5) | 0% (0/72; 0-5) | 22% / 12% |

MCP and README false positives are all `unicode_tags` benign items (flag emoji in a description or README).

## By payload source (attack items)

| payload source | Ingress 0.10.0 (real entry points) (pub / held) | Ingress text scan (pub / held) | Ingress classifier only (pub / held) | 'ignore previous' regex (pub / held) |
|---|---|---|---|---|
| bipia_code | 26% (28/107) / 29% (30/103) | 21% (22/107) / 18% (19/103) | 0% (0/107) / 0% (0/103) | 0% (0/107) / 0% (0/103) |
| bipia_text | 19% (45/235) / 21% (55/260) | 20% (46/235) / 22% (57/260) | 0% (0/235) / 0% (0/260) | 0% (0/235) / 0% (0/260) |
| injecagent_base | 42% (79/186) / 43% (90/209) | 19% (36/186) / 21% (43/209) | 1% (1/186) / 1% (2/209) | 0% (0/186) / 0% (0/209) |
| injecagent_enhanced | 95% (141/149) / 95% (136/143) | 84% (125/149) / 86% (123/143) | 30% (45/149) / 50% (71/143) | 70% (105/149) / 70% (100/143) |
| paraphrased | 36% (118/325) / 27% (77/287) | 25% (80/325) / 18% (52/287) | 0% (0/325) / 0% (1/287) | 0% (0/325) / 0% (0/287) |


## Reproduce

```sh
git checkout bench/hib-v1 && npm ci && npm run build
pip install -r bench/hib/requirements.txt && npx playwright install chromium-headless-shell
bash bench/hib/run.sh
```

Verdicts: `bench/hib/results/{ingress-0.10.0,textscan,classifier,regex}-{public,heldout}.jsonl`; full reports with
every group and interval: `bench/hib/results/report-{public,heldout}.md`, `summary-*.json`; manifests:
`results/manifest-sha256.txt` (public `eea845b7...`, held-out `9bd0145c...`).
