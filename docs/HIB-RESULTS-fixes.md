# HIB results: fixes for the HIB v1 findings (ruleset 2026.11.28-1)

Ingress package version stays **0.10.0**; the ruleset id moves to **2026.11.28-1** because detector behaviour
changed (`CHANGELOG.md`, "Unreleased"). Baseline is Ingress 0.10.0 as released (`992d1eb`, scored in
`docs/HIB-RESULTS-0.10.0.md`). Both versions were scored through the same real entry points and harness
(`bench/hib/score/ingress.mjs`); see that document for the entry points and environment.

**Conflict of interest, and author bias.** HIB, its held-out splits and Ingress have the same author. In this round
the same agent also wrote the held-out-v2 payloads and templates *and* the detector fixes. Held-out-v2 was written
and frozen before the fixes were scored on it and was never used to tune them, but the person who imagined the new
variants also imagined the fixes, so the two may share blind spots or habits. Read the sealed numbers as the best
estimate available here, not as an independent evaluation.

## Headline: sealed held-out-v2 (scored once)

The held-out-v2 generator (template family C, new variants of every technique, 30 fresh paraphrased payloads) was
frozen in `c9231e6` before any scoring on it. Both versions were scored on it **once** (`9cd5c7b`); no detector was
changed after that.

| held-out-v2, 2,004 items | Ingress 0.10.0 | ruleset 2026.11.28-1 |
|---|---|---|
| attacks caught | 35.5% (356/1002; 32.6-38.5) | **60.1% (602/1002; 57.0-63.1)** |
| truly hidden attacks caught | 28.1% (194/690; 24.9-31.6) | **63.8% (440/690; 60.1-67.3)** |
| false positives | 4.8% (48/1002; 3.6-6.3) | **0.0% (0/1002; 0.0-0.4)** |

Cells: rate (k/n; Wilson 95% interval, %). "Truly hidden" is the report's *hidden payloads only* column: attack items
whose payload a person cannot see (`human_visible` not `yes` or `obfuscated`), so it drops the visible control and
the on-screen obfuscations (zero-width, homoglyph, bidi).

Three held-out-v2 benign items (`v00958`-`v00960`, `js_injected` controls) timed out on 0.10.0 (`unreachable`);
they are counted as not flagged, which if anything flatters the 0.10.0 false-positive rate.

## Held-out v1 (no longer sealed)

The v1 held-out split's generator was public and its 0.10.0 results had been published before the fixes, so it is no
longer a sealed test; it is reported for continuity.

| held-out v1 | Ingress 0.10.0 | ruleset 2026.11.28-1 |
|---|---|---|
| attacks caught | 38.7% (388/1002; 35.8-41.8) | 60.1% (602/1002; 57.0-63.1) |
| truly hidden attacks caught | 33.0% (228/690; 29.6-36.6) | 61.4% (424/690; 57.8-65.0) |
| false positives | 5.1% (51/1002; 3.9-6.6) | 0.3% (3/1002; 0.1-0.9) |

The three remaining false positives are `zero_width` benign items (`h01191`, `h01939`, `h01942`), already flagged
by 0.10.0.

## Public split (tuned on: an upper bound)

The fixes were developed against the public split, so these numbers are an upper bound, not an estimate.

| public | Ingress 0.10.0 | ruleset 2026.11.28-1 |
|---|---|---|
| attacks caught | 41.0% (411/1002; 38.0-44.1) | 77.6% (778/1002; 75.0-80.1) |
| truly hidden attacks caught | 36.5% (252/690; 33.0-40.2) | 86.8% (599/690; 84.1-89.1) |
| false positives | 4.9% (49/1002; 3.7-6.4) | 0.1% (1/1002; 0.0-0.6) |

The remaining false positive is `p01940` (`zero_width` benign), already flagged by 0.10.0.

Note on definitions: `docs/HIB-RESULTS-0.10.0.md` quoted "hidden only" figures that also exclude the tag-character
technique (n=642 per split). On that definition the change is 31.8% → 85.8% (204 → 551 of 642; 82.9-88.3) on public,
28.0% → 58.6% (180 → 376) on held-out v1 and 22.7% → 61.1% (146 → 392; 57.2-64.8) on held-out-v2. The tables above use
the report's own column (n=690) for every split.

## By technique

Attack items caught, 0.10.0 → **2026.11.28-1**. The last column is benign items flagged, 0.10.0 → 2026.11.28-1,
per split. Full cells with intervals, carriers and payload sources: `bench/hib/results/report-*.md`.

| technique | held-out-v2 (sealed) | held-out v1 | public (tuned on) | FP v2 / v1 / public (new) |
|---|---|---|---|---|
| `attr_hidden` | 5/38 → **19/38** | 10/38 → **18/38** | 11/38 → **33/38** | 0→0 / 0→0 / 0→0 |
| `bidi_override` | 48/48 → **48/48** | 48/48 → **48/48** | 48/48 → **48/48** | 0→0 / 0→0 / 0→0 |
| `css_clip` | 8/30 → **20/30** | 6/30 → **14/30** | 14/30 → **26/30** | 0→0 / 0→0 / 0→0 |
| `css_color_match_bg` | 2/30 → **8/30** | 5/30 → **6/30** | 11/30 → **28/30** | 0→0 / 0→0 / 0→0 |
| `css_display_none` | 8/30 → **13/30** | 12/30 → **16/30** | 12/30 → **26/30** | 0→0 / 0→0 / 0→0 |
| `css_font_size_zero` | 6/30 → **19/30** | 14/30 → **24/30** | 6/30 → **26/30** | 0→0 / 0→0 / 0→0 |
| `css_offscreen` | 11/30 → **22/30** | 8/30 → **18/30** | 14/30 → **27/30** | 0→0 / 0→0 / 0→0 |
| `css_opacity_zero` | 7/30 → **18/30** | 5/30 → **14/30** | 9/30 → **25/30** | 0→0 / 0→0 / 0→0 |
| `css_visibility_hidden` | 9/30 → **17/30** | 7/30 → **17/30** | 11/30 → **27/30** | 0→0 / 0→0 / 0→0 |
| `docx_hidden_run` | 7/24 → **20/24** | 13/24 → **20/24** | 8/24 → **19/24** | 0→0 / 0→0 / 0→0 |
| `docx_tiny_text` | 5/24 → **17/24** | 5/24 → **15/24** | 10/24 → **23/24** | 0→0 / 0→0 / 0→0 |
| `docx_white_text` | 7/24 → **17/24** | 9/24 → **16/24** | 6/24 → **24/24** | 0→0 / 0→0 / 0→0 |
| `homoglyph` | 39/48 → **39/48** | 41/48 → **41/48** | 40/48 → **40/48** | 0→0 / 0→0 / 0→0 |
| `html_comment` | 10/48 → **23/48** | 12/48 → **26/48** | 13/48 → **34/48** | 0→0 / 0→0 / 0→0 |
| `iframe_srcdoc` | 8/24 → **17/24** | 3/24 → **15/24** | 11/24 → **20/24** | 0→0 / 0→0 / 0→0 |
| `js_injected` | 0/24 → **0/24** | 0/24 → **18/24** | 0/24 → **20/24** | 0→0 / 0→0 / 0→0 |
| `mcp_param_description` | 0/10 → **0/10** | 2/10 → **2/10** | 3/10 → **3/10** | 0→0 / 0→0 / 0→0 |
| `noscript` | 4/24 → **17/24** | 8/24 → **14/24** | 8/24 → **18/24** | 0→0 / 0→0 / 0→0 |
| `pdf_tiny_text` | 7/24 → **18/24** | 8/24 → **13/24** | 5/24 → **19/24** | 0→0 / 0→0 / 0→0 |
| `pdf_white_text` | 6/24 → **18/24** | 8/24 → **16/24** | 9/24 → **22/24** | 0→0 / 0→0 / 0→0 |
| `png_text_metadata` | 5/24 → **18/24** | 4/24 → **11/24** | 6/24 → **23/24** | 0→0 / 0→0 / 0→0 |
| `pptx_speaker_notes` | 5/24 → **13/24** | 10/24 → **18/24** | 9/24 → **22/24** | 0→0 / 0→0 / 0→0 |
| `svg_text` | 7/24 → **16/24** | 10/24 → **16/24** | 7/24 → **19/24** | 0→0 / 0→0 / 0→0 |
| `template` | 0/24 → **14/24** | 0/24 → **19/24** | 0/24 → **21/24** | 0→0 / 0→0 / 0→0 |
| `ua_cloaking` | 7/24 → **18/24** | 7/24 → **13/24** | 5/24 → **19/24** | 0→0 / 0→0 / 0→0 |
| `unicode_tags` | 48/48 → **48/48** | 48/48 → **48/48** | 48/48 → **48/48** | 48→0 / 48→0 / 48→0 |
| `visible` | 27/144 → **27/144** | 23/144 → **23/144** | 23/144 → **23/144** | 0→0 / 0→0 / 0→0 |
| `xlsx_hidden_cells` | 6/24 → **12/24** | 8/24 → **16/24** | 11/24 → **23/24** | 0→0 / 0→0 / 0→0 |
| `xlsx_hidden_sheet` | 6/24 → **18/24** | 6/24 → **19/24** | 5/24 → **24/24** | 0→0 / 0→0 / 0→0 |
| `zero_width` | 48/48 → **48/48** | 48/48 → **48/48** | 48/48 → **48/48** | 0→0 / 3→3 / 1→1 |

**Nothing got worse.** On every split, no technique, carrier or payload source lost detection, and no benign group
gained a false positive. The false-positive drop is the tag-character fix (48 → 0 in each split: the three RGI
subdivision flags are no longer flagged); the only remaining false positives are the four zero-width benign items above,
unchanged from 0.10.0.

## Still weak on held-out-v2

- **`js_injected`: 0/24.** The same fix caught 18/24 on held-out v1 and 20/24 on public, so the inline-script
  heuristic that decides when to render does not generalize to v2's variants (JSON data islands, reversed strings,
  `document.write`).
- **`mcp_param_description`: 0/10** (nested-property and schema descriptions in MCP tool lists).
- **`css_color_match_bg`: 8/30** (near-background text on a tinted page, `rgb()` or CSS-variable colours).
- **Visible control: 18.8% (27/144)**, unchanged: plain-text detection of task-style requests is still low.
- **Targetless hidden requests:** hidden text that asks for something without naming a target still often passes;
  the `bipia_text` payload source, mostly such requests, is caught at 46.0% (125/272) on v2.

## Plain-text evals, real pages, latency

- **Plain-text evals unchanged vs 0.10.0:** BIPIA, InjecAgent, PINT-style pooled 46.7%, Turkish 0/2875, READMEs 0/35,
  email hold-out 89.6% of attacks and 99.5% of benign passed, SMS 0/2408, corpus 90/90 and 48/48. Two SpamAssassin
  ham false positives were fixed during development, so the ham figure is optimistic (it was in the loop).
- **69 saved real pages:** identical verdicts to 0.10.0; 0 of 62,426 hidden segments fired.
- **Latency:** the render pass on script-inserted text adds about 2 s on about 7% of real pages (about +7% total
  wall time). There is no formal sequential latency benchmark.

## Tests

Re-run on `fix/hib-v1-findings` (Node v22.23.5, linux): **core 542 pass, 0 fail, 3 skipped (545 tests); mcp 9/9.**

## Reproduce

```
npm ci && npm run build && pip install -r bench/hib/requirements.txt
node bench/hib/score/ingress.mjs --split <split>   # with the ruleset under test
python3 bench/hib/score/report.py --split <split> \
  --defense "Ingress 0.10.0 (real entry points)=results/ingress-0.10.0-<split>.jsonl" \
  --defense "Ingress ruleset 2026.11.28-1 (real entry points)=results/ingress-2026.11.28-1-<split>.jsonl"
```

Verdict files: `bench/hib/results/ingress-{0.10.0,2026.11.28-1}-{public,heldout,heldout-v2}.jsonl`.
