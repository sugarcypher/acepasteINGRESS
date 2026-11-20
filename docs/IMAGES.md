# Images and QR codes

A person looks at a picture once, at one size, on one background. A model gets the pixels after a pipeline
has handled them: resized, flattened, one frame picked, the file's metadata sometimes passed along as text.
Each of those steps is a place to put words a person never sees. Ingress reads an image both ways and
compares.

```sh
ingress vision build            # compile the helper on this machine (macOS with Xcode or its command line tools)
ingress vision selftest         # build test pictures, screens and clips and check each trick is caught here
ingress --image photo.png       # gate one picture
ingress --image shot.png --capture=viewport --page-host=shop.example.com   # a browser tool's screenshot of that page
```

Library: `engine.scanImage(bytes, { caption?, source?, sourceText?, screen? })`. MCP: the `ingress_scan_image`
tool, and pictures inside any proxied tool's result. HTTP: `POST /v1/scan-image`. Claude Code: the
`PostToolUse` hook gates pictures the agent reads from disk and pictures in MCP results. Video has its own
page: [`VIDEO.md`](VIDEO.md).

## What is read

| view | what it is | what text found only there means |
|---|---|---|
| as shown | text recognition at full size, on white | this is the picture's visible text; it is delivered |
| resized without smoothing | nearest, bilinear and bicubic resampling to the sizes models use (1568, 1024, 768, 512, 448, 336, 224 px) and to whole-number fractions of the original | an image-scaling attack: words built for the resizer. Refused |
| resized with smoothing | the same sizes, antialiased | the baseline: what a person sees when the picture is shown small |
| contrast raised | histogram equalised; highlights and shadows stretched | text too faint for a person (near-white on white) |
| transparency | on a black background; and the colours of fully transparent pixels | text nobody sees, present for a pipeline that drops the alpha channel |
| later frames | frames 2 to 12 of an animation or multi-page file | a still view shows the first frame only |
| the file | PNG text chunks, JPEG comments, EXIF, XMP, IPTC, GIF comments; bytes after the image's end | text or another file riding along |
| codes | every QR code and barcode | the payload is for the machine: see below |

Text found only in a hidden view becomes concealed content and goes through the same meaning rules and
classifier as hidden text on a web page. Text from the visible view is judged like any visible text.

**Text recognition picks characters; authors do not.** Lookalike-letter checks are not applied to recognised
text (on small print the recogniser mixes alphabets freely). They are applied to metadata and code payloads,
whose characters are really in the file.

## QR codes and barcodes

A person cannot read a code. The payload is judged for what following it would do, and nothing is followed:

| payload | verdict |
|---|---|
| a web link | listed with its host; flagged when it hides its destination (`user@host`, a bare address, a shortener, an international lookalike). Open it only through `ingress_fetch` |
| `WIFI:` | an action: joining a network sends your traffic through whoever runs it. Held |
| `otpauth://` | a one-time-code secret. Held; the secret is never repeated in any message |
| `sms:`, `tel:`, `mailto:` | an action with the words filled in; short codes and `*#` dial codes are named |
| payment links, bank transfer codes | an action. Held |
| app links (`shortcuts://`, any custom scheme) | an action carrying instructions for an app. Held |
| plain text | scanned as concealed content |

When the words beside a code name one site and the code goes to another, that is reported
(`image.caption_mismatch`).

## Interface elements drawn into a page

A page can draw a browser window inside itself: a title bar, an address bar reading some other site's address,
a sign-in form underneath ("browser in the browser"). It can draw an operating-system dialog that asks for the
computer's password. Until 0.9.27 a painted-on dialog was caught only by its words (the paste-this lure) or
by comparing the screenshot with the page's own text (`sourceText`).

**In a picture, a drawn window and a real one are the same pixels.** A screenshot of a desktop with a real
sign-in pop-up over a browser, and a screenshot of a page that painted one, cannot be told apart by looking.
So appearance settles nothing on its own, with one exception that the caller has to supply:

| what the caller says | what a drawn window or dialog is worth |
|---|---|
| nothing | nothing, unless the picture shows its own address bar at the top naming a different site than the window inside it: then a note with next to no weight (`image.drawn_browser_window`, 0.05) |
| `capture: "viewport"`: the picture is a capture of a page's content area, as a browser-automation tool's screenshot is | real browser chrome and real system dialogs are never in such a picture, so the page painted what is seen. A drawn browser window, or a drawn system dialog: recorded below the suspect line (0.18). A drawn system dialog that asks for a password: suspect (0.29), since a page has no business asking for the computer's password |
| `capture: "viewport"` and `pageHost` | when the drawn address bar names a different site than the page is on: suspect (0.33). A site's own sign-in window shown on its own help page is not "a different site" |

Nothing here reaches hostile alone. A help article with a screenshot of a sign-in window is a drawn browser
window too. With other evidence in the same picture (instructions, the paste-this lure, words the page's
source does not have) the ordinary scoring adds them up.

What counts as a drawn browser window: a line that is nothing but an address, not in the top strip of the
picture, with a sign-in form under it (at least two lines of sign-in wording, one of them a short label or
button), inside the same rectangle when the helper found one. What counts as a system dialog: the wording of
a macOS or Windows permission or password prompt, with its buttons.

How to say how a picture was taken: `screen: { capture: "viewport", pageHost? }` in `scanImage`; `capture` and
`pageHost` in `POST /v1/scan-image`; `--capture=viewport --page-host=` on the command line; and for the MCP
proxy, `"screens": "viewport"` in a downstream server's `content` (or one tool's `toolContent`), in which case
the page's address is taken from the tool result's own text when it states one ("Page URL: ..."). The Claude
Code hooks cannot know which pictures are viewport captures, so they do not apply this check.

## Measured

- **Self-test pictures** (generated by the helper, so they are a check that the machinery works, not a
  benchmark): the scaling attack, faint text, text under transparency, second-frame text, a Wi-Fi code and a
  text code are refused; a plain chart, a textless photo and a menu link pass. A page with a browser window
  drawn into it is suspect when declared a viewport capture of another site, and clean when nothing is said;
  the same sign-in form with no window drawn around it is clean either way.
- **Drawn interface elements on ordinary screenshots** (ScreenSpot-v2, Apache-2.0: real web pages, desktop
  applications and phone screens; `tools/images/score-screens.mjs`). Every finding is a false alarm. The set
  was split in two by a hash of each file name before anything was read. Development half: the check fired
  on **0 of 386** screens, so the rules were left as first written. Hold-out half, scored once: **0 of 361**,
  in all three readings (nothing said; every picture declared a viewport capture, which is the worst case
  since desktop and phone screens are not; and declared a capture of a page on an unrelated site), and no
  verdict changed. None in 361 puts the false-alarm rate on screens like these under about 1 in 100. It
  says nothing about how many real drawn windows are caught: **recall is not measured**, and the only positive
  case is the one the helper draws.
- **Ordinary images** (Wikimedia Commons: photographs, posters, newspapers, charts, maps, comics, handwriting,
  logos, book covers, advertisements, QR codes, screenshots; `tools/images/`). Every refusal is a false alarm.
  See the results table in [`tools/images/README.md`](../tools/images/README.md), including the two sets that
  were spent finding problems and the one that was scored once at the end.

No public set of image-injection attacks was scored: none was found whose licence and contents could be
checked without looking at the attacks. Recall on real attacks is therefore **not measured**; what is
measured is that the mechanisms work on constructed cases and how often ordinary images are refused.

## Limits

- **macOS only for pixels.** The helper uses Apple's Vision framework. On other systems the file's metadata
  and structure are still checked, and every result says the picture itself was not read
  (`coverage.image.pixels: false`). The MCP proxy withholds pictures it could not read.
- **The resizing check tries common sizes and three kernels.** An attack built for a size or a resampler not
  in the list is not seen. The hook also reads the resized copy the harness actually produced, which covers
  that harness.
- **Only clear text counts as resize-only.** Lines must be read with full confidence by two kernels and look
  like words. A faint or partly legible payload is missed by that check (and may still be caught as text).
- **Adversarial noise is not text.** Perturbations crafted against one model, with no readable words in any
  view, are not detected. Neither is steganography that needs a decoder.
- **SVG is read as markup,** not rendered: its text is scanned whether shown or hidden.
- **HEIC, AVIF, BMP and ICO metadata is not read;** TIFF trailing data is not measured; an embedded EXIF
  preview picture is noted and not inspected.
- **About 2 to 5 seconds per image** on an Apple Silicon laptop (up to thirty or so text-recognition passes).
- **Text recognition is Apple's,** with its languages and its mistakes. A language it does not read is not read.
