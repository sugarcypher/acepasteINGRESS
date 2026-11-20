# Changelog

Every change bumps the patch version of all three packages. The ruleset id changes only when a detector's
behavior changes; receipts carry it so verdicts are reproducible. Releases up to 0.9.6 are in the
[README](README.md#changes-in-096-2026-11-18-ruleset-20261118-3-unchanged).

## 0.9.24 (2026-11-19, ruleset 2026.11.19-2)

A different page is not yet an attack: the cloaking check now reads what the difference says.

The gate refused a search results page as hostile (score 0.85). The site had answered the AI fetcher with a
bot challenge ("complete the following challenge to confirm this search was made by a human", HTTP 202) and
the browser fetch with the results. 74% of the challenge page's 38 words were not on the results page, and
until now a page that differed that much was hostile on that fact alone, whatever it said.

- **What the agent-only part says now decides.** When most of the AI fetcher's page is absent from the
  browser's copy, the passages only the AI fetcher got are read the way hidden text is read (no person sees
  them): by the meaning rules and the classifier. If they read as instructions, the finding is scored as
  before and the page is hostile. If they do not, the page is suspect at most (a person can override), and
  the finding says so.
- **A stand-in page is unreachable, not an attack.** A short page (150 words or fewer) that says what bot
  challenges, block and rate-limit notices, error pages and "turn on JavaScript" stubs say, and carries no
  instruction, is not the page: nothing is delivered, the tier is `unreachable`, it is not written to the
  attack log, and it is not cached. No site is named in the rule.
- **The same the other way round.** When the browser-fingerprint fetch is the one given a stand-in, there is
  no browser copy to compare with: the page is judged on its own and the receipt records
  `acquire.cloaking_check_incomplete`, as it already did when that fetch failed. A page that instructs the
  agent is still hostile when browsers are shown a stand-in.
- **Unchanged:** the block band (the real page plus a passage only the AI receives) is scored as before, and
  so is a different page that carries instructions. The six earlier cloaking tests pass unmodified.

Measured: the search page, fetched six times after the fix, came back clean twice (both fetches got results),
clean with the comparison recorded as incomplete twice (the browser fetch was challenged), and unreachable
twice (the AI fetcher was challenged); never suspect or hostile. That URL is the case the fix was written
against, so it is a development case, not a held-out one. Corpus 90/90, 48/48, 3/3 and the 36 real pages
(31 clean, 5 suspect) are unchanged.

What this does not do: a site that serves AI fetchers a different page of plain false statements, with no
instruction in it, is suspect, not hostile. The check judges instructions, not truth. And a short page that
imitates a challenge is not delivered at all, which is safe but means an imitation is not reported as an
attack unless it carries an instruction.

Tests: core 381 pass (6 new), proxy 8.

## 0.9.23 (2026-11-19, ruleset 2026.11.19-1)

The retrained classifier is installed.

- **The n-gram classifier was retrained with ordinary text messages added** (2,198 real texts between people,
  from the development half of the UCI SMS set; the training set is now 76,217 texts). The model shipped
  since 0.9.16 had never seen how people text. Nothing else about the pass changed: same features, same
  authority by kind of content, and short-text mode (0.9.19) stays in place.
- **It was put in the repository by a person.** The automated run was not permitted to overwrite the model
  file; the owner ran the trainer and the tests, and this release re-scores and records it.

Re-scored on the sets the earlier model was scored on. Both hold-outs had been used before (the email set for
0.9.16, and its attack rows again as texts for 0.9.19), so they are spent as hold-outs: these are comparisons
with the earlier model on the same rows, not fresh measurements.

| set | 0.9.22 | 0.9.23 |
|---|---|---|
| email hold-out, attacks caught | 89.4% of 3,798 | 89.6% (3,402) |
| email hold-out, legitimate mail passed | 99.5% of 4,550 | 99.5% (4,527) |
| message hold-out, ordinary texts refused | 3 of 2,408 | 0 of 2,408 |
| message hold-out, attack emails sent as texts caught | 80.8% of 3,798 | 80.8% (3,068) |
| public text sets, pooled balanced accuracy | 73.3% | 73.2% (one all-benign set could not be downloaded this time, so the pools differ slightly) |
| built-in corpus | 90/90, 48/48, 3/3 | the same |
| 36 real pages | 30 clean, 5 suspect, 1 unreachable | 31 clean, 5 suspect; no verdict changed |

What it does not change: attacks in a language the model was not trained on (Turkish 3.3%, the multilingual
set about a third caught), and the classifier's limits listed in `tools/classifier/README.md`.

Also in `docs/ROADMAP-LOG.md`: 0.9.22 went to npm on 2026-11-19, and the "needs from a person" list is
brought up to date.

Tests: core 375 pass, proxy 8.

## 0.9.22 (2026-11-18, ruleset 2026.11.18-12)

Three loose ends from the roadmap run.

- **Recordings in MCP tool results are gated** (they were withheld unread). The proxy transcribes each one
  with the configured transcriber; a clean one is handed on with its transcript, and one that says something
  hostile, or cannot be transcribed, is withheld with the reason. The transcript joins what the run has read,
  so a code or an address spoken aloud is known to the action broker.
- **A screenshot against the page's own text** (`scanImage(bytes, { sourceText })`, finding
  `image.screen_not_in_source`): passages on the screen that the page's source does not contain were drawn
  there some other way, which is how a fake dialog is painted into a real window. Needs the caller to supply
  the page's text (its visible DOM text or accessibility tree).
- **README**: the corpus numbers were two releases stale (85/85 and 45/45; they are 90/90 and 48/48).

Still not built, as listed in `docs/ROADMAP-LOG.md`: video, a machine-wide filter, a multilingual model, an
installed retrained classifier.

Tests: core 375 pass (1 new), proxy 8 (1 new).

## 0.9.21 (2026-11-18, ruleset 2026.11.18-11)

Nearby devices, shortcuts, approvals that need a person present, fake "paste this" screens (Phases 7, 9, 10).
The last milestone of `docs/ROADMAP.md`.

- **Nearby** (`nearby.ts`, `kind: "nearby"`, `ingress nearby`): Bonjour service names, Bluetooth device names,
  printer descriptions and beacon links are read as content at the lowest trust (6). An instruction in a name or
  a record refuses the list. Reported: authority names from devices nobody here set up, a name one character
  from a device you know or the same chosen name at another address, links that hide their destination,
  oversized records. `ingress nearby` reads what this Mac lists (read-only: nothing is joined, paired or
  contacted). Found on the first live run and fixed: one device listed over both Bluetooth and Bonjour was
  taken for an impostor of itself.
- **Shortcuts** (`shortcuts.ts`, `kind: "automation"`, `ingress shortcut <file>`): a shortcut's actions are read
  for what it can do. Reads private data, takes input from outside, and can send things out, all three in one
  shortcut, is reported; so is running code. Every piece of text inside is scanned. JSON and XML property
  lists are read; a signed shortcut is encrypted and the result says it was not read.
- **Presence approvals** (`presenceApprover`, `native/ingress-presence.swift`, `INGRESS_APPROVER=macos-presence`,
  `ingress presence build`): after the dialog showing the exact action is approved, macOS confirms a person is
  there (Touch ID, an unlocked Apple Watch, or the login password). Anything else is a refusal.
- **ClickFix screens** (`image.clickfix`): a picture that tells its reader to open a terminal or the Run box
  and paste something.
- **README**: a section listing every channel added since 0.9.6, with where each is measured.
- **Not done.** The presence prompt was compiled and its availability checked (this Mac reports Touch ID), but
  no real approval was given through it: that needs a person. A FIDO2 security key is not supported. Fake
  interface elements in a screenshot, rendered text against page source, cameras, and other automation
  formats (launch agents and cron are covered by the persistence guard; Zapier, IFTTT, n8n exports are not
  read) are not built. No public set of malicious shortcuts or hostile device names was scored: these checks
  are tested on constructed cases.

Tests: core 374 pass (9 new), proxy 7.

## 0.9.20 (2026-11-18, ruleset 2026.11.18-10)

Captions, meeting transcripts and audio (Phase 8). Full description: `docs/AUDIO-CAPTIONS.md`. WebVTT, SubRip
and transcript JSON are now read as captions; `audio` is a new content kind; other verdicts are unchanged.

- **Captions** (`captions.ts`): cues on screen too briefly to read or sized to nothing, cues a `STYLE` block
  makes invisible, `NOTE` blocks, and, given a transcript of the audio (`scan(captions, { spoken })`), passages
  nobody said. Each becomes concealed text.
- **Meeting transcripts**: an utterance that speaks to the notetaker or assistant with something to do is
  reported, more strongly from a speaker listed as outside the organisation. A spoken approval is noted and
  is never an approval.
- **Audio** (`audio.ts`, `engine.scanAudio`, `ingress --audio`): the recording is transcribed as heard, with
  its quiet parts raised, and after three re-encodings a listener would not notice. Speech too quiet to make
  out is concealed text; a transcript that does not survive re-encoding is reported. The file's tags (ID3,
  WAV INFO, Vorbis comments) are scanned.
- **Transcription is pluggable**: `INGRESS_AUDIO_TRANSCRIBER` names a command. `tools/audio/transcribe.py` is a
  reference one (an open Whisper model, on the machine). Without one, tags are read and the result says the
  recording was not transcribed.
- **Found while building**: the speech model stops at the first long pause unless it decodes in short pieces,
  which would have skipped exactly the words hidden after a silence; and it invents "Thank you." for a noise
  floor. Both are handled in the reference transcriber.
- **Measured**: constructed recordings behave (plain speech passes; an instruction 40 dB under a podcast is
  refused; noise yields nothing); 24 of 24 LibriSpeech utterances are clean.
- **Not measured**: adversarial audio (none was made or scored); real recordings with music or crosstalk.
  **Not built**: a native macOS transcriber (needs a permission a person grants), audio in MCP tool results
  (still withheld), video.

Tests: core 365 pass (9 new), proxy 7.

## 0.9.19 (2026-11-18, ruleset 2026.11.18-9)

Messages and notifications (Phase 6): chat, text messages, and the banners an operating system shows
(`messages.ts`). JSON that is plainly a chat export or a notification is now read as one; other verdicts
are unchanged.

- **Chat messages** (`kind: "message"`): Slack, Discord, Telegram, Teams, WhatsApp, Messages and SMS exports,
  or anything with a sender and a text when the caller says it is a conversation. Checked:
  - what the app shows against what a program reads: Slack renders `blocks` and keeps `text` for notifications,
    Teams has a `summary`, a link preview has a plain-text `fallback`. Words only in the unseen one are
    concealed text;
  - hidden text inside an HTML message body, as on a page;
  - display names: "IT Support" or "System" from a bot, a webhook or someone outside the workspace, and names
    shaped like role markers;
  - scam shape, in short messages only: a link that hides where it goes with pressure or a request for a code,
    or a stranger asking for a code in an institution's name;
  - a verification code is noted (the action broker refuses to let one be sent to a destination from content);
  - voice notes, stickers and files are listed as not read.
- **Notifications** (`kind: "notification"`): app, title, body, actions, and the payload a banner does not show
  (concealed text). An alarm in the system's voice sent by a website through a browser, or in a brand's name
  from another site with pressure, is a source mismatch.
- **Short-text mode for the classifier.** In chat, notifications and device names, a text under 15 words is not
  judged by the classifier alone, and one under 40 needs 0.9. People text in imperatives; the model had never
  seen it and rated 1 ordinary text in 100 as an attack.
- **Measured** (`tools/message-eval`), hold-out halves scored once, every message read as from a stranger:
  3 of 2,408 ordinary text messages refused (0.1%); 4 of 2,900 ordinary emails sent as texts; 80.8% of 3,798
  attack emails sent as texts caught (short-text mode costs about 9 points against the email path). Spam texts
  are not caught (0.5%) and are not the target.
- **Not done.** The classifier was not retrained: the training tool takes ordinary texts now
  (`build_training_set.py --benign`), and a retrained model sits outside the repository, but installing a
  generated model file was not possible in this run. No present-day smishing corpus and no chat-native attack
  set were scored. A native notification reader (macOS, Android) is not built: notifications come in through
  the API, the MCP proxy or a caller.

Tests: core 356 pass (13 new), proxy 7.

## 0.9.18 (2026-11-18, ruleset 2026.11.18-8)

Images and QR codes (Phase 6): what a picture says to a person, and what it says only to a machine.
Verdicts on text are unchanged; `image` is a new content kind. Full description: `docs/IMAGES.md`.

- **`engine.scanImage(bytes)`**, `ingress --image <file>`, the MCP tool `ingress_scan_image`, `POST /v1/scan-image`.
  The delivered text is what a person can read in the picture, plus a line for each code in it.
- **The vision helper** (`packages/core/native/ingress-vision.swift`, macOS, Apple's Vision framework, nothing
  leaves the machine). Shipped as source and compiled on each machine (`ingress vision build`); its hash is
  recorded and checked before each use. `ingress vision selftest` builds nine test pictures and checks each trick.
- **Text a person is not shown** becomes concealed content and goes through the ordinary rules and classifier:
  - only after resizing without smoothing (an image-scaling attack): nearest, bilinear and bicubic resampling
    to the sizes models use, compared with every honest view of the picture;
  - only after the contrast is raised (near-white on white);
  - only on another background, or in the colours of fully transparent pixels;
  - only in later frames of an animation;
  - in the file: PNG text chunks, JPEG comments, EXIF, XMP, IPTC, GIF comments, and bytes after the image's
    end (`image-meta.ts`, pure TypeScript, every platform).
- **QR codes and barcodes** (`qr.ts`). The payload is judged for what following it would do: a link is listed
  with its host; joining a Wi-Fi network, a one-time-code secret, a text message, a payment and an app link
  are actions and are held; plain text is scanned as concealed content. Nothing is followed. Words beside a
  code that name another site are a mismatch.
- **Where pictures are gated.** The MCP proxy reads pictures in tool results: a clean one is handed on, one it
  refuses or cannot read is withheld with the reason (before, all pictures were withheld). The Claude Code
  hook reads pictures the agent opens, both the file on disk and the resized copy the harness hands the model,
  and replaces a refused one with a blank picture.
- **Lookalike-letter checks are not applied to recognised text**: the recogniser chose those characters.
- **Measured** (`tools/images/README.md`): on ordinary Wikimedia Commons images, an untouched set scored once
  gives 87 of 89 clean (97.8%), 2 suspect, none hostile. An earlier hold-out gave 93 of 95 before its two
  false alarms were fixed (it is development data since). The first cut refused 26 of 95: every image with
  dense text. Both remaining false alarms are recorded and not fixed.
- **Not measured: recall on real image attacks.** No public set was scored. The constructed test pictures
  show the mechanisms work.
- **Limits.** Pixels are read on macOS only; elsewhere the container is checked and the result says the
  picture was not read. The resizing check covers common sizes and three kernels. Adversarial noise with no
  readable words, and steganography that needs a decoder, are not detected. About 4 seconds per image.

Tests: core 343 pass (17 new, one runs the real helper), proxy 7 (1 new).

## 0.9.17 (2026-11-18, ruleset unchanged)

The egress gate (Phase 3): what an agent sends out or leaves behind, judged with what the run has read.
No verdict on content changes in this release.

- **`egress.ts`, in the action broker.** New checks, each with its reason in plain words:
  - a destination on a local blocklist of botnet and attack infrastructure is refused, whatever the run has
    read (`ingress blocklist update` downloads Feodo Tracker, Spamhaus DROP and Emerging Threats lists;
    `ingress blocklist check <host>`; your own lists go in `<state>/blocklists`);
  - a verification code the run read is refused toward a destination that came from outside content, and
    needs a person anywhere else (codes are recognised by the words around them: "zip code 90210" is not one);
  - a credential in the arguments, a print job, a copy to a removable drive, AirDrop or Bluetooth, a "localhost"
    port owned by a tunnel or proxy, ten or more email addresses in one action, and repeated requests to a
    host the run first met in outside content: each needs a person once the run has read outside content;
  - where a destination first appeared is named in the approval request ("first appeared in <source>").
- **`ingress hook pre-tool-use`**: the same checks for a coding agent. Replies "ask" or "deny" through the
  harness's own permission prompt. Reading outside content does not make every later command a question;
  the specific checks do the work. Shell commands are split so that reading a startup or settings file is
  not mistaken for editing one (`shellWrites`), and uploads are recognised (`shellUploads`: `curl -d @file`,
  `scp`, a pipe into `nc`, `git push <address>`, a request built from another command's output).
- **The session marker.** `SessionStart` states a random marker; any command that carries it, plainly or
  encoded, is refused: the context itself is leaving.
- **Session memory for hooks.** `PostToolUse` records what the session read (sources, hosts named, codes), so
  the egress gate, which runs as a new process per event, knows. What the person typed is recorded as theirs:
  a host they named is never reported as coming from content.
- **Provenance marks** (`provenance.ts`, `ingress provenance`). A file written after the session read outside
  content is marked with the session and its sources. When a later session reads it, the text is scanned and,
  if it is not clean, the reader is told where the file came from. Marks label and never withhold. A file
  macOS recorded as downloaded is gated when read, like a web page.
- **Every question and refusal is recorded** in `<state>/egress-log.jsonl` with its reasons, never the arguments.
- **The MCP proxy** now passes delivered text to the broker (codes, hosts), loads the blocklists and looks up
  what listens behind a loopback port.
- **Measured.** One long real session (1,177 tool calls) replayed as if it had read outside content from the
  start: 22 questions (1.9%), no refusals; 18 of them are the cases the gate exists for (edits to agent
  hooks, tool-server lists and memory; a copy to an external drive). The first cut asked 80 times. This
  session guided the fixes, so it is a development number. `tools/egress-replay/replay.mjs` repeats it.
- **Fixed.** An empty quoted argument (`''`) ended the command it was in for the shell splitter (0.9.14), so
  the words after it were read as a new command.
- **Not done.** AgentDojo was not run (it needs a model API key). Sharing fingerprints of refused destinations
  between machines is not built; everything stays local. Scope is judged by destination only. abuse.ch's
  host lists now need an account key and are not in the default set. The hook reads a command, not what a
  program it starts will do; a machine-wide filter is Phase 4.

Tests: core 326 pass (22 new), proxy 6.

## 0.9.16 (2026-11-18, ruleset 2026.11.18-7)

The learned pass (Phase 0): a small classifier beside the rules (`classifier.ts`, `classifier-model.ts`,
`tools/classifier/`).

- **What it is.** A logistic regression over hashed word 1-2-grams and character 3-5-grams, trained on 74,019
  public and generated texts. It ships inside the package (about 0.7 MB), has no runtime dependency, runs on
  the machine and scores a text in well under a millisecond. The TypeScript featurizer is checked against the
  trainer by parity vectors carried in the model.
- **What it may decide.** Alone it makes content suspect, never hostile; a rule agreeing with it can. Its
  authority depends on what it reads: hidden text anywhere (0.9), messages such as email and chat (0.8), plain
  text of unknown kind (0.85). On the visible text of pages and documents it is recorded and decides nothing,
  because it cannot tell writing about prompts from issuing them. Text is also scored with its quotations
  removed. `classifier: false` in the config reproduces rules-only verdicts.
- **Measured.**
  - Email hold-out, scored once (`tools/email-eval`): 89.4% of 3,798 attack emails caught, 99.5% of 4,550
    legitimate emails passed, 94.4% balanced accuracy (rules only: 32.1%, 99.6%, 65.8%).
  - Public text sets (`tools/pint`), a development set for this release: 46.7% of 2,021 attacks caught, 99.8%
    of 4,855 benign passed, 73.3% balanced accuracy (rules only: 11.1%, 99.9%, 55.5%).
  - Corpus eval unchanged: 90/90 attacks, 48/48 benign, 3/3 ambiguous.
  - 36 real pages (`npm run pages`): 30 clean, 5 suspect, none hostile.
- **What went wrong on the way, and is recorded in `tools/classifier/README.md` and `tools/email-eval/README.md`:**
  the first model had learned the email challenge's fixed goal (95% fell to 72% with the goal masked) and
  rated an unsubscribe footer at 0.94. Both were found by testing for them and fixed in the training data.
- **Limits.** Turkish attacks are caught no better than before (3.3%): a bag of words does not transfer between
  languages. The email number is one style of attack. Not a PINT score.

Also in this release:

- A hidden image with a few short named parameters is a tracking pixel, not exfiltration. Every analytics
  snippet has one in `<noscript>`; Wikipedia's rated its own article on prompt injection hostile. A hidden
  image counts when its address carries text out or the hidden text around it gives an order.
- `npm run pages`: fetches the pages in `tools/pages/real-pages.txt` through the gate and prints verdicts.

## 0.9.15 (2026-11-18, ruleset 2026.11.18-6)

Email and calendars as content types (Phases 1, 2, 9a, 9b; `email.ts`, `calendar.ts`, `served.ts`).

- **Email adapter.** Raw messages (MIME: nested multiparts, base64, quoted-printable, encoded headers) and
  the JSON that Gmail, Microsoft Graph and simple mail tools return, singly or as a list. Each piece becomes
  a segment with the visibility a person had of it: shown headers and the HTML part's visible text are
  visible; text the HTML hides, headers no client shows, and text only the plain part has are not.
  - *Plain part vs. HTML part:* a passage only the plain part has is read as hidden text
    (`email.part_divergence`).
  - *The sender:* Reply-To at another site (unless the message declares itself a mailing list), a display
    name that is another address, an authority name on a free mail address, failed authentication
    (`email.sender_mismatch`, `email.authentication_failed`).
  - *What it would fetch:* remote images and stylesheets are listed and never loaded
    (`email.remote_content`); an address with a placeholder to fill with data is flagged.
  - *Attachments:* text, HTML, invitations and nested messages are read; the rest are listed as not
    inspected (`email.uninspected_part`).
  - Marketing furniture (a hidden preheader, tracking pixels, a longer plain-text footer) is not a refusal.
- **Calendar adapter.** iCalendar text (events, to-dos, alarms) and Google Calendar and Graph event JSON.
  Titles, places, descriptions and attendee names are visible; alarm text, extension properties, links and
  inline attachments are not. A plain description that says what the formatted one does not is a divergence;
  an alarm that runs a program or sends email is reported (`calendar.alarm_action`).
- Mail and calendar JSON is recognised by its shape, raw messages by their headers, `.eml` and `.ics` by name.
- **MCP proxy:** a downstream server can be given `content: { kind, trust, channel }` (and `toolContent` per
  tool), so a mail server's results are read as email at the trust level the operator sets.
- The jailbreak-suffix check counts only beside other evidence in messages, logs and events, whose last lines
  are signatures and disclaimers.
- **Measured** (`tools/email-eval/`, `npm run email-eval`): on a hold-out sample scored once, 32.1% of 3,798
  LLMail-Inject attack emails caught and 99.6% of 4,550 legitimate emails (Enron, SpamAssassin ham) passed:
  65.8% balanced accuracy, rules only. Development sample: 36.0%, 99.8%, 67.9%. No attack message was read.

## 0.9.14 (2026-11-18, ruleset unchanged)

Hooks for coding agents: `ingress hook <event>` (Phases 10a and 12; `agent-hooks.ts`, `shell-commands.ts`,
`integrations/claude-code/`).

- **`post-tool-use`:** outside content a tool brought back is replaced by what the gate lets through.
  `WebFetch` is fetched again by the gate (with the cloaking comparison) and paged; `WebSearch`, MCP tools,
  shell commands that reach the network and background-task output files are scanned. Shell output is read
  as terminal output, so text hidden with control codes is found. Loopback is gated; only requests addressed
  solely to the Ingress service's own port are skipped. Fails closed in the tool's own output shape.
- **`user-prompt-submit`, the paste gate:** hidden characters anywhere in a prompt, and a pasted block rated
  hostile, stop the prompt and are shown to the person. A suspect paste goes through with a note to the model.
  A paste with markup partway through is also read as a page, and the stricter verdict kept. Typed text is
  never judged for what it asks. `[ingress: send as is]`, typed outside the paste, sends it anyway.
- **`pre-compact`, `post-compact`, `session-start`, the summary gate:** the summariser is asked to keep
  outside content marked as such; the summary is scanned; when it is flagged, the model is told at the
  restart that follows compaction. A session start also says when `ingress stop` is in effect.
- The engine runs in the hook's own process, or the hooks use a running Ingress service
  (`INGRESS_HOOK_SERVICE`) so its audit trail records what they gated.
- `integrations/claude-code/README.md` and `settings.example.json`. Nothing is installed by this release.

## 0.9.13 (2026-11-18, ruleset 2026.11.18-5)

Precision on real documentation. Found when the gate refused the Claude Code hooks reference as hostile
(score 1.0) while this roadmap was being built. Seven causes, each a refusal on a real page.

How pages are read (`visibility.ts`, `character.ts`):

- **Properties are matched by their exact names.** `-webkit-tap-highlight-color:transparent`, in the base
  stylesheet of every Tailwind 4 site, was read as transparent text on `<html>`, so the whole page counted
  as hidden. `background-color:rgba(0,0,0,0)`, `fill-opacity:0` and `--tw-bg-opacity:0` were misread the same
  way. Declarations are now parsed, not searched.
- **`var()` is resolved before judging.** Tailwind 4 writes every text size as `font-size:var(--text-sm)`;
  any variable-driven size, opacity, transform or display was treated as hidden. A variable is now resolved
  against every definition the stylesheet and the page's style attributes give it, and its fallback. It hides
  when any of those hides (`--o:0` with `opacity:var(--o)` is still caught); an undefined one is unknown.
- **Selectors that do not describe the default page are skipped.** A pseudo-element rule
  (`.scroll::-webkit-scrollbar{display:none}` hides a scrollbar) hid every table on the page. Rules for
  pseudo-elements, states (`:hover`, `[data-state=closed]`), theme or state ancestors, and media queries for
  print, dark mode or phone widths are no longer applied. `:not(.class)` and `.a.b` are now checked exactly.
- **Class names hide only as whole names.** `overflow-hidden`, `overflow-x-clip` and `bg-clip-text` were read
  as `hidden` and `clip`. Responsive variants are read for a desktop reader: `hidden lg:block` is shown,
  `lg:hidden` is not.
- **A zero-width character counts when it splits a word or runs in a row.** One alone (VitePress puts one in
  every heading anchor; ten rated vuejs.org hostile) or beside punctuation is layout. All are still removed
  from delivered text.

What reads as an instruction (`meaning.ts`):

- **Sending context out** needs the object to be the reader's own ("your conversation", "the system
  prompt"). "Send the messages array", "list API keys for a project" and "embed the conversation widget" are
  documentation. `include`, `attach` and `paste` count only in imperative position.
- **Descriptive shapes do not corroborate each other.** "The agent must call the API" and "Claude should use
  the weather tool" are a description; either beside a concealment, an override, a destination or a named
  secret still refuses.
- **A standing order** needs the order itself after its trigger ("from now on, respond only..."). "Whenever a
  hook exits with code 2, Claude Code prints..." has a subject doing the printing.
- **Concealment** is also recognised as "must not tell the user" and "without telling the user".
- A line-start label (`system:masters`) with no instruction within reach counts for half. Code under `<pre>`
  on an HTML page is scored as code.

Measured: 26 real documentation pages, 22 clean (the four refused are suspect: three are about or for AI
prompts, one serves AI fetchers different content). Before this release 8 of the first 20 were refused, one
as hostile. Eval unchanged (90/90 attacks, 48/48 benign). Public sets: 55.5% balanced accuracy on 6,876
inputs (0.9.12: 55.6%); attacks caught 11.1% (11.3%), the cost of the tighter context-exfiltration rule.
No attack example from those sets was read.

## 0.9.12 (2026-11-18, ruleset unchanged)

The environment audit looks at what is attached to the machine and what it exposes (`audit-local.ts`;
Phases 7, 10b, 10d, 11). All read-only, all tracked with the change tracking from 0.9.9.

- **Devices that can type** (macOS, `hidutil list`): every external device with a keyboard interface. One whose
  name says it is something else (a cable, a charger, a drive, a hub), or that has no name, is rated high. The
  audit cannot watch typing; it says which keyboards exist, so a new one is noticed.
- **Listening services** (`lsof`): grouped by program and exposure, not by port. A model or tool server
  reachable from the network (ollama, LM Studio, an MCP server) is rated high. Local-only listeners are
  listed but not tracked, since dev servers come and go.
- **Tunnels and forwards** among running processes: ngrok, cloudflared, ssh `-R` and `-D`, tailscale funnel,
  bore, frpc and others. Tokens in their arguments are not printed.
- **Printers** (`lpstat -v`): local printers are noted; one reached outside the local network, or two that share
  a name with different addresses, are for review. On Linux a running `cups-browsed` is flagged.
- **Network interfaces** (macOS): tracked by port name, so a new plug-in adapter shows up as a change.

## 0.9.11 (2026-11-18, ruleset 2026.11.18-4)

Streams, logs and terminal output (Phase 8a), and the groundwork every later channel uses.

- **Content kinds and source trust.** `scan()` takes `kind` (the channel: `log` now; `email`, `calendar`,
  `message`, `notification`, `nearby`, `automation`, `captions` as their adapters land) and `source`
  (`channel`, `sender`, `trust` 1 to 6). From trust level 4 (strangers) down, less evidence is needed to
  refuse: the suspect line is multiplied by 0.9, 0.85 (open channels, logs) and 0.7 (broadcasts). Trust never
  loosens the default. The receipt records the trust level when one was given. HTTP `/v1/scan` and the MCP
  `ingress_scan` tool accept the same hints.
- **Logs and terminal output (`terminal.ts`).** A terminal does not show what its bytes say. The adapter
  replays the bytes far enough to separate what a person would still see from what was hidden from them:
  concealed text (SGR 8), text in the background colour, text written and then erased, overwritten,
  cleared with the screen or the scrollback, or put in the window title. Hidden text is read by the meaning
  pass as hidden, so an instruction in it refuses the content; spinners and progress bars are not reported.
  Control codes that act on the person's machine are findings on their own: a clipboard write (OSC 52), and a
  link whose text names one site and whose target is another (OSC 8). Content with control sequences is
  detected as `log` whatever it claims to be; clean output is delivered without its colour codes.
- **Log injection.** An instruction planted in a field a visitor controls (a User-Agent, a username, an error
  message) is refused when the log is scanned.
- **`StreamScanner` / `scanStream()` (`stream.ts`).** Content judged as it arrives: each scan covers the
  unreleased text plus an overlap of text already released, so an instruction split across chunks is seen
  whole; the newest part is held back until more arrives; a verdict that turns bad stops the stream and names
  the already-released stretch to distrust (cut and retract). Tested at every chunk boundary through an
  attack: the instruction is never released, and a benign stream is released byte for byte.
- New pass name `channel` for findings about a channel's own structure.
- Public-set score unchanged: 55.6% on 6,876 inputs.

## 0.9.10 (2026-11-18, ruleset unchanged)

Broker safeguards that apply whatever the run has read (`safeguards.ts`; Phases 9d and 12).

- **Persistence guard.** An action that creates something which acts later always needs a person, even in a
  run that has read nothing from outside: scheduled jobs (cron, launchd, systemd), startup items and shell
  startup files, automations and shortcuts, mail rules and forwarding addresses, webhooks, hooks (git,
  agent settings), edits to an agent's own instruction or memory files and its list of tool servers, and
  login access (`authorized_keys`, sudoers). Recognised by tool name (writes only), field names, paths and
  shell commands. Policy: `persistenceGuard: "always" | "tainted" | "off"` (default `always`).
- **Canary tripwire.** `broker.plantCanary(runId)` returns a marker for the run's context; the MCP server
  hands it over with every delivered envelope. An action whose arguments carry it (plain, base64 at any
  alignment, hex, URL-encoded, reversed, or without its fixed prefix) is denied, not sent for approval:
  nothing a person asked for needs the marker to leave, so the conversation itself is being sent out.
- **Burst guard.** More than 20 actions a minute, or the same action more than 3 times in ten minutes, waits
  for a person (`burst` in the policy). Read-only tools never count.
- **Stop switch.** `ingress stop [reason]` makes every broker on the machine refuse every action, read-only
  tools included, until `ingress resume`. Anyone may stop, an agent included; resuming needs an interactive
  terminal. `ingress_status` reports it.
- Proxy end-to-end tests for the marker and the stop switch.

## 0.9.9 (2026-11-18, ruleset unchanged)

Change tracking, from Kith & Revere (`Baselines.swift`, `Changes.swift`), and tool definitions as outside content.

- **`changes.ts`:** snapshots compared run to run, and "confirm these are correct" baselines. Items are
  identified by what they are, never by notes, sizes or dates; a group new in this version is not a change on
  the machine; a confirmed set stays confirmed only while it is exactly that set. State lives in
  `INGRESS_STATE_DIR` (default `~/.acepaste-ingress/state`), owner-readable only, identities only.
- **Environment audit:** `ingress audit` now starts with what changed since the last audit and which areas a
  person has not confirmed. `ingress audit confirm <area>` confirms an area, from an interactive terminal only.
  An edited instruction file or hook counts as a change; blocklist sizes and the network's DNS servers do not.
- **MCP proxy, tool definitions:** a downstream server's tool names, descriptions and parameter schemas
  reached the model unchecked. Each definition is now gated (everything in it a model would read, including
  parameter descriptions and default values), and its fingerprint is recorded. A definition that is not
  clean is withheld. A definition that changes, or a tool that appears, after the set was recorded is held
  (a "rug pull"): the model sees a notice in its place and calls are refused until a person runs
  `ingress tools confirm <server>`. `ingress_status` lists held tools.
- First end-to-end tests of the proxy (`npm test -w @acepaste/ingress-mcp`): a real downstream server, the
  real proxy and a real client over stdio.

## 0.9.8 (2026-11-18, ruleset unchanged)

Phase 11, loopback: "it came from localhost" is not a trust boundary.

- **HTTP service local guard.** When `INGRESS_HOST` is a loopback address (or `INGRESS_ALLOWED_HOSTS` is set),
  every request must name this service in its `Host` header and may not carry another site's `Origin`. A web
  page in the user's browser can otherwise reach a local gate by DNS rebinding or a cross-site request; both
  are now refused with 403, on the endpoints that need no key too. `checkLocalRequest` and `isLoopbackBind`
  are exported for other local services.
- **Every spelling of a private address.** IPv6 addresses are expanded before they are judged, so
  `0:0:0:0:0:0:0:1`, `::ffff:127.0.0.1`, `::ffff:7f00:1`, zone ids (`fe80::1%en0`), IPv4-compatible `::127.0.0.1`,
  6to4 (`2002:7f00:1::`), NAT64 and deprecated site-local all give the same answer; an address that cannot be
  parsed is blocked. Hosts are compared without a trailing dot (`localhost.`).
- Tests for decimal, hex, octal and short IPv4 forms, and for public names that resolve to private space.

## 0.9.7 (2026-11-18, ruleset unchanged)

- `docs/ROADMAP.md`: the plan to extend Ingress to every channel an agent reads from or acts through, and to
  what agents send out. `docs/ROADMAP-LOG.md` tracks each change against it.
- This changelog. `tools/release/bump-version.mjs` bumps every package, the pins and `ENGINE_VERSION` in one step.
