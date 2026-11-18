# Roadmap log

One line per change, newest last. Status: **done** (built and tested here), **partial** (built as far as it can
be tested without the listed need), **not built** (with the reason).

| version | phase | what | status | notes |
|---|---|---|---|---|
| 0.9.7 | - | Roadmap, this log, CHANGELOG.md, version bump tool | done | Releases from 0.9.7 are in CHANGELOG.md; older ones stay in the README |
| 0.9.8 | 11 | HTTP service Host and Origin checks; every spelling of a loopback or private address refused | done | Live-tested: rebinding and cross-site requests get 403. The Claude Code hook's loopback skip was fixed on the author's machine the same day (not a repo file then; shipped in the repo in a later version) |
| 0.9.9 | K&R | Change tracking (snapshots, confirmed baselines) for the environment audit; MCP tool definitions gated and fingerprinted | done | Found while building: downstream tool descriptions reached the model unscanned. Poisoned definitions are withheld; changed ones are held until `ingress tools confirm <server>`. First-seen sets are recorded, not confirmed |
| 0.9.10 | 9d, 12 | Broker safeguards: persistence guard (automation write guard), canary tripwire, burst guard, stop switch | done | Persistence needs a person even in a clean run. A canary hit is a denial, not an approval question. Stop: anyone may stop, only a person at a terminal may resume |
| 0.9.11 | 8a, foundations | Content kinds and source trust on `scan()`; log and terminal adapter; log injection; `StreamScanner` with cut and retract | done | Added beyond the plan: terminal control codes that hide text from a person or act on their machine (clipboard write, mismatched link). Streams release raw text, not normalised text |
| 0.9.12 | 7, 10b, 10d, 11 | Audit: devices that can type, listening services, tunnels, printers, network interfaces | done (macOS; lsof/ps/lpstat parts also on Linux) | The "Allow accessories to connect" setting is not read: no documented, readable location for it was found. Composite-device detection (keyboard plus storage) is by name only |
| 0.9.13 | 0 (precision) | Seven causes of refusing real documentation fixed: CSS property matching, `var()`, pseudo-element and state selectors, class-name hints, zero-width layout characters, descriptive instruction shapes, `<pre>` code | done | Not planned: found because the gate on the author's machine refused the Claude Code hooks reference as hostile. 22 of 26 real pages clean after; recall on public sets 11.3% to 11.1% |
| 0.9.14 | 10a, 12 | `ingress hook <event>`: PostToolUse routing, paste gate, summary gate, stop notice; Claude Code integration folder | done (repo only, not installed) | Replaces the one-off Python hook on the author's machine with a tested implementation. PostCompact cannot change a summary, so a flagged summary is reported at the SessionStart that follows. The PreToolUse egress hook comes with Phase 3 |
| 0.9.15 | 1, 2, 9a, 9b | Email adapter (MIME and mail JSON), calendar adapter (iCalendar and event JSON), remote content listed not loaded, MCP proxy content hints, email scoring tools | done | Hold-out: 32.1% of real attack emails caught, 99.6% of legitimate mail passed (rules only). PDF and Office attachments are listed as not inspected. IMAP proxy and mail-client plug-in not built: the MCP proxy and the hooks are the supported routes |
| 0.9.16 | 0 | Learned pass: n-gram classifier in the engine, training and scoring tools; hidden tracking pixels no longer count as exfiltration | done, with limits | Email hold-out 65.8% to 94.4% balanced accuracy; public text sets 55.5% to 73.3%. Decides on hidden text, messages and plain text, not on visible page text. Not built: a multilingual embedding model (Turkish unchanged at 3.3%). Still needed from Lakera: an official PINT run |
| 0.9.17 | 3, 9, 10, 11, 12 | Egress gate in the broker and as a PreToolUse hook: blocklists, verification codes, credentials, uploads, peripherals, tunnels behind localhost, calling home, mass sending; session marker; provenance marks on agent-written files; downloaded files gated on read; decision log | done, with limits | 1.9% of a real session's 1,177 tool calls questioned, none refused (development measurement). Not done: AgentDojo run (needs a model API key), shared fingerprints, scope by meaning. abuse.ch host lists need an account key |
| 0.9.18 | 6 (images, QR codes) | `scanImage`: vision helper (Swift, compiled per machine), resizing, contrast, transparency and frame checks, metadata and appended data, QR payload judge; pictures gated in the MCP proxy and the Claude Code hook | done, with limits | Ordinary images, untouched set scored once: 87 of 89 clean, none hostile. Recall on real image attacks not measured (no public set scored). Pixels are read on macOS only. Not built: on-device reading on Linux or Windows; rendering SVG; reading embedded EXIF previews |
| 0.9.19 | 6 (messages, notifications), 0 (short-text mode) | Message adapter (Slack, Discord, Telegram, Teams, WhatsApp, SMS exports) and notification adapter; shown-vs-read divergence, sender names, scam shape, payload fields; classifier short-text mode | done, with limits | Hold-out: 0.1% of 2,408 ordinary texts refused; 80.8% of attack emails sent as texts caught. Not done: retrained classifier installed (see below); present-day smishing and chat-native attack sets; native notification readers |
| 0.9.20 | 8 (audio, captions), 12 | Caption adapter (unreadable and hidden cues, captions vs. speech), meeting transcripts (speaking to the notetaker; a voice is never an approval), `scanAudio` with a pluggable transcriber and a reference Whisper script, audio tags | done, with limits | Constructed cases pass; 24 of 24 real speech clips clean. Not measured: adversarial audio, noisy real-world recordings. Not built: native macOS transcriber, audio in MCP results, video frames |
| 0.9.21 | 7, 9c, 10e, 8 (screens, part) | Nearby adapter and `ingress nearby`; shortcut scanner; presence approver (Touch ID or password through macOS); ClickFix screen check; README channel table | done, with limits | Live nearby scan of the author's Mac: 17 records, clean after one false alarm was fixed. Not done: a real approval through the presence prompt (needs a person), FIDO2 keys, fake-interface detection in screenshots, rendered-vs-source, cameras, other automation formats |

## What was not built at all

| item | why |
|---|---|
| Phase 4, machine-wide egress filter | Needs Apple's Network Extension entitlement and notarization (see below). The roadmap marked it optional |
| Phase 1: IMAP proxy, mail-client plug-in | The MCP proxy and the hooks are the supported routes; a mail proxy handles credentials for every account and deserves its own design |
| Phase 3: sharing fingerprints of refused destinations between machines | Everything stays on the machine; a sharing service is a product decision, not a build step |
| Phase 6: native notification readers (macOS, Android) | No supported way to read other apps' notifications from a command-line tool; notifications come in through the API |
| Phase 8: video (briefly shown frames, captions against the picture), cameras | Not started; audio and captions took the milestone |
| Phase 8: fake interface elements in screenshots, rendered text against page source | Only the ClickFix text pattern is built |
| Phase 0: a multilingual embedding model | The n-gram classifier does not transfer between languages (Turkish 3.3%); a second model was not trained |

## Needs from a person

Items that cannot be finished from this machine, and exactly what each needs. Filled in as the work proceeds.

| item | needs |
|---|---|
| Publishing to npm | Two-factor approval: `npm publish -w packages/core && npm publish -w packages/mcp -w packages/http` in a regular Terminal |
| Phase 4, machine-wide egress | An Apple Developer ID with the Network Extension entitlement, and notarization |
| An AgentDojo score (Phase 3 proof) | A model API key (Anthropic or OpenAI) and a budget for the runs; the suite drives a live model through its tasks |
| Malware host lists from abuse.ch (URLhaus, ThreatFox) | A free abuse.ch account key; save the lists into `~/.acepaste-ingress/state/blocklists/` |
| Reading pictures on this Mac | Nothing to buy: `ingress vision build` after installing a published version (it compiles the helper with the Swift compiler already here) |
| A score on real image attacks | A set of image-injection attacks someone is entitled to share; none was found that could be checked without reading the attacks |
| Installing a retrained classifier | A person to run the trainer with its output in the repository: `python tools/classifier/train.py <work> --out packages/core/src/classifier-model.ts`, then `npm test` (the parity test checks it) and re-scoring. The automated run was not permitted to overwrite the model file, which is a fair line: a generated 0.7 MB file that changes what a security gate refuses should be put there by someone who can be asked why |
| Transcribing audio on this Mac | A Python environment with `torch transformers scipy numpy` and `INGRESS_AUDIO_TRANSCRIBER` pointing at `tools/audio/transcribe.py` (one exists on the lab drive). A native transcriber on Apple's speech framework would need you to grant Speech Recognition permission when it first runs |
| Trying the presence approval | You: `ingress presence build`, set `INGRESS_APPROVER=macos-presence` for the MCP server, and approve one action with your finger. It was compiled and checked here, never answered |
| An official PINT score | Only Lakera can produce one: email `opensource@lakera.ai` with `tools/pint/ingress_pint.py`, or request the dataset for research from `support@lakera.ai` |
| Turning the hooks on | They ship in the repo only. To use them: publish, `npm install -g @acepaste/ingress`, and merge `integrations/claude-code/settings.example.json` into `~/.claude/settings.json` (replacing the `ingress-route` Python hook there) |
