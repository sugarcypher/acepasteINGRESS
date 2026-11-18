# AcePaste Ingress roadmap

Written 2026-11-18 against 0.9.6. Progress is tracked in [ROADMAP-LOG.md](ROADMAP-LOG.md).

Ingress gates web pages, tool results and documents before an AI agent reads them. This plan extends it to every
channel an agent can read from or act through, and adds the other direction: what agents send out.

## What sets Ingress apart

1. **What a person sees vs. what the machine gets.** Text a person would not see or notice is the signal: hidden
   CSS today; then an email's text part vs. its HTML part, an image that changes when shrunk, captions vs. spoken
   audio, the rendered page vs. its source, a notification vs. its summary.
2. **Where it came from, over time.** Ingress sees both the content an agent read and the action it then tries.
   Every refusal names its cause. Content an agent writes during a tainted run keeps that mark, so a planted
   reminder or memory file is still untrusted when a later session reads it.
3. **Everything stays on the machine.** Text recognition, transcription and the classifier run on-device.
   Receipts store fingerprints, not text. Email, messages and notifications never enter any shared feed.

## Shared foundations

**Content types.** Each channel is a content type with its own adapter, so the existing passes run on it
unchanged: `email`, `calendar`, `message`, `notification`, `image`, `audio`, `video`, `screen`, `nearby`,
`automation`, `log`. Every item carries where it came from.

**Trust by source.** Who could have written the content sets how strict the verdict is.

| level | source |
|---|---|
| 1 | you, typing or approving through the broker's own channel |
| 2 | known contacts, your own calendars and lists, files you created |
| 3 | content agents wrote earlier (trusted only if the run that wrote it was clean) |
| 4 | strangers: unknown senders, voicemail, fax, invitations, downloaded files |
| 5 | open channels: public chat channels, group chats, subscribed calendars, the web |
| 6 | broadcasts: Bonjour, Bluetooth, beacons, anything on a shared Wi-Fi |

**Rules that do not change.** Delivered content is never altered. A verdict never authorizes an action; only a
person approves, through a channel the model cannot drive. Scores come from held-out sets, spent sets are
disclosed, and no rule is written from attack examples.

**Change tracking (from Kith & Revere).** Items are identified by what they are (path, label, program), never by
notes, sizes or dates. Each run is compared with the previous one. "Confirm these are correct" baselines pass
until something changes, then show exactly what changed. Files are verified by hash before use. Applied to: the
environment audit, MCP tool definitions (a changed description goes back to review), hooks and instruction
files, automations, paired devices, printers, and content read again.

## Phases

| phase | channel | the new idea |
|---|---|---|
| 0 | Detection core | A local learned classifier next to the rules |
| 1 | Email | Text part vs. HTML part; email furniture never refuses on its own |
| 2 | What email makes agents fetch | No auto-loading; link checks with the cloaking comparison |
| 3 | Egress | Every outbound action checked, with the content that caused it |
| 4 | Machine-wide egress | Network filter tied to agent provenance (optional; needs Apple entitlement) |
| 6 | Images, QR codes, messages, notifications | Scaling check; QR payloads; sender trust; codes never leave |
| 7 | Nearby: Bonjour, Bluetooth, printers | Broadcast strings as the lowest-trust content |
| 8 | Streams, audio, visual | Streaming verdicts; audio transformation check; captions vs. audio |
| 9 | Calendars, reminders, shortcuts, automations | Provenance marks over time; write guard for persistence |
| 10 | Peripherals and the clipboard | Paste gate; fake-keyboard audit; hardware-key approvals |
| 11 | Loopback and local services | localhost is not a trust boundary |
| 12 | Protecting the agent itself | Canary tripwires, summary and memory gates, a stop switch, scope checks |

There is no Phase 5; the numbers follow the order the topics were added in.

### Phase 0: detection core
Recall on reworded attacks is 11% (55.6% balanced accuracy on 6,876 public inputs; 6 of 4,855 benign refused).
Add a learned classifier pass, on-device, voting alongside the rules. The classifier alone reaches suspect;
hostile needs agreement with a rule, hidden placement or another signal. Short-text mode for messages,
notifications and device names. Proof: held-out public sets and an official PINT run requested from Lakera.

### Phase 1: email
Adapter for MIME, `.eml`, Gmail and Graph JSON. Checks: text part vs. HTML part, hidden text addressing an
assistant, sender details aimed at the agent (Reply-To vs. From, authority display names), attachments, scans
and faxes. Preheaders and tracking pixels are furniture: recorded, never a refusal alone. Runs first behind
the MCP proxy. Proof: LLMail-Inject (attacks), Enron and SpamAssassin public mail (benign), licenses checked.

### Phase 2: what an email makes the agent fetch
Remote images, CSS and pixels are listed, never fetched into the agent's context. Links the agent wants to
follow go through `ingress_fetch` with the cloaking check. Data-carrying links are flagged.

### Phase 3: egress
PreToolUse egress hook plus the broker: secrets and personal data leaving, destinations that came from
untrusted content, encoded payloads, mass sending, calling home, known-bad destinations (local blocklists).
Print jobs, removable drives, AirDrop and Bluetooth transfers are side effects. One-time codes never leave.
Every refusal records its cause. Shared defense is opt-in and shares fingerprints only. Scope: detect, block,
report; no counterattacks. Proof: AgentDojo, including the workspace suite.

### Phase 4: machine-wide egress (optional)
A macOS network filter for every app. Needs Apple's Network Extension entitlement and notarization. Build only
if Phase 3 shows the content-to-action link is valuable.

### Phase 6: images, QR codes, messages, notifications
- **Images:** on-device text recognition (Vision via a Swift helper); the scaling check (text or a different
  picture that appears only after shrinking); contrast check; transparency tricks; extra frames, thumbnails and
  companion images; text inside the file (EXIF, XMP, PNG text chunks, trailing data, polyglots); the
  "decode the hidden message" two-stage attack. Limit: pixel-level adversarial noise is not reliably detectable.
- **Messages:** group and channel injection, smishing, invisible Unicode, link previews, spoofed names; sender
  trust from the ladder; behind the MCP proxy first.
- **Notifications:** a `notification` type with source app and sender; text that does not fit its source;
  one-time codes never leave. Platform access is limited, so it ships as an API first.
- **QR codes:** decode every code; judge the payload (`WIFI:`, `otpauth://`, `sms:`, `tel:`, deep links,
  payment links, plain text); caption vs. contents; links through `ingress_fetch`.

### Phase 7: nearby devices and the local network
A `nearby` type for Bonjour names and TXT records, Bluetooth names and data, beacon URLs, printer strings.
Checks: meaning and character passes, impersonation, lookalike services, timing. Audit: cups-browsed, printers
added automatically, copied device names. Limit: Ingress cannot stop broadcasts, only gate what agents read.

### Phase 8: streams, audio, visual
- **Streams:** `scanStream()` with overlapping windows, a hold-back buffer and cut-and-retract; log injection.
- **Audio:** on-device transcription; the transformation check (commands that survive only some re-encodings);
  hidden speech; speaker trust for meeting notetakers; a voice is never an approval.
- **Visual:** captions vs. audio; hidden caption cues; briefly shown frames; screenshot interception and fake
  UI for computer-use agents; rendered text vs. page source; cameras.

### Phase 9: calendars, reminders, shortcuts, automations
- **Calendars:** every event field scanned with its sender; events as dormant triggers; subscribed calendars
  rescanned on refresh.
- **Reminders:** who wrote an item decides; provenance marks on everything an agent writes during a tainted run.
- **Shortcuts:** scan actions before import; flag reads-private-data + outside input + can-send-out.
- **Automations:** outsider-controlled triggers; a write guard so creating automations, email rules,
  forwarding addresses, scheduled jobs or login items always needs approval; audit comparisons.

### Phase 10: peripheral devices and the clipboard
Paste gate on prompts (pastejacking, ClickFix, invisible Unicode). Fake keyboards and BadUSB in the audit.
File names as content; quarantine attributes as provenance. New network interfaces. Hardware-key approvals.

### Phase 11: loopback and local services
Content from localhost is outside content. Host and Origin checks on the HTTP service. Tests for every
spelling of a loopback address. Audit of what listens and to whom. A loopback port that is a tunnel or proxy
is an internet destination.

### Phase 12: protecting the agent itself
Checks an agent would want between itself and the world:
- **Canary tripwires:** a secret marker placed in the agent's context; if it ever appears in an outbound
  action, exfiltration is proven and the action is refused.
- **Summary gate:** when a long conversation is compacted, the summary is scanned, so an instruction planted in
  earlier content cannot ride into the next context as if the agent or user had written it.
- **Memory and instruction-file gate:** memory files and instruction files are scanned when read and
  fingerprinted when approved; a change sends them back to review.
- **Task-scope check:** an action that touches a destination or resource unrelated to what the person asked
  for needs approval.
- **Stop switch:** one file or command that makes the broker deny every side effect until a person clears it.
- **Loop and burst guard:** repeated identical or rapidly repeated side effects are held.
- **Coverage honesty:** every result says what was not inspected, so "clean" never means "not looked at".

## Build order

1. **Foundations and quick wins:** loopback gaps, change tracking, paste gate, automation write guard, log
   injection on the streaming API, keyboard-device audit, agent self-protection basics. Classifier starts.
2. **Email and calendar** behind the MCP proxy; no auto-loading; link checks.
3. **Egress gate,** provenance marks, canaries, scope checks.
4. **Images and QR codes.**
5. **Messages and notifications.**
6. **Streams, captions and audio.**
7. **Screens, nearby, printers, shortcuts, quarantine provenance, hardware-key approvals.**

Later, on demand: machine-wide egress, camera agents, native notification readers.

## What Ingress will not claim

- Detecting pixel-level adversarial noise in images, or physical adversarial patches.
- Detecting cloned voices, or ultrasonic commands from a normal recording.
- Stopping broadcasts or attacks on other devices.
- Counterattacks or takedowns. It blocks and reports.
- An official PINT score before Lakera runs one.
