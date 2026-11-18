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

## Needs from a person

Items that cannot be finished from this machine, and exactly what each needs. Filled in as the work proceeds.

| item | needs |
|---|---|
| Publishing to npm | Two-factor approval: `npm publish -w packages/core && npm publish -w packages/mcp -w packages/http` in a regular Terminal |
| Phase 4, machine-wide egress | An Apple Developer ID with the Network Extension entitlement, and notarization |
| An official PINT score | Only Lakera can produce one: email `opensource@lakera.ai` with `tools/pint/ingress_pint.py`, or request the dataset for research from `support@lakera.ai` |
| Turning the hooks on | They ship in the repo only. To use them: publish, `npm install -g @acepaste/ingress`, and merge `integrations/claude-code/settings.example.json` into `~/.claude/settings.json` (replacing the `ingress-route` Python hook there) |
