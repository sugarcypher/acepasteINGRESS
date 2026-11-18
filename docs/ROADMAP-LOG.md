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

## Needs from a person

Items that cannot be finished from this machine, and exactly what each needs. Filled in as the work proceeds.

| item | needs |
|---|---|
| Publishing to npm | Two-factor approval: `npm publish -w packages/core && npm publish -w packages/mcp -w packages/http` in a regular Terminal |
| Phase 4, machine-wide egress | An Apple Developer ID with the Network Extension entitlement, and notarization |
