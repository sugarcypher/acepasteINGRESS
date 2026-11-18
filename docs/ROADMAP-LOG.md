# Roadmap log

One line per change, newest last. Status: **done** (built and tested here), **partial** (built as far as it can
be tested without the listed need), **not built** (with the reason).

| version | phase | what | status | notes |
|---|---|---|---|---|
| 0.9.7 | - | Roadmap, this log, CHANGELOG.md, version bump tool | done | Releases from 0.9.7 are in CHANGELOG.md; older ones stay in the README |
| 0.9.8 | 11 | HTTP service Host and Origin checks; every spelling of a loopback or private address refused | done | Live-tested: rebinding and cross-site requests get 403. The Claude Code hook's loopback skip was fixed on the author's machine the same day (not a repo file then; shipped in the repo in a later version) |

## Needs from a person

Items that cannot be finished from this machine, and exactly what each needs. Filled in as the work proceeds.

| item | needs |
|---|---|
| Publishing to npm | Two-factor approval: `npm publish -w packages/core && npm publish -w packages/mcp -w packages/http` in a regular Terminal |
| Phase 4, machine-wide egress | An Apple Developer ID with the Network Extension entitlement, and notarization |
