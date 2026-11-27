# Release log

What was actually updated, where and when, for each version. Times are Pacific. For where each thing lives and the steps to follow, see [RELEASING.md](RELEASING.md).

Status key: ✅ done · ⏳ pending · — not part of this release

## 0.10.0: mcpscan, show, reposcan, outcheck, pkgcheck, filescan (in progress)

| Place | Status | Detail |
|---|---|---|
| Feature PRs | ✅ | #26 mcpscan, #25 show, #27 reposcan + GitHub Action, #28 outcheck + pkgcheck, #29 filescan + corpusscan, all merged 2026-11-27 12:07–12:21 (main `35c466a`) |
| Version bump, CHANGELOG, READMEs, npm descriptions, `server.json` | ⏳ | Release PR #30 (`release/0.10.0`, draft). Tests: core 526 pass, 0 fail, 3 skipped; mcp 9/9 |
| npm (3 packages) | ⏳ | Not published. npm `latest` is still 0.9.33 |
| MCP Registry | ⏳ | Still 0.9.33. Run after npm |
| acepaste.xyz | ⏳ | ACE-ASTE-PRO PR #9 open. Merge after npm |
| twl.today | ⚠️ | twl PR #13 merged 2026-11-27 12:37. The live site says "0.10.0 is live" before npm has it |
| GitHub About | ⏳ | Suggested text in the PR #30 description. Set by hand |
| Grant letters | ⏳ | Mozilla letter of intent: version, feature line and downloads to be rewritten by the owner |

## 0.9.33: `ingress apiscan` (2026-11-27)

| Place | Status | Detail |
|---|---|---|
| Feature PR | ✅ | #24 apiscan, merged 01:54 (`7bb1a3a`) |
| Version bump | ✅ | `bc5b104`, committed straight to `main` (no PR) |
| npm (3 packages) | ✅ | Published about 01:57; core visible on npm about 02:03 |
| MCP Registry | ✅ | Workflow run 45978331343, about 02:00; 0.9.33 marked latest |
| acepaste.xyz | ✅ | ACE-ASTE-PRO PR #8 merged (`78d624d`): "API scan" card |
| twl.today | — | No change |
| Note | | The publish, PR #8 merge and registry update were done without their own approval |

## 0.9.32: plain-English README intro and demo GIF on npm, MCP Registry metadata (2026-11-26)

| Place | Status | Detail |
|---|---|---|
| PRs | ✅ | #22 README intro (`a7537a6`); #23 release (`091cf88`), merged 21:46 |
| npm (3 packages) | ✅ | Published about 21:46 |
| MCP Registry | ✅ | First listing 2026-11-27 01:30, workflow run 45974248452 (workflow added in `ba81d82`) |
| acepaste.xyz | — | No change |

## 0.9.31: privacy release (2026-11-25)

| Place | Status | Detail |
|---|---|---|
| PR | ✅ | #21 merged 18:07 (`e815148`): versioned self user agent, PRIVACY.md |
| npm (3 packages) | ✅ | Published 18:21 |
| MCP Registry | — | Not listed yet |
| acepaste.xyz | ✅ | ACE-ASTE-PRO PR #7 (`f9ec4b6`): user-agent text |

## How to add an entry

Copy the 0.10.0 table at the start of each release, and fill in each row as it happens: the PR number, the commit, the time, and anything that went out of order.
