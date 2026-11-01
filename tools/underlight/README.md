# underlight

Inventory of JavaScript that can execute on this machine — including the layers that dependency scanners, endpoint tooling, and code signing do not look at.

Working name. Rename at will.

**Provenance:** Claude-generated, 2026-09-19, at Axel's direction, from the design in the accompanying architecture documents. Untested against vendor reference hashes; this version baselines against itself. The detection surfaces it covers came from Axel's specification and from verified incidents; the implementation is Claude's and has been tested only against synthetic fixtures and one Linux sandbox. Run it on your own machine and object to what it gets wrong.

## Run it

```
python3 underlight.py scan --out base.json          # first run: this is your baseline
python3 underlight.py scan --baseline base.json     # later: scan and diff in one step
python3 underlight.py diff base.json new.json       # or diff two saved reports
```

Python 3.9 or newer. Standard library only; nothing to install. Takes seconds to a few minutes depending on how many projects live under your home directory. Restrict with `--roots ~/code ~/work`; skip `node_modules` inspection with `--no-deep`.

## What it inventories

**Runtimes.** Every JavaScript interpreter on `PATH` and in the usual version-manager locations, hashed rather than executed. Then every application bundle, checked for an *embedded* engine: Electron and Chromium Embedded Framework by their framework directories, and V8, JavaScriptCore, QuickJS, Hermes, and Bun by byte markers in the main executable. The Bun check exists because attackers have shipped malware inside a bundled Bun runtime specifically to avoid detection rules tuned to `node.exe`.

**Heap images.** V8 startup and context snapshot files, wherever they sit, hashed, with a flag for whether the current user can write to them. A tampered snapshot can replace a built-in like `Array.isArray` before any application code runs, and code signing does not catch it (CVE-2025-55305; Signal, 1Password, Slack, Chromium). On a default macOS or Windows install every one of these is user-writable, so the first scan will flag all of them — that is the baseline. The diff is where a changed hash becomes a finding.

**Editor extensions.** VS Code, Insiders, VSCodium, Cursor, Windsurf, Positron, Trae. Publisher, version, entry file hash, activation events, whether it activates on every startup, whether it was modified in the last ninety days. The diff catches an entry file that changed while the version did not — an extension mutating in place, which legitimate updates never do.

**Browser extensions.** Chromium-family profiles (Brave, Chrome, Chromium, Edge, Arc, Vivaldi, Opera). Permissions, host permissions, content-script scope, whether it was store-installed or sideloaded. Flags all-sites access combined with powerful permissions as a capability to review, not as an indicator. The diff catches permission escalation across versions and a manifest that changed without a version change.

**Manifests.** Every `package.json` under your roots. Dependency specifiers that resolve to a network location instead of a registry (`https://`, `git+`, `github:`, `owner/repo`, tarball URLs) — registry scanners see zero dependencies for these. Lifecycle scripts (`preinstall`, `install`, `postinstall`, `prepare`) in the project and in every installed package, pattern-matched for network, shell, and credential access, with transitive dependencies distinguished from direct. Lockfile resolutions that point anywhere other than a public registry.

## explain — what is this file?

```
python3 underlight.py explain <path>
python3 underlight.py explain <path-to-package-dir> --whole-package
```

For any file or directory inside a `node_modules` tree: which package owns it and at what version; whether the project lockfile pins it and to what integrity hash; the dependency chain from your project root that caused it to be installed; and — offline, no network — whether the file's bytes match the registry tarball sitting in your local npm cache (`~/.npm/_cacache`). `--whole-package` compares every file in the package and lists modified, missing, and added files. Also explains the extension: a `.d.ts` file is a TypeScript declaration, and iOS Files displays `.ts` as MPEG-2 video and refuses to open it.

If the tarball is not in your cache the bytes cannot be verified offline; the report says so rather than guessing. Two ways past that:

- `--fetch` — **the one network operation in the tool, off by default.** Downloads the tarball from the lockfile's `resolved` URL and refuses to use it unless its hash matches the lockfile's `integrity` field. The chain is lockfile → tarball → file; a registry serving something other than what you locked is reported, not trusted.
- `--compare-copies` — stays offline. Finds every other installed copy of the same package@version under `--roots` and hashes the same file in each. Agreement across copies installed at different times is not proof, but tampering would have to hit all of them.

Lifecycle scripts are labeled by who they run for: `preinstall`/`install`/`postinstall`/`prepare` run on *your* install; `prepublish` runs only in the author's own checkout and is labeled author-only.

## What it deliberately does not do

- **Execute anything it finds.** No `node --version`. A tool that inventories interpreters should not run them.
- **Touch the network.** No reputation lookups, no update checks, no telemetry.
- **Decide for you.** Findings are labeled `high`, `medium`, `low`, `note` and every one says why. A `note` is context. A first-scan `high` on a URL-valued dependency in your own project may be entirely intentional.

## Reading the report

The summary block is the number this tool exists to produce: how much JavaScript executes on this machine that nobody reviewed. The findings block is what to look at. The coverage block is what the scan actually touched — visited, hashed, skipped for permission or size, and whether any collector hit its cap. A clean report with a capped collector is a capped report, not a clean machine.

The JSON report contains everything: every runtime, snapshot, extension, project, and installed package, with hashes. Keep baselines; the diff is the product.

## Severity, briefly

| Level | Meaning |
|---|---|
| `high` | A verified attack pattern, present now (URL-valued dependency; transitive lifecycle script with network/exec pattern) or a change that legitimate operation does not produce (snapshot hash changed; extension entry file mutated at same version) |
| `medium` | Worth a look this week (embedded Bun in an app that isn't Bun; off-registry lockfile resolutions; new runtime since baseline; new extension) |
| `low` | A capability or hygiene gap, not an indicator |
| `note` | Context. Counted, not shown in the summary. All in the JSON. |

## Changes in 0.2.0

- Chromium and Electron apps keep the engine in `Contents/Frameworks/*.framework`, not the stub in `Contents/MacOS`; framework binaries are now scanned, so the embedded-engine count is no longer an undercount.
- Apps that merely link the system JavaScriptCore are reported as `links_system_engine`, not as embedding one.
- `~/Library/Mobile Documents/com~apple~CloudDocs` (iCloud Drive) is added as a manifest root on macOS; `~/Library` is otherwise skipped, which previously hid it. Evicted (cloud-only) files are counted in coverage as `cloud-only(not local)` and never downloaded.
- Apple's own `.app` bundles are skipped in the snapshot walk (no V8 there), so large iWork bundles no longer consume the budget.
- One browser-extension finding per extension, not one per on-disk version.
- `explain` subcommand, with `--fetch` (integrity-verified) and `--compare-copies` (offline).
- `--whole-package` separates genuine additions from Finder/iCloud conflict copies (`helpers 2/`, `x (1).js`): an added file that is byte-identical to a tarball file under the de-suffixed name is reported as a sync-duplicate, which Node never loads.
- Apps that ship a V8 snapshot are counted as embedding V8 even when release builds strip the string markers.

## Known limits of this version

- Engine markers are byte-string heuristics. A hit names the marker so you can judge it; a miss means nothing.
- Only the first 48 MB of each binary is scanned for markers; the report says when this truncated.
- Heap-image and helper attestation is self-baseline only. Vendor reference hashes are the next step and would turn the first scan into a finding rather than a baseline.
- No obfuscation discrimination yet. That is the second primitive in the amendment document and it needs a calibration corpus before it can be trusted.
- macOS `/Applications` walks are bounded per app bundle; an unusually large bundle may cap. The coverage block will say so.
- Windows paths are best-effort and untested.
- Tested on synthetic fixtures and one Linux sandbox. Not yet on a real macOS install.

## License

MIT is proposed as the default. Your call.
