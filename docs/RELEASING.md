# Release checklist: every place a version or description lives

Use this list for each release. Every **publish**, **merge to main** and **live-site change** needs the owner's explicit OK, one step at a time.

## Version numbers (semver)

- New commands or features: **minor** bump (0.10.0 → 0.11.0).
- Fixes and docs only: **patch** bump (0.10.0 → 0.10.1).
- 1.0.0 means the command-line options and library API are stable.

## 1. In this repo

| Place | What to change |
|---|---|
| `package.json` (root) | `version` |
| `packages/core/package.json` | `version`, `description`, `keywords` |
| `packages/http/package.json` | `version`, the `@acepaste/ingress` pin, `description`, `keywords` |
| `packages/mcp/package.json` | `version`, the `@acepaste/ingress` pin, `description`, `keywords`, `mcpName` stays |
| `packages/core/src/types.ts` | `ENGINE_VERSION` (the user agent `AcePasteIngress/<major.minor>` follows it) |
| `package-lock.json` | root `version`, the three entries in `packages`, the pins |
| `server.json` | `version`, the package entry `version`, `description` (100 characters max) |
| `CHANGELOG.md` | turn `## Unreleased` into `## X.Y.Z (date, ruleset …)` |
| `README.md`, `packages/*/README.md` | one-liner, feature list, example commands (npm shows the package READMEs) |
| `PRIVACY.md` | one row for each new network contact; the user-agent version |
| `integrations/github-action/action.yml` | default `version` input |
| `integrations/github-action/README.md`, `docs/REPOSCAN.md` | "requires X.Y.Z or later" notes |
| `LAUNCH.md`, `DEPLOY.md`, `Dockerfile` | quoted descriptions or versions, if any |
| `docs/demo/make-gif.py`, `docs/demo/ingress-demo.gif` | title bar version (regenerate the GIF, or keep the README caption saying which version it shows) |

`tools/release/bump-version.mjs` bumps `ENGINE_VERSION`, the package versions and the pins. It does **not** touch `server.json` or `package-lock.json`, so do those by hand or run `npm install --package-lock-only` afterwards.

Find any version strings left over (keep the dated CHANGELOG history):

```sh
OLD=0.10.0
grep -rn --exclude-dir={node_modules,dist,.git} -F "$OLD" . | grep -v CHANGELOG.md
grep -rn --exclude-dir={node_modules,dist,.git} -E "AcePasteIngress/[0-9]+\.[0-9]+" .
```

## 2. Outside this repo

| Place | How it updates | Approval |
|---|---|---|
| **npm**: `@acepaste/ingress`, `-http`, `-mcp` | `npm publish --access public --tag latest` in `packages/core`, then `http`, then `mcp`, from `main`. The README and description on npmjs.com change only when you publish. | Yes |
| **MCP Registry** | After npm, with `server.json` bumped on `main`, run the `mcp-registry.yml` workflow (Actions → Run workflow). Verify at https://registry.modelcontextprotocol.io/v0/servers?search=io.github.sugarcypher/acepaste-ingress | Yes |
| **GitHub repo About** (description and topics) | By hand: repo page → ⚙ next to About | Yes |
| **GitHub tag and release** | Not used so far (no tags or releases yet). Optional: tag `vX.Y.Z` on the release commit. | Yes |
| **acepaste.xyz** (`sugarcypher/ACE-ASTE-PRO`) | `ingress/index.html`: hero version, feature cards, install snippet version, meta and og descriptions, user-agent section. `index.html`: the home banner. `sitemap.xml`: lastmod. A push to `main` goes live in about 18 seconds, so always open a PR and merge it after npm has the version. | Yes |
| **twl.today** (`sugarcypher/twl`, private) | `index.html`: banner and work card. `articles/acepaste-ingress.html`: feature section and `dateModified`. Merging to `main` runs `publish.yml`, which copies the site to `sugarcypher/twl-site`. Merge after npm. | Yes |
| **Grant and fellowship letters** (Mozilla letter of intent and others) | The owner rewrites them in their own words. Update version, feature line and download figures. | Owner |
| **Chrome extension listing** | A separate product. It isn't tied to this version. | n/a |

## 3. Release day, in order

1. Bump versions and docs on a `release/X.Y.Z` branch. Open a draft PR.
2. `npm ci && npm run build && npm test`. Everything passes. `npm pack --dry-run` in each package shows the new version and `README.md`.
3. **OK to merge?** Merge the release PR.
4. **OK to publish?** Publish to npm: core, then http, then mcp.
5. Verify npm. Caches lag several minutes, so check with `Cache-Control: no-cache` and a cache-busting query, e.g. `curl -s -H 'Cache-Control: no-cache' "https://registry.npmjs.org/@acepaste%2fingress/X.Y.Z?x=$RANDOM"`.
6. **OK to update the registry?** Run `mcp-registry.yml` and verify the registry entry.
7. **OK to go live on the sites?** Merge the acepaste.xyz and twl.today PRs. Check both pages load.
8. Update the GitHub About text if the description changed.
9. Note the new version and download figures for any open grant letters.
