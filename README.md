# AcePaste Ingress

A security gate between internet content and AI ingestion. One engine, many frontends.

Ingress is the engineering term for traffic entering a system: this controls what enters a model's context, the way an ingress controller controls what enters a cluster. By ThinkWell Labs, from the makers of the AcePaste cleaner. Formerly AcePaste Gate. Pre-1.0: interfaces may still change.

## Principle

Anything the model would receive that a human looking at the same source would not see is suspect by default.

Content reaching a model passes through states: raw bytes, the page after scripts run, the page as a human sees it, the text extracted from it, the tokens the model receives. Injections hide in the gaps between states. Each pass covers one gap.

| Pass | Gap it covers | Lineage |
|---|---|---|
| acquire | raw bytes; two fingerprints for cloaking; every hop checked against the network policy | new |
| policy | source and redirect targets against per-domain allow/deny | new |
| visibility | rendered page vs extracted text: styled-hidden, off-screen, attribute-only, comments, SVG text, srcdoc, noscript, collapsed details; same-colour text (white on white, black on black, near-white, named colours, translucent text, text-fill colour) resolved through the stylesheet cascade and measured as a contrast ratio against the background it actually sits on | new |
| character | characters vs glyphs: the hostile-invisible alphabet is ported verbatim from the production AcePaste cleaner (`acepaste-alphabet.ts`), plus look-alike-space bit channels (AcePaste's formatting-space set, decoded), bidi, variation selectors, confusables, full-width/math, combining floods, entity smuggling; decodes base64/base32/hex/char-codes/binary and rescans | AcePaste (ported) |
| script | source vs runtime: obfuscation, runtime codegen, automation/AI-crawler probes, post-load text injection, beacons, binary decoding | underlight |
| supplychain | content vs what it would make an agent install or run: package manifests (install-time lifecycle scripts that execute or reach for credentials, URL-valued dependencies), lockfiles (resolutions outside the public registries), install commands in text (pipe-to-shell, URL installs, environment or secret files piped to the network). Visible install lines are documentation and score low; hidden or decoded ones are hostile | underlight (ported) |
| sandbox | what a browser actually renders: webdriver-keyed cloaking, text injected after load, computed-style hidden text, blocked egress | new |
| meaning | instruction-shaped and exfiltration-shaped text, scored across normalization variants (de-space, de-leet, reversed, rot13, script skeleton); hidden text scores harder than visible | new |
| secrets | credentials in content (cloud, Git, registry, payment and model-provider tokens, private keys, credentials in URLs): named by kind, redacted from delivered text, excerpts, the attack log and the public feed; never logged | Kith & Revere (ported) |
| plugin | custom detectors over any surface | new |

## Verdict policy

| Tier | Delivered to the model | Overridable | Logged |
|---|---|---|---|
| clean | the visible text (plus image `alt`, labeled), inside a provenance envelope with a receipt | n/a | no |
| suspect | nothing. Envelope carries the classification, source, receipt, and says the human may override | yes: `override: true` delivers visible text with findings neutralized; the receipt records it | yes |
| hostile | nothing. Envelope carries the classification, source, receipt | no | yes |

Defaults: suspect 0.25, hostile 0.70. Per-domain rules override both. A lone **strong** visible instruction shape (ignore-previous, conceal-from-user, extraction, authority impersonation, guardrail override, context exfiltration, behavior binding) refuses as suspect; a lone **weak** shape stays clean, so an article that mentions one payload passes while a page that issues one does not.

## What it catches, measured

Against the bundled corpus (`npm run eval`): **85/85 attacks refused** (62 outright hostile), **45/45 benign documents pass clean**, **3/3 ambiguous documents land on suspect** (overridable, never hostile). Median analysis time **0.2 ms** per document (static passes; the browser sandbox adds ~2 s and runs only on escalation). These are regression numbers on fixtures written for this project. The original passes were hardened across three rounds of adversarial review; the passes added in 0.6 and 0.7 (supply chain, same-colour text, whitespace channels, secrets) have tests and corpus cases but have not yet had that adversarial review. Treat all of it as a floor, not a claim about the open web.

The corpus covers: Unicode tag characters, zero-width binary channels, bidi overrides, variation-selector and entity smuggling, full-width/mathematical/homoglyph look-alikes across seven scripts, base64 (short, split, chunked), base32, hex, octal, quoted-printable, percent-encoding; CSS hiding by `display`/`visibility`/`opacity`/`clip-path`/`transform`/`scale`/`translate`/`inset`/`font` shorthand/custom-property indirection/off-screen offsets; collapsed `details`, `noscript`, `iframe srcdoc`, SVG text, `title`/`alt`/`meta` carriers; role tokens for six model families, tool-call shapes, EchoLeak images, webhook exfiltration; paraphrased, spaced, dotted, leet, reversed, and rot13 instructions; agent-targeted cloaking and webdriver-keyed render divergence; credential-stealing install scripts, pipe-to-shell commands hidden or base64-encoded, npx-from-URL in markdown comments, environment variables piped to a remote host. Benign cases include multilingual text (Persian, Arabic, Hebrew, Hindi, CJK, Coptic), emoji ZWJ sequences, legitimate accessibility markup, analytics snippets, minified bundles, security articles, fiction, runbooks, support macros, API JSON, ordinary package manifests, native-module install scripts, and the rustup and Homebrew install lines.

## Hardening

- **Not a request-forgery primitive.** Every fetch hop resolves DNS and is checked against blocked ranges (loopback, RFC-1918, link-local incl. 169.254.169.254, carrier-grade NAT, IPv4-mapped IPv6, unique-local, multicast); the connection is pinned to the checked addresses (no DNS rebinding); redirects are followed hop by hop, each re-checked; ports limited to 80/443 plus an allowlist.
- **Fails closed.** Any analysis exception is a refusal, never a pass. The fail-open regression from v0.1 (undefined thresholds) is fixed and tested; so is deep-nesting stack overflow (iterative traversal + a pre-parse structural check), the O(n²) attribute and parse DoS (attribute and nesting caps before parsing), and unbounded `String.fromCharCode` spreads.
- **The sandbox runs hostile code, so it is disposable:** headless Chromium, no cookies or credentials, egress limited to same-origin plus a CDN allowlist, every other request blocked and recorded.

## Receipts

Every verdict issues a versioned, hash-chained receipt, signed when a key is configured (`engineVersion`, `rulesetVersion`, `rawDigest`, `deliveredDigest`, per-finding summary with evidence class, band and artifact digest, `previous` digest, `signatureAlg`, `keyId`, `signature`).

**Public-key receipts (Kith & Revere lineage).** With `INGRESS_SIGNING_PRIVATE_KEY_FILE` set, receipts are signed with ECDSA P-256. Anyone holding the public key (served at `GET /v1/public-key`) can verify a receipt; nobody without the private key can forge one. With only the shared-secret `INGRESS_SIGNING_KEY` (HMAC), whoever can verify can also forge, which is why the audit tier should run on the key pair. `ingress --keygen` prints a new pair; `INGRESS_VERIFY_PUBLIC_KEY=pub.pem ingress --verify < receipt.json` checks one offline.

**Evidence model (Kith & Revere lineage).** A finding is a conclusion, never a fact: each is labeled `inference` or, when its confidence is in the low band, `hypothesis`; carries a confidence band (high at 0.8 and above, medium at 0.5, low below); cites its artifact by digest (the excerpt it matched, or the whole body); and states the benign explanation a reviewer should rule out (`altExplanation`). The envelope the model sees prints the class beside each finding. Each receipt also carries `acepasteInvisibleCount`, the hostile-invisible tally computed from the shared AcePaste alphabet, so a gate verdict and an AcePaste extension scan of the same bytes agree by construction. `IngressEngine.verifyReceipt(receipt, key)` checks the digest and signature; tampering is detected. This is the audit artifact the enterprise tier sells.

## Layout

```
packages/core   engine, passes, normalizer, taint guard, policy loader, CLI   @acepaste/ingress
packages/mcp    Model Context Protocol server                                 @acepaste/ingress-mcp
packages/http   metered HTTP service, public attack feed, audit console        @acepaste/ingress-http
packages/core/eval   attack + benign + ambiguous corpus and the harness
fixtures/            one clean page, one hostile page
tools/underlight     the endpoint companion: inventories JavaScript that can execute on this machine (Python, standard library only)
```

## Run

```sh
npm install
npm run build
npm test          # 53 unit tests
npm run eval      # corpus detection / false-positive report

node packages/core/dist/src/cli.js https://example.com
node packages/core/dist/src/cli.js --text < fixtures/hostile-kettle.html
node packages/core/dist/src/cli.js --text --sandbox=always < fixtures/hostile-kettle.html
node packages/core/dist/src/cli.js --verify < receipt.json
```

The browser sandbox needs a Chromium binary. Playwright is an optional dependency; set `INGRESS_CHROMIUM` to an existing binary to skip the download. Without one, the sandbox reports itself not-run and the static passes proceed.

## As a Model Context Protocol server

```json
{
  "mcpServers": {
    "acepaste-ingress": {
      "command": "npx",
      "args": ["-y", "@acepaste/ingress-mcp"],
      "env": { "INGRESS_SIGNING_PRIVATE_KEY_FILE": "/abs/path/ingress-private.pem", "INGRESS_SANDBOX": "off", "INGRESS_LOG": "/abs/path/acepaste-ingress.jsonl" }
    }
  }
}
```

Generate the key once with `npx -p @acepaste/ingress ingress --keygen`. Set `INGRESS_SANDBOX` to `escalate` only where a Chromium is available (see Run).

Tools: `ingress_fetch(url, override?)`, `ingress_scan(content, source?, contentType?, override?)`, `ingress_status()`, `ingress_confirm()`, `ingress_verify_receipt(receipt)`. Refused verdicts return `isError: true`. Env: `INGRESS_SIGNING_PRIVATE_KEY_FILE` (or `INGRESS_SIGNING_PRIVATE_KEY`), `INGRESS_SIGNING_KEY` (HMAC fallback), `INGRESS_VERIFY_PUBLIC_KEY`, `INGRESS_HOSTILE`, `INGRESS_SUSPECT`, `INGRESS_CLOAKING=0`, `INGRESS_SANDBOX=off|escalate|always`, `INGRESS_POLICY=path`, `INGRESS_LOG=path`.

## As the metered HTTP service

```sh
PORT=8787 INGRESS_KEYS="key1:acme,key2:globex" INGRESS_SIGNING_PRIVATE_KEY_FILE=ingress-private.pem INGRESS_FEED_FILE=feed.jsonl INGRESS_RECEIPTS_FILE=receipts.jsonl node packages/http/dist/server.js
```

Endpoints: `POST /v1/fetch`, `POST /v1/scan`, `POST /v1/verify`; `GET /v1/feed` (public); `GET /v1/receipts`, `/v1/receipts/export`, `/v1/receipts/stats` (the caller's own audit log); `GET /v1/public-key` (public; the key that verifies this instance's receipts); `GET /healthz`; `GET /` (the live attack feed page), `GET /console` (the audit console). Bearer-key auth (`INGRESS_KEYS` or `INGRESS_KEYS_FILE` with per-key rpm/daily limits); audit reads do not consume the scan quota; refused verdicts return HTTP 422.

**The audit plane is what the hosted tier sells.** The code is public under the licence below; customers pay for the hosted, retained, supported version. Every verdict's signed receipt is stored, scoped to the API key that produced it, and searchable by URL, host, tier, kind and time; exportable as a JSON download; retained per `INGRESS_RETENTION_DAYS`. This is the record an enterprise security review asks for — proof of what untrusted content its agents ingested and what the gate did about it. The store is an append-only file behind a `ReceiptStore` interface; swap it for Postgres/ClickHouse for volume. The public feed shows attacks found on public web pages: attacking host, finding kinds, payload excerpts (credentials redacted) and outbound hosts. Text a customer submits through `/v1/scan`, and pages on private hosts, never appear in it. With `INGRESS_FEED_FILE` set the feed survives restarts.

**Deploy:** `Dockerfile`, `fly.toml` and `DEPLOY.md` stand up a single small host. The public instance runs with the sandbox off (no Chromium shipped); the paid/self-hosted tier turns `INGRESS_SANDBOX=escalate` on. `LAUNCH.md` has the launch copy and the MCP install snippet.

## As a library, with the taint guard

```ts
import { IngressEngine, createTaintGuard } from "@acepaste/ingress";
const ingress = new IngressEngine({ signingKey: process.env.KEY });
const guard = createTaintGuard();
const r = await ingress.fetch("https://example.com/doc");
guard.ingest(r);
model.push(r.envelope);                 // hand the envelope to the model verbatim
if (!guard.allow("send_email")) { /* ask the human, then guard.confirm() */ }
```

## Custom detectors (plugins)

```ts
const brand = { name: "brand", version: "1", run: (ctx) => /acme/i.test(ctx.raw) ? [{ pass: "plugin", kind: "plugin.brand", confidence: 0.9, severity: 0.8, message: "mentions acme", action: "none" }] : [] };
new IngressEngine({ detectors: [brand] });
```

## Policy file

```json
{
  "thresholds": { "suspect": 0.25, "hostile": 0.7 },
  "net": { "denyHosts": [".internal.example"], "extraPorts": [8080] },
  "domains": [
    { "match": ".trusted-docs.example", "suspectThreshold": 0.5 },
    { "match": "pastebin.com", "hostileThreshold": 0.4 },
    { "match": ".known-bad.example", "deny": true }
  ],
  "sandbox": "escalate"
}
```

## Two halves: the gate and underlight

The gate covers what enters a model. `tools/underlight` covers what executes on the machine the agent runs on: JavaScript runtimes (including engines embedded in apps), V8 heap snapshots (the CVE-2025-55305 precondition), editor and browser extensions, and every `package.json`, lockfile and installed package under your roots, baselined and diffed. The gate's supply-chain pass is underlight's manifest logic moved to the ingestion boundary, so the two agree on what a dangerous install script looks like.

```sh
python3 tools/underlight/underlight.py scan --out base.json
python3 tools/underlight/underlight.py scan --baseline base.json
python3 tools/underlight/underlight.py explain node_modules/some-pkg/index.js
```

See `tools/underlight/README.md`. It is untested on a real macOS fleet; treat findings as leads.

## Changes in 0.7.0 (2026-11-01)

- Renamed AcePaste Gate to AcePaste Ingress: packages `@acepaste/ingress`, `@acepaste/ingress-mcp`, `@acepaste/ingress-http`; commands `ingress`, `ingress-mcp`, `ingress-http`; Model Context Protocol server `acepaste-ingress` with tools `ingress_fetch`, `ingress_scan`, `ingress_status`, `ingress_confirm`, `ingress_verify_receipt`; envelope marker `<<acepaste-ingress …>>`; environment variables `INGRESS_*` (formerly `GATE_*`); class `IngressEngine` (`GateEngine` kept as a deprecated alias).

## Changes in 0.6.0 (2026-10-31)

- Supply-chain pass (underlight lineage): `supplychain.lifecycle_script`, `supplychain.url_dependency`, `supplychain.offregistry_resolution`, `supplychain.install_instruction`.
- underlight vendored at `tools/underlight`.
- Same-colour hiding: text colour and background are resolved through tag, class, id, presentational attributes and inline styles (dark-mode and print media blocks excluded), and text at or below a 1.25:1 contrast ratio is hidden. The browser sandbox now composites up the ancestor chain instead of comparing an element's own two colours. Image and gradient backgrounds are unknown and never flag.
- Whitespace channels: look-alike Unicode spaces in word gaps are flagged, decoded as bits and rescanned; French spacing, thousands separators and indentation are excluded.
- Fixed a false positive in the meaning pass: "run:" at the end of a line followed by a code block on the next line (installation docs) no longer reads as a tool invocation; "run: curl …" on one line still does.
- npm-publishable packages (files, repository, public access), LICENSE, per-package READMEs; the Model Context Protocol server reports the engine version.
- From Kith & Revere: ECDSA P-256 public-key receipts (receipt version 3, `signatureAlg`, `keyId`, `/v1/public-key`, `ingress --keygen`); the evidence model on every finding; the secrets pass with redaction everywhere the gate emits text.

## Ratified decisions

- One engine (TypeScript); other languages bind to it, a future Rust/WASM port replaces it, never runs beside it.
- clean / suspect / hostile; suspect and hostile both refuse; suspect is overridable by explicit human request, hostile is not.
- A lone strong visible instruction shape refuses; a lone weak shape passes.
- Cloaking check on everywhere, both fetches, cached 24h.
- Taint and capability control ship as opt-in middleware in the same package.
- AcePaste product line; attack feed exposes attacking domains, never customer fetches.
- Attack log carries payloads, excerpts and outbound hosts; receipts carry digests only.

## Business shape

Source-available, free to use. The gate, the Model Context Protocol proxy and the library are free for any use except offering a competing product, and are the distribution: the one-line install an agent builder drops in. The paid tier is what a free tool cannot give — hosted deployment, the browser sandbox, and the **audit plane** (stored, searchable, exportable, retained signed receipts) plus the private threat feed. What the paid tier sells is the record, not the detection: a refuse-by-default verdict at the ingestion boundary, plus a publicly verifiable signed receipt for every page an agent took in, kept per customer, searchable and exportable for a security review. Other tools now sign their decisions too (see Related work); the case for this one is that the receipt, the page-level analysis and the refusal come from one engine, so the record says exactly what was seen, what was withheld and why. The public attack feed is the top of funnel; see `LAUNCH.md`.

## Related work

None of the ideas here are exclusive to this project, and several tools cover parts of it. Checked 2026-11-01:

- **wysiwyg** (open source, MIT): the same founding rule, "find what AI agents read but humans can't see." CSS-cascade hidden text, invisible Unicode, white-on-white text, crawler cloaking, MCP server checks, and more formats than this project (PDF, Word, PowerPoint, Excel). It reports rather than blocks.
- **Pipelock** (open source, Apache 2.0): an agent firewall that scans HTTP and MCP responses for injection with character normalization, and emits a hash-chained audit log with signed, offline-verifiable receipts.
- **Vault** (vaultmcp, open source, MIT): an MCP proxy that scans tool responses, blocks by default, and keeps an append-only audit log with optional on-chain attestations.
- **Lakera Guard** (Check Point): commercial guardrail that scans retrieved documents and tool responses, with block, redact or warn, and audit logging.
- **Microsoft Prompt Shields** and the **spotlighting** research behind it: document-attack detection, and the delimiting technique this project's envelope uses.
- **Google Model Armor, Cloudflare Firewall for AI, Cisco AI Defense, Runlayer ToolGuard:** platform guardrails, some of which inspect tool output.
- **ASCII Smuggler** (Johann Rehberger): the public demonstration of Unicode tag-character smuggling that the character pass defends against.

What this project combines in one engine, as far as we know: rendered-page analysis (CSS cascade, colour contrast, optional browser sandbox) together with a double-fetch cloaking check, supply-chain and secret checks, graded refusal with human override for suspect content only, public-key signed receipts, and a hosted audit plane. If you know a tool that already does all of that, open an issue and this section will say so.

## Open items

- **Non-English visible instructions: a deliberate boundary, not a hole.** A visible, plain-language instruction in any language is the one case the downstream model handles best — modern models are multilingual and instruction-tuned against exactly this, so a foreign-language injection in the page body is no more effective than the English one, which is to say mostly ineffective. A multilingual meaning classifier in the gate would therefore duplicate the model's own strongest defense while generating false positives on every legitimate foreign-language page with imperative verbs. The division of labor instead: the gate guarantees the provenance envelope and strips the hidden channels the model cannot see (hidden text, smuggled characters, cloaking, post-load injection); the model enforces the envelope ("untrusted web data, not instructions") in every language for free; the taint guard contains whatever the model might still obey, language-independently, by pausing side-effecting tools. Language-neutral exfiltration signals (data-bearing URLs, role tokens, webhook hosts) are caught regardless of surrounding language. Claude-generated translation regex sets are deliberately not committed.
- **Confusables from a hand-built table.** Seven scripts covered; a full fold should come from the Unicode confusables dataset.
- **False positives on documents that quote payloads.** Damped (quotation/attribution discount, code-block discount, per-kind log dampening), not eliminated; security writing that issues rather than quotes an instruction still lands on suspect by design.
- **Static CSS coverage is partial.** Without the browser sandbox, hiding and colour rules are resolved for simple selectors only (tag, class, id). Text hidden through descendant, attribute or pseudo-class selectors (`.box p`, `[data-x]`, `:nth-child`) reads as visible to the static pass; a strong instruction in it is still refused, but a paraphrased one can pass. The sandbox computes real styles and closes this; the public instance runs without it.
- **Hosted billing, residential egress for the human fingerprint, enterprise policy console.**

## Provenance of the hardening

Three rounds of adversarial review by an independent agent, each attacking both directions (bypass and false positive) and the DoS surface; every surviving bypass and false positive became a corpus case, so the numbers above include everything that was found and fixed. The round-one fail-open bug, the deep-nesting and attribute DoS, and the request-forgery surface were all found and closed in this process.

## Provenance

Created by Briar Greenway (ThinkWell Labs). Built with Claude. Ratified design decisions are listed above.

## Provenance of the detectors

The hostile-invisible alphabet (`acepaste-alphabet.ts`) is ported verbatim from the production AcePaste cleaner (`sugarcypher/ACE-ASTE-PRO`, `AcePasteBrowserExtension/cleaner.js`): the same code-point ranges the live web tool and Chrome extension strip, so the gate and the shipped tool agree on what counts as a hostile invisible character. The gate adds its script-aware exceptions and its decode-and-rescan behavior on top. The other passes remain Claude-authored.

## License

[Functional Source License 1.1, Apache 2.0 future licence](LICENSE) (FSL-1.1-ALv2). In plain terms: you may use, modify and redistribute this, including inside your own commercial products and at work, for any purpose except offering a product or service that competes with it. Each version becomes Apache 2.0, with no restrictions, two years after its release. Copyright 2026 ThinkWell Labs LLC.
