# @acepaste/ingress

**Stops your AI agent from obeying instructions that web pages hide from you.**

![Ingress refusing a page with white-on-white instructions, then passing a clean page](https://raw.githubusercontent.com/sugarcypher/acepasteINGRESS/main/docs/demo/ingress-demo.gif)

**The problem:** a web page can hide text that a person never sees, and an AI agent reads all of it: white-on-white text, invisible Unicode, off-screen notes, or a different page served only to bots. The agent can follow those instructions, and afterward nobody can show what it read. Ingress sits in front of your agent's web fetch and refuses anything the model would receive that you would not see.

- **Refuses hidden instructions:** invisible Unicode, CSS-hidden or background-coloured text, and payloads in attributes, comments, SVG or `srcdoc`.
- **Catches cloaking:** fetches twice, and can render in a throwaway browser, to catch pages that show bots something different.
- **Signs a receipt for every verdict:** hash-chained and signed with ECDSA P-256, so you can prove later what your agent read.
- **Quarantines sources:** block a host and see everything it already delivered.
- **Asks a person before risky actions:** once outside content is read, side-effecting tool calls need human approval.
- **Checks your own APIs:** `ingress apiscan` looks for exposed files, open CORS, missing auth, leaked keys and responses an agent would obey, using only safe read requests.
- **Runs on your machine:** MCP server, CLI and library, or HTTP service. No telemetry ([PRIVACY.md](https://github.com/sugarcypher/acepasteINGRESS/blob/main/PRIVACY.md)).


---

The AcePaste Ingress engine: a security gate between internet content and AI ingestion. Anything a model would receive that a human looking at the same source would not see is suspect by default.

```ts
import { IngressEngine } from "@acepaste/ingress";
const ingress = new IngressEngine({ signingKey: process.env.INGRESS_SIGNING_KEY });
const r = await ingress.fetch("https://example.com/doc");   // or ingress.scan(text)
model.push(r.envelope);   // clean text in a provenance envelope, or a refusal with the reason
```

Verdicts: `clean` (delivered with a signed receipt), `suspect` (refused, human-overridable), `hostile` (refused, not overridable). Passes: acquire, policy, visibility, character (the production AcePaste invisible alphabet), script and supply-chain (underlight lineage), sandbox (optional headless Chromium), meaning, plugins.

CLI: `npx @acepaste/ingress https://example.com` or `ingress --text < page.html`.

## API scan

`ingress apiscan <base-url> [--spec openapi.json|url] [--auth-header "Name: value"] [--burst] [--json] [--max-requests N]`
checks an HTTP API you own, or are authorized to test, for common mistakes: plain HTTP, missing security headers,
open CORS, routes that answer without auth (from a JSON OpenAPI spec), exposed files such as `.env` and `.git`,
stack traces, version headers, leaked credentials, missing rate limits (only with `--burst`), and responses an AI
agent would read as instructions. It sends only GET, HEAD and OPTIONS requests, no bodies and no attack payloads,
about 60 at most, to the URL you give. Exit code 1 when any finding is high. In code: `apiscan(url, options)`.
YAML specs are not read; convert them to JSON.

Full documentation: https://github.com/sugarcypher/acepasteINGRESS
