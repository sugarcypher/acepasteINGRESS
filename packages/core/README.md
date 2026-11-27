# @acepaste/ingress

**Stops your AI agent from obeying hidden instructions in web pages, files, repos and MCP tools, and catches data leaks.**

![Ingress refusing a page with white-on-white instructions, then passing a clean page](https://raw.githubusercontent.com/sugarcypher/acepasteINGRESS/main/docs/demo/ingress-demo.gif)

**The problem:** an AI agent reads everything, including what a person never sees: white-on-white text on a web page, invisible Unicode in a repo, a hidden layer in a PDF, a poisoned tool description in an MCP server. It can follow those instructions, slip your data out inside a link or an image, or install a package an AI made up, and afterward nobody can show what it read. Ingress checks what goes into your agent and what comes out, and refuses anything the model would receive that you would not see.

- **Refuses hidden instructions in web pages:** invisible Unicode, CSS-hidden or same-colour text, payloads in attributes, comments, SVG or `srcdoc`, and pages that show bots something different. `ingress https://example.com`
- **Shows you what your agent sees:** `ingress show` writes one HTML page with what a person sees beside what the agent receives, hidden text highlighted. `ingress show https://example.com --open`
- **Checks files and knowledge bases:** `ingress filescan` finds hidden text in PDFs, Word, Excel, PowerPoint and images; `ingress corpusscan` checks a whole RAG folder and moves hostile files aside. `ingress corpusscan ./docs --quarantine ./held`
- **Checks your MCP servers:** `ingress mcpscan` finds poisoned tool descriptions, look-alike tool names and tools that changed since you pinned them. `ingress mcpscan --connect`
- **Gates repos for coding agents:** `ingress reposcan` and a GitHub Action flag Trojan Source Unicode, instructions hidden in markdown, poisoned AGENTS.md files and risky install scripts. `ingress reposcan --diff origin/main`
- **Catches data leaving in links and images:** `ingress outcheck` reads a model's reply for data hidden in image URLs, links and subdomains before it is rendered; the action broker does the same for tool calls. `ingress outcheck --safe < reply.md`
- **Checks packages before install:** `ingress pkgcheck` catches made-up package names, lookalikes of popular ones and brand-new packages with install scripts. `ingress pkgcheck npm left-pad`
- **Checks your own APIs:** `ingress apiscan` looks for exposed files, open CORS, missing auth, leaked keys and responses an agent would obey, with safe read-only requests. `ingress apiscan https://api.example.com`
- **Signs a receipt for every verdict, and asks a person before risky actions:** hash-chained ECDSA P-256 receipts prove later what your agent read; once outside content is read, side-effecting tool calls need human approval.
- **Quarantines sources:** block a host and see everything it already delivered.
- **Runs on your machine:** MCP server, CLI and library, or HTTP service. No telemetry ([PRIVACY.md](https://github.com/sugarcypher/acepasteINGRESS/blob/main/PRIVACY.md)).

Every command runs as `npx @acepaste/ingress <command>`, or as `ingress <command>` after `npm install -g @acepaste/ingress`.


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

## MCP scan

`ingress mcpscan [--config file] [--connect] [--url URL [--header "Name: value"]] [--json]` checks the MCP servers
in your AI apps' config files (Claude Desktop, Claude Code, Cursor, Windsurf, VS Code, Gemini CLI, `./.mcp.json`).
Without `--connect` it reads only the configs: download-and-run launch commands, unpinned `npx`/`uvx` packages,
credentials written into the file (names only) and plain-http servers. With `--connect` it starts each server
(this runs the server's code), lists its tools, prompts and resources, and shuts it down; no tool is ever called.
Every description is scanned for hidden instructions, invisible characters, orders aimed at the model, orders about
another server's tools, and look-alike tool names. Each server's tool list is pinned by fingerprint in the Ingress
state directory; later scans show tools added, removed or changed, with the old and new text. `ingress mcpscan pin
--connect` accepts the current tools. Exit code 1 when any finding is high. In code: `mcpscan(options)`.

## API scan

`ingress apiscan <base-url> [--spec openapi.json|url] [--auth-header "Name: value"] [--burst] [--json] [--max-requests N]`
checks an HTTP API you own, or are authorized to test, for common mistakes: plain HTTP, missing security headers,
open CORS, routes that answer without auth (from a JSON OpenAPI spec), exposed files such as `.env` and `.git`,
stack traces, version headers, leaked credentials, missing rate limits (only with `--burst`), and responses an AI
agent would read as instructions. It sends only GET, HEAD and OPTIONS requests, no bodies and no attack payloads,
about 60 at most, to the URL you give. Exit code 1 when any finding is high. In code: `apiscan(url, options)`.
YAML specs are not read; convert them to JSON.

## See what your agent sees

`ingress show <url|file> [--out report.html] [--open]` writes one static HTML page with what a person sees beside
what your AI agent receives. Hidden text is highlighted in place by kind (CSS, colour match, invisible Unicode,
comments and attributes, text served only to AI fetchers), with the verdict, the findings linked to their
highlights, the bots-versus-browsers comparison and the receipt digest. No scripts or remote content; everything
from the page is escaped. `ingress show --term <url|file>` prints the same in the terminal with hidden spans in red
brackets. In code: `show()`, `renderShowHtml()`, `renderShowTerm()`.

## Repo scan

`ingress reposcan [dir] [--diff <git-ref>] [--json] [--sarif <file>|-]` checks a repository before a coding
agent reads it: bidirectional and invisible Unicode (Trojan Source, tag characters, zero-width), instructions
hidden in markdown comments, `<details>`, hidden styles, link titles and alt text, agent instruction files
(AGENTS.md, CLAUDE.md, .cursorrules and the rest) that tell the agent to run downloads, read secrets, turn off
safety or skip review, install scripts that download and run code, and risky MCP configs. Local only, no network.
`--diff` scans only files changed since a git ref; `--sarif` writes SARIF 2.1.0 for GitHub code scanning. Exit
code 1 when any finding is high. In code: `reposcan(dir, options)` and `toSarif(report)`. GitHub Action and
pre-commit hook: https://github.com/sugarcypher/acepasteINGRESS/blob/main/docs/REPOSCAN.md

## Package check

`ingress pkgcheck <npm|pypi> <name>[@version]... [--json] [--offline]` looks each package up on the public
registry before you install it. High: not on the registry (often a name an AI made up, "slopsquatting"), a version
that does not exist, a name one edit from a popular package. Also flagged: first published under 30 days ago, npm
install scripts, PyPI releases without a wheel, no source repository, deprecation, and a README aimed at an AI
agent. `--command "<install line>"` and `--hook` (a Claude Code PreToolUse event on stdin) read `npm install`,
`pnpm add`, `yarn add`, `pip install` and `uv add` lines. Contacts only registry.npmjs.org and pypi.org;
`--offline` contacts nothing. Exit code 1 on a high finding. In code: `pkgcheck(specs, options)`.

## Exfiltration guard

`ingress outcheck [--session <id>] [--safe] [--json] < reply` reads a model's reply for data hidden in image and
link addresses, HTML and CSS URLs, and subdomains (encoded runs, credentials, the session marker, text from earlier
tool results) before a chat window renders it. Exit code 1 when hostile; `--safe` prints the reply with those
addresses taken out. In code: `outcheck(text, options)`. The action broker applies the same checks to tool calls.

## File and corpus scan

`ingress filescan <file...> [--clean-out <dir>] [--json]` gates files before an agent reads them. It separates what a
person sees from what only an extractor reads: in PDFs white, tiny, off-page, covered and invisible-mode (`Tr 3`)
text, annotations, properties and JavaScript; in Word, Excel and PowerPoint hidden runs, white or tiny text,
comments, notes, alt text, hidden sheets, rows and shapes, `;;;` cells, macros and remote templates; in images their
metadata. Every piece goes through the engine. `--clean-out` writes only the visible text, re-checked on its own.
`ingress corpusscan <dir> [--quarantine <dir> [--copy] [--suspect]]` does the same for a folder (a RAG knowledge
base), four files at a time, and moves or copies hostile files aside with a manifest of hashes and verdicts. It never
deletes. No network requests. In code: `filescan(path, options)`, `corpusscan(dir, options)`.

Full documentation: https://github.com/sugarcypher/acepasteINGRESS
