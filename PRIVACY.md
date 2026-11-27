# Privacy: who Ingress talks to

Ingress has no telemetry or analytics, and it never phones home. Scanning is deterministic and runs on your
machine. No model and no outside scanning service is involved. In library, CLI and MCP mode, what it reads
stays on your machine. Its state lives in `~/.acepaste-ingress` with owner-only file permissions.

It does still make some network connections. Every one is listed below. Nothing else is contacted.

| Who | What they learn | When |
|---|---|---|
| Each site the gate fetches | Your IP address and the page requested. By default each page is fetched twice: once with an AI-assistant user agent (one of ChatGPT-User, Claude-User or Perplexity-User, picked at random), and once with a desktop Chrome user agent, to catch cloaking. If a site refuses the AI user agent, it fetches once more as `AcePasteIngress/0.10 (+https://acepaste.xyz/ingress)`. | Every fetch you or your agent asks for. `INGRESS_AGENT_UA=honest` sends only the gate's own name. `INGRESS_AGENT_UA` and `INGRESS_SELF_UA` let you choose the strings yourself. `INGRESS_HUMAN_PROXY` sends the browser-fingerprint fetch through a proxy. |
| abuse.ch, Spamhaus, Emerging Threats | Your IP address and the gate's user agent | Once a day at most, when the downloaded lists are more than a day old (on by default). `INGRESS_BLOCKLIST_AUTO=off` stops it; `ingress blocklist update` then refreshes by hand. |
| Cloudflare (`cloudflare-dns.com`), plus a fixed list of watched sites | The names on a fixed list of watched domains (search engines, AI providers, code registries, Wikipedia), not your browsing | Only with `ingress audit --network`, which compares your DNS answers with Cloudflare's and opens a TLS connection to each of those sites |
| The API you scan with `ingress apiscan` | Your IP address, the gate's own user agent (`AcePasteIngress/0.10`), and a fixed set of read-only requests (about 60 at most). Your auth header, if you give one, goes only to that API. | Only when you run `ingress apiscan <url>`. It contacts only the host in the URL you give, plus the spec URL if you give one, and never follows a redirect to anywhere else. |
| The MCP servers you scan with `ingress mcpscan` | With `--connect`: each server in your AI apps' configs is started on your machine or, for a remote one, contacted with your IP address, the gate's own user agent and the headers from your config, exactly as your AI app would. With `--url`: that one server, with the headers you give. Only `initialize` and list requests are sent; no tool is called. | Only with `ingress mcpscan --connect` or `--url`. Without them it reads config files and contacts nothing. Pins stay in your state directory. |
| Nobody, for `ingress reposcan` | Nothing. It reads files in the directory you give it and runs `git` locally; it opens no network connection, and the engine it uses is handed a fetch that refuses. | Never. The GitHub Action that wraps it downloads `@acepaste/ingress` from the npm registry and uploads its SARIF report to your own repository's GitHub code scanning, both from GitHub's runner and through GitHub's own actions. |
| The site you open with `ingress show` | The same as any page the gate fetches (first row): your IP address and the page, fetched with the same two user agents. | Only with `ingress show <url>`, or `GET /v1/show?url=` on an HTTP service. `ingress show <file>` reads the file and contacts nothing. The report it writes loads no scripts or remote content. |
| Nobody, for `ingress outcheck`, `ingress filescan` and `ingress corpusscan` | Nothing. They read the reply or the files you give them on your machine. Links, remote templates and embedded addresses are reported, never fetched. | Never. `corpusscan --quarantine` moves or copies files on your own disk. |
| The npm registry (`registry.npmjs.org`) and PyPI (`pypi.org`) | Your IP address, the gate's own user agent, and the names of the packages you check (one GET per package) | Only when you run `ingress pkgcheck` without `--offline`, or install its optional Claude Code hook (then on each install command an agent runs). Nothing else is contacted, and the list of popular names it compares against is built in, never downloaded. |
| An Ingress HTTP service you call (ThinkWell Labs's hosted one, or anyone else's) | The URLs and text you send, usage records per API key (operation, verdict and duration), and verdicts with the URL and source host | Only with `--remote`, `INGRESS_API_KEY` hooks, or when you call a hosted service directly. A hosted service runs on someone's servers. ThinkWell Labs's hosted service runs on Fly.io. |

## The public attack feed of a hosted service

`@acepaste/ingress-http` publishes a feed of recent non-clean verdicts at `/v1/feed`. For a page on a public
host, an entry holds:

- the host name (not the full URL)
- the verdict, its score and the content type
- the kinds of findings
- the outside hosts the payload tried to reach
- up to six excerpts of the hidden payload, each cut to 160 characters

Text you submit yourself (`/v1/scan`, inline sources) never appears in the feed. Neither do pages on private,
local or unresolvable hosts.

**A page you ask a hosted service to fetch (`/v1/fetch`) that turns out suspect or hostile can appear in the
feed as its host name and excerpts.** If that matters, run your own copy of the service, or use the library,
CLI or MCP server, which publish nothing.

If you run the HTTP service yourself, the feed is yours: it lives in memory, and in `INGRESS_FEED_FILE` if you
set one.

## Not yet confirmed

The optional headless-browser render sends its requests through the gate's network policy. That path has not
been traced end to end, and neither has the macOS helper code in `packages/core/native`, to confirm that
nothing leaves outside the connections above.
