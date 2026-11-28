#!/usr/bin/env node
// HIB fixture server. Serves generated carriers over HTTP so a defense can be scored through its real URL entry
// point, and simulates user-agent cloaking and MCP servers. Local only; no third-party dependencies.
//
//   node server/fixtures.mjs [--data bench/hib/data] [--port 8765]
//
//   GET  /<split>/<id>          the carrier file (web pages as text/html). For ua_cloaking items the copy depends
//                               on the User-Agent (see CLOAK_RULES below).
//   POST /mcp/<split>/<id>      a minimal MCP streamable-HTTP server (JSON responses) whose tools/list returns the
//                               item's tool definitions.
//   GET  /_served               JSON counts of which copy each cloaking item served (for checking the fixture works).
import { createServer } from "node:http";
import { readFileSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";

import { fileURLToPath } from "node:url";
let DATA = resolve(join(import.meta.dirname, "..", "data"));

// Tokens of AI crawlers and AI assistants' fetchers, as published by their operators and collected by the
// ai.robots.txt project. A cloaking site keys on these; HIB does not key on any one defense's user agents.
const AI_TOKENS = /(GPTBot|ChatGPT-User|OAI-SearchBot|ClaudeBot|Claude-User|Claude-Web|Claude-SearchBot|anthropic-ai|PerplexityBot|Perplexity-User|Google-Extended|GoogleOther|CCBot|Bytespider|cohere-ai|meta-externalagent|Meta-ExternalFetcher|Amazonbot|Applebot-Extended|DuckAssistBot|MistralAI-User|YouBot|Diffbot|AI2Bot|PetalBot)/i;
// A mainstream desktop or mobile browser: "Mozilla/5.0 (<platform>) ... Chrome/|Firefox/|Safari/"
const BROWSER = /^Mozilla\/5\.0 \([^)]*\) .*(Chrome|Firefox|Safari)\/[\d.]+/;
const CLOAK_RULES = {
  ai_ua_tokens: (ua) => AI_TOKENS.test(ua),                        // agent copy for known AI user agents
  non_browser_ua: (ua) => AI_TOKENS.test(ua) || !BROWSER.test(ua), // agent copy for anything that is not a mainstream browser
  // held-out-v2 (family C): known AI tokens, headless browsers and HTTP libraries / command-line clients
  automation_ua: (ua) => AI_TOKENS.test(ua) || /HeadlessChrome|PhantomJS|python-requests|python-urllib|aiohttp|httpx|curl\/|Wget|node-fetch|undici|axios|Go-http-client|okhttp|libwww-perl|Scrapy/i.test(ua) || ua === "",
};

const manifests = new Map();
function item(split, id) {
  if (!manifests.has(split)) {
    const p = join(DATA, split, "manifest.jsonl");
    if (!existsSync(p)) return undefined;
    manifests.set(split, new Map(readFileSync(p, "utf8").split("\n").filter(Boolean).map((l) => { const r = JSON.parse(l); return [r.id, r]; })));
  }
  return manifests.get(split).get(id);
}

const served = {};
const TYPES = { html: "text/html; charset=utf-8", md: "text/markdown; charset=utf-8", json: "application/json", eml: "message/rfc822",
  pdf: "application/pdf", png: "image/png", docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", pptx: "application/vnd.openxmlformats-officedocument.presentationml.presentation" };

function mcp(req, res, r, body) {
  let msg; try { msg = JSON.parse(body); } catch { res.writeHead(400).end(); return; }
  const listing = JSON.parse(readFileSync(join(DATA, r.split, r.file), "utf8"));
  if (msg.id === undefined) { res.writeHead(202).end(); return; } // notification
  const reply = (result) => { res.writeHead(200, { "content-type": "application/json", "mcp-session-id": `hib-${r.id}` }); res.end(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result })); };
  if (msg.method === "initialize") return reply({ protocolVersion: msg.params?.protocolVersion ?? "2025-06-18", capabilities: { tools: {} }, serverInfo: listing.server });
  if (msg.method === "tools/list") return reply({ tools: listing.tools });
  if (msg.method === "prompts/list") return reply({ prompts: [] });
  if (msg.method === "resources/list") return reply({ resources: [] });
  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify({ jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: "method not found" } }));
}

/** Start the fixture server in this process. Resolves to the server once it listens. */
export function startFixtures({ data = DATA, port = 8765 } = {}) {
  DATA = resolve(data);
  return new Promise((ok) => { const srv = createServer(handle); srv.listen(port, "127.0.0.1", () => ok(srv)); });
}

function handle(req, res) {
  const url = new URL(req.url, "http://x");
  const parts = url.pathname.split("/").filter(Boolean);
  if (parts[0] === "_served") { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(served)); return; }
  if (parts[0] === "mcp" && parts.length === 3) {
    const r = item(parts[1], parts[2]);
    if (!r) { res.writeHead(404).end(); return; }
    if (req.method === "DELETE") { res.writeHead(200).end(); return; }
    if (req.method !== "POST") { res.writeHead(405).end(); return; }
    let body = ""; req.on("data", (c) => (body += c)); req.on("end", () => mcp(req, res, r, body)); return;
  }
  if (parts.length !== 2) { res.writeHead(404).end("not found"); return; }
  const r = item(parts[0], parts[1].replace(/\.[a-z]+$/, ""));
  if (!r) { res.writeHead(404).end("not found"); return; }
  let file = r.file;
  if (r.agent_file) {
    const ua = req.headers["user-agent"] ?? "";
    const agent = CLOAK_RULES[r.cloak_rule.split("/")[0]](ua);
    if (agent) file = r.agent_file;
    (served[r.id] ??= { agent: 0, human: 0 })[agent ? "agent" : "human"]++;
  }
  const ext = file.split(".").pop();
  res.writeHead(200, { "content-type": TYPES[ext] ?? "application/octet-stream", "cache-control": "no-store" });
  res.end(readFileSync(join(DATA, r.split, file)));
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const opt = (k, d) => { const i = args.indexOf(`--${k}`); return i >= 0 ? args[i + 1] : d; };
  const port = Number(opt("port", 8765));
  await startFixtures({ data: opt("data", DATA), port });
  console.error(`hib fixtures on http://127.0.0.1:${port}/ serving ${DATA}`);
}
