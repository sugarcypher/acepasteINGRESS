#!/usr/bin/env node
// Score AcePaste Ingress on HIB through its real entry points. Writes one verdict per item (JSON Lines), resumable.
//
//   INGRESS_REPO=. node bench/hib/score/ingress.mjs --split public [--data bench/hib/data] [--out results/x.jsonl]
//        [--fixtures http://127.0.0.1:8765] [--concurrency 4] [--limit N]
//
// Entry points (each as the shipped engine runs it; nothing here changes a threshold or a rule):
//   page  (web_*)          IngressEngine.fetch(url) = `ingress <url>`, default config: cloaking check on (two fetches,
//                          agent and browser user agents), external stylesheets on, sandbox "escalate" (headless
//                          Chromium when static suspicion >= 0.5). Only changes: the network policy allows the
//                          loopback fixture server, the cache is off, the jitter between the two fetches is zero
//                          and the engine's random choices are seeded (none of these touches a verdict rule).
//   text  (email_html)     IngressEngine.scan(raw .eml) = `ingress --text < mail.eml` (kind detected as email).
//   file  (readme, pdf, docx, xlsx, pptx, png)   filescan(path) = `ingress filescan <file>`.
//   mcp   (mcp_tools_json) mcpscan({url}) = `ingress mcpscan --url <fixture>`; flagged when any finding is "high"
//                          (the command's exit-1 condition). "review" findings are recorded separately.
// A verdict is "flagged" when the tier is hostile or suspect (refused / not delivered as clean), as in docs/EVAL-0.10.0.md.
import { readFileSync, existsSync, appendFileSync, mkdtempSync, rmSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { pathToFileURL } from "node:url";

const args = process.argv.slice(2);
const opt = (k, d) => { const i = args.indexOf(`--${k}`); return i >= 0 ? args[i + 1] : d; };
const repo = resolve(process.env.INGRESS_REPO ?? process.cwd());
const split = opt("split", "public");
const data = resolve(opt("data", join(import.meta.dirname, "..", "data")));
const out = resolve(opt("out", join(import.meta.dirname, "..", "results", `ingress-0.10.0-${split}.jsonl`)));
let fixtures = opt("fixtures");
let fixtureServer;
if (!fixtures) { // no external fixture server given: run one in this process
  const { startFixtures } = await import("../server/fixtures.mjs");
  fixtureServer = await startFixtures({ data, port: 0 });
  fixtures = `http://127.0.0.1:${fixtureServer.address().port}`;
}
const conc = Number(opt("concurrency", 4));
const limit = Number(opt("limit", 1e9));

const core = (p) => import(pathToFileURL(`${repo}/packages/core/dist/src/${p}`).href);
const { IngressEngine } = await core("index.js");
const { ENGINE_VERSION, RULESET_VERSION } = await core("types.js");
const { filescan } = await core("filescan.js");
const { mcpscan } = await core("mcpscan.js");

// seeded randomness for the engine's user-agent choice and fetch order (mulberry32)
let s = 0x9e3779b9; const random = () => { s |= 0; s = (s + 0x6d2b79f5) | 0; let t = Math.imul(s ^ (s >>> 15), 1 | s); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
const port = Number(new URL(fixtures).port || 80);
const pageEngine = new IngressEngine({ cacheTtlSeconds: 0, net: { denyHosts: [], allowHosts: [], extraPorts: [port], allowPrivate: true } }, { log: () => {}, sleep: async () => {}, random });
const textEngine = new IngressEngine({}, { log: () => {} });

const rows = readFileSync(join(data, split, "manifest.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
const done = new Set(existsSync(out) ? readFileSync(out, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l).id) : []);
const only = opt("ids") ? new Set(opt("ids").split(",")) : null;
const todo = rows.filter((r) => !done.has(r.id) && (!only || only.has(r.id))).slice(0, limit);
const flaggedTier = (t) => t === "hostile" || t === "suspect";
const kinds = (fs) => [...new Set((fs ?? []).filter((f) => (f.severity ?? 0) > 0 || f.weight > 0).map((f) => f.kind))].slice(0, 8);

async function judge(r) {
  const t0 = performance.now();
  const path = join(data, split, r.file);
  if (r.entry === "page") {
    const res = await pageEngine.fetch(`${fixtures}/${split}/${r.id}`);
    return { tier: res.tier, flagged: flaggedTier(res.tier), score: res.score, kinds: kinds(res.findings), passes: res.passesRun, ms: performance.now() - t0 };
  }
  if (r.entry === "text") {
    const res = await textEngine.scan(readFileSync(path, "utf8"));
    return { tier: res.tier, flagged: flaggedTier(res.tier), score: res.score, kinds: kinds(res.findings), detected_kind: res.kind, ms: performance.now() - t0 };
  }
  if (r.entry === "file") {
    const res = await filescan(path);
    return { tier: res.tier, flagged: flaggedTier(res.tier), score: res.score, kinds: res.reasons.map((x) => x.kind).slice(0, 8), status: res.status, complete: res.complete, hidden_parts: res.hidden.map((x) => x.where).slice(0, 5), ms: performance.now() - t0 };
  }
  if (r.entry === "mcp") {
    const dir = mkdtempSync(join(tmpdir(), "hib-mcp-"));
    try {
      const rep = await mcpscan({ url: `${fixtures}/mcp/${split}/${r.id}`, dir, timeoutMs: 10000 });
      const high = rep.findings.filter((f) => f.severity === "high"), review = rep.findings.filter((f) => f.severity === "review");
      const failed = rep.servers.some((x) => x.mode === "failed");
      return { tier: failed ? "unreachable" : high.length ? "high" : review.length ? "review" : "clean", flagged: high.length > 0, review: review.length > 0, ids: [...new Set(rep.findings.filter((f) => f.severity !== "info").map((f) => f.id))], ms: performance.now() - t0 };
    } finally { rmSync(dir, { recursive: true, force: true }); }
  }
  throw new Error(`unknown entry ${r.entry}`);
}

let i = 0, n = 0;
const t0 = performance.now();
async function worker() {
  while (i < todo.length) {
    const r = todo[i++];
    let v;
    try { v = await judge(r); } catch (e) { v = { tier: "error", flagged: false, error: String(e?.message ?? e).slice(0, 200) }; }
    appendFileSync(out, JSON.stringify({ id: r.id, defense: `acepaste-ingress ${ENGINE_VERSION} (ruleset ${RULESET_VERSION})`, ...v }) + "\n");
    n++;
  }
}
await Promise.all(Array.from({ length: conc }, worker));
fixtureServer?.close();
console.log(JSON.stringify({ split, scored: n, already: done.size, total: rows.length, seconds: ((performance.now() - t0) / 1000).toFixed(1), out }));
