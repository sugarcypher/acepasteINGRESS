#!/usr/bin/env node
/**
 * AcePaste Gate — HTTP service. This is the metered product.
 *
 *   POST /v1/fetch   { url, override? }                          -> GateResult
 *   POST /v1/scan    { content, source?, contentType?, override?}-> GateResult
 *   POST /v1/verify  { receipt }                                 -> { digestOk, signatureOk }
 *   GET  /v1/feed                 recent non-clean verdicts, anonymized (public)
 *   GET  /v1/receipts             the caller's own receipts, searchable (audit plane)
 *   GET  /v1/receipts/export      the caller's receipts as a JSON download
 *   GET  /v1/receipts/stats       counts for the caller's key
 *   GET  /healthz
 *   GET  /            -> the public attack feed page
 *   GET  /console     -> the audit console
 *
 * Auth: `Authorization: Bearer <key>`. Keys from GATE_KEYS ("k:name,k2:name2")
 * or GATE_KEYS_FILE (JSON { key: { name, rpm, daily } }). No key configured =
 * open (development only; logs a warning). The public feed and pages need no key.
 *
 * Config: GATE_SIGNING_KEY, GATE_SANDBOX, GATE_CLOAKING, GATE_POLICY, GATE_LOG,
 * GATE_RECEIPTS_FILE (audit store path; omit for in-memory), GATE_RETENTION_DAYS.
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { appendFileSync, readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, normalize } from "node:path";
import { GateEngine, loadPolicyFile, type GateConfig, type GateResult, type TaintReceipt } from "@acepaste/gate-core";
import { JsonlReceiptStore, toStored, type ReceiptStore } from "./store.js";

const env = process.env;
const PORT = Number(env.PORT ?? 8787);
const MAX_BODY = 6 * 1024 * 1024;
const PUBLIC_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "public");

// ---------- config ----------
const cfg: Partial<GateConfig> = env.GATE_POLICY ? loadPolicyFile(env.GATE_POLICY) : {};
if (env.GATE_SIGNING_KEY) cfg.signingKey = env.GATE_SIGNING_KEY;
if (env.GATE_SANDBOX === "off" || env.GATE_SANDBOX === "escalate" || env.GATE_SANDBOX === "always") cfg.sandbox = env.GATE_SANDBOX;
if (env.GATE_CLOAKING === "0") cfg.cloakingCheck = false;

// ---------- attack log + feed ----------
const FEED_MAX = 500;
const feed: Record<string, unknown>[] = [];
const logPath = env.GATE_LOG;
const log = (e: Record<string, unknown>) => {
  const line = JSON.stringify(e) + "\n";
  if (logPath) { try { appendFileSync(logPath, line); } catch { /* best effort */ } } else process.stderr.write(line);
  if (e.event === "gate.verdict") {
    feed.unshift({
      at: e.at, tier: e.tier, score: e.score, sourceHost: e.sourceHost, contentKind: e.contentKind,
      kinds: (e.findings as Array<{ kind: string }>).map((f) => f.kind),
      outboundHosts: e.outboundHosts,
      payloadExcerpts: [
        ...(e.decodedPayloads as string[]).map((p) => p.slice(0, 160)),
        ...(e.findings as Array<{ excerpt?: string }>).map((f) => f.excerpt).filter((x): x is string => !!x).map((x) => x.slice(0, 160)),
      ].slice(0, 6),
    });
    if (feed.length > FEED_MAX) feed.length = FEED_MAX;
  }
};

const engine = new GateEngine(cfg, { log });

// ---------- audit store ----------
const store: ReceiptStore = new JsonlReceiptStore({ path: env.GATE_RECEIPTS_FILE });
const retentionDays = Number(env.GATE_RETENTION_DAYS ?? 0);
if (retentionDays > 0) {
  store.prune(retentionDays);
  setInterval(() => store.prune(retentionDays), 6 * 3600 * 1000).unref();
}
function record(keyName: string, r: GateResult) {
  try { store.put(toStored(keyName, r.receipt, [...new Set(r.findings.map((f) => f.kind))])); } catch { /* audit is best-effort, never blocks a verdict */ }
}

// ---------- keys + metering ----------
interface KeyInfo { name: string; rpm: number; daily: number }
const keys = new Map<string, KeyInfo>();
if (env.GATE_KEYS_FILE) {
  const j = JSON.parse(readFileSync(env.GATE_KEYS_FILE, "utf8")) as Record<string, Partial<KeyInfo>>;
  for (const [k, v] of Object.entries(j)) keys.set(k, { name: v.name ?? k.slice(0, 6), rpm: v.rpm ?? 60, daily: v.daily ?? 5000 });
} else if (env.GATE_KEYS) {
  for (const pair of env.GATE_KEYS.split(",")) { const [k, name] = pair.split(":"); if (k) keys.set(k.trim(), { name: (name ?? k.slice(0, 6)).trim(), rpm: 60, daily: 5000 }); }
}
const open = keys.size === 0;
if (open) process.stderr.write(JSON.stringify({ event: "gate.warn", message: "no API keys configured; server is open (development only)" }) + "\n");

class Meter {
  private minute = new Map<string, { win: number; n: number }>();
  private day = new Map<string, { day: string; n: number }>();
  take(key: string, info: KeyInfo): { ok: true } | { ok: false; reason: string; retryAfter: number } {
    const now = Date.now();
    const win = Math.floor(now / 60000);
    const m = this.minute.get(key);
    if (!m || m.win !== win) this.minute.set(key, { win, n: 1 });
    else if (m.n >= info.rpm) return { ok: false, reason: "rate limit (per minute)", retryAfter: 60 - Math.floor((now % 60000) / 1000) };
    else m.n++;
    const today = new Date(now).toISOString().slice(0, 10);
    const d = this.day.get(key);
    if (!d || d.day !== today) this.day.set(key, { day: today, n: 1 });
    else if (d.n >= info.daily) return { ok: false, reason: "daily quota", retryAfter: 3600 };
    else d.n++;
    return { ok: true };
  }
  usage(key: string) { return { minute: this.minute.get(key)?.n ?? 0, today: this.day.get(key)?.n ?? 0 }; }
}
const meter = new Meter();

// ---------- http helpers ----------
function send(res: ServerResponse, status: number, body: unknown, extra: Record<string, string> = {}) {
  const json = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "content-length": Buffer.byteLength(json), "cache-control": "no-store", "x-content-type-options": "nosniff", ...extra });
  res.end(json);
}
function sendFile(res: ServerResponse, name: string) {
  const path = normalize(join(PUBLIC_DIR, name));
  if (!path.startsWith(PUBLIC_DIR) || !existsSync(path)) return send(res, 404, { error: "not found" });
  const body = readFileSync(path);
  res.writeHead(200, { "content-type": "text/html; charset=utf-8", "content-length": body.length, "cache-control": "public, max-age=60", "x-content-type-options": "nosniff" });
  res.end(body);
}
async function readJson(req: IncomingMessage): Promise<any> {
  const chunks: Buffer[] = []; let total = 0;
  for await (const c of req) { total += (c as Buffer).length; if (total > MAX_BODY) throw new Error("body too large"); chunks.push(c as Buffer); }
  const text = Buffer.concat(chunks).toString("utf8");
  return text ? JSON.parse(text) : {};
}
function auth(req: IncomingMessage): { key: string; info: KeyInfo } | null {
  if (open) return { key: "open", info: { name: "open", rpm: 600, daily: 100000 } };
  const m = (req.headers.authorization ?? "").match(/^Bearer\s+(\S+)$/i);
  if (!m) return null;
  const info = keys.get(m[1]);
  return info ? { key: m[1], info } : null;
}

const server = createServer(async (req, res) => {
  const started = Date.now();
  const url = new URL(req.url ?? "/", "http://localhost");
  const path = url.pathname;
  try {
    // public, no key
    if (req.method === "GET" && path === "/healthz") return send(res, 200, { ok: true, sandbox: engine.config.sandbox, keys: keys.size, receipts: store.stats("").total });
    if (req.method === "GET" && (path === "/" || path === "/feed")) return sendFile(res, "feed.html");
    if (req.method === "GET" && path === "/console") return sendFile(res, "console.html");
    if (req.method === "GET" && path === "/v1/feed") {
      const limit = Math.min(200, Number(url.searchParams.get("limit") ?? 50));
      return send(res, 200, { count: feed.length, items: feed.slice(0, limit) }, { "access-control-allow-origin": "*" });
    }

    // authed
    const a = auth(req);
    if (!a) return send(res, 401, { error: "missing or unknown API key" }, { "www-authenticate": "Bearer" });

    // audit reads do not consume the scan quota
    if (req.method === "GET" && (path === "/v1/receipts" || path === "/v1/receipts/export")) {
      const q = {
        key: a.info.name,
        url: url.searchParams.get("url") ?? undefined,
        host: url.searchParams.get("host") ?? undefined,
        tier: url.searchParams.get("tier") ?? undefined,
        kind: url.searchParams.get("kind") ?? undefined,
        since: url.searchParams.get("since") ?? undefined,
        until: url.searchParams.get("until") ?? undefined,
        limit: path.endsWith("export") ? 100000 : Number(url.searchParams.get("limit") ?? 100),
        offset: Number(url.searchParams.get("offset") ?? 0),
      };
      const out = store.query(q);
      if (path.endsWith("export")) {
        const body = JSON.stringify({ exportedAt: new Date().toISOString(), key: a.info.name, total: out.total, receipts: out.items }, null, 2);
        res.writeHead(200, { "content-type": "application/json", "content-disposition": 'attachment; filename="acepaste-receipts.json"', "content-length": Buffer.byteLength(body), "cache-control": "no-store" });
        return res.end(body);
      }
      return send(res, 200, { ...out, stats: store.stats(a.info.name) });
    }
    if (req.method === "GET" && path === "/v1/receipts/stats") return send(res, 200, store.stats(a.info.name));

    if (req.method !== "POST") return send(res, 405, { error: "method not allowed" });

    if (path === "/v1/verify") {
      const body = await readJson(req);
      if (!body.receipt || typeof body.receipt !== "object") return send(res, 400, { error: "receipt required" });
      return send(res, 200, GateEngine.verifyReceipt(body.receipt as TaintReceipt, env.GATE_SIGNING_KEY));
    }

    // scan / fetch consume the quota
    const m = meter.take(a.key, a.info);
    if (!m.ok) return send(res, 429, { error: m.reason }, { "retry-after": String(m.retryAfter) });
    const body = await readJson(req);

    if (path === "/v1/fetch") {
      if (typeof body.url !== "string") return send(res, 400, { error: "url required" });
      const r = await engine.fetch(body.url, { override: body.override === true });
      record(a.info.name, r);
      log({ event: "gate.usage", key: a.info.name, op: "fetch", tier: r.tier, ms: Date.now() - started, usage: meter.usage(a.key) });
      return send(res, r.tier === "clean" || r.overridden ? 200 : 422, r);
    }
    if (path === "/v1/scan") {
      if (typeof body.content !== "string") return send(res, 400, { error: "content required" });
      const r = await engine.scan(body.content, { url: body.source, contentType: body.contentType, isHtml: body.isHtml, override: body.override === true });
      record(a.info.name, r);
      log({ event: "gate.usage", key: a.info.name, op: "scan", tier: r.tier, ms: Date.now() - started, usage: meter.usage(a.key) });
      return send(res, r.tier === "clean" || r.overridden ? 200 : 422, r);
    }
    return send(res, 404, { error: "not found" });
  } catch (e) {
    const msg = (e as Error).message;
    return send(res, msg === "body too large" ? 413 : msg?.startsWith("Unexpected") ? 400 : 500, { error: msg });
  }
});

server.listen(PORT, () => process.stderr.write(JSON.stringify({ event: "gate.listen", port: PORT, open, sandbox: engine.config.sandbox, audit: !!env.GATE_RECEIPTS_FILE }) + "\n"));
