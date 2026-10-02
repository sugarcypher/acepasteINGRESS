#!/usr/bin/env node
/**
 * AcePaste Gate — HTTP service. This is the metered product.
 *
 *   POST /v1/fetch   { url, override? }                     -> GateResult
 *   POST /v1/scan    { content, source?, contentType?, override? } -> GateResult
 *   POST /v1/verify  { receipt }                            -> { digestOk, signatureOk }
 *   GET  /v1/feed    recent non-clean verdicts, anonymized (attacking hosts, kinds, payload excerpts)
 *   GET  /healthz
 *
 * Auth: `Authorization: Bearer <key>`. Keys come from GATE_KEYS ("key1:name1,key2:name2")
 * or a GATE_KEYS_FILE (JSON { key: { name, rpm, daily } }). No key configured = open
 * (development only; the server logs a warning).
 *
 * Metering: per-key counters in memory plus a usage log line per request; swap
 * `Meter` for a database-backed implementation in production.
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { appendFileSync, readFileSync } from "node:fs";
import { GateEngine, loadPolicyFile, type GateConfig, type TaintReceipt } from "@acepaste/gate-core";

const env = process.env;
const PORT = Number(env.PORT ?? 8787);
const MAX_BODY = 6 * 1024 * 1024;

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
  if (logPath) appendFileSync(logPath, line); else process.stderr.write(line);
  if (e.event === "gate.verdict") {
    feed.unshift({
      at: e.at, tier: e.tier, score: e.score, sourceHost: e.sourceHost, contentKind: e.contentKind,
      kinds: (e.findings as Array<{ kind: string }>).map((f) => f.kind),
      outboundHosts: e.outboundHosts,
      payloadExcerpts: [
        ...(e.decodedPayloads as string[]).map((p) => p.slice(0, 160)),
        ...(e.findings as Array<{ excerpt?: string }>).map((f) => f.excerpt).filter((x): x is string => !!x).map((x) => x.slice(0, 160)),
      ].slice(0, 8),
    });
    if (feed.length > FEED_MAX) feed.length = FEED_MAX;
  }
};

const engine = new GateEngine(cfg, { log });

// ---------- keys and metering ----------
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

// ---------- http ----------
function send(res: ServerResponse, status: number, body: unknown, extra: Record<string, string> = {}) {
  const json = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "content-length": Buffer.byteLength(json), "cache-control": "no-store", "x-content-type-options": "nosniff", ...extra });
  res.end(json);
}

async function readJson(req: IncomingMessage): Promise<any> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const c of req) {
    total += (c as Buffer).length;
    if (total > MAX_BODY) throw new Error("body too large");
    chunks.push(c as Buffer);
  }
  const text = Buffer.concat(chunks).toString("utf8");
  return text ? JSON.parse(text) : {};
}

function auth(req: IncomingMessage): { key: string; info: KeyInfo } | null {
  if (open) return { key: "open", info: { name: "open", rpm: 600, daily: 100000 } };
  const h = req.headers.authorization ?? "";
  const m = h.match(/^Bearer\s+(\S+)$/i);
  if (!m) return null;
  const info = keys.get(m[1]);
  return info ? { key: m[1], info } : null;
}

const server = createServer(async (req, res) => {
  const started = Date.now();
  const url = new URL(req.url ?? "/", "http://localhost");
  try {
    if (req.method === "GET" && url.pathname === "/healthz") return send(res, 200, { ok: true, engine: engine.config.sandbox, keys: keys.size });
    if (req.method === "GET" && url.pathname === "/v1/feed") {
      const limit = Math.min(200, Number(url.searchParams.get("limit") ?? 50));
      return send(res, 200, { count: feed.length, items: feed.slice(0, limit) });
    }

    const a = auth(req);
    if (!a) return send(res, 401, { error: "missing or unknown API key" }, { "www-authenticate": "Bearer" });
    const m = meter.take(a.key, a.info);
    if (!m.ok) return send(res, 429, { error: m.reason }, { "retry-after": String(m.retryAfter) });

    if (req.method !== "POST") return send(res, 405, { error: "method not allowed" });
    const body = await readJson(req);

    if (url.pathname === "/v1/fetch") {
      if (typeof body.url !== "string") return send(res, 400, { error: "url required" });
      const r = await engine.fetch(body.url, { override: body.override === true });
      log({ event: "gate.usage", key: a.info.name, op: "fetch", tier: r.tier, ms: Date.now() - started, usage: meter.usage(a.key) });
      return send(res, r.tier === "clean" || r.overridden ? 200 : 422, r);
    }
    if (url.pathname === "/v1/scan") {
      if (typeof body.content !== "string") return send(res, 400, { error: "content required" });
      const r = await engine.scan(body.content, { url: body.source, contentType: body.contentType, isHtml: body.isHtml, override: body.override === true });
      log({ event: "gate.usage", key: a.info.name, op: "scan", tier: r.tier, ms: Date.now() - started, usage: meter.usage(a.key) });
      return send(res, r.tier === "clean" || r.overridden ? 200 : 422, r);
    }
    if (url.pathname === "/v1/verify") {
      if (!body.receipt || typeof body.receipt !== "object") return send(res, 400, { error: "receipt required" });
      return send(res, 200, GateEngine.verifyReceipt(body.receipt as TaintReceipt, env.GATE_SIGNING_KEY));
    }
    return send(res, 404, { error: "not found" });
  } catch (e) {
    const msg = (e as Error).message;
    return send(res, msg === "body too large" ? 413 : msg.startsWith("Unexpected") ? 400 : 500, { error: msg });
  }
});

server.listen(PORT, () => process.stderr.write(JSON.stringify({ event: "gate.listen", port: PORT, open }) + "\n"));
