/**
 * The egress proxy: where programs an agent runs actually connect.
 *
 * The egress hook reads a command. It does not read the program the command starts: `python upload.py` sends
 * whatever the script sends. Stopping that for a whole machine needs a network filter Apple licenses. This is
 * the part that needs no licence: an HTTP forward proxy on 127.0.0.1 that the agent's shell commands are
 * pointed at (HTTPS_PROXY and friends), which decides each connection by its destination.
 *
 *   - CONNECT (everything over TLS) and plain HTTP. It sees a host name and a port, and counts bytes. It never
 *     reads what is sent: TLS is not opened.
 *   - Every client presents a token made for one agent session. No token, no service. The token says whose
 *     connection this is, so the decision can use what that session has read.
 *   - The decision reuses what the action broker knows (see ActionBroker.hostStanding): a blocklisted host or
 *     address is refused; an address on this machine or a private network is refused (the proxy must not be a
 *     way around the checks the gate's own fetches make); a host that came into the session only through
 *     outside content, and that no command named, is refused (or put to a person, when an approver is
 *     configured); a host on the allowlist, or one the person typed, passes. Anything else passes and is
 *     logged, or is refused in strict mode.
 *   - Every connection is logged in <state>/egress-proxy/connections.jsonl: time, session, host, port, bytes
 *     each way, decision. Never content.
 *
 * What it is not: a firewall. A program that ignores proxy settings connects directly unless it runs under the
 * sandbox wrapper below (`ingress run`). A host that is allowed can pass data on to another. It covers what
 * the agent starts, not the machine.
 */

import { createServer, request as httpRequest, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { connect as netConnect, isIP, type Socket } from "node:net";
import { lookup } from "node:dns/promises";
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, readFileSync, realpathSync, renameSync, statSync, writeFileSync } from "node:fs";
import { spawn, spawnSync } from "node:child_process";
import { homedir } from "node:os";
import { join } from "node:path";
import { stateDir } from "./changes.js";
import { stopReason } from "./safeguards.js";
import { ActionBroker, type Approver, type ApprovalRequest, type SerializedRun } from "./broker.js";
import { Blocklist } from "./egress.js";
import { isPrivateIP } from "./netpolicy.js";

export const EGRESS_PROXY_PORT = 8788;
const HEALTH_PATH = "/.well-known/ingress-egress-proxy";
/** how long a host named in a command the hook let through stays usable by what that command started */
export const VISIBLE_HOST_TTL_MS = 10 * 60_000;

const proxyDir = (dir: string) => join(dir, "egress-proxy");
const safeName = (session: string) => session.replace(/[^A-Za-z0-9_-]/g, "_").slice(0, 80);
/** the same file the hooks keep a session's state in (agent-hooks.ts) */
const sessionStatePath = (dir: string, session: string) => join(dir, "sessions", `${safeName(session)}.json`);
const cleanHost = (h: string) => h.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
const hmac = (secret: string, text: string) => createHmac("sha256", secret).update(text, "utf8").digest("hex");

function writeAtomic(path: string, text: string): void {
  writeFileSync(`${path}.${process.pid}.tmp`, text, { mode: 0o600 });
  renameSync(`${path}.${process.pid}.tmp`, path);
}
function readJson<T>(path: string): T | undefined {
  try { return JSON.parse(readFileSync(path, "utf8")) as T; } catch { return undefined; }
}

// ---------- tokens: whose connection is this ----------

/** The secret tokens are made with. Created on first use; readable by this user only. */
export function proxySecret(dir: string = stateDir()): string {
  const p = join(proxyDir(dir), "secret");
  try { const s = readFileSync(p, "utf8").trim(); if (s.length >= 32) return s; } catch { /* made below */ }
  mkdirSync(proxyDir(dir), { recursive: true, mode: 0o700 });
  try { writeFileSync(p, randomBytes(32).toString("hex") + "\n", { mode: 0o600, flag: "wx" }); } catch { /* another process made it first */ }
  return readFileSync(p, "utf8").trim();
}

/** A token for one session: the session's name and a keyed digest of it. Safe to put in a URL. */
export function sessionToken(secret: string, session: string): string {
  const s = session.slice(0, 200);
  return `${Buffer.from(s, "utf8").toString("base64url")}.${hmac(secret, `session:${s}`).slice(0, 40)}`;
}

/** The session a token was made for, or undefined when it was not made with this secret. */
export function sessionOfToken(secret: string, token: string): string | undefined {
  const dot = token.lastIndexOf(".");
  if (dot <= 0) return undefined;
  let session: string;
  try { session = Buffer.from(token.slice(0, dot), "base64url").toString("utf8"); } catch { return undefined; }
  if (!session) return undefined;
  const want = Buffer.from(hmac(secret, `session:${session}`).slice(0, 40)), got = Buffer.from(token.slice(dot + 1));
  return want.length === got.length && timingSafeEqual(want, got) ? session : undefined;
}

/** The variables that point a command's network calls at the proxy. Loopback is left alone. */
export function proxyEnv(port: number, token: string): Record<string, string> {
  const url = `http://ingress:${token}@127.0.0.1:${port}`;
  const none = "localhost,127.0.0.1,::1";
  return {
    HTTPS_PROXY: url, HTTP_PROXY: url, ALL_PROXY: url, https_proxy: url, http_proxy: url, all_proxy: url,
    NO_PROXY: none, no_proxy: none,
    NODE_USE_ENV_PROXY: "1", // Node 22.21 / 24 and later: fetch and http(s) honour the variables above
    INGRESS_EGRESS_PROXY_URL: url,
  };
}

// ---------- what the hooks leave for the proxy, and the proxy for the hooks ----------

/** Hosts named in a command the egress hook let through: what that command starts may connect to them. */
export function noteVisibleHosts(dir: string, session: string, hosts: readonly string[], now: number = Date.now()): void {
  if (!session || !hosts.length) return;
  const p = join(proxyDir(dir), "visible", `${safeName(session)}.json`);
  const seen = readJson<Record<string, number>>(p) ?? {};
  for (const h of hosts) seen[cleanHost(h)] = now;
  const kept = Object.entries(seen).filter(([, at]) => now - at < VISIBLE_HOST_TTL_MS).sort((a, b) => b[1] - a[1]).slice(0, 200);
  mkdirSync(join(proxyDir(dir), "visible"), { recursive: true, mode: 0o700 });
  writeAtomic(p, JSON.stringify(Object.fromEntries(kept)));
}

export function isVisibleHost(dir: string, session: string, host: string, now: number = Date.now()): boolean {
  const seen = readJson<Record<string, number>>(join(proxyDir(dir), "visible", `${safeName(session)}.json`));
  if (!seen) return false;
  const h = cleanHost(host);
  return Object.entries(seen).some(([named, at]) => now - at < VISIBLE_HOST_TTL_MS && (h === named || h.endsWith("." + named)));
}

/** When a shell command started, so the hook that runs after it can ask what connected meanwhile. */
export function noteCommandStart(dir: string, session: string, toolUseId: string, now: number = Date.now()): void {
  if (!session) return;
  const p = join(proxyDir(dir), "commands", `${safeName(session)}.json`);
  const all = readJson<Record<string, number>>(p) ?? {};
  all[toolUseId || "last"] = now; all.last = now;
  const kept = Object.entries(all).sort((a, b) => b[1] - a[1]).slice(0, 60);
  mkdirSync(join(proxyDir(dir), "commands"), { recursive: true, mode: 0o700 });
  writeAtomic(p, JSON.stringify(Object.fromEntries(kept)));
}

export function commandStart(dir: string, session: string, toolUseId: string | undefined): number | undefined {
  const all = readJson<Record<string, number>>(join(proxyDir(dir), "commands", `${safeName(session)}.json`));
  return all?.[toolUseId || "last"];
}

export interface ProxyConnection {
  at: string; session: string; host: string; port: number; decision: "allow" | "refuse";
  /** why, in a few words a person can read */
  reason: string; code: string;
  up?: number; down?: number; ms?: number; flag?: string; id: string; closed?: boolean;
}

const logPath = (dir: string) => join(proxyDir(dir), "connections.jsonl");

/** Connections a session opened (or was refused) since a moment. One entry per connection, with the bytes when it has closed. */
export function connectionsSince(dir: string, session: string, sinceMs: number): ProxyConnection[] {
  let text: string;
  try { text = readFileSync(logPath(dir), "utf8"); } catch { return []; }
  if (text.length > 4_000_000) text = text.slice(-4_000_000);
  const byId = new Map<string, ProxyConnection>();
  for (const line of text.split("\n")) {
    if (!line.includes(`"session":${JSON.stringify(session)}`)) continue;
    let e: ProxyConnection;
    try { e = JSON.parse(line) as ProxyConnection; } catch { continue; }
    if (e.session !== session || typeof e.id !== "string") continue;
    const first = byId.get(e.id);
    if (first) byId.set(e.id, { ...first, up: e.up, down: e.down, ms: e.ms, flag: e.flag ?? first.flag, closed: true });
    else if (Date.parse(e.at) >= sinceMs && !e.closed) byId.set(e.id, e);
  }
  return [...byId.values()];
}

// ---------- the decision ----------

export interface ProxyPolicy {
  /** "log": what no rule refuses passes and is logged. "strict": only allowlisted, typed and command-named hosts pass. */
  mode: "log" | "strict";
  /** hosts that pass without a question (a leading dot covers subdomains) */
  allowHosts: string[];
  /** hosts that may resolve to this machine or a private network */
  allowPrivate: string[];
  /** ports besides 80 and 443 */
  ports: number[];
  /** a host known only from outside content: refuse, or ask the approver */
  contentHosts: "refuse" | "ask";
  /** bytes sent on one connection, after the session has read outside content, that get the connection flagged */
  uploadFlagBytes: number;
}

export const DEFAULT_PROXY_POLICY: ProxyPolicy = { mode: "log", allowHosts: [], allowPrivate: [], ports: [], contentHosts: "refuse", uploadFlagBytes: 1_000_000 };

const hostIn = (host: string, list: readonly string[]) => list.some((a) => { const x = cleanHost(a); return x.startsWith(".") ? host === x.slice(1) || host.endsWith(x) : host === x; });

export interface ConnectionDecision { decision: "allow" | "refuse" | "ask"; code: string; reason: string }

/**
 * Decide one connection. Pure: everything it needs is handed in.
 * `addresses` are what the name resolved to (or the literal address); the caller connects to one of exactly those.
 * Without `addresses` only the rules about the name are applied. The proxy asks that way first: a name it is
 * going to refuse is never looked up, because a lookup of `<anything>.their-domain` is itself a message to
 * whoever runs that domain.
 */
export function decideConnection(
  c: { host: string; port: number; addresses?: readonly string[] },
  ctx: { policy: ProxyPolicy; blocklist: Blocklist; standing: { allowed: boolean; typed: boolean; fromContent?: string; tainted: boolean }; visible: boolean; stopped?: string },
): ConnectionDecision {
  const host = cleanHost(c.host), p = ctx.policy;
  if (ctx.stopped) return { decision: "refuse", code: "stopped", reason: `a person has stopped all agent actions (${ctx.stopped})` };
  if (c.port !== 80 && c.port !== 443 && !p.ports.includes(c.port)) return { decision: "refuse", code: "port", reason: `port ${c.port} is not one this proxy carries (80 and 443${p.ports.length ? `, ${p.ports.join(", ")}` : ""})` };
  const listed = ctx.blocklist.match(host) ?? c.addresses?.map((a) => ctx.blocklist.match(a)).find(Boolean);
  if (listed) return { decision: "refuse", code: "blocklisted", reason: `${host} is on a blocklist of malware and botnet infrastructure (${listed})` };
  if (c.addresses && !c.addresses.length) return { decision: "refuse", code: "unresolvable", reason: `${host} does not resolve to an address` };
  const local = host === "localhost" || /\.(localhost|local|internal|arpa)$/.test(host) || (c.addresses ?? []).some((a) => isPrivateIP(a));
  if (local && !hostIn(host, p.allowPrivate)) return { decision: "refuse", code: "private", reason: `${host} is this machine or a private network address` };
  if (ctx.standing.allowed || hostIn(host, p.allowHosts)) return { decision: "allow", code: "allowlisted", reason: "on the allowlist" };
  if (ctx.standing.typed) return { decision: "allow", code: "typed", reason: "named by the person" };
  if (ctx.visible) return { decision: "allow", code: "named-in-command", reason: "named in a command the egress gate let through" };
  if (ctx.standing.fromContent !== undefined) {
    const reason = `${host} first appeared in ${ctx.standing.fromContent}, not in anything the person typed, and no command names it`;
    return { decision: p.contentHosts === "ask" ? "ask" : "refuse", code: "content-only", reason };
  }
  if (p.mode === "strict") return { decision: "refuse", code: "not-listed", reason: `${host} is not on the allowlist, was not named by the person and is not named in a command (strict mode)` };
  return { decision: "allow", code: "default", reason: "no rule against it" };
}

// ---------- the server ----------

export interface EgressProxyOptions {
  dir?: string;
  /** 0 picks a free port (tests) */
  port?: number;
  policy?: Partial<ProxyPolicy>;
  blocklist?: Blocklist;
  /** who answers when a host known only from content is put to a person */
  approver?: Approver;
  /** how long a person has to answer */
  approvalMs?: number;
  resolve?: (host: string) => Promise<string[]>;
  now?: () => number;
  /** leave when nothing has connected for this long (a proxy a hook started on demand) */
  idleExitMs?: number;
  onIdle?: () => void;
}

export interface RunningEgressProxy { port: number; server: Server; close(): Promise<void> }

const defaultResolve = async (host: string) => (await lookup(host, { all: true, verbatim: true })).map((a) => a.address);

/** Start the proxy on 127.0.0.1. Resolves once it is listening. */
export function startEgressProxy(o: EgressProxyOptions = {}): Promise<RunningEgressProxy> {
  const dir = o.dir ?? stateDir();
  const policy: ProxyPolicy = { ...DEFAULT_PROXY_POLICY, ...(o.policy ?? {}) };
  const now = o.now ?? Date.now;
  const resolve = o.resolve ?? defaultResolve;
  const secret = proxySecret(dir);
  const since = new Date(now()).toISOString();
  mkdirSync(proxyDir(dir), { recursive: true, mode: 0o700 });
  let blocklist = o.blocklist ?? Blocklist.load(join(dir, "blocklists")), blocklistAt = now();
  let lastUse = now(), seq = 0;
  const answers = new Map<string, { answer: "approved" | "denied"; at: number }>();
  const asking = new Map<string, Promise<"approved" | "denied">>();

  const log = (e: Omit<ProxyConnection, "at">) => {
    try {
      const p = logPath(dir);
      try { if (statSync(p).size > 8_000_000) renameSync(p, `${p}.1`); } catch { /* no log yet */ }
      appendFileSync(p, JSON.stringify({ at: new Date(now()).toISOString(), ...e }) + "\n", { mode: 0o600 });
    } catch { /* a connection is decided whether or not it could be recorded */ }
  };

  const sessionOf = (req: IncomingMessage): string | undefined => {
    const h = String(req.headers["proxy-authorization"] ?? "");
    const m = h.match(/^Basic\s+([A-Za-z0-9+/=_-]+)$/i);
    if (!m) return undefined;
    const creds = Buffer.from(m[1], "base64").toString("utf8");
    return sessionOfToken(secret, creds.slice(creds.indexOf(":") + 1));
  };

  /** Ask a person about one host for one session; one dialog at a time per host, and the answer is kept a while. */
  const askPerson = (session: string, host: string, port: number, reason: string, sources: string[]): Promise<"approved" | "denied"> => {
    const key = `${session}\n${host}`;
    const kept = answers.get(key);
    if (kept && now() - kept.at < (kept.answer === "approved" ? VISIBLE_HOST_TTL_MS : 120_000)) return Promise.resolve(kept.answer);
    const running = asking.get(key);
    if (running) return running;
    const args = JSON.stringify({ host, port });
    const digest = hmac("approval", `${session}\n${args}`);
    const req: ApprovalRequest = { id: digest.slice(0, 16), runId: session, tool: "network connection (a program the agent started)", canonicalArgs: args, digest, reasons: [reason], destinations: [host], fields: [], sources, createdAt: now(), expiresAt: now() + (o.approvalMs ?? 90_000) };
    let timer: ReturnType<typeof setTimeout> | undefined;
    const p = (async (): Promise<"approved" | "denied"> => {
      let a: string;
      try { a = await Promise.race([o.approver!.request(req), new Promise<string>((r) => { timer = setTimeout(() => r("timeout"), o.approvalMs ?? 90_000); })]); } catch { a = "denied"; }
      finally { if (timer) clearTimeout(timer); }
      const answer = a === "approved" ? "approved" : "denied";
      answers.set(key, { answer, at: now() });
      asking.delete(key);
      return answer;
    })();
    asking.set(key, p);
    return p;
  };

  /** Everything up to "may this connection be made, and to which address". */
  const admit = async (session: string, hostRaw: string, port: number): Promise<{ ok: true; addresses: string[]; tainted: boolean; id: string } | { ok: false; reason: string }> => {
    lastUse = now();
    const host = cleanHost(hostRaw), id = `${process.pid}-${++seq}`;
    if (!o.blocklist && now() - blocklistAt > 10 * 60_000) { blocklist = Blocklist.load(join(dir, "blocklists")); blocklistAt = now(); }
    const broker = new ActionBroker({ allowHosts: policy.allowHosts });
    const run = readJson<Partial<SerializedRun>>(sessionStatePath(dir, session));
    broker.importRun(session, run);
    const standing = broker.hostStanding(session, host);
    const ctx = { policy, blocklist, standing, visible: isVisibleHost(dir, session, host, now()), stopped: stopReason(dir) };
    // The name first, then the addresses: a name that is going to be refused is never looked up.
    let addresses: string[] = isIP(host) ? [host] : [];
    let d = decideConnection({ host, port, addresses: isIP(host) ? addresses : undefined }, ctx);
    if (d.decision === "ask") {
      const answer = o.approver ? await askPerson(session, host, port, d.reason, broker.state(session).sources) : "denied";
      d = answer === "approved"
        ? { decision: "allow", code: "approved", reason: `${d.reason}; a person at this machine approved it` }
        : { decision: "refuse", code: d.code, reason: `${d.reason}; ${o.approver ? "a person at this machine was asked and did not approve it" : "no approver is configured"}` };
    }
    if (d.decision === "allow" && !isIP(host)) {
      try { addresses = await resolve(host); } catch { addresses = []; }
      // the name is settled; only what its addresses add can change the answer
      const again = decideConnection({ host, port, addresses }, ctx);
      if (again.decision === "refuse" && ["blocklisted", "unresolvable", "private"].includes(again.code)) d = again;
    }
    log({ session, host, port, decision: d.decision === "allow" ? "allow" : "refuse", reason: d.reason, code: d.code, id });
    if (d.decision !== "allow") return { ok: false, reason: d.reason };
    return { ok: true, addresses, tainted: standing.tainted, id };
  };

  const refusalText = (reason: string) => `AcePaste Ingress egress proxy refused this connection: ${reason}.\nThis is a refusal, not a fault. Do not route around the proxy; tell the person.\n`;
  const closed = (session: string, host: string, port: number, id: string, started: number, up: number, down: number, tainted: boolean) => {
    const flag = tainted && up >= policy.uploadFlagBytes ? `sent ${up} bytes to ${host} after the session had read outside content` : undefined;
    log({ session, host, port, decision: "allow", reason: "closed", code: "closed", id, up, down, ms: now() - started, closed: true, ...(flag ? { flag } : {}) });
  };

  const server = createServer((req: IncomingMessage, res: ServerResponse) => { void onRequest(req, res); });

  // ---- CONNECT: a tunnel. Only the host name and port are seen.
  server.on("connect", (req: IncomingMessage, client: Socket, head: Buffer) => {
    void (async () => {
      const say = (status: string, body = "", extra = "") => { try { client.end(`HTTP/1.1 ${status}\r\n${extra}Content-Type: text/plain; charset=utf-8\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`); } catch { /* gone */ } };
      client.on("error", () => { /* the client went away */ });
      const session = sessionOf(req);
      if (!session) return say("407 Proxy Authentication Required", "AcePaste Ingress egress proxy: this connection carries no session token.\n", 'Proxy-Authenticate: Basic realm="ingress-egress"\r\n');
      const m = String(req.url ?? "").match(/^(\[[0-9a-fA-F:.]+\]|[^:\s]+):(\d{1,5})$/);
      if (!m) return say("400 Bad Request", "AcePaste Ingress egress proxy: not a host and port.\n");
      const host = cleanHost(m[1]), port = Number(m[2]);
      const a = await admit(session, host, port);
      if (!a.ok) return say("403 Forbidden", refusalText(a.reason), "X-Ingress-Egress: refused\r\n");
      const started = now();
      let up = head.length, down = 0, done = false, tried = 0;
      const dial = () => {
        const upstream = netConnect({ host: a.addresses[tried], port });
        let established = false;
        upstream.setTimeout(30_000, () => upstream.destroy(new Error("timeout")));
        upstream.once("connect", () => {
          established = true;
          upstream.setTimeout(0);
          client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
          if (head.length) upstream.write(head);
          client.on("data", (c: Buffer) => { up += c.length; });
          upstream.on("data", (c: Buffer) => { down += c.length; });
          client.pipe(upstream); upstream.pipe(client);
          const finish = () => { if (done) return; done = true; client.destroy(); upstream.destroy(); closed(session, host, port, a.id, started, up, down, a.tainted); };
          client.on("close", finish); upstream.on("close", finish);
        });
        upstream.on("error", () => {
          if (established) return; // the tunnel was up: its close event finishes it
          if (++tried < a.addresses.length) return dial();
          say("502 Bad Gateway", `AcePaste Ingress egress proxy: could not reach ${host}:${port}.\n`);
        });
      };
      dial();
    })();
  });

  // ---- plain HTTP: the request line carries a full URL. Headers and body pass through unread.
  async function onRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = String(req.url ?? "");
    const send = (status: number, body: string, headers: Record<string, string> = {}) => { res.writeHead(status, { "content-type": "text/plain; charset=utf-8", ...headers }); res.end(body); };
    if (url.startsWith("/")) {
      // who is listening here: proved by a keyed digest of the caller's challenge, so a hook is not fooled by another program on this port
      const u = new URL(url, "http://127.0.0.1");
      if (req.method === "GET" && u.pathname === HEALTH_PATH) return send(200, JSON.stringify({ ok: true, proof: hmac(secret, `health:${u.searchParams.get("c") ?? ""}`), pid: process.pid, since, mode: policy.mode }), { "content-type": "application/json" });
      return send(400, "AcePaste Ingress egress proxy: this is a forward proxy; ask for a full URL.\n");
    }
    const session = sessionOf(req);
    if (!session) return send(407, "AcePaste Ingress egress proxy: this connection carries no session token.\n", { "proxy-authenticate": 'Basic realm="ingress-egress"' });
    let target: URL;
    try { target = new URL(url); } catch { return send(400, "AcePaste Ingress egress proxy: not a URL.\n"); }
    if (target.protocol !== "http:") return send(400, "AcePaste Ingress egress proxy: only http and CONNECT are carried.\n");
    const host = cleanHost(target.hostname), port = target.port ? Number(target.port) : 80;
    const a = await admit(session, host, port);
    if (!a.ok) return send(403, refusalText(a.reason), { "x-ingress-egress": "refused" });
    const started = now();
    let up = 0, down = 0, done = false;
    const headers: Record<string, string | string[] | undefined> = { ...req.headers };
    for (const h of ["proxy-authorization", "proxy-connection"]) delete headers[h];
    const out = httpRequest({ host: a.addresses[0], port, method: req.method, path: `${target.pathname}${target.search}`, headers, setHost: false, timeout: 60_000 }, (back) => {
      res.writeHead(back.statusCode ?? 502, back.headers);
      back.on("data", (c: Buffer) => { down += c.length; });
      back.pipe(res);
    });
    const finish = () => { if (done) return; done = true; closed(session, host, port, a.id, started, up, down, a.tainted); };
    req.on("data", (c: Buffer) => { up += c.length; });
    out.on("timeout", () => out.destroy(new Error("timeout")));
    out.on("error", () => { if (!res.headersSent) send(502, `AcePaste Ingress egress proxy: could not reach ${host}:${port}.\n`); else res.destroy(); finish(); });
    res.on("close", finish);
    req.pipe(out);
  }

  return new Promise((ok, fail) => {
    server.once("error", fail);
    server.listen(o.port ?? EGRESS_PROXY_PORT, "127.0.0.1", () => {
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : o.port ?? EGRESS_PROXY_PORT;
      try { writeAtomic(join(proxyDir(dir), "proxy.json"), JSON.stringify({ port, pid: process.pid, since })); } catch { /* informational */ }
      let idle: ReturnType<typeof setInterval> | undefined;
      if (o.idleExitMs) { idle = setInterval(() => { if (now() - lastUse > o.idleExitMs!) o.onIdle?.(); }, 60_000); idle.unref(); }
      ok({ port, server, close: () => new Promise<void>((done) => { if (idle) clearInterval(idle); server.closeAllConnections?.(); server.close(() => done()); }) });
    });
  });
}

/** Options from the environment, shared by `ingress egress-proxy` and the HTTP service. */
export function egressProxyOptionsFromEnv(env: Record<string, string | undefined> = process.env): EgressProxyOptions {
  const list = (v: string | undefined) => (v ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  const port = Number(env.INGRESS_EGRESS_PROXY_PORT);
  const flag = Number(env.INGRESS_EGRESS_UPLOAD_FLAG_BYTES);
  return {
    port: Number.isInteger(port) && port > 0 && port < 65536 ? port : EGRESS_PROXY_PORT,
    policy: {
      mode: env.INGRESS_EGRESS_PROXY_MODE === "strict" ? "strict" : "log",
      allowHosts: list(env.INGRESS_EGRESS_ALLOW_HOSTS),
      allowPrivate: list(env.INGRESS_EGRESS_PROXY_ALLOW_PRIVATE),
      ports: list(env.INGRESS_EGRESS_PROXY_PORTS).map(Number).filter((n) => Number.isInteger(n) && n > 0 && n < 65536),
      ...(Number.isFinite(flag) && flag > 0 ? { uploadFlagBytes: flag } : {}),
    },
  };
}

export const egressProxyOn = (env: Record<string, string | undefined> = process.env) => /^(on|1|true|yes)$/i.test(env.INGRESS_EGRESS_PROXY ?? "");

// ---------- is it running; start it ----------

/** Is our proxy (one that holds this state folder's secret) listening on the port? */
export async function proxyHealth(port: number, dir: string = stateDir(), timeoutMs = 800): Promise<"ours" | "other" | "down"> {
  const c = randomBytes(8).toString("hex");
  try {
    const res = await fetch(`http://127.0.0.1:${port}${HEALTH_PATH}?c=${c}`, { signal: AbortSignal.timeout(timeoutMs) });
    const body = (await res.json().catch(() => undefined)) as { proof?: string } | undefined;
    return body?.proof === hmac(proxySecret(dir), `health:${c}`) ? "ours" : "other";
  } catch {
    // no answer to the question: is anything listening at all?
    return new Promise((done) => {
      const s = netConnect({ host: "127.0.0.1", port });
      const say = (v: "other" | "down") => { s.destroy(); done(v); };
      s.setTimeout(timeoutMs, () => say("other"));
      s.once("connect", () => say("other"));
      s.once("error", () => say("down"));
    });
  }
}

/**
 * Make sure the proxy is listening, starting `ingress egress-proxy` as a detached process when it is not.
 * Never throws. "other": something else has the port, and nothing was started.
 */
export async function ensureEgressProxy(o: { port?: number; dir?: string; cli?: string; waitMs?: number; spawnImpl?: (command: string, args: string[]) => void } = {}): Promise<{ ok: boolean; why?: string }> {
  const port = o.port ?? EGRESS_PROXY_PORT, dir = o.dir ?? stateDir();
  try {
    const state = await proxyHealth(port, dir);
    if (state === "ours") return { ok: true };
    if (state === "other") return { ok: false, why: `port ${port} on this machine answers, but not as this installation's egress proxy` };
    const cli = o.cli ?? process.argv[1];
    if (!o.spawnImpl && (!cli || !existsSync(cli))) return { ok: false, why: "the ingress command could not be found to start it" };
    (o.spawnImpl ?? ((command: string, args: string[]) => { spawn(command, args, { detached: true, stdio: "ignore", env: { ...process.env, INGRESS_EGRESS_PROXY_PORT: String(port) } }).unref(); }))(process.execPath, [cli, "egress-proxy", "--idle-exit"]);
    const until = Date.now() + (o.waitMs ?? 4000);
    while (Date.now() < until) {
      await new Promise((r) => setTimeout(r, 120));
      if ((await proxyHealth(port, dir, 400)) === "ours") return { ok: true };
    }
    return { ok: false, why: "it was started and did not answer in time" };
  } catch (e) { return { ok: false, why: String((e as Error).message ?? e) }; }
}

// ---------- the sandbox wrapper: programs that ignore proxy settings ----------

const SANDBOX_EXEC = "/usr/bin/sandbox-exec";
const sb = (s: string) => `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
const real = (p: string) => { try { return realpathSync(p); } catch { return p; } };

/**
 * A macOS sandbox profile (the language `sandbox-exec` reads): everything is allowed except the process's own
 * outbound network, which may only reach the proxy.
 *   loopback "proxy-only"  nothing but the proxy's port
 *   loopback "allow"       other ports on this machine too (a test suite talking to its own server), except
 *                          the name-service ports: a resolver listening on this machine would carry data out
 * Name lookups through the system (which is how nearly every program resolves a name) go over a local socket
 * to a system service; "deny network-outbound" covers that socket, so they fail. A program using the proxy
 * does not need them: the proxy resolves. The files that would let a program speak for another session, or
 * use the Ingress service as a relay, cannot be read.
 */
export function sandboxProfile(o: { proxyPort: number; loopback?: "proxy-only" | "allow"; denyRead?: string[] }): string {
  const lines = ["(version 1)", "(allow default)", "(deny network-outbound)"];
  if (o.loopback === "allow") lines.push('(allow network-outbound (remote ip "localhost:*"))', ...[53, 853, 5353].filter((p) => p !== o.proxyPort).map((p) => `(deny network-outbound (remote ip "localhost:${p}"))`));
  lines.push(`(allow network-outbound (remote ip "localhost:${o.proxyPort}"))`);
  for (const p of o.denyRead ?? []) lines.push(`(deny file-read* (literal ${sb(real(p))}))`);
  return lines.join("\n") + "\n";
}

/** Files a sandboxed program must not read: the token secret, and the keys of the local Ingress service. */
export function sandboxSecrets(dir: string = stateDir()): string[] {
  const home = join(homedir(), ".acepaste-ingress");
  return [join(proxyDir(dir), "secret"), join(home, "local-api-key"), join(home, "private.pem")];
}

/** Can this process start a sandbox? Not on other systems, and not from inside another sandbox. */
export function sandboxUsable(): { ok: boolean; why?: string } {
  if (process.platform !== "darwin") return { ok: false, why: "the sandbox wrapper is built for macOS only (sandbox-exec); nothing equivalent is built for this system" };
  if (!existsSync(SANDBOX_EXEC)) return { ok: false, why: `${SANDBOX_EXEC} is not on this Mac` };
  const r = spawnSync(SANDBOX_EXEC, ["-p", "(version 1)(allow default)", "/usr/bin/true"], { stdio: "ignore", timeout: 10_000 });
  if (r.status !== 0) return { ok: false, why: "this process cannot start a sandbox, which is what happens inside another sandbox (an agent harness's own sandbox mode, or an app sandbox). Run it outside that sandbox, or rely on that sandbox's own network rules" };
  return { ok: true };
}

/**
 * Run a command with its network confined to the proxy. Returns the command's exit status.
 * The command inherits this process's terminal. Its children are confined too: a sandbox cannot be left.
 */
export function runSandboxed(argv: string[], o: { proxyPort: number; token: string; dir?: string; loopback?: "proxy-only" | "allow"; env?: Record<string, string | undefined> }): number {
  const profile = sandboxProfile({ proxyPort: o.proxyPort, loopback: o.loopback, denyRead: sandboxSecrets(o.dir ?? stateDir()) });
  const r = spawnSync(SANDBOX_EXEC, ["-p", profile, ...argv], { stdio: "inherit", env: { ...(o.env ?? process.env), ...proxyEnv(o.proxyPort, o.token) } as NodeJS.ProcessEnv });
  if (r.error) throw r.error;
  return r.status ?? (r.signal ? 128 : 1);
}
