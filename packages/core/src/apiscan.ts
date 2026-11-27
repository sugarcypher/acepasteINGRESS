/**
 * ingress apiscan: a non-destructive security check of an HTTP API you own or may test.
 *
 * Hard rules, enforced here and not left to callers:
 *  - only GET, HEAD and OPTIONS; never a request body, never an injection or fuzz payload, never a login attempt
 *  - only the origin of the base URL is contacted (plus the spec URL, when the person gives one); redirects are
 *    reported, never followed
 *  - a fixed request budget (60 by default), a pause between requests, a timeout on each one
 *  - the gate's own honest user agent (HONEST_USER_AGENT), never a borrowed one
 *  - the rate-limit burst (about 20 quick GETs to one endpoint) runs only when asked for
 * Evidence is cut short and has credentials redacted with the same code the gate uses (secrets.ts).
 */
import { readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { HONEST_USER_AGENT } from "./acquire.js";
import { redactSecrets, collectSecrets, scrubExcerpt } from "./secrets.js";
import type { Tier } from "./types.js";

export type ApiScanSeverity = "high" | "review" | "info";

export interface ApiScanFinding {
  /** stable id of the check, e.g. "cors.reflected_origin_with_credentials" */
  id: string;
  check: ApiScanCheck;
  severity: ApiScanSeverity;
  title: string;
  /** METHOD url */
  endpoint: string;
  /** truncated, credentials redacted */
  evidence: string;
  /** one line, plain English */
  fix: string;
  /** other endpoints where the same finding was seen */
  alsoAt?: string[];
}

export type ApiScanCheck = "transport" | "headers" | "cors" | "auth" | "exposed-files" | "errors" | "version" | "secrets" | "rate-limit" | "agent-content";

/** what the scanner needs from fetch; the global fetch fits, and tests can pass their own */
export type ApiScanFetch = (url: string, init: { method: string; headers: Record<string, string>; redirect: "manual"; signal: AbortSignal }) => Promise<{ status: number; headers: { get(name: string): string | null; forEach?(cb: (value: string, key: string) => void): void }; arrayBuffer(): Promise<ArrayBuffer> }>;

/** the text gate: returns the verdict on a body (the same scan `ingress --text` runs) */
export type ApiScanGate = (text: string, url: string, contentType: string) => Promise<{ tier: Tier; findings: Array<{ kind: string; message: string }> }>;

export interface ApiScanOptions {
  spec?: string;
  /** "Name: value" */
  authHeader?: string;
  burst?: boolean;
  /** default 60 */
  maxRequests?: number;
  /** pause between requests, default 250 ms */
  delayMs?: number;
  /** per request, default 10 s */
  timeoutMs?: number;
  fetch?: ApiScanFetch;
  gate?: ApiScanGate;
  /** read a spec file; defaults to readFileSync */
  readFile?: (path: string) => string;
}

export interface ApiScanReport {
  target: string;
  notice: string;
  startedAt: string;
  requestsUsed: number;
  maxRequests: number;
  findings: ApiScanFinding[];
  summary: { high: number; review: number; info: number };
  /** what was not checked, and why */
  notes: string[];
}

export const APISCAN_NOTICE = "Only point apiscan at APIs you own or are authorized to test.";
export const APISCAN_DEFAULT_BUDGET = 60;
export const APISCAN_BURST_SIZE = 20;
const EVIL_ORIGIN = "https://evil.example";
const MAX_BODY = 512 * 1024;
const EVIDENCE_MAX = 200;

interface Resp {
  url: string;
  method: string;
  status: number;
  headers: Map<string, string>;
  bytes: Buffer;
  body: string;
  authed: boolean;
  error?: { code: string; message: string };
}

const isLoopback = (host: string) => /^(localhost|127\.\d+\.\d+\.\d+|\[::1\]|::1)$/i.test(host);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const TLS_CODES = /CERT|SELF_SIGNED|UNABLE_TO_VERIFY|ALTNAME|UNABLE_TO_GET_ISSUER|TLS|SSL|EPROTO/i;

/** parse argv after "apiscan": both --flag value and --flag=value */
export function parseApiscanArgs(argv: string[]): { base?: string; json: boolean; opts: ApiScanOptions; error?: string } {
  const opts: ApiScanOptions = {};
  let base: string | undefined, json = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const take = (name: string): string | undefined => {
      if (a.startsWith(`--${name}=`)) return a.slice(name.length + 3);
      if (a === `--${name}`) return argv[++i];
      return undefined;
    };
    if (a === "--json") json = true;
    else if (a === "--burst") opts.burst = true;
    else if (a === "--spec" || a.startsWith("--spec=")) opts.spec = take("spec");
    else if (a === "--auth-header" || a.startsWith("--auth-header=")) opts.authHeader = take("auth-header");
    else if (a === "--max-requests" || a.startsWith("--max-requests=")) {
      const n = Number(take("max-requests"));
      if (!Number.isInteger(n) || n < 1) return { json, opts, error: "--max-requests needs a whole number of 1 or more" };
      opts.maxRequests = n;
    } else if (!a.startsWith("--") && !base) base = a;
    else return { json, opts, error: `unknown argument: ${a}` };
  }
  if (!base) return { json, opts, error: "missing base URL" };
  if (!/^https?:\/\//i.test(base)) return { base, json, opts, error: "the base URL must start with http:// or https://" };
  if (opts.authHeader !== undefined && !/^[A-Za-z0-9-]+:\s*\S/.test(opts.authHeader)) return { base, json, opts, error: '--auth-header must look like "Name: value"' };
  return { base, json, opts };
}

/** GET operations from an OpenAPI 3 or Swagger 2 document (JSON), with whether each declares security */
export function parseOpenApiJson(text: string): { ops: Array<{ path: string; secured: boolean; params: Array<{ name: string; type?: string }> }>; version: string } {
  let doc: any;
  try { doc = JSON.parse(text); } catch {
    if (/^\s*(openapi|swagger)\s*:/m.test(text)) throw new Error("this looks like a YAML spec; apiscan reads JSON specs only (convert it to JSON first)");
    throw new Error("the spec is not valid JSON");
  }
  if (!doc || typeof doc !== "object" || (!doc.openapi && !doc.swagger) || typeof doc.paths !== "object") throw new Error("the spec is not an OpenAPI 3 or Swagger 2 document (no openapi/swagger field or no paths)");
  const declares = (sec: unknown) => Array.isArray(sec) && sec.length > 0 && !sec.some((s) => s && typeof s === "object" && Object.keys(s).length === 0);
  const ops: Array<{ path: string; secured: boolean; params: Array<{ name: string; type?: string }> }> = [];
  for (const [path, item] of Object.entries<any>(doc.paths)) {
    const op = item?.get;
    if (!op || typeof op !== "object") continue;
    const secured = op.security !== undefined ? declares(op.security) : declares(doc.security);
    const params = [...(Array.isArray(item.parameters) ? item.parameters : []), ...(Array.isArray(op.parameters) ? op.parameters : [])]
      .filter((p: any) => p && p.in === "path" && typeof p.name === "string")
      .map((p: any) => ({ name: p.name as string, type: (p.schema?.type ?? p.type) as string | undefined }));
    ops.push({ path, secured, params });
  }
  return { ops, version: String(doc.openapi ?? doc.swagger) };
}

const fillPath = (path: string, value: (name: string) => string) => path.replace(/\{([^}]+)\}/g, (_, n: string) => encodeURIComponent(value(n)));

/** soft-404 and validation helpers */
const looksHtml = (s: string) => /^\s*(<!doctype html|<html|<head|<body|<\?xml)/i.test(s) || /<html[\s>]/i.test(s.slice(0, 2000));
function parseJson(s: string): unknown { try { return JSON.parse(s); } catch { return undefined; } }
const isJsonObject = (s: string) => { const v = parseJson(s.trim()); return !!v && typeof v === "object"; };
function envLike(s: string): boolean {
  if (looksHtml(s)) return false;
  const lines = s.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
  if (lines.length === 0) return false;
  const kv = lines.filter((l) => /^(export\s+)?[A-Za-z_][A-Za-z0-9_.]*\s*=/.test(l)).length;
  return kv >= 1 && kv / lines.length >= 0.8;
}

interface ProbeSpec { path: string; severity: ApiScanSeverity; title: string; fix: string; valid: (r: Resp) => boolean; severityFor?: (r: Resp) => ApiScanSeverity }
const ok2xx = (r: Resp) => r.status >= 200 && r.status < 300;
const PROBES: ProbeSpec[] = [
  { path: "/.env", severity: "high", title: "environment file is downloadable", fix: "Remove .env from the web root or block dotfiles at the server.", valid: (r) => ok2xx(r) && envLike(r.body) },
  { path: "/.git/config", severity: "high", title: "git repository config is downloadable", fix: "Do not deploy the .git folder; block /.git at the server.", valid: (r) => ok2xx(r) && /\[core\]/.test(r.body) && /repositoryformatversion/.test(r.body) },
  { path: "/.git/HEAD", severity: "high", title: "git repository is downloadable", fix: "Do not deploy the .git folder; block /.git at the server.", valid: (r) => ok2xx(r) && /^(ref: refs\/|[0-9a-f]{40}\s*$)/.test(r.body) },
  { path: "/actuator", severity: "review", title: "Spring Boot actuator index is public", fix: "Expose only the health endpoint, or put actuator behind authentication.", valid: (r) => ok2xx(r) && isJsonObject(r.body) && /"_links"/.test(r.body) },
  { path: "/actuator/env", severity: "high", title: "Spring Boot actuator environment is public", fix: "Disable the env endpoint or put actuator behind authentication.", valid: (r) => ok2xx(r) && isJsonObject(r.body) && /"(propertySources|activeProfiles)"/.test(r.body) },
  { path: "/debug", severity: "review", title: "debug endpoint answers", fix: "Turn off debug routes in production or require authentication.", valid: (r) => ok2xx(r) && /goroutine|pprof|Werkzeug Debugger|"cmdline"|"memstats"|debug toolbar/i.test(r.body) },
  { path: "/server-status", severity: "review", title: "Apache server-status page is public", fix: "Restrict mod_status to localhost or an admin network.", valid: (r) => ok2xx(r) && /Apache Server Status|Server uptime:/i.test(r.body) },
  { path: "/phpinfo.php", severity: "high", title: "phpinfo() page is public", fix: "Delete phpinfo.php from the server.", valid: (r) => ok2xx(r) && /phpinfo\(\)|<title>PHP \d|PHP Version \d/i.test(r.body) },
  { path: "/swagger.json", severity: "info", title: "API description is public", fix: "Fine if the API is meant to be public; otherwise put the spec behind authentication.", valid: (r) => ok2xx(r) && isJsonObject(r.body) && /"(swagger|openapi)"\s*:/.test(r.body) },
  { path: "/openapi.json", severity: "info", title: "API description is public", fix: "Fine if the API is meant to be public; otherwise put the spec behind authentication.", valid: (r) => ok2xx(r) && isJsonObject(r.body) && /"(swagger|openapi)"\s*:/.test(r.body) },
  { path: "/api-docs", severity: "info", title: "API documentation is public", fix: "Fine if the API is meant to be public; otherwise put the docs behind authentication.", valid: (r) => ok2xx(r) && (isJsonObject(r.body) ? /"(swagger|openapi)"\s*:/.test(r.body) : /swagger-ui|redoc/i.test(r.body)) },
  { path: "/graphql", severity: "info", title: "GraphQL endpoint found (introspection may be on; not tested)", fix: "If the schema is private, turn off introspection in production.", valid: (r) => {
    if (r.status >= 500 || r.status === 404) return false;
    const j = parseJson(r.body) as any;
    if (j && typeof j === "object" && (Array.isArray(j.errors) || "data" in j)) return /query|graphql|operation|syntax/i.test(r.body) || "data" in j;
    return ok2xx(r) && /graphiql|graphql playground|apollo sandbox/i.test(r.body);
  } },
  { path: "/.DS_Store", severity: "review", title: ".DS_Store file is downloadable (lists folder contents)", fix: "Delete .DS_Store files from the web root and block dotfiles.", valid: (r) => ok2xx(r) && r.bytes.length >= 8 && r.bytes.readUInt32BE(0) === 1 && r.bytes.subarray(4, 8).toString("latin1") === "Bud1" },
  { path: "/backup.zip", severity: "high", title: "backup archive is downloadable", fix: "Move backups off the web server.", valid: (r) => ok2xx(r) && r.bytes.length >= 4 && r.bytes.readUInt32BE(0) === 0x504b0304 },
  { path: "/config.json", severity: "review", title: "config file is downloadable", fix: "Do not serve configuration files; move them out of the web root.", valid: (r) => ok2xx(r) && isJsonObject(r.body) && !/"(swagger|openapi)"\s*:/.test(r.body),
    severityFor: (r) => (collectSecrets([r.body]).length || /"[^"]*(password|passwd|secret|api_?key|private_?key|token)[^"]*"\s*:\s*"[^"]{4,}"/i.test(r.body) ? "high" : "review") },
];

/** what an exposed file shows in the report: binary files by signature, settings files by their key names only (values can be secrets) */
function probeEvidence(path: string, r: Resp): string {
  if (path === "/backup.zip") return `${r.bytes.length} bytes, zip signature`;
  if (path === "/.DS_Store") return `${r.bytes.length} bytes, .DS_Store signature`;
  if (path === "/.env") {
    const keys = r.body.split(/\r?\n/).map((l) => /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*=/.exec(l)?.[1]).filter(Boolean);
    return `${keys.length} setting(s): ${keys.slice(0, 12).map((k) => `${k}=…`).join(" ")}`;
  }
  if (path === "/config.json" || path === "/actuator/env") {
    const v = parseJson(r.body);
    return v && typeof v === "object" ? `keys: ${Object.keys(v as object).slice(0, 15).join(", ")} (values not shown)` : "(values not shown)";
  }
  return r.body;
}

const STACK_PATTERNS: Array<{ re: RegExp; what: string; severity: ApiScanSeverity }> = [
  { re: /Werkzeug Debugger|The debugger caught an exception in your WSGI application/, what: "Werkzeug interactive debugger (can run code)", severity: "high" },
  { re: /You're seeing this error because you have <code>DEBUG = True<\/code>|DEBUG = True in your Django settings/, what: "Django debug page", severity: "review" },
  { re: /Whoops! There was an error|Illuminate\\[A-Z]|Symfony\\Component\\Debug/, what: "PHP framework debug page", severity: "review" },
  { re: /Action Controller: Exception caught|ActionController::RoutingError/, what: "Rails debug page", severity: "review" },
  { re: /Server Error in '\/' Application|ASP\.NET is configured to show verbose error messages/, what: "ASP.NET verbose error page", severity: "review" },
  { re: /Traceback \(most recent call last\)/, what: "Python stack trace", severity: "review" },
  { re: /at Object\.<anonymous>|\n\s+at [\w$.<>]+ \((?:file:\/\/)?\/[^)]+\.[cm]?js:\d+:\d+\)/, what: "Node.js stack trace", severity: "review" },
  { re: /Exception in thread "|\n\s*at [a-z][\w$]*(?:\.[\w$]+)+\([\w$]+\.java:\d+\)/, what: "Java stack trace", severity: "review" },
  { re: /You have an error in your SQL syntax|SQLSTATE\[|ORA-\d{5}|PG::[A-Z]\w+Error|psycopg2\.|SQLiteException|sqlite3\.OperationalError|syntax error at or near "|Unclosed quotation mark after the character string/, what: "database error message", severity: "high" },
];

const TEXTUAL = (ct: string) => /json|^text\/(plain|markdown|csv)|\+json|xml/i.test(ct);

export async function apiscan(baseInput: string, o: ApiScanOptions = {}): Promise<ApiScanReport> {
  const base = new URL(baseInput);
  if (base.protocol !== "http:" && base.protocol !== "https:") throw new Error("the base URL must be http or https");
  base.hash = "";
  const maxRequests = Math.max(1, o.maxRequests ?? APISCAN_DEFAULT_BUDGET);
  const delayMs = o.delayMs ?? 250;
  const timeoutMs = o.timeoutMs ?? 10_000;
  const doFetch: ApiScanFetch = o.fetch ?? ((u, init) => fetch(u, init));
  const notes: string[] = [];
  const findings: ApiScanFinding[] = [];
  const responses: Resp[] = [];
  let used = 0, last = 0;

  let auth: { name: string; value: string } | undefined;
  if (o.authHeader) {
    const i = o.authHeader.indexOf(":");
    auth = { name: o.authHeader.slice(0, i).trim(), value: o.authHeader.slice(i + 1).trim() };
  }

  const budgetLeft = () => maxRequests - used;
  async function request(url: string, method: "GET" | "HEAD" | "OPTIONS", h: { auth?: boolean; origin?: boolean; noDelay?: boolean } = {}): Promise<Resp | undefined> {
    if (used >= maxRequests) return undefined;
    const target = new URL(url);
    // only the origin we were given (and the spec URL, fetched separately)
    if (target.host !== base.host) throw new Error(`refusing to contact ${target.host}: apiscan only talks to ${base.host}`);
    if (!h.noDelay && used > 0) { const wait = last + delayMs - Date.now(); if (wait > 0) await sleep(wait); }
    used++;
    const headers: Record<string, string> = { "user-agent": HONEST_USER_AGENT, accept: "application/json, text/plain;q=0.9, */*;q=0.5" };
    if (h.auth !== false && auth) headers[auth.name.toLowerCase()] = auth.value;
    if (h.origin) { headers.origin = EVIL_ORIGIN; if (method === "OPTIONS") headers["access-control-request-method"] = "GET"; }
    const r: Resp = { url, method, status: 0, headers: new Map(), bytes: Buffer.alloc(0), body: "", authed: !!(h.auth !== false && auth) };
    try {
      const res = await doFetch(url, { method, headers, redirect: "manual", signal: AbortSignal.timeout(timeoutMs) });
      r.status = res.status;
      if (res.headers.forEach) res.headers.forEach((v, k) => r.headers.set(k.toLowerCase(), v));
      else for (const k of ["content-type", "location", "server", "x-powered-by", "strict-transport-security", "x-content-type-options", "cache-control", "access-control-allow-origin", "access-control-allow-credentials", "retry-after", "ratelimit-limit", "ratelimit-remaining", "ratelimit", "x-ratelimit-limit", "x-ratelimit-remaining"]) { const v = res.headers.get(k); if (v !== null) r.headers.set(k, v); }
      if (method !== "HEAD") {
        const buf = Buffer.from(await res.arrayBuffer());
        r.bytes = buf.length > MAX_BODY ? buf.subarray(0, MAX_BODY) : buf;
        r.body = r.bytes.toString("utf8");
      }
    } catch (e) {
      const err = e as Error & { cause?: { code?: string; message?: string } };
      const code = err.cause?.code ?? (err.name === "TimeoutError" ? "TIMEOUT" : err.name);
      r.error = { code: String(code), message: err.cause?.message ?? err.message };
    }
    last = Date.now();
    responses.push(r);
    return r;
  }

  // evidence: cut short, credentials and the auth header value redacted
  const evidence = (s: string) => {
    let t = s.replace(/\s+/g, " ").trim();
    if (auth?.value && auth.value.length >= 4) t = t.split(auth.value).join("[redacted: auth header]");
    t = redactSecrets(t);
    if (t.length > EVIDENCE_MAX) t = t.slice(0, EVIDENCE_MAX) + "…";
    return t;
  };
  const add = (f: Omit<ApiScanFinding, "evidence"> & { evidence: string }) => {
    const same = findings.find((x) => x.id === f.id && x.title === f.title);
    if (same) { if (same.endpoint !== f.endpoint && !(same.alsoAt ??= []).includes(f.endpoint)) same.alsoAt.push(f.endpoint); return; }
    findings.push({ ...f, evidence: evidence(f.evidence) });
  };
  const ep = (r: Resp) => `${r.method} ${r.url}`;
  const join = (path: string) => { const u = new URL(base.href); u.pathname = (base.pathname.replace(/\/+$/, "") + path).replace(/\/{2,}/g, "/"); u.search = ""; return u.href; };
  const root = (path: string) => new URL(path, base.origin).href;

  // ---- 1. base request and transport
  const loop = isLoopback(base.hostname);
  const baseResp = await request(base.href, "GET");
  if (!baseResp) throw new Error("no request budget");
  if (baseResp.error) {
    if (base.protocol === "https:" && TLS_CODES.test(baseResp.error.code + " " + baseResp.error.message)) {
      add({ id: "transport.tls_certificate", check: "transport", severity: "high", title: "TLS certificate problem", endpoint: ep(baseResp), evidence: `${baseResp.error.code}: ${baseResp.error.message}`, fix: "Serve a valid certificate for this host name from a trusted CA (and include the full chain)." });
      notes.push("The base URL could not be reached over TLS, so the other checks were not run.");
    } else notes.push(`The base URL could not be reached (${baseResp.error.code}: ${baseResp.error.message}); the other checks were not run.`);
    return finish();
  }
  if (base.protocol === "https:") {
    if (!baseResp.headers.get("strict-transport-security")) add({ id: "transport.no_hsts", check: "transport", severity: "review", title: "no Strict-Transport-Security header", endpoint: ep(baseResp), evidence: "response has no Strict-Transport-Security header", fix: "Send Strict-Transport-Security: max-age=31536000; includeSubDomains on HTTPS responses." });
    const plain = new URL(base.href); plain.protocol = "http:";
    const p = await request(plain.href, "GET");
    if (p && !p.error) {
      const loc = p.headers.get("location") ?? "";
      if (p.status >= 300 && p.status < 400) {
        if (!/^https:\/\//i.test(loc)) add({ id: "transport.http_redirect_not_https", check: "transport", severity: "high", title: "http:// redirects somewhere other than https://", endpoint: ep(p), evidence: `${p.status} Location: ${loc}`, fix: "Redirect every http:// request to the same URL on https://." });
      } else if (p.status < 400) add({ id: "transport.http_not_redirected", check: "transport", severity: "high", title: "API answers over plain http:// without redirecting to https://", endpoint: ep(p), evidence: `${p.status} on http:// with no redirect`, fix: "Redirect every http:// request to https:// (or close port 80)." });
    }
  } else if (loop) notes.push("Transport checks (HTTPS redirect, TLS, HSTS) skipped: the target is on this machine.");
  else {
    const loc = baseResp.headers.get("location") ?? "";
    if (baseResp.status >= 300 && baseResp.status < 400 && /^https:\/\//i.test(loc)) add({ id: "transport.use_https", check: "transport", severity: "info", title: "http:// redirects to https://; scan the https:// URL instead", endpoint: ep(baseResp), evidence: `${baseResp.status} Location: ${loc}`, fix: "Re-run apiscan with the https:// URL to check TLS and the API itself." });
    else add({ id: "transport.http_not_redirected", check: "transport", severity: "high", title: "API answers over plain http:// without redirecting to https://", endpoint: ep(baseResp), evidence: `${baseResp.status} on http:// with no redirect`, fix: "Serve the API over HTTPS and redirect every http:// request to it." });
  }

  // ---- soft-404 baseline and verbose errors
  const nonce = randomBytes(6).toString("hex");
  const missing = await request(root(`/ingress-apiscan-${nonce}`), "GET", { auth: false });
  const soft404 = missing && ok2xx(missing) ? missing.body : undefined;
  const badParam = new URL(base.href); badParam.search = "page=not-a-number&limit=not-a-number";

  // ---- broken auth via spec
  const apiResps: Resp[] = [baseResp];
  let specOps: ReturnType<typeof parseOpenApiJson>["ops"] = [];
  if (o.spec) {
    try {
      let text: string;
      if (/^https?:\/\//i.test(o.spec)) {
        // the spec URL is one the person gave; it counts against the budget
        if (used >= maxRequests) throw new Error("no request budget left for the spec");
        used++;
        const res = await doFetch(o.spec, { method: "GET", headers: { "user-agent": HONEST_USER_AGENT, accept: "application/json", ...(auth && new URL(o.spec).host === base.host ? { [auth.name.toLowerCase()]: auth.value } : {}) }, redirect: "manual", signal: AbortSignal.timeout(timeoutMs) });
        last = Date.now();
        if (res.status < 200 || res.status >= 300) throw new Error(`the spec URL answered ${res.status}`);
        text = Buffer.from(await res.arrayBuffer()).toString("utf8");
      } else {
        if (/\.ya?ml$/i.test(o.spec)) throw new Error("YAML specs are not supported; convert the spec to JSON first");
        text = (o.readFile ?? ((p: string) => readFileSync(p, "utf8")))(o.spec);
      }
      const parsed = parseOpenApiJson(text);
      specOps = parsed.ops;
    } catch (e) { notes.push(`Spec not used: ${(e as Error).message}`); }
  } else notes.push("No --spec given, so the unauthenticated-access check (broken auth) was not run.");

  const reserve = (o.burst ? APISCAN_BURST_SIZE : 0) + 4 /* CORS x2, errors x2 */;
  const secured = specOps.filter((x) => x.secured);
  if (o.spec && specOps.length && !secured.length) notes.push("The spec declares no security on any GET operation, so there was nothing to test without auth.");
  let skippedOps = 0;
  for (const op of secured) {
    if (budgetLeft() - reserve - PROBES.length <= 0) { skippedOps++; continue; }
    const r = await request(join(fillPath(op.path, () => "1")), "GET", { auth: false });
    if (!r || r.error) continue;
    apiResps.push(r);
    if (ok2xx(r) && r.body.trim().length > 0 && r.body !== soft404 && !looksHtml(r.body)) add({ id: "auth.answers_without_auth", check: "auth", severity: "high", title: "endpoint answers without authentication (the spec says it needs auth)", endpoint: `${ep(r)}  (spec: GET ${op.path})`, evidence: `${r.status}, ${r.bytes.length} bytes: ${r.body}`, fix: "Enforce authentication on this route on the server; do not rely on clients sending a token." });
  }
  if (skippedOps) notes.push(`${skippedOps} secured spec operation(s) not tested: request budget (raise --max-requests).`);

  // ---- CORS
  const pre = await request(base.href, "OPTIONS", { origin: true });
  const cg = await request(base.href, "GET", { origin: true });
  for (const r of [pre, cg]) {
    if (!r || r.error) continue;
    const acao = (r.headers.get("access-control-allow-origin") ?? "").trim();
    const creds = /^true$/i.test((r.headers.get("access-control-allow-credentials") ?? "").trim());
    const ev = `Origin: ${EVIL_ORIGIN} -> Access-Control-Allow-Origin: ${acao}${creds ? ", Access-Control-Allow-Credentials: true" : ""}`;
    if ((acao === EVIL_ORIGIN || acao === "*") && creds) add({ id: "cors.any_origin_with_credentials", check: "cors", severity: "high", title: "any website can read responses with the user's cookies or credentials (CORS)", endpoint: ep(r), evidence: ev, fix: "Allow only your own origins by exact match, and never combine a reflected or * origin with credentials." });
    else if (acao === EVIL_ORIGIN) add({ id: "cors.reflected_origin", check: "cors", severity: "review", title: "CORS reflects any Origin (without credentials)", endpoint: ep(r), evidence: ev, fix: "Check the Origin against an allowlist instead of echoing it back." });
  }

  // ---- verbose errors
  await request(badParam.href, "GET");

  // ---- exposed files and debug paths (always without auth: exposure means public)
  const probeResps: Resp[] = [];
  for (const p of PROBES) {
    if (budgetLeft() - (o.burst ? APISCAN_BURST_SIZE : 0) <= 0) { notes.push(`Exposed-file checks stopped at ${p.path}: request budget.`); break; }
    const r = await request(root(p.path), "GET", { auth: false });
    if (!r || r.error) continue;
    probeResps.push(r);
    if (soft404 !== undefined && r.body === soft404) continue;
    if (!p.valid(r)) continue;
    add({ id: `exposed.${p.path.replace(/[^a-z0-9]+/gi, "_").replace(/^_|_$/g, "")}`, check: "exposed-files", severity: p.severityFor ? p.severityFor(r) : p.severity, title: `${p.path}: ${p.title}`, endpoint: ep(r), evidence: `${r.status} ${r.headers.get("content-type") ?? ""}: ${probeEvidence(p.path, r)}`, fix: p.fix });
  }

  // ---- rate limiting (opt-in)
  if (o.burst) {
    const n = Math.min(APISCAN_BURST_SIZE, budgetLeft());
    if (n < 5) notes.push("Rate-limit burst skipped: not enough request budget left.");
    else {
      let limited = false, any = 0;
      for (let i = 0; i < n; i++) {
        const r = await request(base.href, "GET", { noDelay: true });
        if (!r || r.error) continue;
        any++;
        const hs = [...r.headers.keys()];
        if (r.status === 429 || hs.some((k) => /^(x-)?rate-?limit|^retry-after$/i.test(k))) { limited = true; break; }
      }
      if (any && !limited) add({ id: "ratelimit.none_seen", check: "rate-limit", severity: "review", title: `no rate limiting seen after ${any} quick requests`, endpoint: `GET ${base.href}`, evidence: `${any} GETs in a row: no 429 and no RateLimit or Retry-After headers`, fix: "Add per-client rate limits (and send RateLimit or Retry-After headers so clients can back off)." });
    }
  } else notes.push("Rate limiting not tested (add --burst to send about 20 quick GETs to the base URL).");

  // ---- checks on every response collected
  const all = responses.filter((r) => !r.error);
  for (const r of [...apiResps]) {
    if (!ok2xx(r)) continue;
    const ct = r.headers.get("content-type") ?? "";
    const json = r.body.trim().length > 0 && isJsonObject(r.body);
    if (json && !/json/i.test(ct)) add({ id: "headers.json_content_type", check: "headers", severity: "review", title: ct ? "JSON is served with the wrong Content-Type" : "JSON is served without a Content-Type", endpoint: ep(r), evidence: `Content-Type: ${ct || "(none)"}`, fix: "Send Content-Type: application/json on JSON responses." });
    if ((json || /json/i.test(ct)) && !/nosniff/i.test(r.headers.get("x-content-type-options") ?? "")) add({ id: "headers.no_nosniff", check: "headers", severity: "review", title: "missing X-Content-Type-Options: nosniff", endpoint: ep(r), evidence: `X-Content-Type-Options: ${r.headers.get("x-content-type-options") ?? "(none)"}`, fix: "Send X-Content-Type-Options: nosniff on every response." });
    if (r.authed && !/no-store|private/i.test(r.headers.get("cache-control") ?? "")) add({ id: "headers.auth_cacheable", check: "headers", severity: "review", title: "authenticated response may be cached by shared caches", endpoint: ep(r), evidence: `Cache-Control: ${r.headers.get("cache-control") ?? "(none)"}`, fix: "Send Cache-Control: no-store (or private) on responses that need authentication." });
  }
  for (const r of all) {
    // verbose errors (any response, the error probes included)
    for (const s of STACK_PATTERNS) {
      const m = s.re.exec(r.body);
      if (!m) continue;
      const at = Math.max(0, m.index - 40);
      add({ id: "errors.verbose", check: "errors", severity: s.severity, title: `verbose error: ${s.what}`, endpoint: ep(r), evidence: `${r.status}: ${r.body.slice(at, at + 240)}`, fix: "Return a short generic error to clients and log the details on the server; turn off debug mode in production." });
      break;
    }
    // version disclosure
    const server = r.headers.get("server");
    if (server && /\d+\.\d+/.test(server)) add({ id: "version.server", check: "version", severity: "review", title: "Server header gives a version", endpoint: ep(r), evidence: `Server: ${server}`, fix: "Hide the version in the Server header (e.g. server_tokens off in nginx)." });
    const xpb = r.headers.get("x-powered-by");
    if (xpb) add({ id: "version.powered_by", check: "version", severity: /\d+\.\d+/.test(xpb) ? "review" : "info", title: /\d+\.\d+/.test(xpb) ? "X-Powered-By header gives a version" : "X-Powered-By header names the framework", endpoint: ep(r), evidence: `X-Powered-By: ${xpb}`, fix: "Remove the X-Powered-By header (e.g. app.disable('x-powered-by') in Express)." });
    // secrets in bodies (exposed-file hits already report their file)
    if (r.body && !(probeResps.includes(r) && findings.some((f) => f.check === "exposed-files" && (f.endpoint === ep(r) || f.alsoAt?.includes(ep(r)))))) {
      const red = redactSecrets(r.body);
      const kinds = [...new Set([...red.matchAll(/\[redacted: ([^\]]+)\]/g)].map((m) => m[1]))];
      if (kinds.length) {
        const i = red.indexOf("[redacted:");
        add({ id: "secrets.in_response", check: "secrets", severity: "high", title: `response contains a credential (${kinds.join(", ")})`, endpoint: ep(r), evidence: red.slice(Math.max(0, i - 60), i + 120), fix: "Remove the credential from the response and rotate it now; treat it as leaked." });
      }
    }
  }

  // ---- what an AI agent would read in these responses
  const gate = o.gate ?? (await defaultGate());
  const seen = new Set<string>();
  for (const r of all) {
    const ct = r.headers.get("content-type") ?? "";
    if (!r.body.trim() || looksHtml(r.body)) continue;
    if (!TEXTUAL(ct) && !isJsonObject(r.body)) continue;
    if (soft404 !== undefined && r.body === soft404 && r !== missing) continue;
    if (seen.has(r.body)) continue;
    seen.add(r.body);
    try {
      const v = await gate(r.body, r.url, ct || "application/json");
      if (v.tier === "hostile" || v.tier === "suspect") {
        const kinds = [...new Set(v.findings.map((f) => f.kind))].slice(0, 4).join(", ");
        add({ id: `agent.${v.tier}`, check: "agent-content", severity: v.tier === "hostile" ? "high" : "review", title: `this API returns content an AI agent would read as instructions (Ingress verdict: ${v.tier})`, endpoint: ep(r), evidence: `${kinds}: ${r.body}`, fix: "Find where this text comes from (user input, a stored record, a third party) and stop serving it as-is to clients that feed AI agents." });
      }
    } catch (e) { notes.push(`Ingress scan failed on ${r.url}: ${(e as Error).message}`); }
  }
  return finish();

  function finish(): ApiScanReport {
    // a second scrub over every evidence string, for a credential cut in half by truncation
    const known = collectSecrets(responses.map((r) => r.body));
    for (const f of findings) f.evidence = scrubExcerpt(f.evidence, known);
    const order: Record<ApiScanSeverity, number> = { high: 0, review: 1, info: 2 };
    findings.sort((a, b) => order[a.severity] - order[b.severity]);
    return {
      target: base.href, notice: APISCAN_NOTICE, startedAt: new Date().toISOString(), requestsUsed: used, maxRequests,
      findings, summary: { high: findings.filter((f) => f.severity === "high").length, review: findings.filter((f) => f.severity === "review").length, info: findings.filter((f) => f.severity === "info").length },
      notes,
    };
  }
}

async function defaultGate(): Promise<ApiScanGate> {
  const { IngressEngine } = await import("./engine.js");
  const engine = new IngressEngine({ cloakingCheck: false, sandbox: "off" }, { log: () => {} });
  return async (text, url, contentType) => { const r = await engine.scan(text, { url, contentType }); return { tier: r.tier, findings: r.findings }; };
}

/** the human report */
export function formatApiscan(r: ApiScanReport): string {
  const out: string[] = [`apiscan ${r.target}`, r.notice, ""];
  const label: Record<ApiScanSeverity, string> = { high: "HIGH", review: "REVIEW", info: "INFO" };
  for (const sev of ["high", "review", "info"] as const) {
    const fs = r.findings.filter((f) => f.severity === sev);
    if (!fs.length) continue;
    out.push(`${label[sev]} (${fs.length})`);
    for (const f of fs) {
      out.push(`  [${f.check}] ${f.title}`);
      out.push(`      at:  ${f.endpoint}${f.alsoAt?.length ? `  (+${f.alsoAt.length} more: ${f.alsoAt.slice(0, 3).join(", ")}${f.alsoAt.length > 3 ? ", …" : ""})` : ""}`);
      out.push(`      saw: ${f.evidence}`);
      out.push(`      fix: ${f.fix}`);
    }
    out.push("");
  }
  if (!r.findings.length) out.push("No findings.", "");
  for (const n of r.notes) out.push(`note: ${n}`);
  out.push(`summary: ${r.summary.high} high, ${r.summary.review} review, ${r.summary.info} info; ${r.requestsUsed} of ${r.maxRequests} requests used`);
  return out.join("\n");
}
