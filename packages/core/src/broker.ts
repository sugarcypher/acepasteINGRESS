/**
 * Action broker: the enforcement point between an agent and its side-effecting tools.
 *
 * The gate's verdict never authorizes an action. The broker decides, outside the model:
 *   - a run is tainted as soon as it has taken in any outside content, whatever that
 *     content scored (a low score is a prioritization signal, not proof of safety)
 *   - while tainted, tools the policy marks as side-effecting need a person's approval of
 *     the EXACT call (tool + arguments, by digest); approvals are single-use, short-lived
 *     and bound to the run
 *   - approvals come only from an Approver: a channel the model cannot drive (a native
 *     dialog, a console behind its own credential). There is no tool the model can call
 *     to approve itself
 *   - arguments that carry data out (long query strings, encoded blobs, URLs to hosts
 *     outside an allowlist) need approval while tainted, even on "read" tools
 *   - a run that touched a quarantined source is denied side effects outright
 *
 * Limit, stated plainly: the broker enforces only on calls routed through it. A tool the
 * agent can reach directly is outside its control.
 */

import { createHash, randomBytes } from "node:crypto";

export type ActionDecision = "allow" | "require_approval" | "deny";

export interface ActionRule {
  /** tool name, exact or with * wildcards ("*__send_*", "filesystem__write_file") */
  tool: string;
  /** decision when the run has not taken in outside content */
  clean?: ActionDecision;
  /** decision when the run is tainted */
  tainted?: ActionDecision;
  /** if set, any host found in the arguments must match one of these (exact or ".suffix") or the call needs approval */
  allowDestinations?: string[];
}

export interface BrokerPolicy {
  name: string;
  version: number;
  rules: ActionRule[];
  /**
   * Tools that only read and may run without approval while tainted (globs). Everything
   * else that has no rule needs approval once the run is tainted: a tool the broker does not
   * know is treated as able to act, never guessed from its name.
   */
  readOnlyTools: string[];
  /** words that mark a tool as side-effecting; used only to explain decisions, never to allow */
  sideEffectHints: string[];
  /** hosts any call may send to without approval while tainted (exact or ".suffix") */
  allowHosts: string[];
  /** while tainted, arguments shaped like data leaving (see exfilShapes) need approval */
  guardOutboundData: boolean;
  /** how long an approval stays usable */
  approvalTtlMs: number;
  /** arguments longer than this cannot be shown in full to the person, so they are refused */
  maxShownArgChars: number;
  /** what to do when approval is needed but no approver is configured or it fails */
  onApproverUnavailable: "deny";
}

export const DEFAULT_BROKER_POLICY: BrokerPolicy = {
  name: "default",
  version: 2,
  rules: [],
  readOnlyTools: ["ingress_fetch", "ingress_scan", "ingress_status", "ingress_instructions", "ingress_environment_audit", "ingress_verify_receipt"],
  sideEffectHints: ["send", "email", "mail", "post", "publish", "write", "edit", "create", "update", "delete", "remove", "move", "rename", "pay", "transfer", "purchase", "order", "execute", "exec", "run", "shell", "bash", "command", "deploy", "push", "commit", "merge", "install", "upload", "share", "invite", "message", "reply", "comment", "schedule", "start", "kill", "set", "insert", "drop", "save", "put", "submit", "trigger", "invoke", "eval", "navigate", "type", "click", "fork"],
  allowHosts: [],
  guardOutboundData: true,
  approvalTtlMs: 120_000,
  maxShownArgChars: 4000,
  onApproverUnavailable: "deny",
};

export interface ProposedAction {
  runId: string;
  tool: string;
  args: unknown;
}

export interface ApprovalRequest {
  id: string;
  runId: string;
  tool: string;
  /** canonical JSON of the arguments, exactly what will run */
  canonicalArgs: string;
  digest: string;
  reasons: string[];
  /** hosts and addresses found in the arguments, listed first for the person */
  destinations?: string[];
  /** every field name in the arguments */
  fields?: string[];
  /** outside sources this run has taken in, for the person deciding */
  sources: string[];
  createdAt: number;
  expiresAt: number;
}

export interface Approver {
  /** show the exact action to a person and return their answer. Must not be reachable by the model. */
  request(req: ApprovalRequest): Promise<"approved" | "denied" | "timeout">;
  readonly name: string;
}

export interface BrokerVerdict {
  decision: ActionDecision;
  /** final outcome after any approval: run it or not */
  permitted: boolean;
  reasons: string[];
  digest: string;
  approval?: { id: string; outcome: "approved" | "denied" | "timeout" | "unavailable" };
  policy: { name: string; version: number };
}

export interface BrokerEvent {
  event: "broker.decision";
  at: string;
  runId: string;
  tool: string;
  digest: string;
  decision: ActionDecision;
  permitted: boolean;
  reasons: string[];
  approval?: BrokerVerdict["approval"];
  sources: string[];
  policy: { name: string; version: number };
}

interface RunState { sources: Set<string>; receipts: Set<string>; hosts: Set<string>; quarantined: Set<string> }

/** deterministic JSON: object keys sorted at every depth, so one call has one digest */
export function canonicalJson(v: unknown): string {
  const seen = new WeakSet<object>();
  const norm = (x: unknown): unknown => {
    if (x === null || typeof x !== "object") return typeof x === "number" && !Number.isFinite(x) ? String(x) : x;
    if (seen.has(x as object)) throw new Error("cyclic arguments");
    seen.add(x as object);
    if (Array.isArray(x)) return x.map(norm);
    return Object.fromEntries(Object.keys(x as Record<string, unknown>).sort().map((k) => [k, norm((x as Record<string, unknown>)[k])]));
  };
  return JSON.stringify(norm(v) ?? null);
}

export function actionDigest(runId: string, tool: string, canonicalArgs: string): string {
  return createHash("sha256").update(JSON.stringify(["ingress-action:v1", runId, tool, canonicalArgs]), "utf8").digest("hex");
}

/** the tool's own name: the part after the first "server__" prefix */
const ownName = (tool: string) => { const i = tool.indexOf("__"); return i >= 0 ? tool.slice(i + 2) : tool; };

/**
 * Whether a tool's name says it acts. Used only to explain a decision: an unknown tool
 * needs approval while tainted whatever its name says.
 */
export function isSideEffectName(tool: string, hints: readonly string[]): boolean {
  const words = ownName(tool).replace(/([a-z0-9])([A-Z])/g, "$1 $2").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  return words.some((w) => hints.some((h) => w === h || w.startsWith(h)));
}

function globMatch(pattern: string, name: string): boolean {
  const re = new RegExp("^" + pattern.split("*").map((p) => p.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*") + "$");
  return re.test(name);
}

const LIMITS = { depth: 32, strings: 5000, bytes: 1_000_000 };

/** every string (and object key) inside the arguments; `complete` is false if a limit cut the walk short */
function walkStrings(v: unknown): { strings: string[]; fields: string[]; complete: boolean } {
  const strings: string[] = [], fields = new Set<string>();
  let bytes = 0, complete = true;
  const go = (x: unknown, depth: number) => {
    if (!complete) return;
    if (depth > LIMITS.depth || strings.length > LIMITS.strings || bytes > LIMITS.bytes) { complete = false; return; }
    if (typeof x === "string") { strings.push(x); bytes += x.length; }
    else if (typeof x === "number" || typeof x === "boolean" || x === null || x === undefined) return;
    else if (Array.isArray(x)) for (const y of x) go(y, depth + 1);
    else if (typeof x === "object") for (const [k, y] of Object.entries(x as Record<string, unknown>)) { fields.add(k); strings.push(k); go(y, depth + 1); }
  };
  go(v, 0);
  return { strings, fields: [...fields], complete };
}

const URLISH = /(?:\b[a-z][a-z0-9+.-]{1,15}:(?:\/\/|\\\\)?|(?<![\w/])\/\/)[^\s"'<>()]+/gi;
const BARE_DOMAIN = /(?<![\w@.-])(?:[\p{L}\p{N}](?:[\p{L}\p{N}-]{0,61}[\p{L}\p{N}])?\.)+[\p{L}]{2,24}(?![\p{L}\p{N}-])/giu;
const EMAIL_DOMAIN = /@(\[[^\]\s]{2,64}\]|(?:[\p{L}\p{N}-]+\.)+[\p{L}]{2,24})/giu;
const IPV4 = /(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])/g;

const toAsciiHost = (h: string): string | undefined => {
  const t = h.replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
  if (/^[\d.]+$/.test(t) || t.includes(":")) return t;
  try { return new URL(`http://${t}/`).hostname.replace(/\.$/, ""); } catch { return undefined; }
};

/** hosts and addresses named in the arguments, broadly: URLs of any scheme, scheme-less URLs, bare domains, email domains, IP addresses */
export function destinationsIn(args: unknown): { hosts: string[]; oddities: string[]; complete: boolean } {
  const { strings, complete } = walkStrings(args);
  const hosts = new Set<string>(), oddities: string[] = [];
  for (const s of strings) {
    for (const m of s.matchAll(URLISH)) {
      const raw = m[0];
      if (/^(?:data|blob|about|javascript|mailto|tel):/i.test(raw)) { if (/^javascript:/i.test(raw)) oddities.push("a javascript: URL"); continue; }
      if (raw.includes("\\")) oddities.push(`a URL with a backslash (${raw.slice(0, 60)}), which parsers read differently`);
      const auth = raw.replace(/^[a-z][a-z0-9+.-]*:/i, "").replace(/^[\\/]+/, "").split(/[\\/?#]/)[0];
      if (auth.includes("@")) oddities.push(`a URL with credentials or an @ before the host (${raw.slice(0, 60)}), which parsers read differently`);
      try { const u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `http://${auth}/`); if (u.hostname) hosts.add(u.hostname.replace(/\.$/, "").toLowerCase()); }
      catch { oddities.push(`an address that does not parse (${raw.slice(0, 60)})`); }
    }
    for (const m of s.matchAll(EMAIL_DOMAIN)) { const h = toAsciiHost(m[1]); if (h) hosts.add(h); }
    for (const m of s.matchAll(BARE_DOMAIN)) { const h = toAsciiHost(m[0]); if (h) hosts.add(h); }
    for (const m of s.matchAll(IPV4)) hosts.add(m[0]);
  }
  for (const h of hosts) if (/^xn--|\.xn--/.test(h)) oddities.push(`an international domain (${h}) that may imitate another`);
  return { hosts: [...hosts], oddities, complete };
}

/** characters of a token that look like data rather than words: mixed letter cases and digits */
const dataLike = (t: string) => t.length >= 6 && [/[a-z]/, /[A-Z]/, /[0-9]/].filter((r) => r.test(t)).length >= 2;

/** argument shapes that look like data leaving through a URL: encoded tokens anywhere in it, long subdomains, long query or fragment */
export function exfilShapes(args: unknown): string[] {
  const why: string[] = [];
  const { strings, complete } = walkStrings(args);
  if (!complete) why.push("arguments too large or deep to inspect fully");
  for (const s of strings) {
    for (const m of s.matchAll(URLISH)) {
      let u: URL;
      try { u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(m[0]) ? m[0] : `http://${m[0].replace(/^[a-z][a-z0-9+.-]*:/i, "").replace(/^[\\/]+/, "")}`); } catch { continue; }
      let decoded = `${u.hostname} ${u.pathname} ${u.search} ${u.hash}`;
      try { decoded = decodeURIComponent(decoded); } catch { /* keep encoded */ }
      const tokens = decoded.split(/[^A-Za-z0-9+=]+/).filter(Boolean);
      const dataChars = tokens.filter(dataLike).reduce((n, t) => n + t.length, 0);
      if (dataChars >= 24) why.push(`URL to ${u.hostname} carries ${dataChars} characters that look like encoded data`);
      if (u.hostname.split(".").some((l) => l.length >= 40)) why.push(`URL to ${u.hostname} has a very long subdomain label`);
      if (u.search.length + u.hash.length > 150) why.push(`URL to ${u.hostname} carries ${u.search.length + u.hash.length} characters of query and fragment`);
      if (u.username || u.password) why.push(`URL to ${u.hostname} carries credentials`);
    }
  }
  return [...new Set(why)];
}

const hostAllowed = (host: string, allow: string[]) => allow.some((a) => { const x = a.toLowerCase().replace(/\.$/, ""); return x.startsWith(".") ? host === x.slice(1) || host.endsWith(x) : host === x; });
const hostMatches = (host: string, q: string) => host === q || host.endsWith("." + q);

export class ActionBroker {
  readonly policy: BrokerPolicy;
  private runs = new Map<string, RunState>();
  private globalQuarantine = new Set<string>();
  private used = new Set<string>();

  constructor(policy: Partial<BrokerPolicy> = {}, private deps: { approver?: Approver; log?: (e: BrokerEvent) => void; now?: () => number } = {}) {
    this.policy = { ...DEFAULT_BROKER_POLICY, ...policy, readOnlyTools: policy.readOnlyTools ?? DEFAULT_BROKER_POLICY.readOnlyTools };
  }

  private run(runId: string): RunState {
    let r = this.runs.get(runId);
    if (!r) { r = { sources: new Set(), receipts: new Set(), hosts: new Set(), quarantined: new Set() }; this.runs.set(runId, r); }
    return r;
  }

  private quarantineHit(ref: string | undefined, host: string | undefined): string | undefined {
    for (const q of this.globalQuarantine) {
      if (ref && (ref === q || ref.startsWith(q))) return q;
      if (host && hostMatches(host, q)) return q;
    }
    return undefined;
  }

  /** is this URL or host quarantined? (check before fetching, and on the final URL after redirects) */
  isQuarantined(urlOrHost: string): string | undefined {
    let host: string | undefined;
    try { host = new URL(urlOrHost).hostname.toLowerCase().replace(/\.$/, ""); } catch { host = urlOrHost.toLowerCase().replace(/\.$/, ""); }
    return this.quarantineHit(urlOrHost, host);
  }

  /** record outside content the run has taken in. Any source taints the run, whatever its verdict. */
  ingest(runId: string, source: { ref: string; receiptDigest?: string; host?: string }): { tainted: true; sources: string[] } {
    const r = this.run(runId);
    r.sources.add(source.ref);
    if (source.receiptDigest) r.receipts.add(source.receiptDigest);
    const host = source.host?.toLowerCase().replace(/\.$/, "");
    if (host) r.hosts.add(host);
    const q = this.quarantineHit(source.ref, host) ?? (source.receiptDigest && this.globalQuarantine.has(source.receiptDigest) ? source.receiptDigest : undefined);
    if (q) r.quarantined.add(q);
    return { tainted: true, sources: [...r.sources] };
  }

  /** mark a source (URL prefix, host with its subdomains, or receipt digest) as quarantined everywhere; returns the runs that already touched it */
  quarantine(ref: string): string[] {
    const q = /^https?:/i.test(ref) ? ref : ref.toLowerCase().replace(/\.$/, "");
    this.globalQuarantine.add(q);
    const hit: string[] = [];
    for (const [id, r] of this.runs) {
      const touched = r.receipts.has(q) || [...r.sources].some((s) => s.startsWith(q)) || [...r.hosts].some((h) => hostMatches(h, q));
      if (touched) { r.quarantined.add(q); hit.push(id); }
    }
    return hit;
  }

  state(runId: string) {
    const r = this.run(runId);
    return { tainted: r.sources.size > 0, sources: [...r.sources], quarantined: [...r.quarantined] };
  }

  /** decide without asking anyone (for previews and tests) */
  classify(action: ProposedAction): { decision: ActionDecision; reasons: string[]; digest: string; canonicalArgs: string; destinations: string[]; fields: string[] } {
    const r = this.run(action.runId);
    const tainted = r.sources.size > 0;
    const canonicalArgs = canonicalJson(action.args);
    const digest = actionDigest(action.runId, action.tool, canonicalArgs);
    const reasons: string[] = [];
    const rule = this.policy.rules.find((x) => globMatch(x.tool, action.tool));
    const readOnly = !rule && this.policy.readOnlyTools.some((g) => globMatch(g, action.tool));
    const dest = destinationsIn(action.args);
    const fields = walkStrings(action.args).fields;
    let decision: ActionDecision;
    if (rule) {
      decision = (tainted ? rule.tainted : rule.clean) ?? (tainted ? "require_approval" : "allow");
      reasons.push(`rule ${rule.tool}: ${decision}${tainted ? " (run has taken in outside content)" : ""}`);
      if (rule.allowDestinations && decision === "allow") {
        const outside = dest.hosts.filter((h) => !hostAllowed(h, rule.allowDestinations!));
        if (outside.length) { decision = "require_approval"; reasons.push(`destination outside the allowlist: ${outside.join(", ")}`); }
        if (!dest.complete) { decision = "require_approval"; reasons.push("arguments too large or deep to check every destination"); }
        if (dest.oddities.length) { decision = "require_approval"; reasons.push(...dest.oddities); }
      }
    } else if (!tainted) {
      decision = "allow";
    } else if (readOnly) {
      decision = "allow";
    } else {
      decision = "require_approval";
      reasons.push(isSideEffectName(action.tool, this.policy.sideEffectHints)
        ? "a tool that acts, in a run that has taken in outside content"
        : "a tool not known to be read-only, in a run that has taken in outside content");
    }
    if (tainted && this.policy.guardOutboundData) {
      const ex = exfilShapes(action.args).filter((w) => !this.policy.allowHosts.some((a) => w.includes(` ${a.replace(/^\./, "")} `)));
      if (ex.length) { decision = strongest(decision, "require_approval"); reasons.push(...ex); }
      if (dest.oddities.length && decision === "allow") { decision = "require_approval"; reasons.push(...dest.oddities); }
    }
    if (r.quarantined.size && decision !== "allow" || r.quarantined.size && !readOnly) {
      decision = "deny";
      reasons.push(`run touched a quarantined source: ${[...r.quarantined].join(", ")}`);
    }
    return { decision, reasons, digest, canonicalArgs, destinations: dest.hosts, fields };
  }

  /**
   * Decide, asking the approver when needed. The caller must then execute EXACTLY the
   * arguments it gets back (frozen) or not at all.
   */
  async authorize(action: ProposedAction): Promise<BrokerVerdict & { args: unknown }> {
    const c = this.classify(action);
    const now = this.deps.now?.() ?? Date.now();
    const policyRef = { name: this.policy.name, version: this.policy.version };
    let verdict: BrokerVerdict;
    if (c.decision === "allow") verdict = { decision: "allow", permitted: true, reasons: c.reasons, digest: c.digest, policy: policyRef };
    else if (c.decision === "deny") verdict = { decision: "deny", permitted: false, reasons: c.reasons, digest: c.digest, policy: policyRef };
    else if (c.canonicalArgs.length > this.policy.maxShownArgChars) {
      // what the person cannot see in full, they cannot approve
      c.reasons.push(`arguments are ${c.canonicalArgs.length} characters, too long to show in full for approval (limit ${this.policy.maxShownArgChars}), so it was refused`);
      verdict = { decision: "require_approval", permitted: false, reasons: c.reasons, digest: c.digest, approval: { id: "", outcome: "unavailable" }, policy: policyRef };
    } else {
      const req: ApprovalRequest = {
        id: randomBytes(9).toString("base64url"), runId: action.runId, tool: action.tool, canonicalArgs: c.canonicalArgs, digest: c.digest,
        reasons: [...c.reasons], destinations: c.destinations, fields: c.fields, sources: this.state(action.runId).sources, createdAt: now, expiresAt: now + this.policy.approvalTtlMs,
      };
      let outcome: "approved" | "denied" | "timeout" | "unavailable" = "unavailable";
      if (this.deps.approver) {
        try { outcome = await this.deps.approver.request(req); } catch { outcome = "unavailable"; }
      }
      const late = (this.deps.now?.() ?? Date.now()) > req.expiresAt;
      if (outcome === "approved" && late) outcome = "timeout";
      if (outcome === "approved" && this.used.has(req.id)) outcome = "denied";
      if (outcome === "approved") this.used.add(req.id);
      const permitted = outcome === "approved";
      if (!permitted) c.reasons.push(outcome === "unavailable" ? "approval needed but no approver is set up or reachable, so it was refused (fails closed)" : outcome === "denied" ? "the person declined" : "the person did not answer in time");
      verdict = { decision: "require_approval", permitted, reasons: c.reasons, digest: c.digest, approval: { id: req.id, outcome }, policy: policyRef };
    }
    this.deps.log?.({ event: "broker.decision", at: new Date(now).toISOString(), runId: action.runId, tool: action.tool, digest: c.digest, decision: verdict.decision, permitted: verdict.permitted, reasons: verdict.reasons, approval: verdict.approval, sources: this.state(action.runId).sources, policy: policyRef });
    return { ...verdict, args: deepFreeze(JSON.parse(c.canonicalArgs)) };
  }
}

function strongest(a: ActionDecision, b: ActionDecision): ActionDecision {
  const rank = { allow: 0, require_approval: 1, deny: 2 } as const;
  return rank[a] >= rank[b] ? a : b;
}

function deepFreeze<T>(o: T): T {
  if (o && typeof o === "object") { Object.freeze(o); for (const v of Object.values(o as object)) deepFreeze(v); }
  return o;
}

/** readable text of an approval request for a human: destinations and field names first, every invisible or format character made visible */
export function describeApproval(req: ApprovalRequest, maxArgs = 4000): string {
  const vis = (t: string) => t.replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\u00ad\u034f\u115f\u1160\u180e\u3164\uffa0]/gu, (c) => (c === "\n" ? "\\n" : `<U+${c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}>`));
  const args = req.canonicalArgs.length > maxArgs ? req.canonicalArgs.slice(0, maxArgs) + ` … (${req.canonicalArgs.length - maxArgs} more characters NOT SHOWN: deny)` : req.canonicalArgs;
  return [
    `An AI agent wants to run: ${vis(req.tool)}`,
    req.destinations?.length ? `It names these hosts or addresses: ${req.destinations.map(vis).join(", ")}` : "It names no hosts or addresses.",
    req.fields?.length ? `Fields: ${req.fields.map(vis).join(", ")}` : "",
    `Arguments (exactly what will run): ${vis(args)}`,
    `Why this needs you: ${req.reasons.map(vis).join("; ")}`,
    req.sources.length ? `Outside content this run has read: ${req.sources.slice(-5).map(vis).join(", ")}` : "",
    `Action fingerprint: ${req.digest.slice(0, 16)}`,
  ].filter(Boolean).join("\n\n");
}
