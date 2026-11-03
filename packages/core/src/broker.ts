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
  /** tool-name fragments treated as side-effecting when no rule matches */
  sideEffectHints: string[];
  /** decision for a side-effecting tool with no rule, by taint state */
  defaultSideEffect: { clean: ActionDecision; tainted: ActionDecision };
  /** decision for any other tool with no rule, by taint state */
  defaultOther: { clean: ActionDecision; tainted: ActionDecision };
  /** while tainted, arguments shaped like data leaving (see exfilShapes) need approval */
  guardOutboundData: boolean;
  /** how long an approval stays usable */
  approvalTtlMs: number;
  /** what to do when approval is needed but no approver is configured or it fails */
  onApproverUnavailable: "deny";
}

export const DEFAULT_BROKER_POLICY: BrokerPolicy = {
  name: "default",
  version: 1,
  rules: [],
  sideEffectHints: ["send", "email", "mail", "post", "publish", "write", "edit", "create", "update", "delete", "remove", "move", "rename", "pay", "transfer", "purchase", "order", "execute", "exec", "run", "shell", "bash", "command", "deploy", "push", "commit", "merge", "install", "upload", "share", "invite", "message", "reply", "comment", "schedule"],
  defaultSideEffect: { clean: "allow", tainted: "require_approval" },
  defaultOther: { clean: "allow", tainted: "allow" },
  guardOutboundData: true,
  approvalTtlMs: 120_000,
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

interface RunState { sources: Set<string>; receipts: Set<string>; quarantined: Set<string> }

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

/**
 * Words of the tool's own name (the part after a "server__" prefix), split on separators
 * and camelCase. A tool is side-effecting when one of its words is a hint ("send_email",
 * "createIssue"); substrings do not count, so "read_messages" or "truncate_text" are not.
 */
export function isSideEffectName(tool: string, hints: readonly string[]): boolean {
  const own = tool.includes("__") ? tool.slice(tool.lastIndexOf("__") + 2) : tool;
  const words = own.replace(/([a-z0-9])([A-Z])/g, "$1 $2").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  // a name that starts with a read verb is a read ("read_messages", "get_mail", "list_posts")
  if (words.length && READ_VERBS.has(words[0])) return false;
  return words.some((w) => hints.includes(w) || (w.endsWith("s") && hints.includes(w.slice(0, -1))));
}

const READ_VERBS = new Set(["read", "get", "list", "search", "fetch", "find", "query", "lookup", "view", "show", "describe", "count", "check", "inspect", "status", "info", "head", "stat", "browse"]);

function globMatch(pattern: string, name: string): boolean {
  const re = new RegExp("^" + pattern.split("*").map((p) => p.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*") + "$", "i");
  return re.test(name);
}

/** every string inside the arguments, depth-limited */
function stringsIn(v: unknown, out: string[] = [], depth = 0): string[] {
  if (depth > 8 || out.length > 500) return out;
  if (typeof v === "string") out.push(v);
  else if (Array.isArray(v)) for (const x of v) stringsIn(x, out, depth + 1);
  else if (v && typeof v === "object") for (const x of Object.values(v)) stringsIn(x, out, depth + 1);
  return out;
}

const URL_RE = /\bhttps?:\/\/[^\s"'<>]+/gi;
const EMAIL_RE = /\b[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})\b/gi;

/** hosts named in the arguments (URLs and email domains) */
export function destinationsIn(args: unknown): string[] {
  const hosts = new Set<string>();
  for (const s of stringsIn(args)) {
    for (const m of s.matchAll(URL_RE)) { try { hosts.add(new URL(m[0]).hostname.toLowerCase()); } catch { /* ignore */ } }
    for (const m of s.matchAll(EMAIL_RE)) hosts.add(m[1].toLowerCase());
  }
  return [...hosts];
}

/** argument shapes that look like data leaving: a long query string, a long encoded token in a URL */
export function exfilShapes(args: unknown): string[] {
  const why: string[] = [];
  for (const s of stringsIn(args)) {
    for (const m of s.matchAll(URL_RE)) {
      let u: URL;
      try { u = new URL(m[0]); } catch { continue; }
      if (u.search.length > 120) why.push(`URL to ${u.hostname} carries ${u.search.length} characters of query data`);
      const blob = (u.pathname + u.search).match(/[A-Za-z0-9+/_=-]{48,}/);
      if (blob) why.push(`URL to ${u.hostname} carries a ${blob[0].length}-character encoded token`);
    }
  }
  return why;
}

const hostAllowed = (host: string, allow: string[]) => allow.some((a) => (a.startsWith(".") ? host === a.slice(1) || host.endsWith(a) : host === a));

export class ActionBroker {
  readonly policy: BrokerPolicy;
  private runs = new Map<string, RunState>();
  private globalQuarantine = new Set<string>();
  private used = new Set<string>();

  constructor(policy: Partial<BrokerPolicy> = {}, private deps: { approver?: Approver; log?: (e: BrokerEvent) => void; now?: () => number } = {}) {
    this.policy = { ...DEFAULT_BROKER_POLICY, ...policy, defaultSideEffect: { ...DEFAULT_BROKER_POLICY.defaultSideEffect, ...(policy.defaultSideEffect ?? {}) }, defaultOther: { ...DEFAULT_BROKER_POLICY.defaultOther, ...(policy.defaultOther ?? {}) } };
  }

  private run(runId: string): RunState {
    let r = this.runs.get(runId);
    if (!r) { r = { sources: new Set(), receipts: new Set(), quarantined: new Set() }; this.runs.set(runId, r); }
    return r;
  }

  /** record outside content the run has taken in. Any source taints the run, whatever its verdict. */
  ingest(runId: string, source: { ref: string; receiptDigest?: string; host?: string }): { tainted: true; sources: string[] } {
    const r = this.run(runId);
    r.sources.add(source.ref);
    if (source.receiptDigest) r.receipts.add(source.receiptDigest);
    for (const q of [source.ref, source.receiptDigest, source.host]) if (q && this.globalQuarantine.has(q)) r.quarantined.add(q);
    return { tainted: true, sources: [...r.sources] };
  }

  /** mark a source (URL, host or receipt digest) as quarantined everywhere; returns the runs that already touched it */
  quarantine(ref: string): string[] {
    this.globalQuarantine.add(ref);
    const hit: string[] = [];
    for (const [id, r] of this.runs) {
      const touched = r.sources.has(ref) || r.receipts.has(ref) || [...r.sources].some((s) => { try { return new URL(s).hostname === ref; } catch { return false; } });
      if (touched) { r.quarantined.add(ref); hit.push(id); }
    }
    return hit;
  }

  state(runId: string) {
    const r = this.run(runId);
    return { tainted: r.sources.size > 0, sources: [...r.sources], quarantined: [...r.quarantined] };
  }

  /** decide without asking anyone (for previews and tests) */
  classify(action: ProposedAction): { decision: ActionDecision; reasons: string[]; digest: string; canonicalArgs: string } {
    const r = this.run(action.runId);
    const tainted = r.sources.size > 0;
    const canonicalArgs = canonicalJson(action.args);
    const digest = actionDigest(action.runId, action.tool, canonicalArgs);
    const reasons: string[] = [];
    const rule = this.policy.rules.find((x) => globMatch(x.tool, action.tool));
    const sideEffect = isSideEffectName(action.tool, this.policy.sideEffectHints);
    let decision: ActionDecision;
    if (rule) {
      decision = (tainted ? rule.tainted : rule.clean) ?? (tainted ? this.policy.defaultSideEffect.tainted : "allow");
      reasons.push(`rule ${rule.tool}: ${decision}${tainted ? " (run has taken in outside content)" : ""}`);
      if (rule.allowDestinations) {
        const outside = destinationsIn(action.args).filter((h) => !hostAllowed(h, rule.allowDestinations!));
        if (outside.length) { decision = strongest(decision, "require_approval"); reasons.push(`destination outside the allowlist: ${outside.join(", ")}`); }
      }
    } else if (sideEffect) {
      decision = tainted ? this.policy.defaultSideEffect.tainted : this.policy.defaultSideEffect.clean;
      reasons.push(tainted ? "side-effecting tool in a run that has taken in outside content" : "side-effecting tool");
    } else {
      decision = tainted ? this.policy.defaultOther.tainted : this.policy.defaultOther.clean;
    }
    if (tainted && this.policy.guardOutboundData) {
      const ex = exfilShapes(action.args);
      if (ex.length) { decision = strongest(decision, "require_approval"); reasons.push(...ex); }
    }
    if (r.quarantined.size && (sideEffect || rule || decision !== "allow")) {
      decision = "deny";
      reasons.push(`run touched a quarantined source: ${[...r.quarantined].join(", ")}`);
    }
    return { decision, reasons, digest, canonicalArgs };
  }

  /**
   * Decide, asking the approver when needed. The caller must then execute EXACTLY the
   * arguments it passed here (the broker hands them back frozen) or not at all.
   */
  async authorize(action: ProposedAction): Promise<BrokerVerdict & { args: unknown }> {
    const c = this.classify(action);
    const now = this.deps.now?.() ?? Date.now();
    const policyRef = { name: this.policy.name, version: this.policy.version };
    let verdict: BrokerVerdict;
    if (c.decision === "allow") verdict = { decision: "allow", permitted: true, reasons: c.reasons, digest: c.digest, policy: policyRef };
    else if (c.decision === "deny") verdict = { decision: "deny", permitted: false, reasons: c.reasons, digest: c.digest, policy: policyRef };
    else {
      const req: ApprovalRequest = {
        id: randomBytes(9).toString("base64url"), runId: action.runId, tool: action.tool, canonicalArgs: c.canonicalArgs, digest: c.digest,
        reasons: c.reasons, sources: this.state(action.runId).sources, createdAt: now, expiresAt: now + this.policy.approvalTtlMs,
      };
      let outcome: "approved" | "denied" | "timeout" | "unavailable" = "unavailable";
      if (this.deps.approver) {
        try { outcome = await this.deps.approver.request(req); } catch { outcome = "unavailable"; }
      }
      const late = (this.deps.now?.() ?? Date.now()) > req.expiresAt;
      if (outcome === "approved" && late) outcome = "timeout";
      // single use: the same approval id can never authorize twice
      if (outcome === "approved" && this.used.has(req.id)) outcome = "denied";
      if (outcome === "approved") this.used.add(req.id);
      const permitted = outcome === "approved";
      if (!permitted) c.reasons.push(outcome === "unavailable" ? "approval needed but no approver is set up or reachable, so it was refused (fails closed)" : outcome === "denied" ? "the person declined" : "the person did not answer in time");
      verdict = { decision: "require_approval", permitted, reasons: c.reasons, digest: c.digest, approval: { id: req.id, outcome }, policy: policyRef };
    }
    this.deps.log?.({ event: "broker.decision", at: new Date(now).toISOString(), runId: action.runId, tool: action.tool, digest: c.digest, decision: verdict.decision, permitted: verdict.permitted, reasons: verdict.reasons, approval: verdict.approval, sources: this.state(action.runId).sources, policy: policyRef });
    // hand back a frozen copy of exactly what was approved
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

/** readable text of an approval request for a human, with control characters made visible */
export function describeApproval(req: ApprovalRequest, maxArgs = 1500): string {
  const vis = (s: string) => s.replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩﻿]/g, (c) => `<U+${c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}>`);
  const args = req.canonicalArgs.length > maxArgs ? req.canonicalArgs.slice(0, maxArgs) + ` … (${req.canonicalArgs.length - maxArgs} more characters)` : req.canonicalArgs;
  return [
    `An AI agent wants to run: ${vis(req.tool)}`,
    `Arguments (exactly what will run): ${vis(args)}`,
    `Why this needs you: ${req.reasons.map(vis).join("; ")}`,
    req.sources.length ? `Outside content this run has read: ${req.sources.slice(-5).map(vis).join(", ")}` : "",
    `Action fingerprint: ${req.digest.slice(0, 16)}`,
  ].filter(Boolean).join("\n\n");
}
