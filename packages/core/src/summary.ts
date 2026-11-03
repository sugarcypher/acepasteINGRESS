/**
 * Compact, machine-readable digest of a result: findings grouped by pass and
 * kind with counts and peak weight, plus the heaviest findings first.
 * Adapted from Briar Greenway's probe script (2026-11-03).
 */

import type { Finding, IngressResult } from "./types.js";

export interface FindingGroup { pass: string; kind: string; count: number; maxWeight: number | null }
export interface TopFinding { pass: string; kind: string; weight: number | null; message: string; excerpt: string }
export interface ResultSummary {
  url: string;
  tier: IngressResult["tier"];
  score: number;
  contentKind: IngressResult["contentKind"];
  findingCount: number;
  groups: FindingGroup[];
  top: TopFinding[];
}

/** confidence x severity, or null when either is not a finite number */
export function findingWeight(f: Pick<Finding, "confidence" | "severity">): number | null {
  const n = f.confidence * f.severity;
  return Number.isFinite(n) ? n : null;
}

const rounded = (n: number | null) => (n === null ? null : Number(n.toFixed(2)));

export function summarize(result: IngressResult, topN = 6): ResultSummary {
  const groups = new Map<string, FindingGroup>();
  for (const f of result.findings) {
    // a tuple key cannot collide even if a pass or kind contains a colon
    const key = JSON.stringify([f.pass, f.kind]);
    const g = groups.get(key) ?? { pass: f.pass, kind: f.kind, count: 0, maxWeight: null };
    g.count++;
    const w = findingWeight(f);
    if (w !== null && (g.maxWeight === null || w > g.maxWeight)) g.maxWeight = w;
    groups.set(key, g);
  }
  const top = result.findings
    .map((f, index) => ({ f, index, w: findingWeight(f) }))
    .sort((a, b) => (b.w ?? -Infinity) - (a.w ?? -Infinity) || a.index - b.index)
    .slice(0, topN)
    .map(({ f, w }) => ({
      pass: f.pass, kind: f.kind, weight: rounded(w),
      message: (f.message || "").slice(0, 140),
      excerpt: (f.excerpt || "").replace(/\s+/g, " ").slice(0, 80),
    }));
  return {
    url: result.receipt.finalUrl || result.receipt.url,
    tier: result.tier, score: result.score, contentKind: result.contentKind,
    findingCount: result.findings.length,
    groups: [...groups.values()].map((g) => ({ ...g, maxWeight: rounded(g.maxWeight) })),
    top,
  };
}

/**
 * Cloaking-check settings from environment variables, shared by the CLI, the
 * MCP server and the HTTP service:
 *   INGRESS_AGENT_UA        "honest" to send only the gate's own name, or a "|"-separated list of user agents
 *   INGRESS_CLOAKING_JITTER "min,max" milliseconds between the two fetches
 *   INGRESS_HUMAN_PROXY     HTTP(S) proxy URL for the browser-fingerprint fetch (e.g. a residential proxy)
 *   INGRESS_HUMAN_FETCH     "browser" to make that fetch in a real headless Chromium
 */
export function cloakingConfigFromEnv(env: Record<string, string | undefined>, honestUserAgent: string): Partial<import("./types.js").IngressConfig> {
  const cfg: Partial<import("./types.js").IngressConfig> = {};
  const ua = env.INGRESS_AGENT_UA?.trim();
  if (ua) cfg.agentUserAgents = ua === "honest" ? [honestUserAgent] : ua.split("|").map((s) => s.trim()).filter(Boolean);
  const j = env.INGRESS_CLOAKING_JITTER?.split(",").map((x) => Number(x.trim()));
  if (j && j.length === 2 && j.every((x) => Number.isFinite(x))) cfg.cloakingJitterMs = [j[0], j[1]];
  if (env.INGRESS_HUMAN_PROXY) cfg.humanProxy = env.INGRESS_HUMAN_PROXY;
  if (env.INGRESS_HUMAN_FETCH === "browser" || env.INGRESS_HUMAN_FETCH === "http") cfg.humanFetch = env.INGRESS_HUMAN_FETCH;
  return cfg;
}
