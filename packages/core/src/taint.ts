/**
 * Taint guard: opt-in capability control (CaMeL-style separation of
 * untrusted data from side-effecting actions).
 *
 * Once a session has ingested content at or above the configured tier,
 * tools named in `sideEffectTools` are held until `confirm()` is called by
 * the user-facing layer. Nothing here is mandatory; it is middleware the
 * integrator wraps around tool dispatch.
 */

import type { IngressResult, Tier } from "./types.js";

export interface TaintPolicy {
  /** tier at which the session becomes tainted; default "suspect" */
  taintAt: Tier;
  /** tool names that must pause while tainted */
  sideEffectTools: string[];
  /** how long a confirmation stays valid, milliseconds */
  confirmationTtlMs: number;
}

export interface TaintGuard {
  /** record a gate result; returns the session's taint state */
  ingest(result: IngressResult): { tainted: boolean; sources: string[] };
  /** true if this tool call may proceed now */
  allow(toolName: string): boolean;
  /** user confirmed a side-effect; unlocks sideEffectTools for the TTL */
  confirm(): void;
  /** forget taint (new task, new context) */
  reset(): void;
  readonly state: { tainted: boolean; sources: string[]; confirmedUntil: number };
}

const TIER_RANK: Record<Tier, number> = { clean: 0, unreachable: 0, suspect: 1, hostile: 2 };

export function createTaintGuard(policy: Partial<TaintPolicy> = {}): TaintGuard {
  const p: TaintPolicy = {
    taintAt: policy.taintAt ?? "suspect",
    sideEffectTools: policy.sideEffectTools ?? ["send", "email", "post", "write", "delete", "pay", "transfer", "execute", "shell", "deploy"],
    confirmationTtlMs: policy.confirmationTtlMs ?? 60_000,
  };
  const state = { tainted: false, sources: [] as string[], confirmedUntil: 0 };

  return {
    state,
    ingest(result) {
      if (TIER_RANK[result.tier] >= TIER_RANK[p.taintAt]) {
        state.tainted = true;
        if (!state.sources.includes(result.receipt.finalUrl)) state.sources.push(result.receipt.finalUrl);
      }
      return { tainted: state.tainted, sources: [...state.sources] };
    },
    allow(toolName) {
      if (!state.tainted) return true;
      const isSideEffect = p.sideEffectTools.some((s) => toolName.toLowerCase().includes(s));
      if (!isSideEffect) return true;
      return Date.now() < state.confirmedUntil;
    },
    confirm() { state.confirmedUntil = Date.now() + p.confirmationTtlMs; },
    reset() { state.tainted = false; state.sources.length = 0; state.confirmedUntil = 0; },
  };
}
