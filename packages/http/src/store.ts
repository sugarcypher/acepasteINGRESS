/**
 * Receipt store — the audit plane.
 *
 * Every verdict's receipt is kept, scoped to the API key that produced it,
 * so a customer can later prove what untrusted content their agents ingested
 * and what the gate did about it. This is the artifact the paid tier sells;
 * the detection is what generates it.
 *
 * This implementation is an append-only JSONL file with an in-memory index,
 * dependency-free and good to a few hundred thousand rows. It is deliberately
 * behind the `ReceiptStore` interface: swap `JsonlReceiptStore` for a
 * Postgres/ClickHouse-backed implementation in production without touching
 * the server.
 */

import { appendFileSync, mkdirSync, readFileSync, existsSync, writeFileSync, renameSync } from "node:fs";
import { dirname } from "node:path";
import type { TaintReceipt } from "@acepaste/ingress";

export interface StoredReceipt {
  /** API key name that produced this verdict (never the raw key) */
  key: string;
  at: string;
  url: string;
  sourceHost: string;
  tier: string;
  score: number;
  contentKind: string;
  overridden: boolean;
  acepasteInvisibleCount: number;
  kinds: string[];
  receiptDigest: string;
  rawDigest: string;
  /** the full signed receipt, the audit artifact itself */
  receipt: TaintReceipt;
}

export interface ReceiptQuery {
  key: string;
  url?: string;
  host?: string;
  tier?: string;
  kind?: string;
  since?: string; // ISO
  until?: string; // ISO
  limit?: number;
  offset?: number;
}

export interface ReceiptStore {
  put(r: StoredReceipt): void;
  query(q: ReceiptQuery): { total: number; items: StoredReceipt[] };
  get(key: string, digest: string): StoredReceipt | undefined;
  stats(key: string): { total: number; byTier: Record<string, number>; oldest?: string; newest?: string };
  prune(retentionDays: number): number;
}

function hostOf(u: string): string { try { return new URL(u).hostname.toLowerCase(); } catch { return ""; } }

export class JsonlReceiptStore implements ReceiptStore {
  private rows: StoredReceipt[] = [];
  private path?: string;
  private cap: number;

  constructor(opts: { path?: string; cap?: number } = {}) {
    this.path = opts.path;
    this.cap = opts.cap ?? 200_000;
    if (this.path && existsSync(this.path)) {
      for (const line of readFileSync(this.path, "utf8").split("\n")) {
        if (!line.trim()) continue;
        try { this.rows.push(JSON.parse(line)); } catch { /* skip a torn line */ }
      }
    } else if (this.path) {
      mkdirSync(dirname(this.path), { recursive: true });
    }
  }

  put(r: StoredReceipt): void {
    this.rows.push(r);
    if (this.path) { try { appendFileSync(this.path, JSON.stringify(r) + "\n"); } catch { /* best effort */ } }
    if (this.rows.length > this.cap) this.rows.splice(0, this.rows.length - this.cap);
  }

  query(q: ReceiptQuery): { total: number; items: StoredReceipt[] } {
    const host = q.host?.toLowerCase();
    const urlNeedle = q.url?.toLowerCase();
    const since = q.since ? Date.parse(q.since) : undefined;
    const until = q.until ? Date.parse(q.until) : undefined;
    const matched = this.rows.filter((r) => {
      if (r.key !== q.key) return false;
      if (q.tier && r.tier !== q.tier) return false;
      if (host && r.sourceHost !== host) return false;
      if (urlNeedle && !r.url.toLowerCase().includes(urlNeedle)) return false;
      if (q.kind && !r.kinds.includes(q.kind)) return false;
      const t = Date.parse(r.at);
      if (since !== undefined && t < since) return false;
      if (until !== undefined && t > until) return false;
      return true;
    });
    matched.reverse(); // newest first
    const offset = Math.max(0, q.offset ?? 0);
    const limit = Math.min(1000, Math.max(1, q.limit ?? 100));
    return { total: matched.length, items: matched.slice(offset, offset + limit) };
  }

  get(key: string, digest: string): StoredReceipt | undefined {
    return this.rows.find((r) => r.key === key && r.receiptDigest === digest);
  }

  stats(key: string): { total: number; byTier: Record<string, number>; oldest?: string; newest?: string } {
    const mine = this.rows.filter((r) => r.key === key);
    const byTier: Record<string, number> = {};
    for (const r of mine) byTier[r.tier] = (byTier[r.tier] ?? 0) + 1;
    return { total: mine.length, byTier, oldest: mine[0]?.at, newest: mine[mine.length - 1]?.at };
  }

  /** Drop rows older than retentionDays; rewrites the file. Returns rows removed. */
  prune(retentionDays: number): number {
    if (!retentionDays || retentionDays <= 0) return 0;
    const cutoff = Date.now() - retentionDays * 86_400_000;
    const before = this.rows.length;
    this.rows = this.rows.filter((r) => Date.parse(r.at) >= cutoff);
    const removed = before - this.rows.length;
    if (removed && this.path) {
      const tmp = this.path + ".tmp";
      writeFileSync(tmp, this.rows.map((r) => JSON.stringify(r)).join("\n") + (this.rows.length ? "\n" : ""));
      renameSync(tmp, this.path);
    }
    return removed;
  }
}

export function toStored(key: string, receipt: TaintReceipt, kinds: string[]): StoredReceipt {
  return {
    key, at: receipt.issuedAt, url: receipt.finalUrl, sourceHost: hostOf(receipt.finalUrl),
    tier: receipt.tier, score: receipt.score, contentKind: receipt.contentKind, overridden: receipt.overridden,
    acepasteInvisibleCount: receipt.acepasteInvisibleCount, kinds, receiptDigest: receipt.digest, rawDigest: receipt.rawDigest, receipt,
  };
}
