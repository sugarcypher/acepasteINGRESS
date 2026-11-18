/**
 * Change tracking (Kith & Revere lineage: Baselines.swift and Changes.swift, ported 2026-11-18).
 *
 * Two questions, asked the same way everywhere in Ingress:
 *   1. What changed since last time?  (diffSnapshots)
 *   2. Did a person say this set is expected, and is it still that set?  (BaselineStore)
 *
 * The rules that make the answers useful are Kith & Revere's:
 *   - An item is identified by what it is (a path, a label, a program), never by notes, sizes or dates,
 *     so routine churn does not count as a change.
 *   - A group that is new in this version of the software is not a change on the machine.
 *   - Groups whose lists churn on their own are left out of comparisons.
 *   - A confirmed set stays confirmed only while it is exactly that set. Any addition or removal sends it
 *     back to review and shows exactly what changed.
 *   - Where an item's content matters (an instruction file, a tool description), its fingerprint is part of
 *     its identity, so an edit is a change.
 */

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";

export interface TrackedItem {
  /** stable identity: what the item is */
  key: string;
  /** what to show a person */
  label: string;
  /** free text for display only; never part of the identity */
  detail?: string;
}

export interface Snapshot {
  at: string;
  /** software version that took it, for the "new group in this version" rule */
  version: string;
  groups: Record<string, TrackedItem[]>;
}

export interface GroupChange {
  group: string;
  added: TrackedItem[];
  /** keys that were present before and are gone now */
  removed: string[];
}

export interface SnapshotDiff {
  previousAt: string;
  changes: GroupChange[];
  /** groups this snapshot has and the previous one did not: new checks, not changes on the machine */
  newGroups: string[];
  addedCount: number;
  removedCount: number;
  isEmpty: boolean;
}

const uniqueByKey = (items: readonly TrackedItem[]) => [...new Map(items.map((i) => [i.key, i])).values()];

/** What changed between two snapshots, group by group. */
export function diffSnapshots(previous: Snapshot, current: Snapshot, opts: { volatile?: readonly string[] } = {}): SnapshotDiff {
  const volatile = new Set(opts.volatile ?? []);
  const changes: GroupChange[] = [];
  const newGroups: string[] = [];
  for (const group of Object.keys(current.groups).sort()) {
    if (volatile.has(group)) continue;
    if (!(group in previous.groups)) { newGroups.push(group); continue; }
    const before = new Set(previous.groups[group].map((i) => i.key));
    const cur = uniqueByKey(current.groups[group]);
    const now = new Set(cur.map((i) => i.key));
    const added = cur.filter((i) => !before.has(i.key));
    const removed = [...before].filter((k) => !now.has(k)).sort();
    if (added.length || removed.length) changes.push({ group, added, removed });
  }
  // a group that existed before and is entirely gone now: everything in it was removed
  for (const group of Object.keys(previous.groups).sort()) {
    if (volatile.has(group) || group in current.groups) continue;
    const removed = [...new Set(previous.groups[group].map((i) => i.key))].sort();
    if (removed.length) changes.push({ group, added: [], removed });
  }
  const addedCount = changes.reduce((n, c) => n + c.added.length, 0);
  const removedCount = changes.reduce((n, c) => n + c.removed.length, 0);
  return { previousAt: previous.at, changes, newGroups, addedCount, removedCount, isEmpty: !changes.length };
}

export interface Baseline {
  confirmedAt: string;
  /** who or what confirmed: "person" (an explicit confirmation) or "first-seen" (recorded on first sight, not yet confirmed) */
  by: "person" | "first-seen";
  keys: string[];
}

export type ConfirmState =
  | { state: "none" }
  | { state: "first-seen"; since: string }
  | { state: "confirmed"; at: string }
  | { state: "changed"; since: string; added: TrackedItem[]; removed: string[] };

/** Compare the current items of a group with its baseline. */
export function confirmState(items: readonly TrackedItem[], baseline: Baseline | undefined): ConfirmState {
  if (!baseline) return { state: "none" };
  const cur = uniqueByKey(items);
  const before = new Set(baseline.keys);
  const now = new Set(cur.map((i) => i.key));
  const added = cur.filter((i) => !before.has(i.key));
  const removed = baseline.keys.filter((k) => !now.has(k)).sort();
  if (added.length || removed.length) return { state: "changed", since: baseline.confirmedAt, added, removed };
  return baseline.by === "person" ? { state: "confirmed", at: baseline.confirmedAt } : { state: "first-seen", since: baseline.confirmedAt };
}

/** Where Ingress keeps its own state: INGRESS_STATE_DIR, else ~/.acepaste-ingress/state. */
export function stateDir(env: NodeJS.ProcessEnv = process.env): string {
  return env.INGRESS_STATE_DIR || join(homedir(), ".acepaste-ingress", "state");
}

function writePrivate(path: string, text: string) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, text, { mode: 0o600 });
  renameSync(tmp, path); // a reader sees the old file or the new one, never half of either
}

/**
 * Confirmed sets, kept in one JSON file readable only by its owner. Only identities are stored.
 * The store never confirms anything on its own: `confirm` is for a person's explicit action, and
 * `recordFirstSeen` only remembers what was there, so a later change can be noticed.
 */
export class BaselineStore {
  private data: Record<string, Baseline> = {};

  constructor(private readonly path: string = join(stateDir(), "baselines.json")) {
    try { if (existsSync(path)) this.data = JSON.parse(readFileSync(path, "utf8")) as Record<string, Baseline>; } catch { this.data = {}; }
  }

  get(group: string): Baseline | undefined { return this.data[group]; }
  state(group: string, items: readonly TrackedItem[]): ConfirmState { return confirmState(items, this.data[group]); }

  /** A person says the current set is expected. */
  confirm(group: string, items: readonly TrackedItem[], now: Date = new Date()): Baseline {
    const b: Baseline = { confirmedAt: now.toISOString(), by: "person", keys: [...new Set(items.map((i) => i.key))].sort() };
    this.data[group] = b;
    this.save();
    return b;
  }

  /** Remember a set the first time it is seen. Does nothing when a baseline already exists. */
  recordFirstSeen(group: string, items: readonly TrackedItem[], now: Date = new Date()): ConfirmState {
    if (!this.data[group]) {
      this.data[group] = { confirmedAt: now.toISOString(), by: "first-seen", keys: [...new Set(items.map((i) => i.key))].sort() };
      this.save();
    }
    return this.state(group, items);
  }

  revoke(group: string): void { delete this.data[group]; this.save(); }
  groups(): string[] { return Object.keys(this.data).sort(); }

  private save() { writePrivate(this.path, JSON.stringify(this.data, null, 1)); }
}

/** Snapshots on disk: one JSON file per run, named so they sort by time. */
export class SnapshotStore {
  constructor(private readonly dir: string, private readonly prefix: string) {}

  save(s: Snapshot): string {
    const name = `${this.prefix}-${s.at.replace(/[:.]/g, "-")}.json`;
    const path = join(this.dir, name);
    writePrivate(path, JSON.stringify(s));
    return path;
  }

  /** The most recent snapshot saved before `before` (default: the newest of all). */
  latest(before?: string): Snapshot | undefined {
    let names: string[];
    try { names = readdirSync(this.dir).filter((n) => n.startsWith(`${this.prefix}-`) && n.endsWith(".json")).sort(); } catch { return undefined; }
    const cut = before ? `${this.prefix}-${before.replace(/[:.]/g, "-")}.json` : undefined;
    const eligible = cut ? names.filter((n) => n < cut) : names;
    for (let i = eligible.length - 1; i >= 0; i--) {
      try { return JSON.parse(readFileSync(join(this.dir, eligible[i]), "utf8")) as Snapshot; } catch { /* a torn file: try the one before */ }
    }
    return undefined;
  }
}

/** Fingerprint of a definition whose content matters: canonical JSON, sorted keys, sha256. */
export function fingerprint(value: unknown): string {
  const canon = (v: unknown): unknown => {
    if (Array.isArray(v)) return v.map(canon);
    if (v && typeof v === "object") return Object.fromEntries(Object.keys(v as object).sort().map((k) => [k, canon((v as Record<string, unknown>)[k])]));
    return v;
  };
  return createHash("sha256").update(JSON.stringify(canon(value)) ?? "null", "utf8").digest("hex");
}

export function formatDiff(d: SnapshotDiff, what = "run"): string {
  if (d.isEmpty) return `Nothing changed since the last ${what} (${d.previousAt}).`;
  const lines = [`Changed since the last ${what} (${d.previousAt}): ${d.addedCount} added, ${d.removedCount} removed`];
  for (const c of d.changes) {
    lines.push(`  ${c.group}`);
    for (const a of c.added) lines.push(`    + ${a.label}${a.detail ? ` (${a.detail})` : ""}`);
    for (const r of c.removed) lines.push(`    - ${r}`);
  }
  return lines.join("\n");
}
