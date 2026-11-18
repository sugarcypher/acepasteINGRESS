/**
 * The environment audit, compared with the last one and with what a person confirmed.
 * Identity rules follow Kith & Revere: what an item is, not its notes or counts.
 */

import { join } from "node:path";
import type { AuditReport } from "./audit.js";
import type { AuditArea, AuditFinding } from "./audit-parsers.js";
import { BaselineStore, SnapshotStore, diffSnapshots, fingerprint, formatDiff, stateDir, type ConfirmState, type Snapshot, type SnapshotDiff, type TrackedItem } from "./changes.js";
import { ENGINE_VERSION } from "./types.js";

/** Areas whose results depend on the network the machine is on right now; they would drown real changes. */
export const AUDIT_VOLATILE: readonly AuditArea[] = ["resolution"];

/**
 * Areas a person should confirm once: things that can change what agents receive or do.
 * Until confirmed (and whenever they change) they need attention.
 */
export const AUDIT_NEEDS_CONFIRMATION: readonly AuditArea[] = [
  "agent-config", "agent-instructions", "certificates", "network-extension", "proxy", "browser-policy", "browser-extension", "browser-search", "hosts", "dns",
  "input-devices", "listening", "tunnels", "printers", "network-interfaces",
];

/** Stable identity of one audit finding, or undefined when the finding is not worth tracking. */
export function auditItemKey(f: AuditFinding): string | undefined {
  // the DNS servers in use change with every network a laptop joins
  if (f.area === "dns" && f.title.startsWith("DNS servers:")) return undefined;
  // local-only listeners come and go with every dev server; the ones the network can reach are what a person confirms
  if (f.area === "listening" && f.title.endsWith("listens on this machine only")) return undefined;
  const where = f.where ?? "";
  // content matters here: an edited instruction file or hook is a change even though its path is the same
  if (f.area === "agent-instructions") {
    const sha = f.detail.match(/fingerprint ([0-9a-f]{12})/)?.[1] ?? "flagged";
    return `${where} @ ${sha}`;
  }
  if (f.area === "agent-config" && /agent hook command/.test(f.title)) return `${where} | agent hooks @ ${fingerprint(f.detail).slice(0, 12)}`;
  // blocklist sizes change whenever the list updates; the fact that a blocklist is there does not
  const title = /\b(blocked|blocks|cloaks)\b/.test(f.title) ? f.title.replace(/\d+/g, "N") : f.title;
  return `${where} | ${title}`;
}

export function auditSnapshot(r: AuditReport): Snapshot {
  const groups: Record<string, TrackedItem[]> = {};
  // every area that was looked at gets a group, so "nothing there" is a state that can change
  for (const c of r.checked) if (c.status === "checked") groups[c.area] ??= [];
  for (const f of r.findings) {
    const key = auditItemKey(f);
    if (key === undefined) continue;
    (groups[f.area] ??= []).push({ key, label: f.title, detail: f.where });
  }
  return { at: r.at, version: ENGINE_VERSION, groups };
}

export interface AuditAttention {
  area: string;
  state: ConfirmState;
  items: TrackedItem[];
}

export interface AuditChanges {
  /** undefined on the first audit: there is nothing to compare with */
  diff?: SnapshotDiff;
  /** areas waiting for a person: never confirmed, or changed since they were */
  needsAttention: AuditAttention[];
  confirmed: string[];
}

/**
 * Save this audit's snapshot and report what changed since the previous one, and which areas a person
 * still needs to confirm. `dir` defaults to Ingress's state folder.
 */
export function trackAudit(r: AuditReport, opts: { dir?: string; save?: boolean } = {}): AuditChanges {
  const dir = opts.dir ?? stateDir();
  const snaps = new SnapshotStore(join(dir, "audit-snapshots"), "audit");
  const baselines = new BaselineStore(join(dir, "baselines.json"));
  const current = auditSnapshot(r);
  const previous = snaps.latest(current.at);
  const diff = previous ? diffSnapshots(previous, current, { volatile: AUDIT_VOLATILE }) : undefined;
  if (opts.save !== false) snaps.save(current);

  const needsAttention: AuditAttention[] = [];
  const confirmed: string[] = [];
  for (const area of AUDIT_NEEDS_CONFIRMATION) {
    const items = current.groups[area];
    if (items === undefined) continue; // not checked on this platform
    const state = baselines.state(`audit:${area}`, items);
    if (state.state === "confirmed") confirmed.push(area);
    // an area with nothing in it and nothing ever confirmed needs no one's attention
    else if (state.state === "changed" || items.length) needsAttention.push({ area, state, items });
  }
  return { diff, needsAttention, confirmed };
}

/** A person confirms the current items of one audit area as expected. */
export function confirmAuditArea(r: AuditReport, area: AuditArea, opts: { dir?: string; now?: Date } = {}): { area: string; items: number } {
  const baselines = new BaselineStore(join(opts.dir ?? stateDir(), "baselines.json"));
  const items = auditSnapshot(r).groups[area] ?? [];
  baselines.confirm(`audit:${area}`, items, opts.now);
  return { area, items: items.length };
}

export function formatAuditChanges(c: AuditChanges): string {
  const lines: string[] = [];
  lines.push(c.diff ? formatDiff(c.diff, "audit") : "First audit on this machine: nothing to compare with yet.");
  if (c.diff?.newGroups.length) lines.push(`  (newly checked in this version, not a change on the machine: ${c.diff.newGroups.join(", ")})`);
  if (c.needsAttention.length) {
    lines.push("", "Needs your confirmation (things that can change what agents receive or do):");
    for (const a of c.needsAttention) {
      if (a.state.state === "changed") {
        lines.push(`  ${a.area}: changed since you confirmed it on ${a.state.since}`);
        for (const x of a.state.added) lines.push(`    + ${x.label}`);
        for (const x of a.state.removed) lines.push(`    - ${x}`);
      } else lines.push(`  ${a.area}: ${a.items.length} item(s), never confirmed`);
    }
    lines.push("  Confirm an area once it looks right: ingress audit confirm <area>");
  }
  if (c.confirmed.length) lines.push("", `Confirmed and unchanged: ${c.confirmed.join(", ")}`);
  return lines.join("\n");
}
