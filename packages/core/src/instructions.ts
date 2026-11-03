/**
 * Instruction-file approval for coding agents.
 *
 * Reading a repository's AGENTS.md to understand a project is one decision; obeying it as
 * guidance is another. A dependency, a pull request or a compromised script can write one.
 * This module finds the files coding agents load as instructions, and serves a file as
 * guidance only when its exact bytes match a version a person approved. Anything else is
 * handed over as untrusted data, gated like web content.
 *
 * Approvals live outside the repository (~/.acepaste-ingress/instruction-approvals.json),
 * each one signed with a local key, and are made only from an interactive terminal
 * (`ingress instructions approve`), never by a tool the model can call.
 *
 * Limits: this is enforcement only where the agent loads instructions through it (the MCP
 * tool, a hook, a wrapper). An agent runtime that reads CLAUDE.md or AGENTS.md natively
 * bypasses it; turn native loading off where the runtime allows. Code running as the same
 * user can read the key and forge approvals. Approval means "this version may be used as
 * project guidance", never "every instruction in it is authorized": tool permissions are
 * still the broker's job.
 */

import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, realpathSync, statSync, writeFileSync, chmodSync } from "node:fs";
import { homedir } from "node:os";
import { join, relative, sep } from "node:path";

/** file names and paths coding agents load as instructions (as of 2026-11) */
export const INSTRUCTION_FILE_PATTERNS: RegExp[] = [
  /(?:^|\/)AGENTS\.md$/i, /(?:^|\/)AGENT\.md$/i, /(?:^|\/)CLAUDE\.md$/i, /(?:^|\/)CLAUDE\.local\.md$/i, /(?:^|\/)GEMINI\.md$/i,
  /(?:^|\/)\.cursorrules$/i, /(?:^|\/)\.cursor\/rules\/[^/]+\.mdc?$/i, /(?:^|\/)\.windsurfrules$/i, /(?:^|\/)\.windsurf\/rules\/[^/]+\.md$/i,
  /(?:^|\/)\.clinerules(?:\/[^/]+\.md)?$/i, /(?:^|\/)\.roo\/rules[^/]*\/[^/]+\.md$/i, /(?:^|\/)\.roorules$/i,
  /(?:^|\/)\.github\/copilot-instructions\.md$/i, /(?:^|\/)\.github\/instructions\/[^/]+\.instructions\.md$/i,
  /(?:^|\/)CONVENTIONS\.md$/i, /(?:^|\/)\.aider\.conf\.yml$/i, /(?:^|\/)\.claude\/(?:commands|agents)\/[^/]+\.md$/i,
];

export interface InstructionFile { relPath: string; absPath: string; bytes: number; sha256: string; inDependency: boolean }

const SKIP_DIRS = new Set([".git", ".hg", ".svn"]);

/** walk a repository for instruction files. Dependencies (node_modules, vendor, .venv) are searched too, and marked. */
export function discoverInstructionFiles(root: string, opts: { maxDepth?: number; maxFiles?: number; maxEntries?: number } = {}): InstructionFile[] {
  const base = realpathSync(root);
  const out: InstructionFile[] = [];
  const maxDepth = opts.maxDepth ?? 8, maxFiles = opts.maxFiles ?? 500, maxEntries = opts.maxEntries ?? 200_000;
  let entries = 0;
  const walk = (dir: string, depth: number) => {
    if (depth > maxDepth || out.length >= maxFiles || entries > maxEntries) return;
    let names: string[];
    try { names = readdirSync(dir); } catch { return; }
    for (const n of names) {
      entries++;
      const abs = join(dir, n);
      let st;
      try { st = statSync(abs); } catch { continue; }
      if (st.isDirectory()) { if (!SKIP_DIRS.has(n)) walk(abs, depth + 1); continue; }
      const rel = relative(base, abs).split(sep).join("/");
      if (!st.isFile() || !INSTRUCTION_FILE_PATTERNS.some((p) => p.test(rel))) continue;
      if (st.size > 1_000_000) continue;
      const buf = readFileSync(abs);
      out.push({ relPath: rel, absPath: abs, bytes: buf.length, sha256: createHash("sha256").update(buf).digest("hex"), inDependency: /(?:^|\/)(?:node_modules|vendor|\.venv|venv|site-packages|third_party)\//.test(rel) });
    }
  };
  walk(base, 0);
  return out.sort((a, b) => a.relPath.localeCompare(b.relPath));
}

export interface ApprovalEntry { root: string; relPath: string; sha256: string; approvedAt: string; approvedBy: string; mac: string }
interface Ledger { version: 1; entries: ApprovalEntry[] }

export interface LedgerOptions { dir?: string }
const ledgerDir = (o: LedgerOptions) => o.dir ?? join(homedir(), ".acepaste-ingress");

function approverKey(o: LedgerOptions, create: boolean): Buffer | undefined {
  const p = join(ledgerDir(o), "approver.key");
  if (existsSync(p)) return Buffer.from(readFileSync(p, "utf8").trim(), "hex");
  if (!create) return undefined;
  mkdirSync(ledgerDir(o), { recursive: true, mode: 0o700 });
  const k = randomBytes(32);
  writeFileSync(p, k.toString("hex"), { mode: 0o600 });
  try { chmodSync(p, 0o600); } catch { /* best effort */ }
  return k;
}

const macOf = (key: Buffer, e: Omit<ApprovalEntry, "mac">) => createHmac("sha256", key).update(JSON.stringify(["instruction-approval:v1", e.root, e.relPath, e.sha256, e.approvedAt, e.approvedBy])).digest("hex");

function readLedger(o: LedgerOptions): ApprovalEntry[] {
  const p = join(ledgerDir(o), "instruction-approvals.json");
  const key = approverKey(o, false);
  if (!existsSync(p) || !key) return [];
  let l: Ledger;
  try { l = JSON.parse(readFileSync(p, "utf8")); } catch { return []; }
  // entries whose signature does not check out are ignored, not trusted
  return (l.entries ?? []).filter((e) => {
    const want = Buffer.from(macOf(key, e), "hex"), got = Buffer.from(String(e.mac ?? ""), "hex");
    return got.length === want.length && timingSafeEqual(got, want);
  });
}

/** record a person's approval of one file's exact bytes. Callers must have confirmed with a human first. */
export function approveInstructionFile(root: string, relPath: string, approvedBy: string, o: LedgerOptions = {}): ApprovalEntry {
  const base = realpathSync(root);
  const f = discoverInstructionFiles(base).find((x) => x.relPath === relPath);
  if (!f) throw new Error(`${relPath} is not an instruction file under ${base}`);
  const key = approverKey(o, true)!;
  const body = { root: base, relPath, sha256: f.sha256, approvedAt: new Date().toISOString(), approvedBy };
  const entry: ApprovalEntry = { ...body, mac: macOf(key, body) };
  const kept = readLedger(o).filter((e) => !(e.root === base && e.relPath === relPath));
  const p = join(ledgerDir(o), "instruction-approvals.json");
  writeFileSync(p, JSON.stringify({ version: 1, entries: [...kept, entry] } satisfies Ledger, null, 2), { mode: 0o600 });
  return entry;
}

export type InstructionStatus = "approved" | "changed" | "unknown";
export interface InstructionCheck extends InstructionFile { status: InstructionStatus; approvedSha256?: string }

export function checkInstructionFiles(root: string, o: LedgerOptions = {}): InstructionCheck[] {
  const base = realpathSync(root);
  const ledger = readLedger(o).filter((e) => e.root === base);
  return discoverInstructionFiles(base).map((f) => {
    const e = ledger.find((x) => x.relPath === f.relPath);
    return { ...f, status: !e ? "unknown" : e.sha256 === f.sha256 ? "approved" : "changed", approvedSha256: e?.sha256 };
  });
}

/**
 * Read each instruction file ONCE and decide from those bytes: approved bytes come back
 * as guidance; anything else comes back only as untrusted data. `gate` is the engine's
 * scan, so even approved files carry a verdict.
 */
export async function loadInstructionFiles(root: string, gate: (text: string, source: string) => Promise<{ tier: string; envelope: string; findings: { kind: string }[] }>, o: LedgerOptions = {}) {
  const base = realpathSync(root);
  const ledger = readLedger(o).filter((e) => e.root === base);
  const out: Array<{ relPath: string; status: InstructionStatus; inDependency: boolean; tier: string; sha256: string; guidance?: string; untrusted?: string }> = [];
  for (const f of discoverInstructionFiles(base)) {
    const buf = readFileSync(f.absPath);
    const sha = createHash("sha256").update(buf).digest("hex");
    const e = ledger.find((x) => x.relPath === f.relPath);
    const status: InstructionStatus = !e ? "unknown" : e.sha256 === sha ? "approved" : "changed";
    const text = buf.toString("utf8");
    const v = await gate(text, `file:${f.relPath}`);
    if (status === "approved" && v.tier !== "hostile") out.push({ relPath: f.relPath, status, inDependency: f.inDependency, tier: v.tier, sha256: sha, guidance: text });
    else out.push({ relPath: f.relPath, status, inDependency: f.inDependency, tier: v.tier, sha256: sha, untrusted: v.envelope });
  }
  return out;
}
