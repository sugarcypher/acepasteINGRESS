/**
 * Provenance marks: what an agent wrote after reading outside content.
 *
 * A run that has read a web page, an email or a tool result may have been steered by it. What that run
 * writes to disk is the way one steered moment reaches a later, clean session: a note, a script, a config.
 * So each file written in such a run is marked: which session, when, and what it had read. When a later
 * session reads the file, the mark says its content is at best "written by an agent earlier" (trust level 3
 * only if the run that wrote it was clean; this one was not).
 *
 * A mark labels; it does not block. The files are the person's own project, and withholding them would stop
 * work. The reader is told, the file is scanned as outside content, and the reading session counts as having
 * read outside content.
 *
 * Marks are kept by path with the file's hash, so a mark also says whether the file changed since.
 * A person clears a mark (`ingress provenance clear <path>`); an agent cannot.
 */

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join, resolve } from "node:path";
import { stateDir } from "./changes.js";

export interface ProvenanceMark {
  path: string;
  /** hash of the file when it was marked; undefined if it could not be read */
  sha256?: string;
  at: string;
  session: string;
  /** the last few things the writing session had read */
  sources: string[];
}

const MAX_MARKS = 5000;
const MAX_HASH_BYTES = 20_000_000;

function hashFile(path: string): string | undefined {
  try {
    if (statSync(path).size > MAX_HASH_BYTES) return undefined;
    return createHash("sha256").update(readFileSync(path)).digest("hex");
  } catch { return undefined; }
}

export class ProvenanceLedger {
  private file: string;
  constructor(dir: string = stateDir()) { this.file = join(dir, "provenance.json"); }

  private read(): Record<string, ProvenanceMark> {
    try { const v = JSON.parse(readFileSync(this.file, "utf8")) as unknown; return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, ProvenanceMark>) : {}; } catch { return {}; }
  }
  private write(marks: Record<string, ProvenanceMark>): void {
    let entries = Object.entries(marks);
    if (entries.length > MAX_MARKS) entries = entries.sort((a, b) => a[1].at.localeCompare(b[1].at)).slice(-MAX_MARKS);
    mkdirSync(join(this.file, ".."), { recursive: true, mode: 0o700 });
    writeFileSync(`${this.file}.${process.pid}.tmp`, JSON.stringify(Object.fromEntries(entries)), { mode: 0o600 });
    renameSync(`${this.file}.${process.pid}.tmp`, this.file);
  }

  /** Mark a file as written by a session that had read outside content. */
  mark(path: string, by: { session: string; sources: readonly string[]; at?: string }): ProvenanceMark {
    const p = resolve(path);
    const mark: ProvenanceMark = { path: p, sha256: hashFile(p), at: by.at ?? new Date().toISOString(), session: by.session, sources: by.sources.slice(-5).map((s) => s.slice(0, 200)) };
    const marks = this.read();
    marks[p] = mark;
    this.write(marks);
    return mark;
  }

  /** The mark on a file, and whether the file is still what was written then. */
  lookup(path: string): { mark: ProvenanceMark; unchanged: boolean } | undefined {
    const p = resolve(path);
    const mark = this.read()[p];
    if (!mark || typeof mark.path !== "string") return undefined;
    return { mark, unchanged: mark.sha256 !== undefined && mark.sha256 === hashFile(p) };
  }

  /** Remove a mark: a person has looked at the file. Returns whether there was one. */
  clear(path: string): boolean {
    const p = resolve(path);
    const marks = this.read();
    if (!(p in marks)) return false;
    delete marks[p];
    this.write(marks);
    return true;
  }

  list(): ProvenanceMark[] { return Object.values(this.read()).sort((a, b) => b.at.localeCompare(a.at)); }
}

/** One sentence for whoever reads a marked file. */
export function describeMark(m: ProvenanceMark, unchanged: boolean): string {
  const from = m.sources.length ? ` (it had read: ${m.sources.slice(-3).join(", ")})` : "";
  return `this file was written on ${m.at.slice(0, 10)} by an agent session that had read outside content${from}${unchanged ? "" : "; it has been changed since"}`;
}

/**
 * Where the operating system says a file came from: macOS marks downloads (and what is unpacked from them)
 * with a quarantine attribute naming the app that fetched them, and often the address. Undefined when the
 * file has no such mark, or on a system without it.
 */
export function downloadOrigin(path: string): { agent?: string; from?: string } | undefined {
  if (process.platform !== "darwin" || !existsSync(path)) return undefined;
  let q: string;
  try { q = execFileSync("/usr/bin/xattr", ["-p", "com.apple.quarantine", path], { encoding: "utf8", timeout: 2000, stdio: ["ignore", "pipe", "ignore"] }).trim(); } catch { return undefined; }
  if (!q) return undefined;
  // flags;timestamp;agent name;event id
  const agent = q.split(";")[2] || undefined;
  let from: string | undefined;
  try {
    const where = execFileSync("/usr/bin/mdls", ["-raw", "-name", "kMDItemWhereFroms", path], { encoding: "utf8", timeout: 2000, stdio: ["ignore", "pipe", "ignore"] });
    from = where.match(/https?:\/\/[^\s",)]+/)?.[0];
  } catch { /* the attribute alone is enough */ }
  return { agent, from };
}
