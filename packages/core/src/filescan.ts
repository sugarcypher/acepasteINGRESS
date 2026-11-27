/**
 * ingress filescan / corpusscan: gate files before an agent reads them, and a knowledge base before it is indexed.
 *
 * An attachment, a download or a document in a RAG folder reaches a model as extracted text. The extracted text
 * holds what a person sees in the file and, often, what they do not: white or tiny text, hidden runs, hidden
 * sheets, notes, metadata, scripts. filescan splits a file into those two kinds of text (pdf.ts, office.ts, and
 * the engine's own image, audio, video and text readers), runs every piece through the engine, and gives the
 * engine's verdict. With a clean-out folder it also writes what a person sees, re-gated on its own, for the
 * agent to read instead of the file.
 *
 * corpusscan walks a folder and runs filescan on each file, a few at a time, with size caps, and can move (or
 * copy) hostile files into a quarantine folder with a manifest of hashes and verdicts. It never deletes.
 *
 * Nothing here makes a network request: files are read from disk, and the engine's text, image, audio and video
 * passes run locally (image pixels and audio only through local helpers, when configured).
 */
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, extname, join, relative, resolve, sep } from "node:path";
import { IngressEngine } from "./engine.js";
import { detectImageFormat } from "./image-meta.js";
import { detectAudioFormat, type AudioRunner } from "./audio.js";
import { detectVideoFormat } from "./video.js";
import { analyzeHtml } from "./visibility.js";
import { adaptJson, adaptMarkdown, adaptText } from "./adapters.js";
import { looksLikeCaptions } from "./captions.js";
import { isZip } from "./zipread.js";
import { extractOffice } from "./office.js";
import { extractPdf } from "./pdf.js";
import { redactSecrets } from "./secrets.js";
import type { VisionRunner } from "./image.js";
import type { ContentKind, Finding, IngressResult, TextSegment, Tier } from "./types.js";

/** what a document reader returns: the text, split by who can see it */
export interface DocExtract {
  format: "pdf" | "docx" | "xlsx" | "pptx";
  segments: TextSegment[];
  findings: Finding[];
  notes: string[];
  /** false when part of the file could not be read (encrypted, an unsupported filter, a cap) */
  complete: boolean;
  pages?: number;
}

export type FileKind = "pdf" | "docx" | "xlsx" | "pptx" | "image" | "audio" | "video" | "captions" | "html" | "markdown" | "json" | "text" | "unsupported";

export interface FileScanResult {
  file: string;
  kind: FileKind;
  bytes: number;
  sha256: string;
  /** scanned; skipped (too large, unsupported, a link); error (could not be read) */
  status: "scanned" | "skipped" | "error";
  /** the engine's verdict; "unreachable" when the file was not scanned */
  tier: Tier;
  score: number;
  /** text an extractor reads and a person does not see, by where it was found */
  hidden: Array<{ where: string; visibility: TextSegment["visibility"]; words: number; excerpt: string }>;
  /** the findings that decided the verdict, strongest first */
  reasons: Array<{ kind: string; weight: number; message: string }>;
  /** what was not read, and why */
  notes: string[];
  /** false when part of the file was not read: unknown is not clean */
  complete: boolean;
  /** the safe text file written for the agent, when one was */
  cleanOut?: string;
  /** why no safe text was written, when asked for */
  cleanOutSkipped?: string;
  /** sha256 of the engine's receipt digest input: ties this result to its receipt */
  rawDigest?: string;
  engineVersion?: string;
  /** the engine's full result, for --json and library callers */
  result?: IngressResult;
}

export interface FileScanOptions {
  engine?: IngressEngine;
  /** write the visible text here as <name>.clean.txt */
  cleanOutDir?: string;
  /** the name to write under cleanOutDir (corpusscan keeps the folder structure); default: the file's own name */
  cleanOutName?: string;
  /** larger files are skipped; default 50 MB */
  maxBytes?: number;
  /** how to read image pixels; default the vision helper when built, false reads metadata only */
  vision?: VisionRunner | false;
  /** how to transcribe audio; default INGRESS_AUDIO_TRANSCRIBER, false reads tags only */
  transcriber?: AudioRunner | false;
  /** keep the engine's full result on the report */
  keepResult?: boolean;
}

export const FILESCAN_DEFAULT_MAX_BYTES = 50_000_000;
const EXCERPT = 160;
const words = (s: string) => (s.match(/\p{L}{2,}/gu) ?? []).length;
const sha256 = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");
const excerpt = (s: string) => redactSecrets(s.replace(/\s+/g, " ").trim()).slice(0, EXCERPT);

const AUDIO_EXT = new Set([".mp3", ".wav", ".m4a", ".flac", ".ogg", ".oga", ".aiff", ".aif", ".aac", ".opus"]);
const VIDEO_EXT = new Set([".mp4", ".mov", ".m4v", ".webm", ".mkv", ".avi"]);
const HTML_EXT = new Set([".html", ".htm", ".xhtml", ".mhtml"]);
const MD_EXT = new Set([".md", ".markdown", ".mdx", ".rst"]);
const JSON_EXT = new Set([".json", ".jsonl", ".ndjson", ".ipynb"]);
const CAPTION_EXT = new Set([".vtt", ".srt"]);

/** What a file is, by its bytes first and its name second. */
export function detectFileKind(path: string, bytes: Uint8Array): FileKind {
  const ext = extname(path).toLowerCase();
  const head = Buffer.from(bytes.subarray(0, 8)).toString("latin1");
  if (head.startsWith("%PDF-") || (ext === ".pdf" && Buffer.from(bytes.subarray(0, 1024)).toString("latin1").includes("%PDF-"))) return "pdf";
  if (isZip(bytes)) {
    if (ext === ".docx" || ext === ".docm" || ext === ".dotx" || ext === ".dotm") return "docx";
    if (ext === ".xlsx" || ext === ".xlsm" || ext === ".xltx" || ext === ".xltm") return "xlsx";
    if (ext === ".pptx" || ext === ".pptm" || ext === ".potx" || ext === ".ppsx") return "pptx";
    const kind = extractOfficeKindFast(bytes);
    return kind ?? "unsupported";
  }
  if (head.startsWith("\xd0\xcf\x11\xe0")) return "unsupported"; // legacy .doc/.xls/.ppt
  const img = detectImageFormat(bytes);
  if (img !== "unknown" && img !== "pdf") return "image";
  if (VIDEO_EXT.has(ext) || (!AUDIO_EXT.has(ext) && detectVideoFormat(bytes) !== "unknown" && !/M4A/.test(Buffer.from(bytes.subarray(8, 12)).toString("latin1")))) return "video";
  if (AUDIO_EXT.has(ext) || detectAudioFormat(bytes) !== "unknown") return "audio";
  // text: no NUL bytes in the first 8 KB
  const sample = bytes.subarray(0, 8192);
  if (sample.includes(0)) return "unsupported";
  if (HTML_EXT.has(ext) || ext === ".svg") return ext === ".svg" ? "image" : "html";
  if (MD_EXT.has(ext)) return "markdown";
  if (JSON_EXT.has(ext)) return "json";
  if (CAPTION_EXT.has(ext)) return "captions";
  const text = new TextDecoder("utf-8", { fatal: false }).decode(sample).trimStart();
  if (/^<!doctype html|^<html[\s>]/i.test(text)) return "html";
  if (looksLikeCaptions(text)) return "captions";
  return "text";
}

function extractOfficeKindFast(bytes: Uint8Array): FileKind | undefined {
  // the part names sit in the archive's directory as plain text
  const tail = Buffer.from(bytes.subarray(Math.max(0, bytes.length - 2_000_000))).toString("latin1");
  if (tail.includes("word/document.xml")) return "docx";
  if (tail.includes("xl/workbook.xml")) return "xlsx";
  if (tail.includes("ppt/presentation.xml")) return "pptx";
  return undefined;
}

const KIND_OF: Partial<Record<FileKind, ContentKind>> = { html: "html", markdown: "markdown", json: "json", text: "text", captions: "captions" };

/** the text a person sees, for kinds the engine reads as text */
function visibleTextOf(kind: FileKind, raw: string): string {
  if (kind === "html") return analyzeHtml(raw).visibleText;
  const r = kind === "markdown" ? adaptMarkdown(raw) : kind === "json" ? adaptJson(raw) : adaptText(raw);
  return r.segments.filter((s) => s.visibility === "visible").map((s) => s.text).join("\n");
}

/** Gate one file. Never throws for a file problem: the report says what happened. */
export async function filescan(path: string, opts: FileScanOptions = {}): Promise<FileScanResult> {
  const engine = opts.engine ?? new IngressEngine({ sandbox: "off", cloakingCheck: false }, { log: () => {} });
  const maxBytes = opts.maxBytes ?? FILESCAN_DEFAULT_MAX_BYTES;
  const base: FileScanResult = { file: path, kind: "unsupported", bytes: 0, sha256: "", status: "scanned", tier: "unreachable", score: 0, hidden: [], reasons: [], notes: [], complete: false };
  let st;
  try { st = lstatSync(path); } catch (e) { return { ...base, status: "error", notes: [`could not be read: ${(e as Error).message}`] }; }
  if (st.isSymbolicLink()) return { ...base, status: "skipped", notes: ["a symbolic link: not followed"] };
  if (!st.isFile()) return { ...base, status: "skipped", notes: ["not a regular file"] };
  base.bytes = st.size;
  if (st.size > maxBytes) return { ...base, status: "skipped", notes: [`${st.size} bytes, over the ${maxBytes} byte cap (--max-bytes)`] };
  let bytes: Uint8Array;
  try { bytes = readFileSync(path); } catch (e) { return { ...base, status: "error", notes: [`could not be read: ${(e as Error).message}`] }; }
  base.sha256 = sha256(bytes);
  const kind = detectFileKind(path, bytes);
  base.kind = kind;
  const url = `file:${basename(path)}`;
  let result: IngressResult;
  let visible: string | undefined;
  let complete = true;
  const notes: string[] = [];
  try {
    if (kind === "pdf" || kind === "docx" || kind === "xlsx" || kind === "pptx") {
      const doc = kind === "pdf" ? extractPdf(bytes) : extractOffice(bytes);
      if (!doc) return { ...base, status: "skipped", notes: ["a ZIP archive that is not a Word, Excel or PowerPoint file: archives are not opened"] };
      notes.push(...doc.notes); complete = doc.complete;
      const report = JSON.stringify({ sha256: base.sha256, format: doc.format, pages: doc.pages, segments: doc.segments.map((s) => ({ path: s.path, visibility: s.visibility, text: s.text })) });
      result = await engine.scanDocument({ segments: doc.segments, findings: doc.findings, report }, { url });
      visible = doc.segments.filter((s) => s.visibility === "visible").map((s) => s.text).join("\n\n");
      base.hidden = doc.segments.filter((s) => s.visibility !== "visible").map((s) => ({ where: s.path, visibility: s.visibility, words: words(s.text), excerpt: excerpt(s.text) }));
    } else if (kind === "image") {
      result = await engine.scanImage(bytes, { url, caption: basename(path), vision: opts.vision });
      if (result.coverage?.image && !result.coverage.image.pixels) { complete = false; notes.push(`pixels not read (no OCR): ${result.coverage.image.pixelsReason ?? "no vision helper"}`); }
    } else if (kind === "audio") {
      result = await engine.scanAudio(bytes, { url, transcriber: opts.transcriber });
      if (result.coverage?.audio && !result.coverage.audio.transcribed) { complete = false; notes.push(`not transcribed: ${result.coverage.audio.reason ?? "no transcriber configured (INGRESS_AUDIO_TRANSCRIBER)"}`); }
    } else if (kind === "video") {
      result = await engine.scanVideo(bytes, { url, transcriber: opts.transcriber });
      complete = false; notes.push("video: frames are read only with the vision helper; see coverage in --json");
    } else if (kind === "unsupported") {
      return { ...base, status: "skipped", notes: ["not a format filescan reads (binary, legacy Office, or an archive)"] };
    } else {
      const raw = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
      result = await engine.scan(raw, { url, kind: KIND_OF[kind] });
      visible = visibleTextOf(kind, raw);
    }
  } catch (e) {
    return { ...base, status: "error", notes: [`could not be scanned: ${(e as Error).message.slice(0, 200)}`] };
  }
  // hidden segments the engine read for kinds whose reader lives inside it (images, audio, video, HTML)
  if (!base.hidden.length && (kind === "html" || kind === "markdown")) {
    const segs = kind === "html" ? analyzeHtml(new TextDecoder().decode(bytes)).segments : adaptMarkdown(new TextDecoder().decode(bytes)).segments;
    base.hidden = segs.filter((s) => s.visibility !== "visible" && words(s.text) >= 1).slice(0, 200).map((s) => ({ where: s.path, visibility: s.visibility, words: words(s.text), excerpt: excerpt(s.text) }));
  }
  const reasons = result.findings
    .map((f) => ({ kind: f.kind, weight: +(f.confidence * f.severity).toFixed(3), message: f.message }))
    .filter((f) => f.weight > 0)
    .sort((a, b) => b.weight - a.weight)
    .slice(0, 8);
  const out: FileScanResult = { ...base, status: "scanned", tier: result.tier, score: result.score, reasons, notes, complete, rawDigest: result.receipt.rawDigest, engineVersion: result.receipt.engineVersion, ...(opts.keepResult ? { result } : {}) };

  if (opts.cleanOutDir) {
    // what a person sees, gated again on its own: written only when that text is clean by itself
    if (visible === undefined) visible = result.tier === "clean" ? result.delivered : undefined;
    if (visible === undefined) out.cleanOutSkipped = `the ${kind}'s visible text is delivered only when the whole file is clean, and this one is ${result.tier}`;
    else if (!visible.trim()) out.cleanOutSkipped = "no visible text";
    else {
      const again = await engine.scan(visible, { url: `${url}#visible`, isHtml: false });
      if (again.tier !== "clean") out.cleanOutSkipped = `the visible text is ${again.tier} on its own`;
      else {
        const target = join(opts.cleanOutDir, `${opts.cleanOutName ?? basename(path)}.clean.txt`);
        mkdirSync(dirname(target), { recursive: true });
        writeFileSync(target, again.delivered + "\n", { mode: 0o644 });
        out.cleanOut = target;
      }
    }
  }
  return out;
}

// ---------- corpus ----------

export interface CorpusScanOptions extends Omit<FileScanOptions, "cleanOutName"> {
  /** move (or copy) hostile files here, with a manifest */
  quarantineDir?: string;
  /** copy instead of move */
  copy?: boolean;
  /** quarantine suspect files too, not only hostile ones */
  includeSuspect?: boolean;
  /** files scanned at once; default 4 */
  concurrency?: number;
  /** stop after this many files; default 100,000 */
  maxFiles?: number;
  /** called after each file */
  onProgress?: (done: number, total: number, r: FileScanResult) => void;
  /** the clock, for the manifest name; tests pass their own */
  now?: () => Date;
}

export interface QuarantineEntry { file: string; from: string; to: string; mode: "moved" | "copied"; sha256: string; bytes: number; tier: Tier; score: number; kind: FileKind; reasons: string[]; note?: string }

export interface CorpusScanReport {
  dir: string;
  startedAt: string;
  files: FileScanResult[];
  summary: { files: number; clean: number; suspect: number; hostile: number; skipped: number; errors: number; incomplete: number; hiddenWords: number };
  quarantine?: { dir: string; manifest: string; entries: QuarantineEntry[] };
  /** files and folders not walked, and why */
  notes: string[];
}

const SKIP_DIRS = new Set([".git", ".hg", ".svn", "node_modules"]);

function walk(root: string, exclude: string[], max: number, notes: string[]): string[] {
  const out: string[] = [];
  const stack = [root];
  while (stack.length) {
    const d = stack.pop()!;
    let names: string[];
    try { names = readdirSync(d).sort(); } catch (e) { notes.push(`${relative(root, d) || "."}: could not be listed (${(e as Error).message})`); continue; }
    for (const n of names) {
      const p = join(d, n);
      if (exclude.some((x) => p === x || p.startsWith(x + sep))) continue;
      let st;
      try { st = lstatSync(p); } catch { continue; }
      if (st.isSymbolicLink()) { notes.push(`${relative(root, p)}: a symbolic link, not followed`); continue; }
      if (st.isDirectory()) { if (SKIP_DIRS.has(n)) notes.push(`${relative(root, p)}: skipped (${n})`); else stack.push(p); continue; }
      if (st.isFile()) { if (out.length >= max) { notes.push(`stopped at ${max} files (--max-files)`); return out; } out.push(p); }
    }
  }
  return out.sort();
}

/** a path under `dir` that does not exist yet: name, name.1, name.2 ... */
function freePath(p: string): string {
  if (!existsSync(p)) return p;
  for (let i = 1; i < 10_000; i++) { const q = `${p}.${i}`; if (!existsSync(q)) return q; }
  throw new Error(`no free name for ${p}`);
}

/** Gate every file in a folder; optionally set hostile ones aside. Never deletes anything. */
export async function corpusscan(dir: string, opts: CorpusScanOptions = {}): Promise<CorpusScanReport> {
  const root = resolve(dir);
  if (!statSync(root).isDirectory()) throw new Error(`${dir} is not a folder`);
  const now = opts.now ?? (() => new Date());
  const startedAt = now().toISOString();
  const notes: string[] = [];
  const qdir = opts.quarantineDir ? resolve(opts.quarantineDir) : undefined;
  const cdir = opts.cleanOutDir ? resolve(opts.cleanOutDir) : undefined;
  const files = walk(root, [qdir, cdir].filter((x): x is string => !!x), opts.maxFiles ?? 100_000, notes);
  const engine = opts.engine ?? new IngressEngine({ sandbox: "off", cloakingCheck: false }, { log: () => {} });
  const results: FileScanResult[] = new Array(files.length);
  let next = 0, done = 0;
  const conc = Math.max(1, Math.min(32, opts.concurrency ?? 4));
  const worker = async () => {
    for (;;) {
      const i = next++;
      if (i >= files.length) return;
      const rel = relative(root, files[i]);
      const r = await filescan(files[i], { ...opts, engine, cleanOutDir: cdir, cleanOutName: rel });
      r.file = rel;
      results[i] = r;
      done++;
      opts.onProgress?.(done, files.length, r);
    }
  };
  await Promise.all(Array.from({ length: Math.min(conc, files.length || 1) }, worker));

  const summary = { files: results.length, clean: 0, suspect: 0, hostile: 0, skipped: 0, errors: 0, incomplete: 0, hiddenWords: 0 };
  for (const r of results) {
    if (r.status === "skipped") summary.skipped++;
    else if (r.status === "error") summary.errors++;
    else if (r.tier === "clean" || r.tier === "suspect" || r.tier === "hostile") summary[r.tier]++;
    if (r.status === "scanned" && !r.complete) summary.incomplete++;
    summary.hiddenWords += r.hidden.reduce((n, h) => n + h.words, 0);
  }
  const report: CorpusScanReport = { dir: root, startedAt, files: results, summary, notes };

  if (qdir) {
    const pick = results.filter((r) => r.status === "scanned" && (r.tier === "hostile" || (opts.includeSuspect && r.tier === "suspect")));
    const entries: QuarantineEntry[] = [];
    mkdirSync(qdir, { recursive: true });
    for (const r of pick) {
      const from = join(root, r.file);
      const to = freePath(join(qdir, r.file));
      mkdirSync(dirname(to), { recursive: true });
      let mode: QuarantineEntry["mode"] = opts.copy ? "copied" : "moved";
      let note: string | undefined;
      // the file must be the one that was scanned: if it changed since, it is left where it is
      const now2 = readFileSync(from);
      if (sha256(now2) !== r.sha256) { notes.push(`${r.file}: changed after it was scanned; not quarantined`); continue; }
      if (opts.copy) copyFileSync(from, to);
      else {
        try { renameSync(from, to); }
        catch (e) {
          // another disk: copy, and leave the original in place rather than delete it
          if ((e as NodeJS.ErrnoException).code !== "EXDEV") throw e;
          copyFileSync(from, to); mode = "copied"; note = "the quarantine folder is on another disk: copied, original left in place";
        }
      }
      const check = sha256(readFileSync(to));
      if (check !== r.sha256) note = `${note ? note + "; " : ""}the quarantined copy's hash does not match`;
      entries.push({ file: r.file, from, to, mode, sha256: r.sha256, bytes: r.bytes, tier: r.tier, score: r.score, kind: r.kind, reasons: r.reasons.slice(0, 4).map((x) => `${x.kind}: ${x.message}`), ...(note ? { note } : {}) });
    }
    const manifest = freePath(join(qdir, `ingress-quarantine-${startedAt.replace(/[:.]/g, "-")}.json`));
    writeFileSync(manifest, JSON.stringify({ tool: "ingress corpusscan", engineVersion: results.find((r) => r.engineVersion)?.engineVersion, createdAt: startedAt, source: root, mode: opts.copy ? "copy" : "move", quarantined: opts.includeSuspect ? "hostile and suspect" : "hostile", entries }, null, 2) + "\n");
    report.quarantine = { dir: qdir, manifest, entries };
  }
  return report;
}

// ---------- the command line ----------

export interface FileScanArgs { files: string[]; json: boolean; cleanOut?: string; maxBytes?: number; noVision: boolean; quarantine?: string; copy: boolean; includeSuspect: boolean; concurrency?: number; maxFiles?: number; quiet: boolean; error?: string }

/** parse the arguments of `ingress filescan` and `ingress corpusscan` (both take `--name value` and `--name=value`) */
export function parseFileScanArgs(a: string[]): FileScanArgs {
  const out: FileScanArgs = { files: [], json: false, noVision: false, copy: false, includeSuspect: false, quiet: false };
  const VALUED = new Set(["clean-out", "max-bytes", "quarantine", "concurrency", "max-files"]);
  for (let i = 0; i < a.length; i++) {
    const t = a[i];
    if (!t.startsWith("--")) { out.files.push(t); continue; }
    const eq = t.indexOf("=");
    const name = t.slice(2, eq < 0 ? undefined : eq);
    let value: string | undefined = eq < 0 ? undefined : t.slice(eq + 1);
    if (VALUED.has(name) && value === undefined) { value = a[++i]; if (value === undefined) { out.error = `--${name} needs a value`; return out; } }
    switch (name) {
      case "json": out.json = true; break;
      case "copy": out.copy = true; break;
      case "suspect": out.includeSuspect = true; break;
      case "no-vision": out.noVision = true; break;
      case "quiet": out.quiet = true; break;
      case "clean-out": out.cleanOut = value; break;
      case "quarantine": out.quarantine = value; break;
      case "max-bytes": case "concurrency": case "max-files": {
        const n = Number(value);
        if (!Number.isInteger(n) || n < 1) { out.error = `--${name} must be a positive whole number`; return out; }
        if (name === "max-bytes") out.maxBytes = n; else if (name === "concurrency") out.concurrency = n; else out.maxFiles = n;
        break;
      }
      default: out.error = `unknown option --${name}`; return out;
    }
  }
  return out;
}

export const FILESCAN_USAGE = `usage: ingress filescan <file...> [--clean-out <dir>] [--json] [--max-bytes N] [--no-vision]
  Gate files before an agent reads them: PDF, Word, Excel, PowerPoint, images, audio, video, HTML, Markdown,
  text, CSV and JSON. Finds text a person does not see (white or tiny text, hidden runs, hidden sheets and rows,
  text off the page, notes, comments, alt text, metadata, scripts) and runs everything through the gate.
  --clean-out <dir>  write <name>.clean.txt: only what a person sees, re-checked on its own, for the agent to read
  Exit code 1 when any file is suspect or hostile.`;
export const CORPUSSCAN_USAGE = `usage: ingress corpusscan <dir> [--quarantine <dir> [--copy] [--suspect]] [--clean-out <dir>] [--concurrency N] [--max-bytes N] [--max-files N] [--json] [--quiet]
  Gate every file in a folder (a RAG knowledge base before indexing), a few at a time, with a summary by file.
  --quarantine <dir>  move hostile files there (--copy: copy them; --suspect: suspect files too) and write a
                      manifest with their hashes and verdicts. Nothing is ever deleted.
  Exit code 1 when any file is suspect or hostile.`;

const MARK: Record<string, string> = { clean: "clean  ", suspect: "SUSPECT", hostile: "HOSTILE", unreachable: "skipped" };

/** a short human report for one file */
export function formatFileScan(r: FileScanResult): string {
  const lines: string[] = [];
  const label = r.status === "scanned" ? MARK[r.tier] : r.status === "error" ? "error  " : "skipped";
  lines.push(`${label}  ${r.file}  (${r.kind}, ${r.bytes} bytes${r.status === "scanned" ? `, score ${r.score}` : ""}${r.status === "scanned" && !r.complete ? ", partly read" : ""})`);
  // link targets are listed in --json; they are addresses, not hidden prose
  const hidden = r.hidden.filter((h) => h.words > 0 && !/\/link$/.test(h.where));
  if (hidden.length) {
    lines.push(`  hidden from a person: ${hidden.reduce((n, h) => n + h.words, 0)} words in ${hidden.length} place(s)`);
    for (const h of hidden.slice(0, 5)) lines.push(`    ${h.where}: "${h.excerpt}"`);
    if (hidden.length > 5) lines.push(`    ... ${hidden.length - 5} more (--json for all)`);
  }
  if (r.tier !== "clean") for (const f of r.reasons.slice(0, 4)) lines.push(`  [${f.kind}] ${f.message}`);
  for (const n of r.notes.slice(0, 4)) lines.push(`  note: ${n}`);
  if (r.cleanOut) lines.push(`  safe text: ${r.cleanOut}`);
  else if (r.cleanOutSkipped) lines.push(`  safe text not written: ${r.cleanOutSkipped}`);
  return lines.join("\n");
}

/** a short human report for a folder */
export function formatCorpusScan(r: CorpusScanReport): string {
  const s = r.summary;
  const lines = [`corpusscan ${r.dir}`, `${s.files} files: ${s.clean} clean, ${s.suspect} suspect, ${s.hostile} hostile, ${s.skipped} skipped, ${s.errors} errors${s.incomplete ? `; ${s.incomplete} only partly read` : ""}; ${s.hiddenWords} words hidden from a person`];
  const flagged = r.files.filter((f) => f.status === "scanned" && f.tier !== "clean");
  if (flagged.length) { lines.push("", "Not clean:"); for (const f of flagged) lines.push(formatFileScan(f)); }
  const skipped = r.files.filter((f) => f.status !== "scanned");
  if (skipped.length) { lines.push("", "Not scanned:"); for (const f of skipped.slice(0, 20)) lines.push(`  ${f.file}: ${f.notes[0] ?? f.status}`); if (skipped.length > 20) lines.push(`  ... ${skipped.length - 20} more`); }
  if (r.quarantine) lines.push("", `Quarantine: ${r.quarantine.entries.length} file(s) ${r.quarantine.entries.some((e) => e.mode === "moved") ? "moved" : "copied"} to ${r.quarantine.dir}`, `  manifest: ${r.quarantine.manifest}`);
  for (const n of r.notes.slice(0, 10)) lines.push(`note: ${n}`);
  return lines.join("\n");
}
