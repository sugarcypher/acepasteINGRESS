/**
 * Images: what a picture says to a person, and what it says only to a machine.
 *
 * An image reaches a model after a pipeline has handled it: resized, flattened, one frame picked, its
 * metadata sometimes passed along as text. Each of those steps is a place to put words a person looking at
 * the picture never sees. This module turns an image into text segments the engine's ordinary passes read:
 *
 *   visible     text recognised in the picture as shown, at full size
 *   concealed   text that exists only after resizing without smoothing (an image-scaling attack), only
 *               after the contrast is raised, only on another background or under transparent pixels, only
 *               in a later frame; text in the file's metadata; the payload of a QR code
 *
 * Reading pixels needs the vision helper (native/ingress-vision.swift, macOS). Without it the container is
 * still read (metadata, appended data, frames), and the result says the pixels were not inspected.
 *
 * Limits, stated plainly: the resizing check tries the common target sizes and three kernels, not every
 * pipeline; noise crafted against one model (adversarial perturbation) is not text and is not detected;
 * steganography that needs a decoder is not detected.
 */

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { stateDir } from "./changes.js";
import { readImageMeta, type ImageMeta } from "./image-meta.js";
import { judgeQrPayload, type QrVerdict } from "./qr.js";
import { hostsMentioned } from "./egress.js";
import type { Finding, TextSegment } from "./types.js";

export interface VisionLine { text: string; conf: number; x: number; y: number; w: number; h: number }
export interface VisionReport {
  version?: number;
  /** false when the picture could not be opened or drawn */
  decoded?: boolean;
  width: number; height: number; frames: number; hasAlpha: boolean;
  full: VisionLine[];
  variants: Array<{ name: string; kind: "scale" | "smooth" | "contrast" | "alpha" | "frame"; lines: VisionLine[] }>;
  barcodes: Array<{ symbology: string; payload: string; variant: string }>;
  notes: string[];
  ms?: number;
}

/** Reads an image's pixels. The default runs the vision helper; tests and other platforms supply their own. */
export type VisionRunner = (path: string) => Promise<VisionReport>;

export interface ImageCoverage {
  format: string;
  /** were the pixels read (text recognition, codes, the resizing, contrast and transparency checks)? */
  pixels: boolean;
  /** why not, when they were not */
  pixelsReason?: string;
  metadata: boolean;
  notes: string[];
}

export interface ImageInspection {
  meta: ImageMeta;
  vision?: VisionReport;
  codes: Array<{ symbology: string; payload: string; verdict: QrVerdict }>;
  segments: TextSegment[];
  findings: Finding[];
  coverage: ImageCoverage;
  /** a stable description of what was found, hashed into the receipt */
  report: string;
}

// ---------- comparing readings ----------

const norm = (s: string) => s.toLowerCase().normalize("NFKD").replace(/[^\p{L}\p{N}]+/gu, " ").trim();
function trigrams(s: string): Set<string> {
  const t = ` ${norm(s)} `, out = new Set<string>();
  for (let i = 0; i + 3 <= t.length; i++) out.add(t.slice(i, i + 3));
  return out;
}
/** share of a line's character trigrams that occur in a reference text: 1 means the reference contains the line */
function containment(line: string, ref: Set<string>): number {
  const g = trigrams(line);
  if (!g.size) return 1;
  let hit = 0;
  for (const x of g) if (ref.has(x)) hit++;
  return hit / g.size;
}
const similar = (a: string, b: string) => { const ga = trigrams(a), gb = trigrams(b); return Math.min(containment(a, gb), containment(b, ga)); };
const wordy = (s: string) => (norm(s).match(/\p{L}{2,}/gu) ?? []).length;
const letters = (s: string) => (s.match(/\p{L}/gu) ?? []).length;
const textOf = (lines: readonly VisionLine[]) => lines.map((l) => l.text).join("\n");
const enough = (lines: readonly string[]) => { const t = lines.join(" "); return wordy(t) >= 3 && letters(t) >= 12; };
/**
 * Does a token look like a word someone wrote? Letters only, in one casing (lower, UPPER or Capitalised), and for
 * Latin letters at least four of them with a vowel. Scripts without case or spaces count from two characters.
 */
function wordlike(tok: string): boolean {
  const t = tok.replace(/^[\p{P}\p{S}]+|[\p{P}\p{S}]+$/gu, "");
  if (!/^\p{L}+$/u.test(t)) return false;
  if (/^[\p{Script=Latin}]+$/u.test(t)) return t.length >= 4 && /[aeiouyáéíóúäëïöüàèìòùâêîôûåæøœ]/i.test(t) && (t === t.toLowerCase() || t === t.toUpperCase() || t === t[0].toUpperCase() + t.slice(1).toLowerCase());
  return t.length >= 2;
}
/**
 * A message, not scraps: at least four word-like tokens, making up most of what was read. Measured on ordinary
 * images: a dense screenshot resized without smoothing is read as "ICD 1CU QuE Fin war: 4' 1CBOWD TOU IC0", with
 * full confidence, by every kernel. Those are scraps of digits. Words built to be read come out as words.
 */
function sentence(lines: readonly string[]): boolean {
  const toks = lines.join(" ").split(/\s+/).map((t) => t.replace(/^[\p{P}\p{S}]+|[\p{P}\p{S}]+$/gu, "")).filter((t) => /[\p{L}\p{N}]/u.test(t));
  const words = toks.filter(wordlike).length;
  // a scrap: letters and digits run together, or casing no writer uses (QuE). Short words (all, the, and) are neither.
  const scraps = toks.filter((t) => (/\p{L}/u.test(t) && /\p{N}/u.test(t)) || (/^[\p{Script=Latin}]+$/u.test(t) && t !== t.toLowerCase() && t !== t.toUpperCase() && t !== t[0].toUpperCase() + t.slice(1).toLowerCase())).length;
  return words >= 4 && scraps <= toks.length * 0.2;
}

/**
 * Text that an unsmoothed resize produces and a smoothed resize to the same size does not.
 * Ordinary text survives both (smoothing reads better, if anything). Text built for the resizer exists only
 * in the unsmoothed one. Two kernels must agree, and the text must not already be plain at full size.
 */
/**
 * Everything an honest look at the picture reads: at full size, and resized with smoothing to each size.
 * (On a page of small print, text recognition reads different fragments at every size; a line that any of
 * these views contains was there for a person to see.)
 */
function honestTrigrams(v: VisionReport, also: string[] = []): Set<string> {
  const kinds = new Set(["smooth", ...also]);
  return trigrams([textOf(v.full), ...v.variants.filter((x) => kinds.has(x.kind)).map((x) => textOf(x.lines))].join("\n"));
}

/**
 * Text that an unsmoothed resize produces and no honest look at the picture does.
 * Ordinary text survives smoothing (it reads better, if anything) and is there at full size. Text built for
 * the resizer exists only after the unsmoothed resize to the size it was built for. Two kernels must read
 * the same words at that size.
 */
function resizedOnly(v: VisionReport): { lines: string[]; at: string[] } {
  // a contrast-raised view counts as honest here: text it shows is faint, not built for a resizer
  const seen = honestTrigrams(v, ["contrast"]);
  const bySize = new Map<string, Array<{ name: string; lines: string[] }>>();
  for (const x of v.variants) {
    if (x.kind !== "scale") continue;
    const size = x.name.match(/to (\d+) px$/)?.[1] ?? "?";
    // Only lines read with full confidence count. On real posters and charts, small print misread the same way
    // by two kernels ("TALK OF THE TOWN" as "ELSIL JC AIX N: THE TOM") is read at half confidence; words built
    // to be read after resizing come out clean. (Measured on 95 ordinary images: 2 false alarms without this.)
    bySize.set(size, [...(bySize.get(size) ?? []), { name: x.name, lines: x.lines.filter((l) => l.conf >= 0.9 && wordy(l.text) >= 1 && containment(l.text, seen) < 0.4).map((l) => l.text) }]);
  }
  let best: { lines: string[]; at: string[] } = { lines: [], at: [] };
  for (const [, kernels] of bySize) {
    const agreed: string[] = [], at = new Set<string>();
    kernels.forEach((k, i) => {
      for (const l of k.lines) {
        const other = kernels.find((o, j) => j !== i && o.lines.some((m) => similar(l, m) >= 0.8));
        if (!other) continue;
        at.add(k.name); at.add(other.name);
        if (!agreed.some((a) => similar(a, l) >= 0.8)) agreed.push(l);
      }
    });
    if (sentence(agreed) && agreed.join(" ").length > best.lines.join(" ").length) best = { lines: agreed, at: [...at] };
  }
  return best;
}

/** Lines some other view of the picture reads and no honest look at it does. */
function onlyIn(v: VisionReport, kind: string, name?: RegExp): { lines: string[]; at: string[] } {
  const seen = honestTrigrams(v);
  let best: { lines: string[]; at: string[] } = { lines: [], at: [] };
  for (const x of v.variants) {
    if (x.kind !== kind || (name && !name.test(x.name))) continue;
    const lines = x.lines.filter((l) => l.conf >= 0.5 && containment(l.text, seen) < 0.4).map((l) => l.text);
    if (enough(lines) && lines.join(" ").length > best.lines.join(" ").length) best = { lines, at: [x.name] };
  }
  return best;
}

// ---------- the helper ----------

/** Where the built helper is expected: INGRESS_VISION_HELPER, or <state>/bin/ingress-vision. */
export function visionHelperPath(): string { return process.env.INGRESS_VISION_HELPER || join(stateDir(), "bin", "ingress-vision"); }

/** Why the helper cannot be used, or undefined when it can. A helper in the state folder must match the hash recorded when it was built. */
export function visionHelperProblem(path: string = visionHelperPath()): string | undefined {
  if (process.platform !== "darwin") return "reading pixels needs the macOS vision helper";
  if (!existsSync(path)) return "the vision helper is not built (run: ingress vision build)";
  if (!process.env.INGRESS_VISION_HELPER) {
    try {
      const want = readFileSync(`${path}.sha256`, "utf8").trim();
      const got = createHash("sha256").update(readFileSync(path)).digest("hex");
      if (want !== got) return "the vision helper does not match the hash recorded when it was built (run: ingress vision build)";
    } catch { return "the vision helper has no recorded hash (run: ingress vision build)"; }
  }
  return undefined;
}

/** The helper's source, shipped with the package. */
export function visionHelperSource(): string { return fileURLToPath(new URL("../../native/ingress-vision.swift", import.meta.url)); }

/**
 * Compile the helper on this machine (macOS with the Swift compiler: Xcode or its command line tools) and
 * record its hash. Built here rather than shipped as a binary, so what runs is what the source says.
 */
export function buildVisionHelper(out: string = join(stateDir(), "bin", "ingress-vision")): Promise<{ path: string; sha256: string }> {
  return new Promise((resolve, reject) => {
    if (process.platform !== "darwin") return reject(new Error("the vision helper is built on macOS only"));
    const src = visionHelperSource();
    if (!existsSync(src)) return reject(new Error(`the helper's source is missing (${src})`));
    mkdirSync(dirname(out), { recursive: true, mode: 0o700 });
    execFile("swiftc", ["-O", "-swift-version", "5", src, "-o", out], { timeout: 300_000, encoding: "utf8" }, (err, _stdout, stderr) => {
      if (err) return reject(new Error(`swiftc failed: ${String(stderr || err.message).split("\n").filter((l) => /error/.test(l))[0]?.slice(0, 200) ?? String(err.message).slice(0, 200)}`));
      const sha256 = createHash("sha256").update(readFileSync(out)).digest("hex");
      writeFileSync(`${out}.sha256`, sha256 + "\n", { mode: 0o600 });
      resolve({ path: out, sha256 });
    });
  });
}

export function helperRunner(path: string = visionHelperPath(), timeoutMs = 60_000): VisionRunner {
  return (image) => new Promise((resolve, reject) => {
    execFile(path, [image], { timeout: timeoutMs, maxBuffer: 64 * 1024 * 1024, encoding: "utf8" }, (err, stdout) => {
      if (err) return reject(new Error(`the vision helper failed (${String(err.message).slice(0, 120)})`));
      try {
        const r = JSON.parse(stdout) as VisionReport;
        if (!Array.isArray(r.full) || !Array.isArray(r.variants) || !Array.isArray(r.barcodes)) throw new Error("unexpected report");
        resolve(r);
      } catch (e) { reject(new Error(`the vision helper's report could not be read (${(e as Error).message})`)); }
    });
  });
}

// ---------- inspection ----------

const EXT: Record<string, string> = { png: "png", jpeg: "jpg", gif: "gif", webp: "webp", bmp: "bmp", tiff: "tiff", heic: "heic", avif: "avif", ico: "ico" };
/** metadata fields that are routinely filled in by cameras and editors and say nothing */
const ROUTINE_FIELD = /^(?:exif:(?:Make|Model|Software|ImageUniqueID|PrintIM)|png:(?:Software|Creation Time|date:\w+|icc:\w+|Raw profile type \w+)|xmp:(?:xmp:CreatorTool|xmpMM:\w+|photoshop:(?:ICCProfile|ColorMode)|tiff:\w+|exif:\w+|stEvt:\w+|dc:format|pdf:Producer))$/i;

export interface InspectOptions {
  /** how to read the pixels; `false` skips them; default: the helper when it is built */
  vision?: VisionRunner | false;
  /** the words shown beside the image (a caption, alt text, a file name), for comparison with what it holds */
  caption?: string;
}

export async function inspectImage(bytes: Uint8Array, opts: InspectOptions = {}): Promise<ImageInspection> {
  const meta = readImageMeta(bytes);
  const segments: TextSegment[] = [];
  const findings: Finding[] = [];
  const coverage: ImageCoverage = { format: meta.format, pixels: false, metadata: !/not read/.test(meta.notes.join(" ")), notes: [...meta.notes] };
  const add = (f: Omit<Finding, "pass" | "action"> & { action?: Finding["action"] }) => findings.push({ pass: "channel", action: "none", ...f });

  // ----- the container -----
  for (const t of meta.texts) {
    if (ROUTINE_FIELD.test(t.field) && wordy(t.text) < 8) continue;
    segments.push({ text: t.text, visibility: "concealed", path: `image/metadata:${t.field}` });
  }
  const said = segments.filter((s) => wordy(s.text) >= 4);
  if (said.length) add({ kind: "image.metadata_text", confidence: 0.1, severity: 0.2, message: `the file's metadata holds text nobody looking at the picture sees (${said.slice(0, 4).map((s) => s.path.replace("image/metadata:", "")).join(", ")})`, inHidden: true });
  if (meta.trailingBytes >= 16) {
    const like = meta.trailingLooksLike;
    add({ kind: "image.trailing_data", confidence: like && like !== "text" ? 0.6 : 0.3, severity: like && like !== "text" ? 0.7 : 0.5, message: `${meta.trailingBytes} bytes follow the end of the image${like ? `; they look like ${like}` : ""}. A viewer ignores them; a program that reads the whole file does not`, inHidden: true });
    if (like === "text" || like === "a web page or script" || like === "a script") {
      const from = bytes.length - meta.trailingBytes;
      segments.push({ text: new TextDecoder("utf-8", { fatal: false }).decode(bytes.subarray(from, from + 20_000)), visibility: "concealed", path: "image/after-end" });
    }
  }
  if (meta.hasThumbnail) coverage.notes.push("an embedded preview picture is present and was not read");

  // ----- the pixels -----
  let vision: VisionReport | undefined;
  const codes: ImageInspection["codes"] = [];
  const format = meta.format;
  if (format === "unknown" || format === "pdf" || format === "svg") coverage.pixelsReason = format === "unknown" ? "not a recognised image format" : `${format.toUpperCase()} is not a pixel image`;
  else if (opts.vision === false) coverage.pixelsReason = "pixel inspection was turned off";
  else {
    const problem = opts.vision ? undefined : visionHelperProblem();
    if (problem) coverage.pixelsReason = problem;
    else {
      const dir = mkdtempSync(join(tmpdir(), "ingress-image-"));
      const file = join(dir, `image.${EXT[format] ?? "bin"}`);
      try {
        writeFileSync(file, bytes, { mode: 0o600 });
        const got = await (opts.vision || helperRunner())(file);
        coverage.notes.push(...got.notes);
        // a picture the system could not open was not read, whatever else the report says
        if (got.decoded === false) coverage.pixelsReason = got.notes[0] ?? "the image could not be decoded";
        else { vision = got; coverage.pixels = true; }
      } catch (e) {
        coverage.pixelsReason = (e as Error).message;
      } finally { try { rmSync(dir, { recursive: true, force: true }); } catch { /* temp folder */ } }
    }
  }

  if (vision) {
    const shown = textOf(vision.full).trim();
    if (shown) segments.unshift({ text: shown, visibility: "visible", path: "image/text" });

    const resized = resizedOnly(vision);
    if (resized.lines.length) {
      segments.push({ text: resized.lines.join("\n"), visibility: "concealed", path: "image/only-when-resized" });
      add({ kind: "image.text_only_when_resized", confidence: 0.7, severity: 0.85, message: `${wordy(resized.lines.join(" "))} words appear only after the image is resized without smoothing (${resized.at.slice(0, 3).join(", ")}): text built for a model's image pipeline, not for a person`, excerpt: resized.lines.join(" / ").slice(0, 160), inHidden: true, action: "quarantined" });
    }
    const faint = onlyIn(vision, "contrast");
    // text the resizing check already explained is not reported twice
    const faintNew = faint.lines.filter((l) => !resized.lines.some((r) => similar(l, r) >= 0.6));
    if (enough(faintNew)) {
      segments.push({ text: faintNew.join("\n"), visibility: "tiny_or_transparent", path: "image/low-contrast" });
      add({ kind: "image.low_contrast_text", confidence: 0.4, severity: 0.5, message: `${wordy(faintNew.join(" "))} words can be read only after the contrast is raised (${faint.at[0]}): too faint for a person, plain to a machine`, excerpt: faintNew.join(" / ").slice(0, 160), inHidden: true });
    }
    const under = onlyIn(vision, "alpha", /transparency dropped/);
    if (under.lines.length) {
      segments.push({ text: under.lines.join("\n"), visibility: "concealed", path: "image/under-transparency" });
      add({ kind: "image.transparency_text", confidence: 0.4, severity: 0.55, message: `${wordy(under.lines.join(" "))} words are drawn in the colours of fully transparent pixels: invisible in any viewer, present for a pipeline that drops transparency`, excerpt: under.lines.join(" / ").slice(0, 160), inHidden: true });
    }
    const dark = onlyIn(vision, "alpha", /black background/);
    const darkNew = dark.lines.filter((l) => !under.lines.some((r) => similar(l, r) >= 0.6));
    if (enough(darkNew)) {
      // light text on a transparent background is how logos for dark pages are made: recorded, and read as hidden text
      segments.push({ text: darkNew.join("\n"), visibility: "concealed", path: "image/on-dark-background" });
      add({ kind: "image.transparency_text", confidence: 0.15, severity: 0.4, message: `${wordy(darkNew.join(" "))} words show on a dark background and not on a light one`, excerpt: darkNew.join(" / ").slice(0, 160), inHidden: true });
    }
    const frames = vision.variants.filter((x) => x.kind === "frame").flatMap((x) => x.lines.filter((l) => l.conf >= 0.5 && containment(l.text, trigrams(shown)) < 0.5).map((l) => ({ frame: x.name, text: l.text })));
    const frameLines = frames.filter((f, i) => frames.findIndex((g) => similar(g.text, f.text) >= 0.8) === i);
    if (enough(frameLines.map((f) => f.text))) {
      segments.push({ text: frameLines.map((f) => f.text).join("\n"), visibility: "concealed", path: "image/later-frames" });
      add({ kind: "image.later_frame_text", confidence: 0.12, severity: 0.4, message: `${wordy(frameLines.map((f) => f.text).join(" "))} words appear only in later frames (${[...new Set(frameLines.map((f) => f.frame))].slice(0, 3).join(", ")}): a still view shows the first frame only`, inHidden: true });
    }

    // codes: the payload is for the machine
    for (const c of vision.barcodes.slice(0, 20)) {
      const verdict = judgeQrPayload(c.payload);
      codes.push({ symbology: c.symbology, payload: c.payload, verdict });
      const what = `${c.symbology} code ${verdict.summary}${verdict.notes.length ? ` (${verdict.notes.join("; ")})` : ""}`;
      if (verdict.action) add({ kind: "image.code_action", confidence: 0.3 + verdict.risk * 0.4, severity: 0.4 + verdict.risk * 0.4, message: `following this ${what}`, inHidden: true });
      else add({ kind: "image.code_payload", confidence: verdict.notes.length ? 0.25 + verdict.risk * 0.3 : 0.05, severity: verdict.notes.length ? 0.5 : 0.2, message: `this ${what}${verdict.url ? ". Open it only through the gate" : ""}`, inHidden: true });
      if (verdict.text) segments.push({ text: verdict.text, visibility: "concealed", path: `image/code:${verdict.kind}` });
      // the words beside a code say one thing; the code says another
      const named = hostsMentioned(`${opts.caption ?? ""} ${shown}`, 20);
      if (verdict.host && named.length && !named.some((n) => verdict.host === n || verdict.host!.endsWith(`.${n}`) || n.endsWith(`.${verdict.host}`))) {
        add({ kind: "image.caption_mismatch", confidence: 0.45, severity: 0.6, message: `the words beside the code name ${named[0]}, and the code goes to ${verdict.host}`, inHidden: true });
      }
    }
    // a line for the reader, so the delivered text says a code is there without carrying its payload as an instruction
    if (codes.length) segments.push({ text: codes.map((c) => `[${c.symbology} code: ${c.verdict.summary}]`).join("\n"), visibility: "visible", path: "image/codes" });
  } else {
    add({ kind: "image.pixels_not_inspected", confidence: 0.1, severity: 0.2, message: `the picture itself was not read: ${coverage.pixelsReason}. Text in it, codes, and the resizing, contrast and transparency checks were not run` });
    segments.push({ text: `[image, ${meta.format}${meta.width ? ` ${meta.width}x${meta.height}` : ""}: its pixels were not inspected (${coverage.pixelsReason})]`, visibility: "visible", path: "image/note" });
  }

  const report = JSON.stringify({
    sha256: createHash("sha256").update(bytes).digest("hex"), format: meta.format, width: vision?.width ?? meta.width, height: vision?.height ?? meta.height, frames: vision?.frames ?? meta.frames,
    pixels: coverage.pixels, segments: segments.map((s) => ({ path: s.path, visibility: s.visibility, text: s.text })), codes: codes.map((c) => ({ symbology: c.symbology, kind: c.verdict.kind, payload: c.payload })),
  });
  return { meta, vision, codes, segments, findings, coverage, report };
}
