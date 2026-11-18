/**
 * Audio: what a listener hears, and what is in the recording only for a machine.
 *
 * A person hears a recording once, through speakers, at the level it was mixed. A transcriber gets the
 * samples. So the recording is transcribed several ways and the transcripts are compared:
 *
 *   as heard             the recording as it is
 *   quiet parts raised   after strong level compression: speech mixed too low for a person to make out
 *                        (under music, under another voice) becomes plain to a transcriber
 *   re-encoded           limited to telephone bandwidth, squeezed through an 8-bit telephone codec, played
 *                        slightly faster. Speech survives all three; a listener would understand every one.
 *                        Audio crafted so that a transcriber hears words that are not there (an adversarial
 *                        example) is fragile, and what is "heard" changes
 *
 * Words found only after the quiet parts are raised are concealed text. A transcript that changes when the
 * audio is re-encoded is reported. The file's tags (title, comment, lyrics) are text nobody hears.
 *
 * Transcription is not built in. The engine calls a transcriber you choose, on this machine:
 * INGRESS_AUDIO_TRANSCRIBER is a command that takes a file path and prints the report as JSON
 * (tools/audio/transcribe.py is one, using an open Whisper model). Without it the tags are still read and the
 * result says the recording was not transcribed.
 *
 * Limits: a voice cannot be told from a clone of it. Nothing above the range of the file (ultrasound played
 * to a microphone) is in the file to find. And a voice is never an approval: what a recording says is content.
 */

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { passagesOnlyIn, servedWords } from "./served.js";
import type { Finding, TextSegment } from "./types.js";

export type AudioFormat = "wav" | "mp3" | "m4a" | "flac" | "ogg" | "aiff" | "unknown";
export interface AudioReport {
  /** seconds */
  duration: number;
  /** false when the recording could not be decoded */
  decoded?: boolean;
  variants: Array<{ name: string; kind: "heard" | "quiet" | "reencoded"; text: string }>;
  notes?: string[];
}
export type AudioRunner = (path: string) => Promise<AudioReport>;
export interface AudioCoverage { format: string; transcribed: boolean; reason?: string; seconds?: number; notes: string[] }
export interface AudioInspection { format: AudioFormat; texts: Array<{ field: string; text: string }>; report: string; transcript?: AudioReport; segments: TextSegment[]; findings: Finding[]; coverage: AudioCoverage }

const ascii = (b: Uint8Array, from: number, to: number) => { let s = ""; for (let i = from; i < to && i < b.length; i++) s += String.fromCharCode(b[i]); return s; };

export function detectAudioFormat(b: Uint8Array): AudioFormat {
  if (ascii(b, 0, 4) === "RIFF" && ascii(b, 8, 12) === "WAVE") return "wav";
  if (ascii(b, 0, 3) === "ID3" || (b.length > 2 && b[0] === 0xff && (b[1] & 0xe0) === 0xe0)) return "mp3";
  if (ascii(b, 4, 8) === "ftyp" && /M4A|M4B|mp4|isom|qt  /.test(ascii(b, 8, 12))) return "m4a";
  if (ascii(b, 0, 4) === "fLaC") return "flac";
  if (ascii(b, 0, 4) === "OggS") return "ogg";
  if (ascii(b, 0, 4) === "FORM" && /AIF[FC]/.test(ascii(b, 8, 12))) return "aiff";
  return "unknown";
}

const TEXT_FRAMES: Record<string, string> = { TIT1: "grouping", TIT2: "title", TIT3: "subtitle", TALB: "album", TPE1: "artist", COMM: "comment", USLT: "lyrics", TXXX: "custom", TCOM: "composer", TENC: "encoded-by", TCOP: "copyright", WXXX: "link" };

/** Text in a recording's tags: ID3v2 frames (MP3, AIFF, WAV), RIFF INFO chunks, Vorbis comments (FLAC, Ogg). */
export function readAudioTags(b: Uint8Array): Array<{ field: string; text: string }> {
  const out: Array<{ field: string; text: string }> = [];
  const push = (field: string, text: string) => { const t = text.replace(/\0+/g, " ").replace(/[\x01-\x08\x0b\x0c\x0e-\x1f]/g, " ").trim().slice(0, 20_000); if (t.length >= 3) out.push({ field, text: t }); };
  const decode = (enc: number, bytes: Uint8Array) => new TextDecoder(enc === 1 ? "utf-16" : enc === 2 ? "utf-16be" : enc === 3 ? "utf-8" : "latin1", { fatal: false }).decode(bytes);
  const id3 = (at: number) => {
    if (ascii(b, at, at + 3) !== "ID3" || at + 10 > b.length) return;
    const major = b[at + 3];
    const size = ((b[at + 6] & 0x7f) << 21) | ((b[at + 7] & 0x7f) << 14) | ((b[at + 8] & 0x7f) << 7) | (b[at + 9] & 0x7f);
    let o = at + 10;
    const end = Math.min(b.length, at + 10 + size);
    let guard = 0;
    while (o + 10 <= end && guard++ < 2000) {
      const id = ascii(b, o, o + 4);
      if (!/^[A-Z0-9]{4}$/.test(id)) break;
      const raw = [b[o + 4], b[o + 5], b[o + 6], b[o + 7]];
      const len = major >= 4 ? ((raw[0] & 0x7f) << 21) | ((raw[1] & 0x7f) << 14) | ((raw[2] & 0x7f) << 7) | (raw[3] & 0x7f) : ((raw[0] << 24) | (raw[1] << 16) | (raw[2] << 8) | raw[3]) >>> 0;
      const data = b.subarray(o + 10, Math.min(end, o + 10 + len));
      const name = TEXT_FRAMES[id];
      if (name && data.length > 1) {
        // COMM and USLT: encoding, 3-letter language, a short description, then the text
        const body = id === "COMM" || id === "USLT" ? data.subarray(4) : data.subarray(1);
        push(`id3:${name}`, decode(data[0], body));
      }
      if (len <= 0) break;
      o += 10 + len;
    }
  };
  id3(0);
  const fmt = detectAudioFormat(b);
  if (fmt === "wav" || fmt === "aiff") {
    const le = fmt === "wav";
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    let o = 12, guard = 0;
    while (o + 8 <= b.length && guard++ < 10_000) {
      const id = ascii(b, o, o + 4), len = dv.getUint32(o + 4, le);
      if (id === "LIST" && ascii(b, o + 8, o + 12) === "INFO") {
        let p = o + 12;
        while (p + 8 <= Math.min(b.length, o + 8 + len)) { const k = ascii(b, p, p + 4), n = dv.getUint32(p + 4, true); push(`info:${k}`, new TextDecoder("utf-8", { fatal: false }).decode(b.subarray(p + 8, Math.min(b.length, p + 8 + n)))); p += 8 + n + (n & 1); }
      } else if (id === "id3 " || id === "ID3 ") id3(o + 8);
      else if (["NAME", "AUTH", "ANNO", "(c) "].includes(id)) push(`aiff:${id.trim()}`, new TextDecoder("latin1").decode(b.subarray(o + 8, Math.min(b.length, o + 8 + len))));
      o += 8 + len + (len & 1);
    }
  }
  if (fmt === "flac" || fmt === "ogg") {
    // Vorbis comments are "KEY=value" strings preceded by a 4-byte length; find them by the vendor block's marker
    const text = new TextDecoder("utf-8", { fatal: false }).decode(b.subarray(0, Math.min(b.length, 1_000_000)));
    for (const m of text.matchAll(/\b(TITLE|DESCRIPTION|COMMENT|LYRICS|ARTIST|ALBUM|UNSYNCEDLYRICS)=([^\0\x01-\x08]{3,4000})/gi)) push(`vorbis:${m[1].toLowerCase()}`, m[2].replace(/[\x0e-\x1f][\s\S]*$/, ""));
  }
  const seen = new Set<string>();
  return out.filter((t) => !seen.has(t.text) && seen.add(t.text)).slice(0, 60);
}

/** The transcriber named by INGRESS_AUDIO_TRANSCRIBER: a command line; the file path is added as its last argument. */
export function commandRunner(command: string = process.env.INGRESS_AUDIO_TRANSCRIBER ?? "", timeoutMs = 600_000): AudioRunner | undefined {
  const parts = command.match(/"[^"]*"|'[^']*'|\S+/g)?.map((p) => p.replace(/^(["'])(.*)\1$/, "$2"));
  if (!parts?.length) return undefined;
  return (path) => new Promise((resolve, reject) => {
    execFile(parts[0], [...parts.slice(1), path], { timeout: timeoutMs, maxBuffer: 64 * 1024 * 1024, encoding: "utf8" }, (err, stdout) => {
      if (err) return reject(new Error(`the transcriber failed (${String(err.message).slice(0, 160)})`));
      try {
        const r = JSON.parse(stdout.slice(stdout.indexOf("{"))) as AudioReport;
        if (!Array.isArray(r.variants)) throw new Error("no variants in its report");
        resolve(r);
      } catch (e) { reject(new Error(`the transcriber's report could not be read (${(e as Error).message})`)); }
    });
  });
}

const EXT: Record<AudioFormat, string> = { wav: "wav", mp3: "mp3", m4a: "m4a", flac: "flac", ogg: "ogg", aiff: "aiff", unknown: "bin" };
const wordSet = (t: string) => new Set(servedWords(t));
/** share of a's words that b also has */
function overlap(a: string, b: string): number {
  const A = servedWords(a), B = wordSet(b);
  return A.length ? A.filter((w) => B.has(w)).length / A.length : 1;
}

export async function inspectAudio(bytes: Uint8Array, opts: { transcriber?: AudioRunner | false } = {}): Promise<AudioInspection> {
  const format = detectAudioFormat(bytes);
  const texts = readAudioTags(bytes);
  const segments: TextSegment[] = [];
  const findings: Finding[] = [];
  const coverage: AudioCoverage = { format, transcribed: false, notes: [] };
  const add = (f: Omit<Finding, "pass" | "action">) => findings.push({ pass: "channel", action: "none", ...f });

  const routine = /^(?:id3:(?:title|album|artist|composer|encoded-by|copyright|grouping)|info:(?:INAM|IART|IPRD|ISFT|ICRD|IGNR|ICOP)|vorbis:(?:title|artist|album)|aiff:(?:NAME|AUTH))$/;
  for (const t of texts) if (!routine.test(t.field) || t.text.split(/\s+/).length >= 12) segments.push({ text: t.text, visibility: "concealed", path: `audio/metadata:${t.field}` });
  if (segments.length) add({ kind: "audio.metadata_text", confidence: 0.1, severity: 0.2, message: `the file's tags hold text nobody hears (${segments.slice(0, 4).map((s) => s.path.replace("audio/metadata:", "")).join(", ")})`, inHidden: true });

  let transcript: AudioReport | undefined;
  const runner = opts.transcriber === false ? undefined : opts.transcriber ?? commandRunner();
  if (format === "unknown") coverage.reason = "not a recognised audio format";
  else if (opts.transcriber === false) coverage.reason = "transcription was turned off";
  else if (!runner) coverage.reason = "no transcriber is configured (set INGRESS_AUDIO_TRANSCRIBER; see tools/audio)";
  else {
    const dir = mkdtempSync(join(tmpdir(), "ingress-audio-"));
    const file = join(dir, `audio.${EXT[format]}`);
    try {
      writeFileSync(file, bytes, { mode: 0o600 });
      const got = await runner(file);
      coverage.notes.push(...(got.notes ?? []));
      if (got.decoded === false) coverage.reason = got.notes?.[0] ?? "the recording could not be decoded";
      else { transcript = got; coverage.transcribed = true; coverage.seconds = got.duration; }
    } catch (e) { coverage.reason = (e as Error).message; }
    finally { try { rmSync(dir, { recursive: true, force: true }); } catch { /* temp folder */ } }
  }

  if (transcript) {
    const heard = transcript.variants.find((v) => v.kind === "heard")?.text.trim() ?? "";
    if (heard) segments.unshift({ text: heard, visibility: "visible", path: "audio/speech" });
    // speech a listener cannot make out
    const re = transcript.variants.filter((v) => v.kind === "reencoded");
    const everythingHeard = [heard, ...re.map((v) => v.text)].join(" ");
    for (const q of transcript.variants.filter((v) => v.kind === "quiet")) {
      const only = passagesOnlyIn(q.text, everythingHeard, 5);
      if (!only.length) continue;
      only.forEach((t, i) => segments.push({ text: t, visibility: "concealed", path: `audio/quiet-speech[${i}]` }));
      add({ kind: "audio.quiet_speech", confidence: 0.4, severity: 0.6, message: `${only.join(" ").split(/\s+/).length} words are spoken too quietly to make out and become plain once the quiet parts are raised (${q.name})`, excerpt: only[0].slice(0, 160), inHidden: true });
      break;
    }
    // what is heard should not depend on an encoding a listener would not notice
    const words = servedWords(heard).length;
    if (words >= 6 && re.length >= 2) {
      const kept = re.map((v) => ({ name: v.name, share: overlap(heard, v.text) }));
      const lost = kept.filter((k) => k.share < 0.4);
      // the re-encodings agreeing with each other while disagreeing with the original is the mark of crafted audio
      const agree = re.length >= 2 ? overlap(re[0].text, re[1].text) : 0;
      if (lost.length >= 2 || (lost.length >= 1 && lost.length === re.length)) {
        add({ kind: "audio.transcript_unstable", confidence: agree >= 0.6 ? 0.5 : 0.35, severity: 0.65, message: `what a transcriber hears changes when the recording is re-encoded in ways a listener would not notice (${lost.map((k) => `${k.name}: ${(k.share * 100).toFixed(0)}% of the words survive`).join("; ")}). Speech does not do that; audio crafted to be mis-heard does` });
        const stable = re.reduce((a, v) => (v.text.length > a.length ? v.text : a), "");
        if (stable.trim()) segments.push({ text: stable, visibility: "visible", path: "audio/speech~after-re-encoding" });
      }
    }
  } else {
    add({ kind: "audio.not_transcribed", confidence: 0.1, severity: 0.2, message: `the recording was not transcribed: ${coverage.reason}. What is said in it was not checked` });
    segments.push({ text: `[audio, ${format}: not transcribed (${coverage.reason})]`, visibility: "visible", path: "audio/note" });
  }

  const report = JSON.stringify({ sha256: createHash("sha256").update(bytes).digest("hex"), format, transcribed: coverage.transcribed, seconds: transcript?.duration, segments: segments.map((s) => ({ path: s.path, visibility: s.visibility, text: s.text })) });
  return { format, texts, report, transcript, segments, findings, coverage };
}
