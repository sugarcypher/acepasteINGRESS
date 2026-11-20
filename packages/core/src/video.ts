/**
 * Video: what a viewer sees, and what is in the file only for a machine.
 *
 * A person watches a video once, at its own speed. A model is handed frames somebody sampled, the subtitle
 * track as text, and a transcript of the sound. Each is a place for words the viewer never took in:
 *
 *   on screen too briefly   a frame or two of text between ordinary pictures. Nobody reads a fifteenth of a
 *                           second; a model handed that frame reads all of it
 *   in a code               a QR code that flashes by, or sits in a corner
 *   in the subtitle track   cues styled invisible or shown too briefly to read; captions that say what was
 *                           neither said nor shown (the caption adapter, captions.ts)
 *   in the sound            speech too quiet to make out (audio.ts), when a transcriber is configured
 *   in the file's tags      a description or comment nobody watching sees
 *
 * Reading frames needs the vision helper (native/ingress-vision.swift, macOS: AVFoundation and Vision). It
 * looks at every frame as a small grey thumbnail to find where the picture changes, then reads the text in
 * the frames that matter: every frame of a short clip; for a long one, each picture that is on screen for
 * under half a second, the frame after each cut, and a regular grid. It reports how many frames there are and
 * how many it read, and so does the result: a partial read is never silent.
 *
 * Limits, stated plainly:
 *  - Containers: what AVFoundation opens (MP4, MOV, M4V). WebM and Matroska are not read, and the result says so.
 *  - Text in a frame is read as shown. The picture checks for faint text and resizing tricks are not run on
 *    every frame.
 *  - In a long video, text that appears without changing the picture enough to register (small print over
 *    moving footage) can fall between the frames that were read.
 *  - A camera frame is a picture: send it to scanImage. There is no camera reader here.
 *  - No public set of video prompt-injection attacks was found to measure recall on; see docs/VIDEO.md.
 */

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { visionHelperPath, visionHelperProblem, judgeCodes, norm, similar, wordy, enough, sentence, trigrams, containment, type VisionLine, type ImageInspection } from "./image.js";
import { inspectAudio, commandRunner, type AudioRunner } from "./audio.js";
import { adaptCaptions } from "./captions.js";
import type { Finding, TextSegment } from "./types.js";

export type VideoFormat = "mp4" | "mov" | "webm" | "matroska" | "avi" | "unknown";

export interface VideoFrame { index: number; t: number; from: number; to: number; reading: number }
export interface VideoReport {
  version?: number;
  /** false when no frame could be decoded */
  decoded?: boolean;
  width: number; height: number;
  /** seconds */
  duration: number; fps: number;
  examinedSeconds: number; frameCount: number;
  sampling: "every frame" | "selected" | "";
  framesRead: number;
  /** pictures on screen for under half a second (fast cuts and movement count), and how many of them were read */
  shortShots: number; shortShotsRead: number;
  /** of those, pictures put in between two frames of the same scene: what hidden frames look like */
  inserts?: number; insertsRead?: number;
  gridStep: number;
  frames: VideoFrame[];
  readings: Array<{ index: number; t: number; lines: VisionLine[]; codes: Array<{ symbology: string; payload: string; variant?: string }> }>;
  tracks: Array<{ type: string; codec: string; language: string }>;
  subtitles: Array<{ start: number; end: number; text: string; track: number }>;
  metadata: Array<{ field: string; text: string }>;
  notes: string[];
  ms?: number;
}

/** Reads a video file. The default runs the vision helper; tests and other platforms supply their own. */
export type VideoRunner = (path: string, o: { maxFrames: number; maxSeconds: number }) => Promise<VideoReport>;
/** Writes the video's sound to `wavPath` as a WAV file a transcriber can read. */
export type AudioExtractor = (videoPath: string, wavPath: string, maxSeconds: number) => Promise<{ ok: boolean; seconds?: number; reason?: string; truncated?: boolean }>;

export interface VideoCoverage {
  format: string;
  /** were the frames read (text and codes on screen, and how long each was shown)? */
  frames: boolean;
  /** why not, when they were not */
  framesReason?: string;
  seconds?: number; examinedSeconds?: number;
  framesTotal?: number; framesRead?: number;
  sampling?: string;
  /** cues read from the file's subtitle tracks (and a captions file given beside it) */
  subtitleCues: number;
  audio: "transcribed" | "not transcribed" | "no audio track" | "unknown";
  audioReason?: string;
  /** were the captions compared with what was said and shown? */
  captionsCompared: boolean;
  notes: string[];
}

export interface VideoInspection {
  format: VideoFormat;
  video?: VideoReport;
  codes: ImageInspection["codes"];
  segments: TextSegment[];
  findings: Finding[];
  coverage: VideoCoverage;
  /** a stable description of what was found, hashed into the receipt */
  report: string;
}

export interface VideoOptions {
  /** how to read the frames; `false` skips them; default: the vision helper when it is built */
  video?: VideoRunner | false;
  /** how to transcribe the sound (default: the command in INGRESS_AUDIO_TRANSCRIBER); `false` skips it */
  transcriber?: AudioRunner | false;
  /** how to get the sound out of the file (default: the vision helper) */
  extractAudio?: AudioExtractor;
  /** a captions file that came with the video (WebVTT or SubRip), read like a subtitle track */
  captions?: string;
  /** at most this many frames are read for text (default 240) */
  maxFrames?: number;
  /** at most this much of the video is examined (default 600 seconds) */
  maxSeconds?: number;
}

/** Text on screen for no longer than this cannot be read by a viewer. */
export const BRIEF_SECONDS = 0.34;
const MAX_SCREEN_TEXT = 200_000;

const ascii = (b: Uint8Array, from: number, to: number) => { let s = ""; for (let i = from; i < to && i < b.length; i++) s += String.fromCharCode(b[i]); return s; };

export function detectVideoFormat(b: Uint8Array): VideoFormat {
  const box = ascii(b, 4, 8);
  if (box === "ftyp") return /^qt/.test(ascii(b, 8, 12)) ? "mov" : "mp4";
  if (["moov", "mdat", "wide", "free", "skip", "pnot"].includes(box)) return "mov";
  if (b.length > 4 && b[0] === 0x1a && b[1] === 0x45 && b[2] === 0xdf && b[3] === 0xa3) return /webm/.test(ascii(b, 0, 64)) ? "webm" : "matroska";
  if (ascii(b, 0, 4) === "RIFF" && ascii(b, 8, 12) === "AVI ") return "avi";
  return "unknown";
}

export function videoHelperRunner(path: string = visionHelperPath(), timeoutMs = 300_000): VideoRunner {
  return (file, o) => new Promise((resolve, reject) => {
    execFile(path, ["--video", file, "--max-frames", String(o.maxFrames), "--max-seconds", String(o.maxSeconds)], { timeout: timeoutMs, maxBuffer: 256 * 1024 * 1024, encoding: "utf8" }, (err, stdout, stderr) => {
      if (err) return reject(new Error(/usage: ingress-vision/.test(String(stderr)) ? "the vision helper on this machine was built before it could read video (run: ingress vision build)" : `the vision helper failed (${String(err.message).slice(0, 120)})`));
      try {
        const r = JSON.parse(stdout) as VideoReport;
        if (!Array.isArray(r.frames) || !Array.isArray(r.readings) || !Array.isArray(r.tracks)) throw new Error("unexpected report");
        resolve(r);
      } catch (e) { reject(new Error(`the vision helper's report could not be read (${(e as Error).message})`)); }
    });
  });
}

export function helperAudioExtractor(path: string = visionHelperPath(), timeoutMs = 300_000): AudioExtractor {
  return (video, wav, maxSeconds) => new Promise((resolve) => {
    execFile(path, ["--extract-audio", video, wav, "--max-seconds", String(maxSeconds)], { timeout: timeoutMs, maxBuffer: 1024 * 1024, encoding: "utf8" }, (err, stdout) => {
      if (err) return resolve({ ok: false, reason: `the sound could not be taken out of the video (${String(err.message).slice(0, 120)})` });
      try { const r = JSON.parse(stdout) as { ok?: boolean; seconds?: number; reason?: string; truncated?: boolean }; resolve({ ok: r.ok === true, seconds: r.seconds, reason: r.reason, truncated: r.truncated }); }
      catch { resolve({ ok: false, reason: "the helper's answer about the sound could not be read" }); }
    });
  });
}

const stamp = (s: number) => (Number.isFinite(s) ? `${String(Math.floor(s / 60)).padStart(2, "0")}:${(s % 60).toFixed(1).padStart(4, "0")}` : "?");
const vttTime = (s: number) => { const t = Math.max(0, Number.isFinite(s) ? s : 0); const h = Math.floor(t / 3600), m = Math.floor((t % 3600) / 60), sec = t % 60; return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${sec.toFixed(3).padStart(6, "0")}`; };
/** The file's subtitle cues as a WebVTT document, so the caption adapter reads them as it reads any captions file. */
export function cuesToVtt(cues: ReadonlyArray<{ start: number; end: number; text: string }>): string {
  return "WEBVTT\n\n" + cues.map((c) => `${vttTime(c.start)} --> ${vttTime(Math.max(c.end, c.start))}\n${c.text.replace(/-->/g, "->").replace(/\n{2,}/g, "\n").trim()}`).join("\n\n") + "\n";
}

/** a line of text and the run of consecutive read frames it was seen in (positions in `frames`) */
interface Run { text: string; key: string; conf: number; start: number; end: number }

function runsOf(frames: readonly VideoFrame[], readings: VideoReport["readings"]): Run[] {
  const runs: Run[] = [];
  let open: Run[] = [];
  frames.forEach((f, p) => {
    const lines = readings[f.reading]?.lines ?? [];
    const next: Run[] = [];
    const byKey = new Map(open.map((r) => [r.key, r] as const));
    const unmatched: VisionLine[] = [];
    for (const l of lines) {
      const text = l.text.trim();
      const key = norm(text);
      if (!key) continue;
      const r = byKey.get(key);
      if (r && !next.includes(r)) { r.end = p; r.conf = Math.max(r.conf, l.conf); next.push(r); }
      else unmatched.push(l);
    }
    // the recogniser reads the same line a little differently from frame to frame
    const rest = open.filter((r) => !next.includes(r));
    for (const l of unmatched) {
      const text = l.text.trim();
      const r = rest.find((o) => !next.includes(o) && similar(o.text, text) >= 0.8);
      if (r) { r.end = p; r.conf = Math.max(r.conf, l.conf); next.push(r); }
      else { const fresh: Run = { text, key: norm(text), conf: l.conf, start: p, end: p }; runs.push(fresh); next.push(fresh); }
    }
    open = next;
  });
  return runs;
}

/** tags that players and encoders fill in and that say nothing */
const SAYS_SOMETHING = /descr|comment|subject|lyric|synops|keyword|©cmt|©des|ldes|\binfo|caption|summary|notes?$/i;

export async function inspectVideo(bytes: Uint8Array, opts: VideoOptions = {}): Promise<VideoInspection> {
  const format = detectVideoFormat(bytes);
  const segments: TextSegment[] = [];
  const findings: Finding[] = [];
  const codes: ImageInspection["codes"] = [];
  const coverage: VideoCoverage = { format, frames: false, subtitleCues: 0, audio: "unknown", captionsCompared: false, notes: [] };
  const add = (f: Omit<Finding, "pass" | "action">) => findings.push({ pass: "channel", action: "none", ...f });
  const maxFrames = Math.max(8, Math.min(2000, opts.maxFrames ?? 240));
  const maxSeconds = Math.max(1, Math.min(7200, opts.maxSeconds ?? 600));

  let video: VideoReport | undefined;
  let speech = "";
  const dir = mkdtempSync(join(tmpdir(), "ingress-video-"));
  try {
    const file = join(dir, `video.${format === "mov" ? "mov" : format === "unknown" ? "bin" : format === "matroska" ? "mkv" : format}`);
    if (format === "unknown") coverage.framesReason = "not a recognised video format";
    else if (format === "webm" || format === "matroska" || format === "avi") coverage.framesReason = `${format === "avi" ? "AVI" : format === "webm" ? "WebM" : "Matroska"} is not read: the helper reads MP4, MOV and M4V`;
    else if (opts.video === false) coverage.framesReason = "reading the frames was turned off";
    else {
      const problem = opts.video ? undefined : visionHelperProblem();
      if (problem) coverage.framesReason = problem.replace("reading pixels", "reading video");
      else {
        try {
          writeFileSync(file, bytes, { mode: 0o600 });
          const got = await (opts.video || videoHelperRunner())(file, { maxFrames, maxSeconds });
          coverage.notes.push(...(got.notes ?? []));
          if (got.decoded === false) coverage.framesReason = got.notes?.[0] ?? "the video could not be decoded";
          else { video = got; coverage.frames = true; }
          // tags and subtitle tracks are read even when no frame could be decoded
          if (!video && (got.metadata?.length || got.subtitles?.length || got.tracks?.length)) video = { ...got, frames: [], readings: [] };
        } catch (e) { coverage.framesReason = (e as Error).message; }
      }
    }

    // ----- the sound -----
    const hasAudio = video?.tracks.some((t) => t.type === "audio");
    if (video && !hasAudio) coverage.audio = "no audio track";
    else if (video && hasAudio) {
      const transcriber = opts.transcriber === false ? undefined : opts.transcriber ?? commandRunner();
      if (opts.transcriber === false) { coverage.audio = "not transcribed"; coverage.audioReason = "transcription was turned off"; }
      else if (!transcriber) { coverage.audio = "not transcribed"; coverage.audioReason = "no transcriber is configured (set INGRESS_AUDIO_TRANSCRIBER; see tools/audio)"; }
      else {
        const wav = join(dir, "sound.wav");
        const got = await (opts.extractAudio ?? helperAudioExtractor())(file, wav, maxSeconds);
        if (!got.ok) { coverage.audio = "not transcribed"; coverage.audioReason = got.reason ?? "the sound could not be taken out of the video"; }
        else {
          if (got.truncated) coverage.notes.push(`only the first ${Math.round(maxSeconds)} seconds of sound were transcribed`);
          const heard = await inspectAudio(readFileSync(wav), { transcriber });
          if (heard.coverage.transcribed) {
            coverage.audio = "transcribed";
            speech = heard.segments.filter((s) => s.path === "audio/speech").map((s) => s.text).join("\n");
            segments.push(...heard.segments);
            findings.push(...heard.findings);
            coverage.notes.push(...heard.coverage.notes);
          } else { coverage.audio = "not transcribed"; coverage.audioReason = heard.coverage.reason ?? "the transcriber gave nothing"; }
        }
      }
      if (coverage.audio === "not transcribed") add({ kind: "audio.not_transcribed", confidence: 0.1, severity: 0.2, message: `the video's sound was not transcribed: ${coverage.audioReason}. What is said in it was not checked` });
    }
  } finally { try { rmSync(dir, { recursive: true, force: true }); } catch { /* temp folder */ } }

  let screenText = "";
  if (video && coverage.frames) {
    coverage.seconds = video.duration; coverage.examinedSeconds = video.examinedSeconds;
    coverage.framesTotal = video.frameCount; coverage.framesRead = video.framesRead; coverage.sampling = video.sampling;
    const frames = [...video.frames].sort((a, b) => a.t - b.t);
    const frameDur = video.frameCount > 0 && video.examinedSeconds > 0 ? video.examinedSeconds / video.frameCount : video.fps > 0 ? 1 / video.fps : 0.04;
    const runs = runsOf(frames, video.readings);
    /**
     * The longest a run's line can have been on screen: the time between the frame read before it and the frame
     * read after it, neither of which has it. Only frames that were read count as evidence. When every frame was
     * read this is exact; when frames were selected, a line is called brief only if the frames right before and
     * right after were read too (the helper reads them for every short-lived picture it chooses).
     */
    const shownFor = (start: number, end: number): number => {
      const before = start > 0 ? frames[start - 1].t : -frameDur;
      const after = end + 1 < frames.length ? frames[end + 1].t : video!.examinedSeconds;
      return Math.max(frames[end].t - frames[start].t + frameDur, after - before - frameDur);
    };
    const textAt = (p: number) => (p >= 0 && p < frames.length ? (video!.readings[frames[p].reading]?.lines ?? []).map((l) => l.text).join("\n") : "");
    // The same line read again a moment later (the recogniser missed it in a frame, or it blinks) is one showing.
    // Same words anywhere in the video: one family. Nearly the same words within a second: the same family too.
    const families = new Map<string, Run[]>();
    let recent: Array<{ fam: Run[]; last: Run }> = [];
    for (const r of [...runs].sort((a, b) => a.start - b.start)) {
      const t = frames[r.start].t;
      recent = recent.filter((x) => t - (frames[x.last.end].t + frameDur) <= 1);
      let fam = families.get(r.key);
      if (!fam) fam = recent.find((x) => Math.abs(x.last.key.length - r.key.length) <= Math.max(3, r.key.length * 0.25) && similar(x.last.key, r.key) >= 0.8)?.fam;
      if (fam) fam.push(r); else { fam = [r]; families.set(r.key, fam); }
      recent.push({ fam, last: r });
      if (recent.length > 400) recent = recent.slice(-400);
    }
    const brief = new Set<Run>();
    for (const fam of families.values()) {
      const spans: Array<{ start: number; end: number }> = [];
      for (const r of fam) {
        const last = spans[spans.length - 1];
        if (last && frames[r.start].t - (frames[last.end].t + frameDur) <= 0.5) last.end = Math.max(last.end, r.end);
        else spans.push({ start: r.start, end: r.end });
      }
      // Only lines read clearly count: on moving footage the recogniser reads a sign in the background a little
      // differently in every frame, at middling confidence, and each reading would look like words that came and went.
      if (spans.every((s) => shownFor(s.start, s.end) <= BRIEF_SECONDS)) for (const r of fam) if (r.conf >= 0.8) brief.add(r);
    }
    // Not hidden: a line that is the beginning of one that stayed (captions that build up word by word), and a
    // line that the frames on either side also have in some reading of it.
    const stayed = runs.filter((r) => !brief.has(r));
    for (const r of [...brief]) {
      const near = stayed.filter((s) => Math.abs(frames[s.start].t - frames[r.start].t) <= 3 || (frames[s.start].t <= frames[r.start].t && frames[s.end].t >= frames[r.start].t));
      if (near.length && containment(r.text, trigrams(near.map((s) => s.text).join("\n"))) >= 0.8) { brief.delete(r); continue; }
      if (containment(r.text, trigrams(`${textAt(r.start - 1)}\n${textAt(r.end + 1)}`)) >= 0.5) brief.delete(r);
    }
    // passages: the brief lines that appeared together. A passage is a message, not scraps (see image.ts).
    const byStart = new Map<number, Run[]>();
    for (const r of brief) byStart.set(r.start, [...(byStart.get(r.start) ?? []), r]);
    const hidden: Array<{ at: number; text: string; seconds: number }> = [];
    for (const [p, rs] of [...byStart.entries()].sort((a, b) => a[0] - b[0])) {
      const texts = rs.map((r) => r.text);
      if (!enough(texts) || !sentence(texts)) { rs.forEach((r) => brief.delete(r)); continue; }
      hidden.push({ at: frames[p].t, text: texts.join("\n"), seconds: Math.max(...rs.map((r) => shownFor(r.start, r.end))) });
    }
    // what a viewer can read, in the order it appears
    let total = 0, dropped = false;
    const said = new Set<string>();
    const shown: string[] = [];
    frames.forEach((f, p) => {
      const fresh = runs.filter((r) => r.start === p && !brief.has(r) && !said.has(r.key));
      if (!fresh.length) return;
      fresh.forEach((r) => said.add(r.key));
      const text = fresh.map((r) => r.text).join("\n");
      if (total + text.length > MAX_SCREEN_TEXT) { dropped = true; return; }
      total += text.length;
      shown.push(text);
      segments.push({ text, visibility: "visible", path: `video/text@${stamp(f.t)}` });
    });
    screenText = shown.join("\n");
    if (dropped) coverage.notes.push(`more than ${MAX_SCREEN_TEXT} characters of text are shown on screen: the rest was not read`);
    hidden.forEach((h) => segments.push({ text: h.text, visibility: "concealed", path: `video/brief-text@${stamp(h.at)}` }));
    if (hidden.length) {
      add({
        kind: "video.brief_frame_text", confidence: 0.3, severity: 0.5, inHidden: true,
        message: `${wordy(hidden.map((h) => h.text).join(" "))} words are on screen for under a third of a second (${hidden.slice(0, 3).map((h) => `at ${stamp(h.at)} for ${h.seconds.toFixed(2)} s`).join("; ")}): a viewer cannot read them, and a model handed that frame reads all of them`,
        excerpt: hidden[0].text.replace(/\s+/g, " ").slice(0, 160),
      });
    }

    // codes in the frames
    const seenCodes = new Map<string, { symbology: string; payload: string; at: string }>();
    for (const r of video.readings) for (const c of r.codes ?? []) if (!seenCodes.has(c.payload)) seenCodes.set(c.payload, { symbology: c.symbology, payload: c.payload, at: stamp(r.t) });
    const judged = judgeCodes([...seenCodes.values()], screenText.slice(0, 20_000), "video");
    codes.push(...judged.codes); findings.push(...judged.findings); segments.push(...judged.segments);

    // a partial read is said out loud
    const partial: string[] = [];
    if (video.duration > video.examinedSeconds + 1) partial.push(`only the first ${Math.round(video.examinedSeconds)} of ${Math.round(video.duration)} seconds were examined`);
    // Pictures put in between two frames of the same scene are what hidden frames look like: any left unread is
    // a gap. Other short-lived pictures (fast cuts, movement) are sampled, and the coverage says how many.
    const inserts = video.inserts ?? 0, insertsRead = video.insertsRead ?? inserts;
    if (inserts > insertsRead) partial.push(`${inserts - insertsRead} of ${inserts} pictures put in between two frames of the same scene were not read`);
    if (video.shortShots > video.shortShotsRead) coverage.notes.push(`${video.shortShots} pictures are on screen for under half a second (fast cuts and movement count); ${video.shortShotsRead} of them were read`);
    if (dropped) partial.push("the text on screen was longer than is read");
    if (partial.length) add({ kind: "video.partly_read", confidence: 0.12, severity: 0.25, message: `the video was only partly read: ${partial.join("; ")}. What is in the rest was not checked` });
  } else {
    add({ kind: "video.frames_not_read", confidence: 0.1, severity: 0.2, message: `the video's frames were not read: ${coverage.framesReason}. Text and codes on screen, and how long they are shown, were not checked` });
  }

  if (video) {
    // the file's tags
    const tagged: string[] = [];
    for (const t of video.metadata ?? []) {
      if (!SAYS_SOMETHING.test(t.field) && wordy(t.text) < 12) continue;
      segments.push({ text: t.text, visibility: "concealed", path: `video/metadata:${t.field.slice(0, 60)}` });
      if (wordy(t.text) >= 4) tagged.push(t.field.slice(0, 40));
    }
    if (tagged.length) add({ kind: "video.metadata_text", confidence: 0.1, severity: 0.2, message: `the file's tags hold text nobody watching sees (${tagged.slice(0, 4).join(", ")})`, inHidden: true });
  }

  // ----- captions: the file's subtitle tracks, and a captions file that came with it -----
  const spokenAndShown = speech.trim().split(/\s+/).length >= 20 ? `${speech}\n${screenText}` : undefined;
  const captionSources: string[] = [];
  if (video?.subtitles?.length) { captionSources.push(cuesToVtt(video.subtitles)); coverage.subtitleCues += video.subtitles.length; }
  if (opts.captions?.trim()) captionSources.push(opts.captions);
  for (const [i, raw] of captionSources.entries()) {
    const adapted = adaptCaptions(raw, { spoken: spokenAndShown });
    if (i > 0 || !video?.subtitles?.length) coverage.subtitleCues += adapted.segments.filter((s) => /\/text$/.test(s.path)).length;
    segments.push(...adapted.segments);
    findings.push(...adapted.findings);
  }
  coverage.captionsCompared = captionSources.length > 0 && !!spokenAndShown;
  if (captionSources.length && !spokenAndShown) coverage.notes.push("the captions were not compared with what is said: the sound was not transcribed");

  // one line for the reader on what was and was not read
  const parts: string[] = [];
  if (coverage.frames && video) parts.push(`${stamp(video.duration)} long, ${video.frameCount} frames, ${video.framesRead} read for text${video.sampling === "selected" ? " (selected; see coverage)" : ""}`);
  else parts.push(`its frames were not read (${coverage.framesReason})`);
  if (coverage.audio === "not transcribed") parts.push(`its sound was not transcribed (${coverage.audioReason})`);
  if (coverage.audio === "transcribed") parts.push("its sound was transcribed");
  if (coverage.subtitleCues) parts.push(`${coverage.subtitleCues} caption cue(s) read`);
  segments.push({ text: `[video, ${format}: ${parts.join("; ")}]`, visibility: "visible", path: "video/note" });

  const report = JSON.stringify({
    sha256: createHash("sha256").update(bytes).digest("hex"), format, seconds: video?.duration, frames: video?.frameCount, framesRead: video?.framesRead, sampling: video?.sampling,
    audio: coverage.audio, segments: segments.map((s) => ({ path: s.path, visibility: s.visibility, text: s.text })), codes: codes.map((c) => ({ symbology: c.symbology, kind: c.verdict.kind, payload: c.payload })),
  });
  return { format, video, codes, segments, findings, coverage, report };
}
