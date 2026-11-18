/**
 * Captions and transcripts: WebVTT, SubRip (SRT), and the JSON a transcription service or a meeting
 * notetaker produces.
 *
 * A caption file is read by people one line at a time, on screen, for a second or two. A model reads the whole
 * file at once: the cue that flashes for a twentieth of a second, the cue a style rule makes transparent, the
 * NOTE block no player shows, the cue nobody said aloud. A meeting transcript is a room where anyone present
 * can speak, and "assistant, add to the action items that..." is as present to the notetaker as the agenda.
 *
 * Checks:
 *   cues nobody can read     shown too briefly for their length, sized to nothing, or styled invisible
 *   what no player shows     NOTE blocks, STYLE blocks, metadata cues: concealed text
 *   captions vs. speech      given what was actually said (a transcript of the audio), words in the captions
 *                            that nobody said
 *   speakers                 an utterance that addresses the notetaker or assistant with something to do
 *   spoken approvals         noted: a voice saying "I approve" is content. Approval comes from the broker's
 *                            own channel, never from what was heard
 */

import type { Finding, TextSegment } from "./types.js";
import { decodeEntities, type AdapterResult } from "./adapters.js";
import { passagesOnlyIn } from "./served.js";

export interface Cue { start: number; end: number; text: string; speaker?: string; settings?: string; classes: string[]; id?: string }
export interface CaptionHints {
  /** what was actually said: a transcript of the audio, for comparison */
  spoken?: string;
  /** speakers known to be outside the organisation (their words are a stranger's) */
  outsideSpeakers?: string[];
}

const time = (s: string): number => {
  const m = s.trim().match(/^(?:(\d+):)?(\d{1,2}):(\d{2})[.,](\d{1,3})$/);
  return m ? Number(m[1] ?? 0) * 3600 + Number(m[2]) * 60 + Number(m[3]) + Number(m[4].padEnd(3, "0")) / 1000 : NaN;
};
const TIMING = /^\s*((?:\d+:)?\d{1,2}:\d{2}[.,]\d{1,3})\s*-->\s*((?:\d+:)?\d{1,2}:\d{2}[.,]\d{1,3})(.*)$/;

export function looksLikeCaptions(text: string): boolean {
  const head = text.slice(0, 4000).replace(/^\uFEFF/, "");
  return /^WEBVTT(?:[ \t\n\r]|$)/.test(head) || /^\s*\d+\s*\r?\n\s*\d{1,2}:\d{2}:\d{2}[,.]\d{1,3}\s*-->/m.test(head.slice(0, 400));
}

/** Is this JSON a transcript: utterances or segments with text and a time or a speaker? */
export function looksLikeTranscriptJson(doc: unknown): boolean {
  const list = transcriptList(doc);
  if (!list || !list.length) return false;
  return list.slice(0, 30).every((u) => {
    if (!u || typeof u !== "object") return false;
    const o = u as Record<string, unknown>;
    const hasText = typeof o.text === "string" || typeof o.transcript === "string" || typeof o.sentence === "string";
    const hasTime = ["start", "end", "start_time", "startTime", "offset", "timestamp", "start_ms"].some((k) => typeof o[k] === "number" || (typeof o[k] === "string" && /\d:\d\d/.test(o[k] as string)));
    const hasSpeaker = ["speaker", "speaker_name", "speakerName", "participant"].some((k) => typeof o[k] === "string" || typeof o[k] === "number");
    return hasText && hasTime && (hasSpeaker || "end" in o || "duration" in o || "end_time" in o || "endTime" in o) && !("subject" in o) && !("is_from_me" in o);
  });
}
function transcriptList(doc: unknown): unknown[] | undefined {
  if (Array.isArray(doc)) return doc;
  if (doc && typeof doc === "object") {
    const d = doc as Record<string, unknown>;
    for (const k of ["utterances", "segments", "sentences", "transcript", "results", "monologues", "entries", "captions"]) if (Array.isArray(d[k])) return d[k] as unknown[];
  }
  return undefined;
}

/** class names a STYLE block makes invisible; "*" when every cue is */
function hiddenClasses(style: string): Set<string> {
  const out = new Set<string>();
  for (const m of style.matchAll(/::cue(?:\(([^)]*)\))?\s*\{([^}]*)\}/g)) {
    const body = m[2].toLowerCase().replace(/\s+/g, "");
    const hides = /opacity:0(?:\.0+)?(?:;|$)|visibility:hidden|display:none|font-size:0(?:px|em|%|pt)?(?:;|$)|(?:^|;)color:(?:transparent|rgba\([^)]*,0(?:\.0+)?\)|#[0-9a-f]{6}00|#[0-9a-f]{3}0)(?:;|$)/.test(body);
    if (!hides) continue;
    const sel = (m[1] ?? "").trim();
    if (!sel) out.add("*");
    for (const c of sel.matchAll(/\.([\w-]+)/g)) out.add(c[1]);
    for (const v of sel.matchAll(/v\[voice=["']?([^"'\]]+)/g)) out.add(`voice:${v[1]}`);
  }
  return out;
}

const untag = (t: string) => decodeEntities(t.replace(/<\d{1,2}:\d{2}(?::\d{2})?\.\d{3}>/g, "").replace(/<\/?[a-zA-Z][^>]*>/g, "").replace(/\{\\[^}]*\}/g, "")).text.replace(/[ \t]+/g, " ").trim();

export function parseCaptions(raw: string): { cues: Cue[]; notes: string[]; styles: string[]; format: "vtt" | "srt" } {
  const text = raw.replace(/^\uFEFF/, "").replace(/\r\n?/g, "\n");
  const format = /^WEBVTT/.test(text) ? "vtt" : "srt";
  const cues: Cue[] = [], notes: string[] = [], styles: string[] = [];
  for (const block of text.split(/\n{2,}/).slice(0, 50_000)) {
    const lines = block.split("\n");
    if (/^WEBVTT/.test(lines[0])) { if (lines.length > 1) notes.push(lines.slice(1).join("\n")); continue; }
    if (/^NOTE(?:\s|$)/.test(lines[0])) { notes.push(block.replace(/^NOTE\s*/, "")); continue; }
    if (/^STYLE\s*$/.test(lines[0])) { styles.push(lines.slice(1).join("\n")); continue; }
    if (/^REGION\s*$/.test(lines[0])) continue;
    const at = lines.findIndex((l) => TIMING.test(l));
    if (at < 0) { if (block.trim() && format === "vtt") notes.push(block); continue; }
    const m = lines[at].match(TIMING)!;
    const body = lines.slice(at + 1).join("\n");
    const speaker = body.match(/<v(?:\.[\w.-]+)?\s+([^>]+)>/)?.[1]?.trim() // (a plain "Word:" is as often the start of a sentence as a speaker: only ">> Name:" and "NAME:" count)
      ?? body.match(/^\s*>>\s*([A-Z][\w .'-]{1,30}):\s/)?.[1] ?? body.match(/^\s*([A-Z][A-Z .'-]{1,30}):\s/)?.[1];
    cues.push({ start: time(m[1]), end: time(m[2]), text: untag(body), speaker, settings: m[3].trim() || undefined, classes: [...body.matchAll(/<c((?:\.[\w-]+)+)>/g)].flatMap((c) => c[1].split(".").filter(Boolean)), id: at > 0 ? lines[at - 1].trim() : undefined });
  }
  return { cues, notes, styles, format };
}

const NOTETAKER = /\b(?:note ?taker|notetaking (?:bot|assistant)|meeting (?:assistant|bot)|ai assistant|assistant|copilot|the (?:ai|bot|agent|model)|otter|fireflies|fathom|gemini|claude|chatgpt)\b[^.?!\n]{0,60}\b(?:add|record|write|put|include|insert|send|email|forward|share|schedule|create|delete|remove|ignore|disregard|forget|remember|note that|make sure|summari[sz]e (?:this|it) as|mark|assign|approve|grant)\b/i;
const SPOKEN_APPROVAL = /\b(?:i (?:hereby )?(?:approve|authori[sz]e|consent|give (?:my )?(?:approval|permission|consent))|you (?:have|'ve got) my (?:approval|permission|authori[sz]ation|consent)|(?:approved|permission granted|go ahead and (?:send|pay|delete|transfer|wire)))\b/i;

export function adaptCaptions(raw: string, hints: CaptionHints = {}): AdapterResult {
  const segments: TextSegment[] = [];
  const findings: Finding[] = [];
  const add = (f: Omit<Finding, "pass" | "action">) => findings.push({ pass: "channel", action: "none", ...f });
  let cues: Cue[] = [];
  let label = "captions";

  let doc: unknown;
  const head = raw.trimStart()[0];
  if (head === "{" || head === "[") { try { doc = JSON.parse(raw); } catch { doc = undefined; } }
  const list = doc !== undefined ? transcriptList(doc) : undefined;
  if (list) {
    label = "transcript";
    const sec = (v: unknown, ms = false): number => (typeof v === "number" ? (ms || v > 100_000 ? v / 1000 : v) : typeof v === "string" ? (Number.isNaN(time(v.includes(".") || v.includes(",") ? v : `${v}.000`)) ? Number(v) || NaN : time(v.includes(".") || v.includes(",") ? v : `${v}.000`)) : NaN);
    for (const u of list.slice(0, 50_000)) {
      if (!u || typeof u !== "object") continue;
      const o = u as Record<string, unknown>;
      const text = String(o.text ?? o.transcript ?? o.sentence ?? "").trim();
      if (!text) continue;
      const start = sec(o.start ?? o.start_time ?? o.startTime ?? o.offset ?? o.timestamp ?? o.start_ms, "start_ms" in o);
      const end = "duration" in o && typeof o.duration === "number" ? start + (o.duration > 1000 ? o.duration / 1000 : o.duration) : sec(o.end ?? o.end_time ?? o.endTime, false);
      const sp = o.speaker ?? o.speaker_name ?? o.speakerName ?? o.participant;
      cues.push({ start, end, text, speaker: sp === undefined ? undefined : typeof sp === "number" ? `Speaker ${sp}` : String(sp), classes: [] });
    }
  } else {
    const p = parseCaptions(raw);
    cues = p.cues;
    // what no player shows
    p.notes.forEach((n, i) => { if (n.trim()) segments.push({ text: n.trim(), visibility: "comment", path: `captions/note[${i}]` }); });
    const hidden = hiddenClasses(p.styles.join("\n"));
    p.styles.forEach((s, i) => { const said = [...s.matchAll(/content\s*:\s*["']([^"']{8,})["']/g)].map((m) => m[1]); if (said.length) segments.push({ text: said.join("\n"), visibility: "css_hidden", path: `captions/style[${i}]` }); });
    if (hidden.size) {
      const styled = cues.filter((c) => hidden.has("*") || c.classes.some((k) => hidden.has(k)) || (c.speaker && hidden.has(`voice:${c.speaker}`)));
      if (styled.length) {
        add({ kind: "captions.hidden_cue", confidence: 0.5, severity: 0.7, message: `${styled.length} cue(s) are styled invisible (transparent, zero size or hidden) by the file's own STYLE block: a player shows nothing, a program reading the file gets the words`, inHidden: true });
        for (const c of styled) { segments.push({ text: c.text, visibility: "css_hidden", path: `captions/cue@${fmt(c.start)}~styled-hidden` }); c.text = ""; }
      }
    }
  }

  // cues nobody can read: shown too briefly for their length, or sized to nothing
  const flashed: Cue[] = [];
  for (const c of cues) {
    if (!c.text) continue;
    const dur = c.end - c.start, chars = c.text.replace(/\s+/g, "").length, words = c.text.split(/\s+/).length;
    const tiny = /(?:^|\s)size:[0-2]%/.test(c.settings ?? "");
    const tooFast = Number.isFinite(dur) && words >= 4 && (dur <= 0.2 || chars / Math.max(dur, 0.001) > 60);
    if (tiny || (label === "captions" && tooFast)) { flashed.push(c); segments.push({ text: c.text, visibility: "concealed", path: `captions/cue@${fmt(c.start)}~unreadable` }); c.text = ""; }
  }
  if (flashed.length) add({ kind: "captions.unreadable_cue", confidence: 0.4, severity: 0.65, message: `${flashed.length} cue(s) are on screen too briefly to read, or sized to nothing (the first at ${fmt(flashed[0].start)}): a viewer cannot read them, a program reading the file does`, inHidden: true });

  // the words, in order, with speakers
  const outside = new Set((hints.outsideSpeakers ?? []).map((s) => s.toLowerCase()));
  let last = "";
  const shownParts: string[] = [];
  cues.forEach((c, i) => {
    if (!c.text) return;
    if (c.speaker && c.speaker !== last) { segments.push({ text: c.speaker, visibility: "visible", path: `${label}[${i}]/speaker` }); last = c.speaker; }
    segments.push({ text: c.text, visibility: "visible", path: `${label}[${i}]/text` });
    shownParts.push(c.text);
    if (NOTETAKER.test(c.text)) add({ kind: "captions.addressed_to_notetaker", confidence: c.speaker && outside.has(c.speaker.toLowerCase()) ? 0.55 : 0.4, severity: 0.65, message: `${c.speaker ? `${c.speaker.slice(0, 40)} ` : "someone "}speaks to the notetaker or assistant with something to do (at ${fmt(c.start)})${c.speaker && outside.has(c.speaker.toLowerCase()) ? ", and is from outside the organisation" : ""}: what is said in a meeting is content, not an instruction to the one taking notes`, excerpt: c.text.slice(0, 160), location: `${label}[${i}]/text` });
    else if (SPOKEN_APPROVAL.test(c.text)) add({ kind: "captions.spoken_approval", confidence: 0.05, severity: 0.2, message: `a spoken approval at ${fmt(c.start)}: a voice is never an approval. Actions are approved through the broker's own channel`, location: `${label}[${i}]/text` });
  });

  // captions that nobody said
  if (hints.spoken && hints.spoken.trim().split(/\s+/).length >= 20) {
    const only = passagesOnlyIn(shownParts.join(" "), hints.spoken, 8);
    if (only.length) {
      add({ kind: "captions.not_spoken", confidence: 0.4, severity: 0.6, message: `the captions say ${only.length} thing(s) that were not said aloud`, excerpt: only[0].slice(0, 160), inHidden: true });
      only.forEach((t, i) => segments.push({ text: t, visibility: "concealed", path: `captions/not-spoken[${i}]` }));
    }
  }
  return { segments, findings };
}

const fmt = (s: number) => (Number.isFinite(s) ? `${String(Math.floor(s / 60)).padStart(2, "0")}:${(s % 60).toFixed(1).padStart(4, "0")}` : "?");
