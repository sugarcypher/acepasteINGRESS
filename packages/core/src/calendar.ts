/**
 * Calendars and to-do items (iCalendar text, and the JSON that Google Calendar and Microsoft Graph return).
 *
 * Anyone can put an event on a calendar: Google Calendar adds invitations from any sender by default, and a
 * subscribed calendar is a file its publisher can change at any time. An assistant asked "what's on today"
 * reads every field of every event. So each field is a segment with the visibility a person would have of it
 * in a calendar app: the title, time, place and description are seen; alternative descriptions, alarm text,
 * attachments and extension properties are not.
 *
 * Beyond what the passes find in the text, three things are specific to the channel:
 *   - a description that says one thing in plain text and another in its HTML alternative
 *   - an alarm that does something (sends email, runs a program) rather than display a reminder
 *   - who the organizer claims to be (left to the caller's trust level: an invitation from a stranger is
 *     trust 4, a subscribed feed trust 5)
 */

import type { Finding, TextSegment } from "./types.js";
import { analyzeHtml } from "./visibility.js";
import { passagesOnlyIn } from "./served.js";

export interface CalendarAdapterResult {
  segments: TextSegment[];
  findings: Finding[];
}

interface IcsProp { name: string; params: Record<string, string>; value: string }
interface IcsComponent { type: string; props: IcsProp[]; children: IcsComponent[] }

const unescape = (v: string) => v.replace(/\\n/gi, "\n").replace(/\\([,;\\])/g, "$1");

/** Parse iCalendar text into nested components. Tolerant: unknown lines are skipped, never thrown on. */
export function parseIcs(text: string): IcsComponent[] {
  const lines = text.replace(/\r\n?/g, "\n").replace(/\n[ \t]/g, "").split("\n");
  const root: IcsComponent = { type: "ROOT", props: [], children: [] };
  const stack = [root];
  for (const line of lines.slice(0, 200_000)) {
    if (!line.trim()) continue;
    // NAME;PARAM=value;PARAM="quoted:value":VALUE  (the first colon outside quotes ends the name part)
    let i = 0, inQuote = false;
    for (; i < line.length; i++) { const c = line[i]; if (c === '"') inQuote = !inQuote; else if (c === ":" && !inQuote) break; }
    if (i >= line.length) continue;
    const head = line.slice(0, i), value = line.slice(i + 1);
    const [rawName, ...rawParams] = head.split(/;(?=(?:[^"]*"[^"]*")*[^"]*$)/);
    const name = rawName.toUpperCase();
    if (name === "BEGIN") { const c: IcsComponent = { type: value.trim().toUpperCase(), props: [], children: [] }; stack[stack.length - 1].children.push(c); if (stack.length < 16) stack.push(c); continue; }
    if (name === "END") { if (stack.length > 1 && stack[stack.length - 1].type === value.trim().toUpperCase()) stack.pop(); continue; }
    const params: Record<string, string> = {};
    for (const p of rawParams) { const eq = p.indexOf("="); if (eq > 0) params[p.slice(0, eq).toUpperCase()] = p.slice(eq + 1).replace(/^"|"$/g, ""); }
    stack[stack.length - 1].props.push({ name, params, value });
  }
  return root.children;
}

const SEEN_PROPS = new Set(["SUMMARY", "DESCRIPTION", "LOCATION", "COMMENT", "CONTACT", "CATEGORIES", "RESOURCES"]);
/** properties that are structure, not prose */
const STRUCTURAL = /^(DT|DUE|COMPLETED|CREATED|LAST-MODIFIED|SEQUENCE|UID|RRULE|EXDATE|RDATE|EXRULE|TRANSP|STATUS|CLASS|PRIORITY|GEO|DURATION|TRIGGER|REPEAT|ACTION|RECURRENCE-ID|PERCENT-COMPLETE|TZ|PRODID|VERSION|CALSCALE|METHOD|FREEBUSY|X-MICROSOFT-CDO|X-APPLE-TRAVEL|X-APPLE-STRUCTURED|X-LIC-|X-GOOGLE-|X-WR-TIMEZONE)/;

function adaptComponent(c: IcsComponent, path: string, segments: TextSegment[], findings: Finding[], depth = 0): void {
  if (depth > 8) return;
  const get = (n: string) => c.props.filter((p) => p.name === n);
  const isAlarm = c.type === "VALARM";
  let plainDescription = "";
  for (const p of c.props) {
    const v = unescape(p.value).trim();
    if (!v) continue;
    if (p.name === "X-ALT-DESC" || (p.name === "DESCRIPTION" && /html/i.test(p.params.FMTTYPE ?? ""))) continue; // handled below
    if (p.name === "ORGANIZER" || p.name === "ATTENDEE") {
      // the display name is free text the sender chose
      if (p.params.CN) segments.push({ text: p.params.CN, visibility: "visible", path: `${path}/${p.name.toLowerCase()}@cn` });
      continue;
    }
    if (p.name === "ATTACH" || p.name === "URL" || p.name === "CONFERENCE") {
      // never fetched: listed so the link checks and the meaning pass see the address
      if (/^https?:/i.test(v)) segments.push({ text: v, visibility: "attribute", path: `${path}/${p.name.toLowerCase()}` });
      else if (p.params.ENCODING?.toUpperCase() === "BASE64" && v.length < 400_000) {
        const decoded = Buffer.from(v, "base64").toString("utf8");
        if (/^[\x09\x0a\x0d\x20-\x7e -￿]{8,}$/.test(decoded.slice(0, 2000))) segments.push({ text: decoded, visibility: "attribute", path: `${path}/attach@inline` });
      }
      continue;
    }
    if (STRUCTURAL.test(p.name)) continue;
    // an alarm's text is never shown in the event; in the event itself only the usual fields are
    const seen = !isAlarm && SEEN_PROPS.has(p.name);
    if (p.name === "DESCRIPTION" && !isAlarm) plainDescription += `${v}\n`;
    segments.push({ text: v, visibility: seen ? "visible" : "attribute", path: `${path}/${p.name.toLowerCase()}` });
  }

  // HTML alternative: what a rich client shows. Text its styles hide is hidden; text only the plain
  // description has is what a rich client's user never sees.
  for (const p of [...get("X-ALT-DESC"), ...get("DESCRIPTION").filter((x) => /html/i.test(x.params.FMTTYPE ?? ""))]) {
    const html = unescape(p.value);
    if (!html.trim()) continue;
    const v = analyzeHtml(html);
    for (const s of v.segments) segments.push({ ...s, path: `${path}/alt-desc${s.path}` });
    findings.push(...v.findings.map((f) => ({ ...f, location: `${path}/alt-desc${f.location ?? ""}` })));
    if (plainDescription.trim()) {
      const only = passagesOnlyIn(plainDescription, v.segments.map((s) => s.text).join(" "));
      if (only.length) {
        findings.push({ pass: "channel", kind: "calendar.description_divergence", confidence: 0.3, severity: 0.6, message: `the event's plain description says ${only.length} thing(s) its formatted description does not`, excerpt: only[0].slice(0, 160), location: `${path}/description`, action: "none" });
        for (const [i, t] of only.entries()) segments.push({ text: t, visibility: "concealed", path: `${path}/description~plain-only[${i}]` });
      }
    }
  }

  if (isAlarm) {
    const action = (get("ACTION")[0]?.value ?? "").trim().toUpperCase();
    if (action === "PROCEDURE") findings.push({ pass: "channel", kind: "calendar.alarm_action", confidence: 0.8, severity: 0.9, message: "an alarm that runs a program when it fires (ACTION:PROCEDURE)", excerpt: (get("ATTACH")[0]?.value ?? "").slice(0, 120), location: path, action: "none" });
    else if (action === "EMAIL") findings.push({ pass: "channel", kind: "calendar.alarm_action", confidence: 0.4, severity: 0.6, message: "an alarm that sends email when it fires (ACTION:EMAIL)", excerpt: get("ATTENDEE").map((a) => a.value).join(", ").slice(0, 120), location: path, action: "none" });
  }
  const counts = new Map<string, number>();
  for (const child of c.children) {
    const n = counts.get(child.type) ?? 0; counts.set(child.type, n + 1);
    adaptComponent(child, `${path}/${child.type.toLowerCase()}[${n}]`, segments, findings, depth + 1);
  }
}

type Json = Record<string, unknown>;
const str = (v: unknown) => (typeof v === "string" ? v : "");

/** One event object as Google Calendar or Microsoft Graph returns it. */
function adaptEventJson(e: Json, path: string, segments: TextSegment[], findings: Finding[]): void {
  const title = str(e.summary) || str(e.subject) || str(e.title);
  if (title) segments.push({ text: title, visibility: "visible", path: `${path}/summary` });
  const loc = typeof e.location === "string" ? e.location : str((e.location as Json | undefined)?.displayName);
  if (loc) segments.push({ text: loc, visibility: "visible", path: `${path}/location` });
  // Google: description is a string that may hold HTML. Graph: body { contentType, content }.
  const body = e.body && typeof e.body === "object" ? (e.body as Json) : undefined;
  const desc = str(e.description) || str(body?.content) || str(e.bodyPreview);
  if (desc) {
    if (/<[a-z][^>]*>/i.test(desc) || /html/i.test(str(body?.contentType))) {
      const v = analyzeHtml(desc);
      for (const s of v.segments) segments.push({ ...s, path: `${path}/description${s.path}` });
      findings.push(...v.findings);
    } else segments.push({ text: desc, visibility: "visible", path: `${path}/description` });
  }
  const people: unknown[] = [e.organizer, e.creator, ...(Array.isArray(e.attendees) ? e.attendees : [])];
  for (const p of people) {
    if (!p || typeof p !== "object") continue;
    const name = str((p as Json).displayName) || str(((p as Json).emailAddress as Json | undefined)?.name);
    if (name) segments.push({ text: name, visibility: "visible", path: `${path}/person@name` });
  }
  for (const k of ["hangoutLink", "htmlLink", "onlineMeetingUrl", "webLink"]) if (/^https?:/i.test(str(e[k]))) segments.push({ text: str(e[k]), visibility: "attribute", path: `${path}/${k}` });
  for (const a of Array.isArray(e.attachments) ? e.attachments : []) {
    if (!a || typeof a !== "object") continue;
    const t = [str((a as Json).title), str((a as Json).name), str((a as Json).fileUrl)].filter(Boolean).join(" ");
    if (t) segments.push({ text: t, visibility: "attribute", path: `${path}/attachment` });
  }
  // properties a calendar app never shows
  const ext = e.extendedProperties && typeof e.extendedProperties === "object" ? JSON.stringify(e.extendedProperties) : "";
  if (ext.length > 2) segments.push({ text: ext, visibility: "attribute", path: `${path}/extendedProperties` });
}

/** Is this parsed JSON a calendar event, or a list of them? */
export function looksLikeCalendarJson(doc: unknown): boolean {
  const one = (e: unknown) => !!e && typeof e === "object" && ("summary" in (e as Json) || "subject" in (e as Json)) && ("start" in (e as Json) || "end" in (e as Json) || "attendees" in (e as Json) || "organizer" in (e as Json));
  if (Array.isArray(doc)) return doc.length > 0 && doc.every(one);
  if (doc && typeof doc === "object") { const d = doc as Json; if (d.kind === "calendar#events" || (Array.isArray(d.items) && d.items.some(one)) || (Array.isArray(d.value) && d.value.some(one))) return true; }
  return one(doc);
}

export function adaptCalendar(raw: string): CalendarAdapterResult {
  const segments: TextSegment[] = [];
  const findings: Finding[] = [];
  if (/BEGIN:VCALENDAR|BEGIN:VEVENT|BEGIN:VTODO/i.test(raw.slice(0, 4000))) {
    const counts = new Map<string, number>();
    const walk = (c: IcsComponent, path: string) => {
      if (c.type === "VCALENDAR") { for (const p of c.props) if (/^X-WR-(CALNAME|CALDESC)$/.test(p.name) && p.value.trim()) segments.push({ text: unescape(p.value), visibility: "visible", path: `calendar/${p.name.toLowerCase()}` }); for (const k of c.children) walk(k, "calendar"); return; }
      const n = counts.get(c.type) ?? 0; counts.set(c.type, n + 1);
      adaptComponent(c, `${path}/${c.type.toLowerCase()}[${n}]`, segments, findings);
    };
    for (const c of parseIcs(raw)) walk(c, "calendar");
    return { segments, findings };
  }
  let doc: unknown;
  try { doc = JSON.parse(raw); } catch { return { segments: [{ text: raw, visibility: "visible", path: "calendar/text" }], findings }; }
  const d = doc as Json;
  const events = Array.isArray(doc) ? doc : Array.isArray(d?.items) ? (d.items as unknown[]) : Array.isArray(d?.value) ? (d.value as unknown[]) : [doc];
  events.slice(0, 2000).forEach((e, i) => { if (e && typeof e === "object") adaptEventJson(e as Json, `calendar/event[${i}]`, segments, findings); });
  return { segments, findings };
}
