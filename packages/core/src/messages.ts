/**
 * Messages and notifications: chat, text messages, and the banners an operating system shows.
 *
 * These are the channels where anyone can write to you. In a group chat or a shared channel one participant's
 * message is, to an assistant reading the conversation, as present as everyone else's. A text message comes
 * from a number. A notification says who it is from, and the claim costs nothing to make.
 *
 * The adapters turn each message into segments and check what the channel's own structure gives away:
 *
 *   what the app shows vs. what an API consumer reads   Slack renders `blocks` and keeps `text` for
 *       notifications; Teams has a `summary` beside the body. Words in the unseen one are concealed text.
 *   link previews            written by the linked site, not the sender; a preview's plain-text fallback is
 *       shown nowhere
 *   sender names             a display name is free text: "System", "IT Support", "[ADMIN]" from a bot, a
 *       webhook or an outsider is a costume
 *   scam shape               an unknown sender, a link that hides where it goes, and pressure or a request for
 *       a code, a password or a payment
 *   verification codes       noted: a code in a message is for the person. The action broker refuses to let
 *       one be sent to a destination that came from content (see egress.ts)
 *   notifications            an alarm in the system's or a brand's voice, delivered by a web browser
 *
 * Trust is per scan. A caller that knows a conversation is with a known contact says so with `source.trust`;
 * a group chat or channel is an open channel (5), an unknown number a stranger (4).
 *
 * Not inspected, and said so: voice messages, stickers, files. Pictures go through scanImage when the caller
 * has their bytes.
 */

import type { Finding, TextSegment } from "./types.js";
import { decodeEntities, type AdapterResult } from "./adapters.js";
import { analyzeHtml } from "./visibility.js";
import { passagesOnlyIn } from "./served.js";
import { oneTimeCodes } from "./egress.js";

type Json = Record<string, unknown>;
const str = (v: unknown) => (typeof v === "string" ? v : "");
const obj = (v: unknown): Json | undefined => (v && typeof v === "object" && !Array.isArray(v) ? (v as Json) : undefined);
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const MAX_ITEMS = 500;

// ---------- shapes ----------

export interface ChatMessage {
  /** the words the app shows */
  shown: string;
  /** true when `shown` is HTML (Teams, Matrix formatted bodies) */
  html: boolean;
  /** words an API consumer reads and the app does not show: a notification fallback, a summary */
  unseen: Array<{ field: string; text: string }>;
  sender: string;
  /** posted by a bot, an app or a webhook rather than a person's own client */
  automated: boolean;
  /** from outside the workspace, or forwarded from somewhere else */
  outside: boolean;
  /** the account's own message */
  self: boolean;
  /** an SMS-like service: the sender is a number or a short code */
  service: string;
  previews: Array<{ shown: string; fallback: string; url: string }>;
  files: string[];
  /** parts that exist and were not read */
  unread: string[];
}

/** text of Slack's block kit: what the app renders when blocks are present */
function blockText(blocks: unknown, out: string[] = [], depth = 0): string[] {
  if (depth > 8) return out;
  for (const b of arr(blocks)) {
    const o = obj(b);
    if (!o) continue;
    const t = o.text;
    if (typeof t === "string") out.push(t);
    else if (obj(t) && typeof obj(t)!.text === "string") out.push(obj(t)!.text as string);
    for (const k of ["fields", "elements", "accessory", "title", "label", "description", "placeholder", "alt_text"]) {
      const v = o[k];
      if (typeof v === "string") out.push(v);
      else if (Array.isArray(v)) blockText(v, out, depth + 1);
      else if (obj(v)) blockText([v], out, depth + 1);
    }
  }
  return out;
}

function one(m: unknown): ChatMessage | undefined {
  // Telegram wraps each update
  const top = obj(m);
  if (!top) return undefined;
  const o = obj(top.message) && (typeof top.update_id === "number" || !("text" in top)) ? obj(top.message)! : top;
  const msg: ChatMessage = { shown: "", html: false, unseen: [], sender: "", automated: false, outside: false, self: false, service: "", previews: [], files: [], unread: [] };

  const author = obj(o.author), from = obj(o.from), profile = obj(o.user_profile), body = obj(o.body);
  // sender, as the channel names them
  msg.sender = str(profile?.display_name) || str(profile?.real_name) || str(o.username) || str(author?.global_name) || str(author?.username) || str(author?.name)
    || str(obj(from?.user)?.displayName) || str(obj(from?.application)?.displayName) || [str(from?.first_name), str(from?.last_name)].filter(Boolean).join(" ") || str(from?.username) || str(from?.name) || str(from?.displayName)
    || str(o.sender_name) || str(o.senderName) || str(o.sender) || str(o.from) || str(o.handle) || str(o.author) || str(o.user_name) || str(o.user);
  msg.automated = !!(o.bot_id || o.webhook_id || o.app_id || author?.bot || from?.is_bot || obj(from?.application) || o.subtype === "bot_message" || o.via_bot || o.is_bot);
  msg.outside = !!(o.is_ext_shared || o.forward_from || o.forward_origin || o.forward_from_chat || o.forwarded || o.is_forwarded || o.external || (typeof o.user_team === "string" && typeof o.team === "string" && o.user_team !== o.team));
  msg.self = o.is_from_me === true || o.is_from_me === 1 || o.fromMe === true || o.outgoing === true;
  msg.service = str(o.service) || (typeof o.is_from_me !== "undefined" ? "SMS" : "") || str(o.channel_type) || str(o.platform);

  // the words
  const blocks = blockText(o.blocks);
  const text = str(o.text) || str(obj(o.text)?.body) || str(o.content) || str(o.caption) || (typeof o.body === "string" ? o.body : "") || (typeof o.message === "string" ? o.message : "") || str(o.snippet);
  if (body && typeof body.content === "string") { msg.shown = body.content; msg.html = /html/i.test(str(body.contentType)); }
  else if (typeof o.formatted_body === "string" && /html/i.test(str(o.format))) { msg.shown = o.formatted_body; msg.html = true; if (text) msg.unseen.push({ field: "body", text }); }
  else if (blocks.length) { msg.shown = blocks.join("\n"); if (text) msg.unseen.push({ field: "text", text }); }
  else msg.shown = text;
  for (const k of ["summary", "notification_text", "fallback", "preview_text"]) if (typeof o[k] === "string" && o[k]) msg.unseen.push({ field: k, text: o[k] as string });
  if (typeof o.subject === "string" && o.subject) msg.shown = `${o.subject}\n${msg.shown}`;

  // previews, embeds and cards: written by whoever controls the link
  for (const a of [...arr(o.attachments), ...arr(o.embeds), ...arr(o.link_previews)].slice(0, 20)) {
    const p = obj(a);
    if (!p) continue;
    const fields = arr(p.fields).map((f) => `${str(obj(f)?.title) || str(obj(f)?.name)} ${str(obj(f)?.value)}`.trim());
    const shown = [str(p.pretext), str(obj(p.author)?.name) || str(p.author_name), str(p.title), str(p.text) || str(p.description), ...fields, str(obj(p.footer)?.text) || (typeof p.footer === "string" ? p.footer : ""), ...blockText(p.blocks)].filter(Boolean).join("\n");
    const url = str(p.title_link) || str(p.url) || str(p.original_url) || str(p.from_url);
    if (typeof p.content === "string" && p.content.length > 2) msg.unread.push("a card");
    if (shown || p.fallback) msg.previews.push({ shown, fallback: str(p.fallback), url });
    if (str(p.filename) || (str(p.name) && (p.url || p.contentUrl))) msg.files.push(str(p.filename) || str(p.name));
  }
  for (const f of arr(o.files).slice(0, 20)) { const n = str(obj(f)?.title) || str(obj(f)?.name); if (n) msg.files.push(n); }
  for (const k of ["voice", "audio", "video", "sticker", "animation", "document", "photo"]) if (o[k]) msg.unread.push(k === "photo" ? "a picture" : `a ${k} part`);
  if (typeof o.type === "string" && /^(audio|voice|ptt|video|sticker|image|document)$/.test(o.type)) msg.unread.push(`a ${o.type} part`);

  if (!msg.shown && !msg.unseen.length && !msg.previews.length && !msg.files.length && !msg.unread.length) return undefined;
  return msg;
}

const LISTS = ["messages", "value", "items", "result", "results", "data", "history", "chats", "events"];

/** Messages in a chat API's JSON, in order. Lenient: used when the caller has said this is a conversation. */
export function parseMessages(doc: unknown): ChatMessage[] {
  const d = obj(doc);
  const list = Array.isArray(doc) ? doc : (LISTS.map((k) => d?.[k]).find(Array.isArray) as unknown[] | undefined) ?? (d ? [d] : []);
  return list.slice(0, MAX_ITEMS).map(one).filter((m): m is ChatMessage => !!m);
}

/** Is this JSON plainly a chat export or a chat API's reply? Strict: decides how unlabelled JSON is read. */
export function looksLikeMessagesJson(doc: unknown): boolean {
  const is = (m: unknown): boolean => {
    const t = obj(m);
    if (!t) return false;
    const o = obj(t.message) && typeof t.update_id === "number" ? obj(t.message)! : t;
    if ("subject" in o && ("from" in o || "sender" in o)) return false; // mail
    if (typeof o.ts === "string" && /^\d{9,}\.\d+$/.test(o.ts) && ("text" in o || "blocks" in o) && ("user" in o || "bot_id" in o || "username" in o)) return true; // Slack
    if (obj(o.author) && typeof obj(o.author)!.username === "string" && "content" in o && ("channel_id" in o || "timestamp" in o)) return true; // Discord
    if (typeof o.message_id === "number" && obj(o.chat) && (obj(o.from) || "sender_chat" in o)) return true; // Telegram
    if (obj(o.body) && typeof obj(o.body)!.content === "string" && obj(o.from) && ("createdDateTime" in o || "messageType" in o)) return true; // Teams
    if ("is_from_me" in o && ("text" in o || "body" in o)) return true; // Messages / SMS exports
    if (typeof o.type === "string" && typeof o.from === "string" && obj(o.text) && typeof obj(o.text)!.body === "string") return true; // WhatsApp Cloud API
    if (typeof o.sender === "string" && typeof o.event_id === "string" && obj(o.content)) return false; // Matrix events: nested content, read as JSON
    return false;
  };
  const d = obj(doc);
  const list = Array.isArray(doc) ? doc : (LISTS.map((k) => d?.[k]).find(Array.isArray) as unknown[] | undefined);
  if (list) return list.length > 0 && list.slice(0, 50).every(is);
  return is(doc);
}

// ---------- checks ----------

const AUTHORITY_NAME = /^\W*(?:system|sys ?admin|admin(?:istrator)?|root|security(?: team| alert)?|it(?: support| help ?desk| department)?|help ?desk|tech(?:nical)? support|support(?: team)?|moderator|mod team|compliance|human resources|hr(?: team)?|payroll|legal|the (?:ceo|cfo|cto|boss|management)|ceo|slack ?bot|workspace admin|claude|chatgpt|gemini|copilot|assistant|ai assistant|anthropic|openai|microsoft(?: support| security)?|apple(?: support| security)?|google(?: support| security)?|your bank|bank security|fraud (?:team|department|prevention))\W*$/i;
const ROLE_IN_NAME = /\[(?:system|admin|assistant|developer|instruction)[^\]]{0,20}\]|^\s*(?:system|assistant|developer)\s*:|<\|[^|]{1,24}\|>|#{3,}/i;
const PRESSURE = /\b(?:urgent(?:ly)?|immediately|right away|within \d+ ?(?:h|hrs?|hours?|min(?:ute)?s?)|final (?:notice|warning|reminder)|last (?:chance|warning)|act now|expires? (?:today|soon|in)|suspend(?:ed)?|locked|restricted|unusual (?:activity|sign-?in)|unauthori[sz]ed|overdue|unpaid|past due|penalt(?:y|ies)|legal action|arrest|failed delivery|could not be delivered|held at|customs fee|redelivery|toll|refund (?:is )?(?:pending|available)|you(?:'ve| have) won|prize|claim (?:your|it)|verify (?:your|now)|confirm (?:your|now)|update (?:your )?(?:payment|billing|details))\b/i;
const ASKS = /\b(?:(?:send|share|give|tell|text|reply with|forward|enter|provide|confirm)\b[^.\n]{0,40}\b(?:code|otp|pin|password|passcode|card (?:number|details)|cvv|ssn|social security|bank details|gift cards?|seed phrase|recovery phrase)|gift cards?|wire (?:the )?(?:money|funds|transfer)|bitcoin|crypto wallet|western union|zelle|cash ?app)\b/i;
const CLAIMS = /\b(?:(?:your |the )?bank|fraud (?:team|department|prevention)|security (?:team|department)|(?:customer|technical|tech) (?:service|support|care)|support team|help ?desk|your (?:provider|carrier|network)|tax office|revenue service|police|court|amazon|paypal|apple|microsoft|google|netflix|irs|hmrc|usps|fedex|dhl|ups)\b/i;
const LINK = /\bhttps?:\/\/[^\s<>"')\]]+|\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|co|me|info|biz|xyz|top|site|online|link|click|ly|gl|gd|cc|to|app|page|shop|live|icu|vip|cfd|sbs)(?:\/[^\s<>"')\]]*)?/gi;
const SHORTENER = /^(?:bit\.ly|t\.co|tinyurl\.com|goo\.gl|is\.gd|ow\.ly|buff\.ly|rebrand\.ly|cutt\.ly|rb\.gy|t\.ly|shorturl\.at|s\.id|tiny\.cc|lnkd\.in|v\.gd|qr\.ae|shorte\.st|bl\.ink|x\.co)$/i;

/** How a link hides where it goes, or undefined when it does not. */
export function linkTrick(link: string): string | undefined {
  let u: URL;
  try { u = new URL(/^https?:\/\//i.test(link) ? link : `https://${link}`); } catch { return "an address that does not parse"; }
  const h = u.hostname.toLowerCase();
  if (u.username || u.password) return "a name before the @ that is not the destination";
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(h)) return "a bare network address";
  if (/^xn--|\.xn--/.test(h)) return "an international name that may imitate another";
  if (SHORTENER.test(h)) return "a shortener";
  if (/\.(?:top|xyz|icu|vip|cfd|sbs|click|link|live|shop|online|site)$/.test(h) && /(?:secure|verify|login|account|update|support|billing|pay|refund|parcel|post|track|bank|apple|paypal|amazon|microsoft|netflix|usps|fedex|dhl|ups|gov|irs|tax)/.test(h)) return "a brand or a service name on an unrelated domain";
  if (h.split(".").length >= 5) return "a long chain of subdomains";
  return undefined;
}

/** plain text with its entities decoded, noting any that decode to characters nobody sees */
function plain(text: string, where: string, findings: Finding[]): string {
  const dec = decodeEntities(text);
  if (dec.suspicious > 0) findings.push({ pass: "character", kind: "unicode.entity_smuggling", confidence: Math.min(0.95, 0.6 + dec.suspicious * 0.05), severity: 0.7, message: `${dec.suspicious} HTML entities decoding to invisible or format characters`, excerpt: dec.sample, location: where, action: "neutralized" });
  return dec.text;
}

const senderIsNumber = (s: string) => /^\+?[\d\s().-]{4,}$/.test(s) || /^\d{3,6}$/.test(s.trim());

export function adaptMessages(raw: string): AdapterResult {
  const segments: TextSegment[] = [];
  const findings: Finding[] = [];
  let doc: unknown;
  try { doc = JSON.parse(raw); } catch { doc = undefined; }
  const add = (f: Omit<Finding, "pass" | "action">) => findings.push({ pass: "channel", action: "none", ...f });
  // not JSON: a transcript or a single message as plain text
  if (doc === undefined || (typeof doc !== "object")) {
    const text = plain(typeof doc === "string" ? doc : raw, "message/text", findings);
    segments.push({ text, visibility: "visible", path: "message/text" });
    scamShape(text, "", "", "message", add);
    for (const c of oneTimeCodes(text).slice(0, 1)) add({ kind: "message.verification_code", confidence: 0.02, severity: 0.1, message: `a verification code (ending ${c.slice(-2)}) in this message: a code is for the person` });
    return { segments, findings };
  }
  const msgs = parseMessages(doc);
  const unread = new Map<string, number>();
  const codes = new Set<string>();
  msgs.forEach((m, i) => {
    const path = `message[${i}]`;
    if (m.sender) segments.push({ text: m.sender, visibility: "visible", path: `${path}/sender` });
    let shownText = m.shown;
    if (m.html) {
      const v = analyzeHtml(m.shown);
      for (const s of v.segments) segments.push({ ...s, path: `${path}/html/${s.path}` });
      findings.push(...v.findings.map((f) => ({ ...f, location: `${path}/html${f.location ? `/${f.location}` : ""}` })));
      shownText = v.segments.map((s) => s.text).join(" ");
    } else if (m.shown.trim()) {
      // chat APIs escape a few characters as entities; decode them here, and notice ones that decode to nothing visible
      shownText = plain(m.shown, `${path}/text`, findings);
      segments.push({ text: shownText, visibility: "visible", path: `${path}/text` });
    }

    // words the app does not show
    const seen = [shownText, ...m.previews.map((p) => p.shown)].join(" ");
    for (const u of m.unseen) {
      const only = passagesOnlyIn(u.text, seen);
      if (!only.length) continue;
      add({ kind: "message.text_divergence", confidence: 0.45, severity: 0.7, message: `the "${u.field}" field says ${only.length} thing(s) the message as shown does not: an app displays one, a program reading the conversation gets both`, excerpt: only[0].slice(0, 160), location: `${path}/${u.field}`, inHidden: true });
      only.forEach((t, j) => segments.push({ text: t, visibility: "concealed", path: `${path}/${u.field}~unseen[${j}]` }));
    }
    m.previews.forEach((p, j) => {
      if (p.shown.trim()) segments.push({ text: p.shown, visibility: "visible", path: `${path}/preview[${j}]` });
      const only = p.fallback ? passagesOnlyIn(p.fallback, `${p.shown} ${shownText}`) : [];
      only.forEach((t, k) => segments.push({ text: t, visibility: "concealed", path: `${path}/preview[${j}]/fallback[${k}]` }));
      if (only.length) add({ kind: "message.text_divergence", confidence: 0.4, severity: 0.65, message: "a link preview's plain-text fallback says something the preview as shown does not", excerpt: only[0].slice(0, 160), location: `${path}/preview[${j}]`, inHidden: true });
    });
    if (m.files.length) segments.push({ text: m.files.join("\n"), visibility: "visible", path: `${path}/files` });
    for (const u of m.unread) unread.set(u, (unread.get(u) ?? 0) + 1);

    // who it says it is from
    if (m.sender && !m.self) {
      if (ROLE_IN_NAME.test(m.sender)) add({ kind: "message.sender_impersonation", confidence: 0.5, severity: 0.7, message: `a sender's display name is shaped like a system or role marker ("${m.sender.slice(0, 40)}")`, location: `${path}/sender` });
      else if (AUTHORITY_NAME.test(m.sender) && (m.automated || m.outside)) add({ kind: "message.sender_impersonation", confidence: 0.4, severity: 0.6, message: `"${m.sender.slice(0, 40)}" is a display name chosen by ${m.automated ? "a bot or webhook" : "someone outside the workspace"}: a name is not an identity`, location: `${path}/sender` });
    }
    if (!m.self) scamShape([shownText, ...m.previews.map((p) => p.shown)].join("\n"), m.sender, m.service, path, add);
    for (const c of oneTimeCodes(shownText)) codes.add(c);
  });
  if (codes.size) add({ kind: "message.verification_code", confidence: 0.02, severity: 0.1, message: `${codes.size} verification code(s) in these messages: a code is for the person. An action that carries one to a destination that came from content is refused by the action broker` });
  if (unread.size) add({ kind: "message.uninspected_part", confidence: 0.02, severity: 0.1, message: `not inspected: ${[...unread].map(([k, n]) => `${n} × ${k}`).join(", ")}` });
  return { segments, findings };
}

/** An unknown sender, a link that hides where it goes, and pressure or a request for a secret or money. */
function scamShape(text: string, sender: string, service: string, path: string, add: (f: Omit<Finding, "pass" | "action">) => void): void {
  if (text.length < 20) return;
  const links = [...text.matchAll(LINK)].map((m) => m[0]).slice(0, 10);
  const tricks = links.map(linkTrick).filter((t): t is string => !!t);
  const pressure = PRESSURE.test(text), asks = ASKS.test(text);
  const stranger = senderIsNumber(sender) || /sms|mms|rcs/i.test(service) || /^[^@\s]+@[^@\s]+$/.test(sender);
  // a hidden destination with pressure is the shape, whoever sent it; a plain link needs both pressure and a stranger
  const why: string[] = [];
  if (tricks.length) why.push(`a link that is ${tricks[0]}`);
  if (pressure) why.push("pressure to act now");
  if (asks) why.push("a request for a code, a password or a payment");
  // A scam text is short: it has one job. Long messages mention deadlines, links and payments all the time
  // (ordinary business mail read as if it were a text from a stranger tripped this 236 times in 3,000 before
  // the length limits).
  const words = text.trim().split(/\s+/).length;
  const strong = words <= 120 && ((tricks.length > 0 && (pressure || asks)) || (asks && pressure && links.length > 0));
  // "can you send me the door code again?" is how friends text; a stranger asking for a code in an institution's
  // name, or with a deadline, is the scam
  const claims = CLAIMS.test(text);
  if (claims && asks) why.push("in the name of an institution");
  const medium = !strong && words <= 60 && stranger && ((links.length > 0 && pressure) || (asks && (pressure || claims)));
  if (!strong && !medium) return;
  add({ kind: "message.scam_shape", confidence: strong ? 0.5 : 0.35, severity: 0.65, message: `shaped like a scam message${stranger ? " from an unknown sender" : ""}: ${why.join(", ")}`, location: `${path}/text` });
}

// ---------- notifications ----------

export interface Notification { app: string; origin: string; title: string; subtitle: string; body: string; sender: string; actions: string[]; payload: Array<{ field: string; text: string }> }

const APP_KEYS = ["app", "appName", "app_name", "application", "packageName", "package", "bundleId", "bundle_id", "bundleIdentifier", "source"];

function oneNote(n: unknown): Notification | undefined {
  const o = obj(n);
  if (!o) return undefined;
  const extras = obj(o.extras) ?? {};
  const note: Notification = {
    app: APP_KEYS.map((k) => str(o[k])).find(Boolean) ?? "",
    origin: str(o.origin) || (/^https?:\/\//.test(str(o.url)) ? str(o.url) : "") || str(o.scope),
    title: str(o.title) || str(extras["android.title"]) || str(o.heading),
    subtitle: str(o.subtitle) || str(o.subText) || str(extras["android.subText"]),
    body: str(o.body) || str(o.bigText) || str(extras["android.bigText"]) || str(o.text) || str(extras["android.text"]) || str(o.message) || str(o.content),
    sender: str(o.sender) || str(o.from) || str(extras["android.conversationTitle"]),
    actions: arr(o.actions).map((a) => (typeof a === "string" ? a : str(obj(a)?.title) || str(obj(a)?.label) || str(obj(a)?.action))).filter(Boolean).slice(0, 10),
    payload: [],
  };
  // fields a banner does not show: the ticker line, and whatever the sender attached for the app
  if (str(o.tickerText)) note.payload.push({ field: "tickerText", text: str(o.tickerText) });
  for (const k of ["data", "userInfo", "payload", "custom"]) {
    const walk = (v: unknown, p: string, depth: number) => {
      if (depth > 4 || note.payload.length > 40) return;
      if (typeof v === "string") { if (v.length >= 12 && /\s/.test(v)) note.payload.push({ field: p, text: v }); }
      else if (Array.isArray(v)) v.slice(0, 20).forEach((x, i) => walk(x, `${p}[${i}]`, depth + 1));
      else if (obj(v)) for (const [kk, x] of Object.entries(v as Json).slice(0, 40)) walk(x, `${p}.${kk}`, depth + 1);
    };
    walk(o[k], k, 0);
  }
  return note.title || note.body ? note : undefined;
}

export function parseNotifications(doc: unknown): Notification[] {
  const d = obj(doc);
  const list = Array.isArray(doc) ? doc : (["notifications", "items", "value", "results"].map((k) => d?.[k]).find(Array.isArray) as unknown[] | undefined) ?? (d ? [d] : []);
  return list.slice(0, MAX_ITEMS).map(oneNote).filter((n): n is Notification => !!n);
}

export function looksLikeNotificationJson(doc: unknown): boolean {
  const is = (n: unknown): boolean => {
    const o = obj(n);
    if (!o || "subject" in o) return false;
    const hasApp = APP_KEYS.slice(0, 9).some((k) => typeof o[k] === "string") || obj(o.extras) !== undefined || (typeof o.origin === "string" && "tag" in o);
    return hasApp && (typeof o.title === "string" || obj(o.extras) !== undefined) && ("body" in o || "text" in o || "bigText" in o || "subtitle" in o || obj(o.extras) !== undefined);
  };
  const d = obj(doc);
  const list = Array.isArray(doc) ? doc : (["notifications", "items"].map((k) => d?.[k]).find(Array.isArray) as unknown[] | undefined);
  if (list) return list.length > 0 && list.slice(0, 50).every(is);
  return is(doc);
}

const BROWSER = /\b(?:chrome|chromium|safari|firefox|edge|msedge|brave|opera|vivaldi|arc|duckduckgo|samsung internet|sbrowser)\b|^(?:com\.android\.chrome|com\.apple\.safari|org\.mozilla\.\w+|com\.microsoft\.(?:edge|emmx)|com\.brave\.\w+|com\.opera\.\w+)/i;
const SYSTEM_VOICE = /\b(?:virus(?:es)?|infected|malware|trojan|spyware|system (?:alert|warning|error|update|scan)|security (?:alert|warning|scan)|critical (?:alert|warning|error)|your (?:mac|pc|iphone|ipad|android|computer|device|phone|system|battery|storage|icloud|account) (?:is|has been|may be|was|will be)|(?:\d+|several|multiple) (?:threats?|virus(?:es)?|issues?) (?:found|detected)|scan now|clean now|protection (?:expired|has expired|disabled)|subscription (?:expired|has expired)|license (?:expired|has expired)|mcafee|norton|avast|kaspersky|windows defender|apple ?care|macos update)\b/i;
const BRANDS = ["apple", "icloud", "microsoft", "windows", "google", "gmail", "paypal", "amazon", "netflix", "facebook", "instagram", "whatsapp", "coinbase", "binance", "chase", "wells fargo", "bank of america", "citibank", "hsbc", "barclays", "usps", "fedex", "dhl", "ups", "irs", "hmrc"];

export function adaptNotifications(raw: string): AdapterResult {
  const segments: TextSegment[] = [];
  const findings: Finding[] = [];
  const add = (f: Omit<Finding, "pass" | "action">) => findings.push({ pass: "channel", action: "none", ...f });
  let doc: unknown;
  try { doc = JSON.parse(raw); } catch { doc = undefined; }
  if (doc === undefined || typeof doc !== "object") {
    segments.push({ text: plain(typeof doc === "string" ? doc : raw, "notification/text", findings), visibility: "visible", path: "notification/text" });
    return { segments, findings };
  }
  const codes = new Set<string>();
  parseNotifications(doc).forEach((n, i) => {
    const path = `notification[${i}]`;
    const shown = [n.title, n.subtitle, n.body].filter(Boolean).join("\n");
    if (n.sender) segments.push({ text: n.sender, visibility: "visible", path: `${path}/sender` });
    if (shown) segments.push({ text: shown, visibility: "visible", path: `${path}/text` });
    if (n.actions.length) segments.push({ text: n.actions.join("\n"), visibility: "visible", path: `${path}/actions` });
    for (const p of n.payload) for (const [j, t] of passagesOnlyIn(p.text, shown, 6).entries()) segments.push({ text: t, visibility: "concealed", path: `${path}/${p.field}[${j}]` });

    // an alarm in the system's voice, or a brand's, delivered by a web browser: any site a person once allowed can send it
    const viaWeb = !!n.origin || BROWSER.test(n.app);
    let host = "";
    try { host = n.origin ? new URL(n.origin).hostname.toLowerCase() : ""; } catch { /* no host */ }
    if (viaWeb && SYSTEM_VOICE.test(shown)) {
      add({ kind: "notification.source_mismatch", confidence: 0.55, severity: 0.65, message: `a notification speaking as the system or a security product was sent by a website${host ? ` (${host})` : ""} through the browser: the operating system does not announce itself that way`, location: `${path}/text` });
    } else if (viaWeb) {
      const brand = BRANDS.find((b) => new RegExp(`\\b${b}\\b`, "i").test(`${n.title} ${n.sender}`));
      if (brand && host && !host.replace(/[^a-z]/g, "").includes(brand.replace(/[^a-z]/g, "")) && (PRESSURE.test(shown) || ASKS.test(shown))) {
        add({ kind: "notification.source_mismatch", confidence: 0.45, severity: 0.6, message: `a notification in the name of ${brand} was sent by ${host}, with pressure to act`, location: `${path}/text` });
      }
    }
    if (ROLE_IN_NAME.test(n.sender) || ROLE_IN_NAME.test(n.title)) add({ kind: "message.sender_impersonation", confidence: 0.5, severity: 0.7, message: "a notification's title or sender is shaped like a system or role marker", location: `${path}/sender` });
    scamShape(shown, n.sender, "", path, add);
    for (const c of oneTimeCodes(shown)) codes.add(c);
  });
  if (codes.size) add({ kind: "message.verification_code", confidence: 0.02, severity: 0.1, message: `${codes.size} verification code(s) in these notifications: a code is for the person, and the action broker refuses to let one be sent to a destination that came from content` });
  return { segments, findings };
}
