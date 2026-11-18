/**
 * Shortcuts: reading an automation before it is installed.
 *
 * A shared shortcut is a program someone else wrote that runs with your contacts, photos, files, messages and
 * network. Its actions are listed in the file. This scanner reads them and says what the shortcut can do, in
 * three questions that matter together:
 *
 *   does it read private data?        contacts, photos, files, the clipboard, location, messages, health
 *   does it take input from outside?  the contents of a web address, a page, a feed, whatever is shared to it
 *   can it send things out?           a web request with a body, a message, an email, a post, a remote script
 *
 * Any one is ordinary. All three in one shortcut is a program that can be told from outside to send your data
 * somewhere, and it is reported as that. Running code (shell, AppleScript, JavaScript on a page, SSH) and
 * running other shortcuts are reported. Every piece of text in it (comments, message bodies, scripts, URLs)
 * is scanned like any other content.
 *
 * Input: the shortcut as JSON or an XML property list (`plutil -convert json -o - file.shortcut` gives JSON).
 * A signed shortcut exported from the app is encrypted to Apple's format and cannot be read here; one opened
 * from a shared link, or saved unsigned, can.
 */

import type { Finding, TextSegment } from "./types.js";
import type { AdapterResult } from "./adapters.js";
import { linkTrick } from "./messages.js";

type Json = Record<string, unknown>;
export interface ShortcutAction { id: string; params: Json }
export interface ShortcutSummary {
  actions: number;
  readsPrivate: string[];
  outsideInput: string[];
  sendsOut: string[];
  runsCode: string[];
  runsOtherShortcuts: string[];
  destinations: string[];
  acceptsSharedInput: boolean;
}

const short = (id: string) => id.replace(/^is\.workflow\.actions\./, "").replace(/^com\.apple\./, "");

const PRIVATE: Array<[RegExp, string]> = [
  [/contacts?$|selectcontacts|getcontact|filter\.contacts/i, "contacts"], [/photos?$|selectphoto|getlastphoto|getlatestlivephotos|filter\.photos|takephoto|getlastscreenshot/i, "photos"],
  [/getclipboard/i, "the clipboard"], [/location$|getcurrentlocation|getmylocation/i, "your location"], [/health\.quantity|filter\.health/i, "health data"],
  [/documentpicker\.open|file\.getfoldercontents|file$|getfile|filter\.files|file\.select/i, "files"], [/getmessages|searchmessages|filter\.messages|imessage\.search/i, "messages"],
  [/filter\.calendarevents|getupcomingevents|filter\.reminders|getupcomingreminders/i, "calendar and reminders"], [/filter\.notes|shownote|getnote/i, "notes"],
  [/getwifi|getipaddress|getdevicedetails|getbatterylevel/i, "device details"], [/dictatetext|recordaudio/i, "the microphone"], [/safari\.geturl|getcurrenturl|getarticle.*safari|readinglist/i, "what you are browsing"],
  [/mail\.search|getemails|filter\.mail/i, "email"], [/password|keychain/i, "saved passwords"],
];
const OUTSIDE: Array<[RegExp, string]> = [
  [/downloadurl$/i, "the contents of a web address"], [/getwebpagecontents|getarticle|gethtmlfromrichtext/i, "a web page"], [/rss|getitemsfromfeed|rss\.extract/i, "a feed"],
  [/url\.expand|getheadersofurl/i, "a web address's reply"], [/detect\.link|geturlcomponent/i, "links found in its input"], [/scanbarcode/i, "a scanned code"],
];
const SENDS: Array<[RegExp, string]> = [
  [/sendmessage|sendimessage/i, "sends a message"], [/sendemail|mail\.send/i, "sends an email"], [/airdropdocument/i, "sends over AirDrop"],
  [/postonfacebook|tweet|postto|instagram|tumblr|wordpress|slack|discord|telegram|whatsapp\.send/i, "posts to a service"], [/dropbox\.savefile|box\.savefile|evernote|uploadto|imgur|cloudapp|pastebin/i, "uploads to a service"],
  [/runsshscript/i, "runs a script on another machine"], [/share$|showsharesheet/i, "opens the share sheet"], [/openurl$|openxcallbackurl|openin$/i, "opens a web address or another app"],
];
const CODE: Array<[RegExp, string]> = [
  [/runshellscript/i, "a shell script"], [/runapplescript|runjavascriptforautomation/i, "AppleScript or JavaScript for Automation"], [/runjavascriptonwebpage/i, "JavaScript on a web page"], [/runsshscript/i, "a script over SSH"],
];

export function looksLikeShortcut(doc: unknown): boolean {
  return !!doc && typeof doc === "object" && !Array.isArray(doc) && Array.isArray((doc as Json).WFWorkflowActions);
}

/** A property list in XML, as far as a shortcut needs: dictionaries, arrays, strings, numbers, booleans. */
export function parsePlistXml(xml: string): unknown {
  const tokens = [...xml.matchAll(/<(\/?)(plist|dict|array|key|string|integer|real|true|false|data|date)\b[^>]*?(\/?)>|([^<]+)/g)];
  let i = 0;
  const dec = (s: string) => s.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n))).replace(/&#x([0-9a-f]+);/gi, (_, n) => String.fromCodePoint(parseInt(n, 16))).replace(/&amp;/g, "&");
  const textUntilClose = (tag: string): string => { let s = ""; while (i < tokens.length && !(tokens[i][1] === "/" && tokens[i][2] === tag)) { s += tokens[i][4] ?? ""; i++; } i++; return dec(s); };
  const value = (depth: number): unknown => {
    while (i < tokens.length && tokens[i][4] !== undefined) i++; // whitespace between elements
    const t = tokens[i++];
    if (!t || depth > 64) return undefined;
    const tag = t[2], selfClosing = t[3] === "/";
    if (tag === "true") return true;
    if (tag === "false") return false;
    if (selfClosing) return tag === "dict" ? {} : tag === "array" ? [] : "";
    if (tag === "string" || tag === "data" || tag === "date") return textUntilClose(tag);
    if (tag === "integer" || tag === "real") return Number(textUntilClose(tag));
    if (tag === "array") { const a: unknown[] = []; for (;;) { while (i < tokens.length && tokens[i][4] !== undefined) i++; if (i >= tokens.length || (tokens[i][1] === "/" && tokens[i][2] === "array")) { i++; break; } a.push(value(depth + 1)); if (a.length > 20_000) break; } return a; }
    if (tag === "dict") {
      const d: Json = {};
      for (;;) { while (i < tokens.length && tokens[i][4] !== undefined) i++; if (i >= tokens.length || (tokens[i][1] === "/" && tokens[i][2] === "dict")) { i++; break; } if (tokens[i][2] !== "key") { i++; continue; } i++; const k = textUntilClose("key"); d[k] = value(depth + 1); }
      return d;
    }
    if (tag === "plist") return value(depth + 1);
    return undefined;
  };
  return value(0);
}

/** every string inside an action's parameters, with the path to it */
function strings(v: unknown, path: string, out: Array<{ path: string; text: string }>, depth = 0): void {
  if (depth > 12 || out.length > 4000) return;
  if (typeof v === "string") { if (v.trim().length >= 2 && !/^[0-9A-F]{8}-[0-9A-F]{4}-/i.test(v)) out.push({ path, text: v }); }
  else if (Array.isArray(v)) v.slice(0, 500).forEach((x, i) => strings(x, `${path}[${i}]`, out, depth + 1));
  else if (v && typeof v === "object") for (const [k, x] of Object.entries(v as Json)) { if (!/^(UUID|GroupingIdentifier|WFSerializationType|OutputUUID|CustomOutputName|Type|WFControlFlowMode)$/.test(k)) strings(x, path ? `${path}.${k}` : k, out, depth + 1); }
}

export function summarizeShortcut(doc: unknown): { summary: ShortcutSummary; actions: ShortcutAction[] } {
  const d = (doc ?? {}) as Json;
  const actions: ShortcutAction[] = (Array.isArray(d.WFWorkflowActions) ? d.WFWorkflowActions : []).slice(0, 5000).map((a) => ({ id: String((a as Json)?.WFWorkflowActionIdentifier ?? ""), params: (((a as Json)?.WFWorkflowActionParameters ?? {}) as Json) }));
  const s: ShortcutSummary = { actions: actions.length, readsPrivate: [], outsideInput: [], sendsOut: [], runsCode: [], runsOtherShortcuts: [], destinations: [], acceptsSharedInput: Array.isArray(d.WFWorkflowInputContentItemClasses) && (d.WFWorkflowInputContentItemClasses as unknown[]).length > 0 && Array.isArray(d.WFWorkflowTypes) && (d.WFWorkflowTypes as unknown[]).some((t) => /ActionExtension|Share|QuickActions|ReceivesOnScreenContent/i.test(String(t))) };
  const push = (list: string[], v: string) => { if (!list.includes(v)) list.push(v); };
  for (const a of actions) {
    const id = short(a.id);
    for (const [re, what] of PRIVATE) if (re.test(id)) push(s.readsPrivate, what);
    for (const [re, what] of OUTSIDE) if (re.test(id)) push(s.outsideInput, what);
    for (const [re, what] of SENDS) if (re.test(id)) push(s.sendsOut, what);
    for (const [re, what] of CODE) if (re.test(id)) push(s.runsCode, what);
    if (/runworkflow$/i.test(id)) push(s.runsOtherShortcuts, String((a.params.WFWorkflowName as string) ?? ((a.params.WFWorkflow as Json)?.workflowName as string) ?? "another shortcut").slice(0, 60));
    // a web request that carries a body is a way out, whatever the action is called
    if (/downloadurl$/i.test(id)) {
      const method = String(a.params.WFHTTPMethod ?? "GET").toUpperCase();
      if (method !== "GET" || a.params.WFHTTPBodyType || a.params.WFFormValues || a.params.WFJSONValues || a.params.WFRequestVariable) push(s.sendsOut, `sends a web request with a body (${method})`);
    }
    const found: Array<{ path: string; text: string }> = [];
    strings(a.params, "", found);
    for (const f of found) for (const m of f.text.matchAll(/\bhttps?:\/\/[^\s"'<>￼]+|\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b|(?<!\d)\+\d[\d\s().-]{7,}\d/g)) push(s.destinations, m[0].slice(0, 120));
  }
  if (s.acceptsSharedInput) push(s.outsideInput, "whatever is shared to it from other apps");
  return { summary: s, actions };
}

export function adaptShortcut(raw: string): AdapterResult {
  const segments: TextSegment[] = [];
  const findings: Finding[] = [];
  const add = (f: Omit<Finding, "pass" | "action">) => findings.push({ pass: "channel", action: "none", ...f });
  let doc: unknown;
  const head = raw.trimStart();
  if (head.startsWith("{")) { try { doc = JSON.parse(raw); } catch { doc = undefined; } }
  else if (/^(?:<\?xml|<!DOCTYPE plist|<plist)/i.test(head)) { try { doc = parsePlistXml(raw); } catch { doc = undefined; } }
  if (!looksLikeShortcut(doc)) {
    // not a shortcut this reader understands: scanned as text, and said
    segments.push({ text: raw, visibility: "visible", path: "automation/text" });
    if (/^AEA1|^bplist00/.test(head)) add({ kind: "automation.unreadable", confidence: 0.1, severity: 0.2, message: head.startsWith("AEA1") ? "a signed shortcut is encrypted to Apple's format and its actions cannot be read here: nothing in it was checked" : "a binary property list: convert it with `plutil -convert json -o - <file>` and scan that" });
    return { segments, findings };
  }
  const { summary: s, actions } = summarizeShortcut(doc);
  const name = String((doc as Json).WFWorkflowName ?? "");
  // what it says about itself, and every piece of text inside it
  segments.push({ text: [`Shortcut${name ? ` "${name}"` : ""}: ${s.actions} actions.`, s.readsPrivate.length ? `Reads: ${s.readsPrivate.join(", ")}.` : "", s.outsideInput.length ? `Takes in: ${s.outsideInput.join(", ")}.` : "", s.sendsOut.length ? `Can send out: ${s.sendsOut.join("; ")}.` : "", s.runsCode.length ? `Runs: ${s.runsCode.join(", ")}.` : "", s.destinations.length ? `Addresses written into it: ${s.destinations.slice(0, 12).join(", ")}.` : ""].filter(Boolean).join("\n"), visibility: "visible", path: "automation/summary" });
  actions.forEach((a, i) => {
    const found: Array<{ path: string; text: string }> = [];
    strings(a.params, "", found);
    // a comment is written for the person; everything else is a parameter nobody reads in a long shortcut
    for (const f of found) segments.push({ text: f.text.replace(/￼/g, " "), visibility: /comment$/i.test(a.id) ? "visible" : "attribute", path: `automation/action[${i}]:${short(a.id)}/${f.path}` });
  });

  if (s.readsPrivate.length && s.outsideInput.length && s.sendsOut.length) {
    add({ kind: "automation.private_outside_send", confidence: 0.5, severity: 0.7, message: `this shortcut reads ${s.readsPrivate.slice(0, 3).join(", ")}, takes in ${s.outsideInput.slice(0, 2).join(" and ")}, and can send things out (${s.sendsOut.slice(0, 2).join("; ")}): content from outside can steer where your data goes` });
  } else if (s.readsPrivate.length && s.sendsOut.some((x) => /web request|script on another|posts to|uploads to/.test(x))) {
    add({ kind: "automation.private_outside_send", confidence: 0.3, severity: 0.6, message: `this shortcut reads ${s.readsPrivate.slice(0, 3).join(", ")} and can send to a server (${s.sendsOut.filter((x) => /web request|script on another|posts to|uploads to/.test(x)).slice(0, 2).join("; ")})` });
  }
  if (s.runsCode.length) add({ kind: "automation.runs_code", confidence: 0.35, severity: 0.6, message: `this shortcut runs ${s.runsCode.join(", ")}: read the script before installing it` });
  if (s.runsOtherShortcuts.length) add({ kind: "automation.runs_code", confidence: 0.1, severity: 0.3, message: `this shortcut runs other shortcuts (${s.runsOtherShortcuts.slice(0, 4).join(", ")}), which were not read` });
  const tricks = s.destinations.filter((x) => /^https?:/i.test(x)).map((u) => [u, linkTrick(u)] as const).filter(([, t]) => t);
  if (tricks.length) add({ kind: "automation.destination", confidence: 0.4, severity: 0.6, message: `an address written into the shortcut is ${tricks[0][1]}`, excerpt: tricks[0][0].slice(0, 120) });
  return { segments, findings };
}
