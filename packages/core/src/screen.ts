/**
 * Screens: interface elements that are part of the picture rather than part of the machine.
 *
 * A page can draw a browser window inside itself: a title, an address bar reading some other site's address,
 * a sign-in form underneath ("browser in the browser"). It can draw an operating-system dialog asking for a
 * password. In a picture, a drawn window and a real one are the same pixels, so appearance alone settles
 * nothing, with one exception that the caller has to supply:
 *
 *   capture: "viewport"   the picture is a capture of a page's content area only (what a browser-automation
 *                         tool's screenshot is). Real browser chrome and real system dialogs are never in such
 *                         a picture. An address bar or a system dialog seen in one was painted by the page.
 *
 * Without that, a picture of a whole screen or window with two address bars in it is a pop-up over a browser:
 * usually real. That case is recorded as a note with next to no weight.
 *
 * Even in a viewport capture this is not proof of an attack: a help page with a screenshot of a sign-in window
 * looks the same. So nothing here reaches "hostile" on its own, and it reaches "suspect" on its own only when
 * the caller also says which site the page is on and the drawn address bar names a different one. With other
 * evidence in the same picture (instructions, a paste-this lure, words the page's own source does not have)
 * the ordinary scoring adds them up.
 *
 * Measured on ordinary screenshots: see docs/IMAGES.md ("Interface elements drawn into a page").
 */

import { siteOf } from "./supplychain.js";
import type { Finding } from "./types.js";

export interface ScreenLine { text: string; conf: number; x: number; y: number; w: number; h: number }
export interface ScreenRect { x: number; y: number; w: number; h: number; conf?: number }
export interface ScreenHints {
  /** how the picture was taken, when the caller knows */
  capture?: "viewport" | "window" | "unknown";
  /** the host of the page a viewport capture shows */
  pageHost?: string;
}
export interface DrawnElement {
  what: "browser-window" | "system-dialog";
  /** the host the drawn address bar names */
  host?: string;
  /** was the element found inside a rectangle that sits wholly inside the picture? */
  framed: boolean;
  /** does it ask for a password or a sign-in? */
  credentials: boolean;
}

/** a line that is nothing but an address: what an address bar shows */
const BAR = /^(?:[^\p{L}\p{N}]{0,3}|(?:not )?secure\s*\|?\s*)?(?:https?:\/\/)?((?:[a-z0-9](?:[a-z0-9-]{0,62})\.)+[a-z]{2,24})(?::\d{2,5})?(?:[/?#]\S*)?$/iu;
const CREDENTIAL = /\b(?:sign[ -]?in|log[ -]?in|password|passcode|passphrase|email or phone|user ?name|verify (?:it'?s|that it'?s) you|verify your identity|one[- ]time code|verification code|2-step|two[- ]factor|continue with (?:google|apple|microsoft|facebook|github))\b/i;
const PASSWORD = /\b(?:password|passcode|passphrase)\b/i;
const SYSTEM_DIALOG = [
  /["“][^"”]{2,40}["”] (?:would like to|wants to|is trying to) (?:access|use|control|make changes|record|receive|send|find|install|modify|add|administer)\b/i,
  /\bdo you want to allow this app to make changes to your (?:device|computer|pc)\b/i,
  /\b(?:macos|system (?:preferences|settings)|software update|installer|keychain(?: access)?|finder|windows security) (?:wants|is trying|needs) to\b/i,
  /\benter (?:your|an administrator'?s?(?: name and)?|the) (?:mac |windows |login |computer )?password to (?:allow|continue|make|unlock)\b/i,
  /\b(?:use )?touch id or enter your password\b/i,
  /\buser account control\b/i,
];

const inside = (l: ScreenLine, r: ScreenRect) => { const cx = l.x + l.w / 2, cy = l.y + l.h / 2; return cx >= r.x && cx <= r.x + r.w && cy >= r.y && cy <= r.y + r.h; };
/** a rectangle that is an element in the picture, not the picture's own edge and not a speck */
const element = (r: ScreenRect) => r.x > 0.01 && r.y > 0.01 && r.x + r.w < 0.99 && r.y + r.h < 0.99 && r.w * r.h >= 0.03 && r.w * r.h <= 0.8;

/**
 * Interface elements that look drawn into the picture. Pure geometry and wording; what they are worth depends
 * on how the picture was taken (see `screenFindings`).
 */
export function drawnElements(lines: readonly ScreenLine[], rects: readonly ScreenRect[] = []): { elements: DrawnElement[]; topBarHost?: string } {
  const out: DrawnElement[] = [];
  const good = lines.filter((l) => l.conf >= 0.4 && l.text.trim().length >= 2);
  const frames = rects.filter(element).sort((a, b) => a.w * a.h - b.w * b.h);
  const bars = good.map((l) => ({ l, host: BAR.exec(l.text.trim().replace(/\s+/g, ""))?.[1]?.toLowerCase() })).filter((b): b is { l: ScreenLine; host: string } => !!b.host && !b.l.text.includes("@") && b.l.text.trim().length <= 140);
  // the bar of the window the picture was taken of, when it shows one: an address in the top strip
  const top = bars.find((b) => b.l.y < 0.1);

  for (const b of bars) {
    if (b.l.y < 0.12) continue;
    // the smallest rectangle that has this address in its top quarter: the drawn window
    const frame = frames.find((r) => inside(b.l, r) && b.l.y + b.l.h / 2 - r.y <= r.h * 0.3);
    // what is under the bar: inside that rectangle, or failing one, in a band below the bar
    const below = good.filter((l) => l !== b.l && l.y > b.l.y && (frame ? inside(l, frame) : l.y - b.l.y <= 0.5 && l.x + l.w >= b.l.x - 0.12 && l.x <= b.l.x + b.l.w + 0.12));
    const asks = below.filter((l) => CREDENTIAL.test(l.text));
    // a sign-in form, not a mention: at least two such lines, one of them short (a label or a button)
    if (asks.length < 2 || !asks.some((l) => l.text.trim().split(/\s+/).length <= 4)) continue;
    if (out.some((e) => e.what === "browser-window" && e.host === b.host)) continue;
    out.push({ what: "browser-window", host: b.host, framed: !!frame, credentials: true });
  }

  // a system dialog's wording, with its buttons nearby
  const groups: ScreenLine[][] = frames.length ? frames.map((r) => good.filter((l) => inside(l, r))).filter((g) => g.length >= 2) : [];
  groups.push([...good]);
  for (const [i, g] of groups.entries()) {
    const text = g.map((l) => l.text).join(" ").replace(/\s+/g, " ");
    if (!SYSTEM_DIALOG.some((re) => re.test(text))) continue;
    const buttons = g.filter((l) => /^(?:allow|don[’']t allow|deny|ok|cancel|yes|no|continue|use password…?|unlock|install(?: software)?|always allow)$/i.test(l.text.trim())).length;
    if (buttons < 1) continue;
    const framed = i < groups.length - 1;
    if (out.some((e) => e.what === "system-dialog")) { if (framed) out.find((e) => e.what === "system-dialog")!.framed = true; continue; }
    out.push({ what: "system-dialog", framed, credentials: PASSWORD.test(text) });
  }
  return { elements: out, topBarHost: top?.host };
}

/** What the drawn elements are worth, given how the picture was taken. */
export function screenFindings(lines: readonly ScreenLine[], rects: readonly ScreenRect[] | undefined, hints: ScreenHints = {}): Finding[] {
  const { elements, topBarHost } = drawnElements(lines, rects ?? []);
  const findings: Finding[] = [];
  const add = (f: Omit<Finding, "pass" | "action">) => findings.push({ pass: "channel", action: "none", ...f });
  const viewport = hints.capture === "viewport";
  const pageSite = hints.pageHost ? siteOf(hints.pageHost) : undefined;
  for (const e of elements) {
    if (e.what === "browser-window") {
      if (viewport) {
        const other = !!pageSite && !!e.host && siteOf(e.host) !== pageSite;
        add({
          kind: "image.drawn_browser_window", confidence: other ? 0.5 : 0.3, severity: other ? 0.65 : 0.6,
          message: `a browser window is drawn inside this page: an address bar reading ${e.host}, with a sign-in form under it${other ? `, on a page served from ${hints.pageHost}` : ""}. A capture of a page's content area never contains the browser's own address bar, so the page painted this one. Whatever is typed into it goes to the page, not to ${e.host}`,
          location: "image/text",
        });
      } else if (topBarHost && e.host && siteOf(topBarHost) !== siteOf(e.host)) {
        add({
          kind: "image.drawn_browser_window", confidence: 0.1, severity: 0.5,
          message: `a second window with its own address bar (${e.host}) and a sign-in form sits inside a window showing ${topBarHost}. A real pop-up and one drawn by the page look the same in a picture: check where the page really is before typing into it`,
          location: "image/text",
        });
      }
    } else if (viewport) {
      add({
        kind: "image.drawn_system_dialog", confidence: e.credentials ? 0.45 : 0.3, severity: e.credentials ? 0.65 : 0.6,
        message: `an operating-system dialog is drawn inside this page${e.credentials ? ", asking for a password" : ""}. A capture of a page's content area never contains a real system dialog, so the page painted it. A page cannot ask for the computer's password or grant itself access`,
        location: "image/text",
      });
    }
  }
  return findings;
}
