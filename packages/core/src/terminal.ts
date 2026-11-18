/**
 * Logs and terminal output.
 *
 * Two things make this channel different from a document:
 *
 *   1. Other people write parts of it. A web server's log holds whatever a visitor put in a User-Agent
 *      header; an error message quotes whatever input caused it. An agent asked to "look at the logs" is
 *      reading text from strangers.
 *
 *   2. A terminal does not show what the bytes say. Control codes can conceal text (SGR 8), paint it in the
 *      background colour, write a line and then erase or overwrite it, or clear the screen and the
 *      scrollback. A person watching the terminal sees the end state; a model reading the bytes sees
 *      everything. That gap is the one Ingress exists to close.
 *
 * This adapter replays the bytes the way a terminal would, far enough to tell what a person would still
 * see from what was hidden from them. Hidden text becomes a concealed segment (so the meaning pass reads it
 * as hidden), and control codes that act on the person's machine rather than the display (clipboard writes,
 * link text that names a different address) are reported.
 */

import type { Finding, TextSegment } from "./types.js";

export interface TerminalAdapterResult {
  segments: TextSegment[];
  findings: Finding[];
}

interface Cell { ch: string; concealed: boolean }

const ESC = "\x1b";
/** hidden text shorter than this is spinner frames and progress bars, not a message */
const MIN_HIDDEN_CHARS = 16;
const MAX_LINES = 200_000;

function sgrState(params: string, st: { conceal: boolean; fg: string; bg: string }) {
  const p = params === "" ? [0] : params.split(/[;:]/).map((x) => (x === "" ? 0 : Number(x)));
  for (let i = 0; i < p.length; i++) {
    const n = p[i];
    if (n === 0) { st.conceal = false; st.fg = ""; st.bg = ""; }
    else if (n === 8) st.conceal = true;
    else if (n === 28) st.conceal = false;
    else if ((n >= 30 && n <= 37) || (n >= 90 && n <= 97)) st.fg = `c${n >= 90 ? n - 90 + 8 : n - 30}`;
    else if ((n >= 40 && n <= 47) || (n >= 100 && n <= 107)) st.bg = `c${n >= 100 ? n - 100 + 8 : n - 40}`;
    else if (n === 39) st.fg = "";
    else if (n === 49) st.bg = "";
    else if (n === 38 || n === 48) {
      // 38;5;n (palette) or 38;2;r;g;b (true colour)
      let v = "";
      if (p[i + 1] === 5) { v = `c${p[i + 2]}`; i += 2; }
      else if (p[i + 1] === 2) { v = `rgb${p[i + 2]},${p[i + 3]},${p[i + 4]}`; i += 4; }
      if (n === 38) st.fg = v; else st.bg = v;
    }
  }
}

/**
 * Replay terminal output. Returns what a person would still see, and what was hidden from them.
 * Text without control codes comes back unchanged as one visible segment.
 */
export function adaptTerminal(raw: string): TerminalAdapterResult {
  const findings: Finding[] = [];
  // fast path: nothing a terminal would interpret (tabs and newlines aside)
  if (!/[\x00-\x08\x0b-\x1f\x7f\x9b]/.test(raw)) return { segments: [{ text: raw, visibility: "visible", path: "log" }], findings };

  const lines: Cell[][] = [[]];
  let row = 0, col = 0;
  const st = { conceal: false, fg: "", bg: "" };
  const hidden: Array<{ text: string; why: string }> = [];
  const lost = (cells: Cell[], why: string) => {
    const t = cells.map((c) => c.ch).join("").trim();
    if (t) hidden.push({ text: t, why });
  };
  const cur = () => (lines[row] ??= []);
  const put = (ch: string) => {
    const line = cur();
    while (line.length < col) line.push({ ch: " ", concealed: false });
    const concealed = st.conceal || (st.fg !== "" && st.fg === st.bg);
    // writing over text that is already there hides it; keep the whole run that was replaced, in order
    const before = line[col];
    if (before) overwritten.push(before.ch); else flushOverwritten();
    line[col] = { ch, concealed };
    col++;
  };
  let overwritten: string[] = [];
  const flushOverwritten = () => { if (overwritten.length) { const t = overwritten.join("").trim(); if (t) hidden.push({ text: t, why: "overwritten" }); overwritten = []; } };

  let osc8Url = "", osc8Text = "";
  let controls = 0;
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (ch === "\n") { flushOverwritten(); row++; col = 0; if (row > MAX_LINES) break; lines[row] ??= []; continue; }
    if (ch === "\r") { flushOverwritten(); col = 0; continue; } // each rewrite of a line is its own frame
    if (ch === "\b" || ch === "\x7f") { if (col > 0) col--; controls++; continue; }
    if (ch === "\t") { const next = (Math.floor(col / 8) + 1) * 8; while (col < next) put(" "); continue; }
    if (ch === ESC || ch === "\x9b") {
      const next = ch === "\x9b" ? "[" : raw[i + 1];
      const start = ch === "\x9b" ? i + 1 : i + 2;
      if (next === "[") {
        // CSI: parameters, intermediates, one final byte
        const m = /^([0-9;:<=>?]*)([ -/]*)([@-~])/.exec(raw.slice(start, start + 64));
        if (!m) { i = start - 1; continue; }
        i = start + m[0].length - 1;
        controls++;
        const [, params, , final] = m;
        const n = Number(params.split(";")[0] || 0);
        if (final === "m") sgrState(params, st);
        else if (final === "K") {
          flushOverwritten();
          const line = cur();
          if (n === 0) lost(line.splice(col), "erased");
          else if (n === 1) { lost(line.slice(0, col + 1), "erased"); for (let k = 0; k <= col && k < line.length; k++) line[k] = { ch: " ", concealed: false }; }
          else { lost(line.splice(0), "erased"); }
        } else if (final === "J") {
          flushOverwritten();
          if (n === 2 || n === 3) {
            // the screen (2) or the screen and scrollback (3): everything so far is gone from view
            for (const l of lines) lost(l, n === 3 ? "cleared with the scrollback" : "cleared from the screen");
            lines.length = 0; lines.push([]); row = 0; col = 0;
          } else if (n === 0) { lost(cur().splice(col), "erased"); for (let r = row + 1; r < lines.length; r++) lost(lines[r].splice(0), "erased"); }
          else if (n === 1) { for (let r = 0; r < row; r++) lost(lines[r].splice(0), "erased"); }
        } else if (final === "A" || final === "F") { flushOverwritten(); row = Math.max(0, row - (n || 1)); if (final === "F") col = 0; }
        else if (final === "B" || final === "E") { flushOverwritten(); row += n || 1; lines[row] ??= []; if (final === "E") col = 0; }
        else if (final === "C") col += n || 1;
        else if (final === "D") col = Math.max(0, col - (n || 1));
        else if (final === "G") col = Math.max(0, (n || 1) - 1);
        else if (final === "H" || final === "f") { flushOverwritten(); const [r, c] = params.split(";").map((x) => Number(x || 1)); row = Math.max(0, (r || 1) - 1); col = Math.max(0, (c || 1) - 1); lines[row] ??= []; }
        else if (final === "M" || final === "X" || final === "P") { const line = cur(); lost(line.splice(col, final === "M" ? line.length : n || 1), "deleted"); }
        continue;
      }
      if (next === "]") {
        // OSC: up to BEL or ST
        const rest = raw.slice(start, start + 8192);
        const end = rest.search(/\x07|\x1b\\/);
        const body = end < 0 ? rest : rest.slice(0, end);
        i = start + (end < 0 ? rest.length : end + (rest[end] === "\x07" ? 1 : 2)) - 1;
        controls++;
        const code = body.split(";")[0];
        if (code === "52") {
          findings.push({ pass: "channel", kind: "visibility.terminal_control", confidence: 0.7, severity: 0.8, message: "terminal control code that writes to the clipboard (OSC 52): what a person pastes next would not be what they copied", excerpt: body.slice(0, 80), location: "log", action: "neutralized" });
        } else if (code === "8") {
          const url = body.split(";").slice(2).join(";");
          if (url) { osc8Url = url; osc8Text = ""; }
          else if (osc8Url) {
            // link closed: does the text name a different address than the link goes to?
            const shown = osc8Text.match(/\b(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})/i)?.[1]?.toLowerCase();
            let target = ""; try { target = new URL(osc8Url).hostname.toLowerCase(); } catch { /* not a URL */ }
            if (shown && target && shown !== target && !target.endsWith("." + shown)) {
              findings.push({ pass: "channel", kind: "visibility.terminal_control", confidence: 0.6, severity: 0.7, message: `terminal link shows ${shown} but goes to ${target}`, excerpt: `${osc8Text.slice(0, 60)} -> ${osc8Url.slice(0, 80)}`, location: "log", action: "none" });
            }
            osc8Url = "";
          }
        } else if ((code === "0" || code === "1" || code === "2") && body.length > 3) {
          // window title: text the bytes carry and the scrollback never shows
          hidden.push({ text: body.slice(2), why: "set as the window title" });
        }
        continue;
      }
      // other two-byte escapes (charset selection, keypad modes): skip the introducer and one byte
      if (next === "(" || next === ")" || next === "#") i += 2; else i += 1;
      controls++;
      continue;
    }
    if (ch < " " ) { controls++; continue; } // remaining C0 controls draw nothing
    if (osc8Url) osc8Text += ch;
    put(ch);
  }
  flushOverwritten();

  // concealed runs still on the grid (SGR 8, or the same colour for text and background)
  const visibleLines: string[] = [];
  for (const line of lines) {
    let vis = "", run = "";
    for (const c of line) {
      if (c.concealed) { run += c.ch; vis += " "; }
      else { if (run.trim()) hidden.push({ text: run.trim(), why: "painted so it cannot be seen" }); run = ""; vis += c.ch; }
    }
    if (run.trim()) hidden.push({ text: run.trim(), why: "painted so it cannot be seen" });
    visibleLines.push(vis.replace(/\s+$/, ""));
  }

  const segments: TextSegment[] = [{ text: visibleLines.join("\n"), visibility: "visible", path: "log" }];
  // spinners and progress bars rewrite the same line with short text; only a real message counts
  const messages = new Map<string, string>();
  for (const h of hidden) if (h.text.length >= MIN_HIDDEN_CHARS && /\p{L}{3,}/u.test(h.text)) messages.set(h.text, h.why);
  // a progress line overwritten by its own next frame is not hidden text: drop anything still visible, where
  // "still visible" ignores the numbers that change from frame to frame ("Downloading 45%" then "Downloading 46%")
  const frame = (t: string) => t.replace(/[\d.,:%/|\\\-=>#*\[\]()█▏▎▍▌▋▊▉░▒▓⠀-⣿\s]+/g, " ").trim();
  const shownFrames = frame(visibleLines.join("\n"));
  let n = 0;
  const seenFrames = new Set<string>();
  for (const [text, why] of messages) {
    const f = frame(text);
    // a spinner's frames differ only in the spinner: one status line replaced by its result is reported once
    if (f.length < 8 || shownFrames.includes(f) || seenFrames.has(f)) continue;
    seenFrames.add(f);
    segments.push({ text, visibility: "concealed", path: `log/hidden[${n++}]` });
    findings.push({ pass: "visibility", kind: "visibility.terminal_hidden", confidence: 0.45, severity: 0.6, message: `text a terminal would not show a person: ${why}`, excerpt: text.slice(0, 160), location: "log", action: "neutralized" });
  }
  void controls;
  return { segments, findings };
}
