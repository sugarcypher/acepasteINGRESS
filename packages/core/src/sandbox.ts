/**
 * Sandbox pass.
 *
 * Runs the page in a disposable headless Chromium context with no cookies,
 * no storage, no credentials, and egress limited to the page's own origin
 * plus stylesheets/scripts it references (so it renders) while every
 * other request is blocked and recorded. Runs twice:
 *
 *   automation-visible  — navigator.webdriver true, headless signals intact
 *   stealth             — webdriver hidden, plugin/language counts normal,
 *                         a desktop user agent
 *
 * Compares the rendered text of the two runs (webdriver-keyed cloaking),
 * the rendered text against the static extraction (text injected after
 * load), and labels text by computed style (true visibility).
 *
 * Playwright is an optional dependency: if it is not installed the pass
 * reports itself as not run and the engine proceeds statically.
 */

import type { Finding, TextSegment } from "./types.js";

export interface SandboxResult {
  ran: boolean;
  reason?: string;
  findings: Finding[];
  /** segments as the browser computed them (stealth run); replaces static segments when present */
  segments?: TextSegment[];
  /** text present only in the automation-visible render: what the attacker shows agents and hides from humans */
  automationOnlyText?: string;
  renderedVisibleText?: string;
  blockedRequests: string[];
  timings: { total: number };
}

interface RenderedSegment { text: string; hidden: boolean; why: string; path: string }

const RENDER_SCRIPT = `
(() => {
  const out = [];
  const walker = document.createTreeWalker(document.body || document.documentElement, NodeFilter.SHOW_TEXT);
  let n;
  while ((n = walker.nextNode())) {
    const t = n.nodeValue;
    if (!t || !t.trim()) continue;
    const el = n.parentElement;
    if (!el) continue;
    const tag = el.tagName.toLowerCase();
    if (tag === 'script' || tag === 'style' || tag === 'noscript' || tag === 'template') continue;
    let hidden = false, why = '';
    let e = el;
    while (e && e !== document.documentElement) {
      const cs = getComputedStyle(e);
      if (cs.display === 'none') { hidden = true; why = 'display:none'; break; }
      if (cs.visibility === 'hidden' || cs.visibility === 'collapse') { hidden = true; why = 'visibility:hidden'; break; }
      if (parseFloat(cs.opacity) === 0) { hidden = true; why = 'opacity:0'; break; }
      if (cs.clipPath === 'inset(100%)' || cs.clip === 'rect(0px, 0px, 0px, 0px)') { hidden = true; why = 'clipped'; break; }
      e = e.parentElement;
    }
    if (!hidden) {
      const cs = getComputedStyle(el);
      const fs = parseFloat(cs.fontSize);
      if (fs <= 1) { hidden = true; why = 'font-size:' + cs.fontSize; }
      else if ((() => {
        // text colour against the nearest painted background up the tree, alpha-composited; unknown (image/gradient) never flags
        const rgba = (c) => { const m = c.match(/rgba?\(([^)]+)\)/); if (!m) return null; const p = m[1].split(/[\s,\/]+/).filter(Boolean).map(Number); return { r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1 }; };
        const mix = (t, u) => ({ r: t.r * t.a + u.r * (1 - t.a), g: t.g * t.a + u.g * (1 - t.a), b: t.b * t.a + u.b * (1 - t.a), a: 1 });
        const lum = (c) => { const f = (x) => { x /= 255; return x <= 0.03928 ? x / 12.92 : Math.pow((x + 0.055) / 1.055, 2.4); }; return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b); };
        const layers = []; let p = el; let unknown = false;
        while (p) { const s = getComputedStyle(p); if (s.backgroundImage && s.backgroundImage !== 'none') { unknown = true; break; } const c = rgba(s.backgroundColor); if (c && c.a > 0) { layers.push(c); if (c.a >= 0.999) break; } p = p.parentElement; }
        if (unknown) return false;
        let bg = { r: 255, g: 255, b: 255, a: 1 };
        for (let i = layers.length - 1; i >= 0; i--) bg = mix(layers[i], bg);
        const fill = cs.webkitTextFillColor && cs.webkitTextFillColor !== cs.color ? rgba(cs.webkitTextFillColor) : null;
        const fg0 = fill || rgba(cs.color); if (!fg0) return false;
        const fg = mix(fg0, bg);
        const a = lum(fg), b = lum(bg);
        const ratio = (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
        if (ratio <= 1.25) { why = 'color matches background (contrast ' + ratio.toFixed(2) + ':1)'; return true; }
        return false;
      })()) { hidden = true; }
      else {
        const r = el.getBoundingClientRect();
        const docW = Math.max(document.documentElement.scrollWidth, innerWidth);
        const docH = Math.max(document.documentElement.scrollHeight, innerHeight);
        if (r.width === 0 && r.height === 0) { hidden = true; why = 'zero box'; }
        else if (r.right < 0 || r.bottom < 0 || r.left > docW || r.top > docH) { hidden = true; why = 'offscreen'; }
      }
    }
    const path = (() => { const parts = []; let p = el; let d = 0; while (p && d < 5) { parts.unshift(p.tagName.toLowerCase() + (p.id ? '#' + p.id : '')); p = p.parentElement; d++; } return parts.join('/'); })();
    out.push({ text: t, hidden, why, path });
  }
  return out;
})()
`;

/** cross-origin script hosts the sandbox may load so ordinary pages render; everything else is blocked and recorded */
export const DEFAULT_SCRIPT_HOSTS = [
  "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com", "ajax.googleapis.com", "code.jquery.com", "cdn.tailwindcss.com", "esm.sh", "fonts.googleapis.com", "fonts.gstatic.com",
];

export async function runSandbox(opts: {
  html: string;
  url: string;
  staticVisibleText: string;
  timeoutMs: number;
  allowedScriptHosts?: string[];
  /** path to a Chromium binary; defaults to INGRESS_CHROMIUM or Playwright's bundled browser */
  executablePath?: string;
}): Promise<SandboxResult> {
  const t0 = performance.now();
  let pw: typeof import("playwright");
  try { pw = await import("playwright"); } catch {
    return { ran: false, reason: "playwright not installed", findings: [], blockedRequests: [], timings: { total: performance.now() - t0 } };
  }

  const findings: Finding[] = [];
  const blocked: string[] = [];
  let origin = "";
  try { origin = new URL(opts.url).origin; } catch { origin = "null"; }

  let browser: import("playwright").Browser;
  try {
    browser = await pw.chromium.launch({
      headless: true,
      executablePath: opts.executablePath ?? process.env.INGRESS_CHROMIUM ?? undefined,
      args: ["--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage", "--disable-extensions", "--no-first-run"],
    });
  } catch (e) {
    return { ran: false, reason: `browser launch failed: ${(e as Error).message.split("\n")[0]}`, findings: [], blockedRequests: [], timings: { total: performance.now() - t0 } };
  }
  try {
    const runOnce = async (stealth: boolean): Promise<{ segs: RenderedSegment[]; text: string }> => {
      const ctx = await browser.newContext({
        javaScriptEnabled: true,
        bypassCSP: false,
        userAgent: stealth
          ? "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"
          : undefined,
        viewport: { width: 1280, height: 900 },
        locale: "en-US",
        offline: false,
        storageState: { cookies: [], origins: [] },
      });
      if (stealth) {
        await ctx.addInitScript(() => {
          Object.defineProperty(navigator, "webdriver", { get: () => false });
          Object.defineProperty(navigator, "languages", { get: () => ["en-US", "en"] });
          Object.defineProperty(navigator, "plugins", { get: () => [1, 2, 3, 4, 5] });
          // @ts-ignore
          window.chrome = { runtime: {} };
        });
      }
      await ctx.route("**/*", (route) => {
        const req = route.request();
        const u = req.url();
        const type = req.resourceType();
        const sameOrigin = u.startsWith(origin);
        // allow the document itself (served from memory), same-origin subresources, and cross-origin css/scripts so the page renders; block everything else
        if (u === opts.url || u === opts.url + "/" ) return route.fulfill({ status: 200, contentType: "text/html; charset=utf-8", body: opts.html });
        if (type === "document") return route.abort("blockedbyclient");
        let host = "";
        try { host = new URL(u).hostname; } catch { /* ignore */ }
        const cdn = (opts.allowedScriptHosts ?? DEFAULT_SCRIPT_HOSTS).some((h) => host === h || host.endsWith("." + h));
        if (sameOrigin && (type === "stylesheet" || type === "script" || type === "font" || type === "image")) return route.continue();
        if (cdn && (type === "stylesheet" || type === "script" || type === "font")) return route.continue();
        blocked.push(u.slice(0, 200));
        return route.abort("blockedbyclient");
      });
      const page = await ctx.newPage();
      page.setDefaultTimeout(opts.timeoutMs);
      try {
        await page.goto(opts.url, { waitUntil: "domcontentloaded", timeout: opts.timeoutMs });
        await page.waitForTimeout(Math.min(1500, opts.timeoutMs / 4));
      } catch { /* a page that never settles still gets evaluated */ }
      let segs: RenderedSegment[] = [];
      try { segs = (await page.evaluate(RENDER_SCRIPT)) as RenderedSegment[]; } catch { /* evaluation blocked */ }
      await ctx.close();
      const text = segs.filter((s) => !s.hidden).map((s) => s.text).join(" ").replace(/\s+/g, " ").trim();
      return { segs, text };
    };

    const [auto, stealth] = await Promise.all([runOnce(false), runOnce(true)]);

    // 1. webdriver-keyed divergence
    const sim = jaccard(auto.text, stealth.text);
    if (sim < 0.6 && (auto.text.length > 200 || stealth.text.length > 200)) {
      findings.push({
        pass: "sandbox", kind: "sandbox.webdriver_keyed_divergence", confidence: Math.min(0.95, 0.55 + (0.6 - sim)), severity: 0.9,
        message: `rendered text differs between an automation-visible browser and a stealth browser (${(sim * 100).toFixed(0)}% overlap)`,
        excerpt: onlyIn(auto.text, stealth.text), action: "none",
      });
    }

    // 2. text injected after load: in the stealth render but not in the static extraction
    const injected = onlyIn(stealth.text, opts.staticVisibleText, 40);
    const injectedWords = injected.split(/\s+/).filter(Boolean).length;
    if (injectedWords >= 8) {
      findings.push({
        pass: "sandbox", kind: "sandbox.text_injected_after_load", confidence: Math.min(0.9, 0.4 + injectedWords / 100), severity: 0.7,
        message: `${injectedWords}+ words appear only after scripts run`, excerpt: injected.slice(0, 200), action: "none",
      });
    }

    // 3. computed-hidden text that static analysis thought visible
    const hiddenSegs = stealth.segs.filter((s) => s.hidden && s.text.trim().split(/\s+/).length >= 6);
    for (const h of hiddenSegs.slice(0, 10)) {
      findings.push({
        pass: "sandbox", kind: "sandbox.computed_hidden_text", confidence: 0.75, severity: 0.6,
        message: `text hidden by computed style (${h.why})`, excerpt: h.text.trim().slice(0, 160), location: h.path, action: "quarantined",
      });
    }

    // 4. blocked egress
    const egress = [...new Set(blocked)];
    if (egress.length) {
      findings.push({
        pass: "sandbox", kind: "sandbox.blocked_egress_attempt", confidence: egress.length > 3 ? 0.5 : 0.3, severity: 0.4,
        message: `${egress.length} cross-origin requests blocked during render`, excerpt: egress.slice(0, 4).join(" "), action: "none",
      });
    }

    // segment-level diff keeps the attacker's sentences intact for the meaning pass
    const stealthSet = new Set(stealth.segs.map((x) => x.text.trim()));
    const automationOnlyText = auto.segs.filter((x) => !x.hidden && !stealthSet.has(x.text.trim())).map((x) => x.text.trim()).join("\n").slice(0, 4000);
    const segments: TextSegment[] = stealth.segs.map((s) => ({ text: s.text, visibility: s.hidden ? (s.why === "offscreen" ? "offscreen" : s.why.startsWith("font-size") || s.why.includes("background") || s.why === "opacity:0" ? "tiny_or_transparent" : "css_hidden") : "visible", path: s.path }));
    return { ran: true, findings, segments, automationOnlyText, renderedVisibleText: stealth.text, blockedRequests: egress, timings: { total: performance.now() - t0 } };
  } finally {
    await browser.close();
  }
}

function jaccard(a: string, b: string): number {
  const A = new Set(a.toLowerCase().split(/\W+/).filter((w) => w.length > 2));
  const B = new Set(b.toLowerCase().split(/\W+/).filter((w) => w.length > 2));
  if (!A.size && !B.size) return 1;
  let inter = 0;
  for (const w of A) if (B.has(w)) inter++;
  return inter / (A.size + B.size - inter);
}

function onlyIn(a: string, b: string, max = 30): string {
  const B = new Set(b.toLowerCase().split(/\W+/));
  return a.split(/\s+/).filter((w) => w.length > 2 && !B.has(w.toLowerCase().replace(/\W/g, ""))).slice(0, max).join(" ");
}
