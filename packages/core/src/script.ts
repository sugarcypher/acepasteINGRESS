/**
 * Script pass (underlight lineage).
 *
 * Static, millisecond-budget analysis of every script on the page. It does
 * not execute anything. A high score marks the page for sandbox escalation
 * (sandbox not yet implemented; the hook is in engine.ts).
 *
 * Surfaces, from the underlight list: obfuscation and minification signatures,
 * runtime code generation, typed-array / binary-buffer decoding, automation
 * detection (agent-targeted cloaking), post-load text injection, and outbound
 * beacons that could carry exfiltrated context.
 */

import * as acorn from "acorn";
import * as walk from "acorn-walk";
import type { Finding, ScriptUnit } from "./types.js";

export interface ScriptResult {
  findings: Finding[];
  /** 0..1, the maximum single-script suspicion; drives sandbox escalation */
  maxSuspicion: number;
}

const AUTOMATION_PROBES = [
  "webdriver", "__webdriver", "_phantom", "callPhantom", "__nightmare", "__selenium", "domAutomation",
  "HeadlessChrome", "puppeteer", "playwright", "__playwright", "chrome.runtime", "navigator.plugins.length",
  "navigator.languages.length", "outerWidth", "connection.rtt", "permissions.query", "notifications",
  "GPTBot", "ClaudeBot", "Claude-Web", "anthropic-ai", "PerplexityBot", "ChatGPT-User", "OAI-SearchBot", "Google-Extended", "cohere-ai", "Bytespider",
];
const EXFIL_SINKS = ["sendBeacon", "XMLHttpRequest", "fetch", "WebSocket", "EventSource"];
const TEXT_SINKS = ["innerHTML", "outerHTML", "textContent", "innerText", "insertAdjacentHTML", "write", "writeln", "appendChild", "replaceChildren", "createTextNode"];
const CODEGEN = ["eval", "Function", "setTimeout", "setInterval", "execScript", "importScripts"];
const BINARY_DECODE = ["TextDecoder", "Uint8Array", "Uint16Array", "Int8Array", "DataView", "ArrayBuffer", "atob", "fromCharCode", "fromCodePoint", "decodeURIComponent", "unescape", "charCodeAt"];

function shannon(s: string): number {
  if (!s) return 0;
  const freq = new Map<string, number>();
  for (const c of s) freq.set(c, (freq.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of freq.values()) { const p = n / s.length; h -= p * Math.log2(p); }
  return h;
}

function memberChain(node: any): string {
  if (!node) return "";
  if (node.type === "Identifier") return node.name;
  if (node.type === "ThisExpression") return "this";
  if (node.type === "MemberExpression") {
    const prop = node.computed ? (node.property.type === "Literal" ? String(node.property.value) : "[]") : node.property.name;
    return `${memberChain(node.object)}.${prop}`;
  }
  if (node.type === "CallExpression") return memberChain(node.callee) + "()";
  return node.type;
}

export function analyzeScript(unit: ScriptUnit): { findings: Finding[]; suspicion: number } {
  const findings: Finding[] = [];
  const src = unit.source;
  const loc = unit.inline ? `inline script #${unit.index}` : `script #${unit.index} src=${unit.src}`;
  if (!src.trim()) return { findings, suspicion: 0 };

  // --- lexical signals, computed before parsing (obfuscated code may not parse)
  const hexIdents = (src.match(/\b_0x[0-9a-f]{2,}\b/g) ?? []).length;
  const escapes = (src.match(/\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}/g) ?? []).length;
  const longStrings = (src.match(/["'`][^"'`\n]{200,}["'`]/g) ?? []);
  const longStringEntropy = longStrings.length ? Math.max(...longStrings.map(shannon)) : 0;
  const bracketAccess = (src.match(/\[\s*["'][A-Za-z_$][\w$]*["']\s*\]/g) ?? []).length;
  const jsfuck = /(\[\]|!\[\]|\+\[\]|\(!\[\]\+\[\]\))\s*[\[\+]/.test(src) && (src.match(/\[\]/g) ?? []).length > 40;
  const nonAscii = ([...src].filter((c) => c.charCodeAt(0) > 127).length) / Math.max(1, src.length);

  let obf = 0;
  // hex identifiers are the javascript-obfuscator.io signature; even a few are diagnostic
  obf += hexIdents >= 3 ? Math.min(0.4, 0.2 + hexIdents / 40) : 0;
  obf += Math.min(0.25, escapes / 80);
  obf += longStringEntropy > 5.2 ? 0.2 : 0;
  obf += Math.min(0.15, bracketAccess / 60);
  obf += jsfuck ? 0.5 : 0;
  obf += nonAscii > 0.05 ? 0.1 : 0;
  // minified-but-legitimate bundles have short identifiers but no hex idents or escapes; keep obf low for them
  if (obf >= 0.3) {
    findings.push({
      pass: "script", kind: "script.obfuscation", confidence: Math.min(0.9, obf), severity: 0.5,
      message: `obfuscation signatures: ${hexIdents} hex identifiers, ${escapes} escapes, string entropy ${longStringEntropy.toFixed(2)}${jsfuck ? ", symbol-only encoding" : ""}`,
      location: loc, action: "none",
    });
  }

  // --- structural signals via AST
  let ast: any;
  try {
    ast = acorn.parse(src, { ecmaVersion: "latest", sourceType: "script", allowHashBang: true, allowReturnOutsideFunction: true });
  } catch {
    try { ast = acorn.parse(src, { ecmaVersion: "latest", sourceType: "module" }); } catch { ast = null; }
  }

  let codegen = 0, automation = 0, textInject = 0, exfil = 0, binary = 0;
  const automationHits = new Set<string>();
  const exfilHits = new Set<string>();
  const urlLiterals = new Set<string>();

  if (ast) {
    walk.simple(ast, {
      CallExpression(node: any) {
        const chain = memberChain(node.callee);
        const tail = chain.split(".").pop() ?? "";
        if (tail === "eval" || tail === "Function" || tail === "execScript") codegen += 1;
        if ((tail === "setTimeout" || tail === "setInterval") && node.arguments[0]?.type !== "FunctionExpression" && node.arguments[0]?.type !== "ArrowFunctionExpression" && node.arguments[0]?.type !== "Identifier") codegen += 0.6;
        if (EXFIL_SINKS.includes(tail) || chain.endsWith("navigator.sendBeacon") || chain === "new Image" ) { exfil += 1; exfilHits.add(tail); }
        if (TEXT_SINKS.includes(tail)) textInject += 0.5;
        if (BINARY_DECODE.includes(tail)) binary += 0.5;
        if (tail === "fromCharCode" && node.arguments.length > 8) binary += 1.5;
      },
      NewExpression(node: any) {
        const name = memberChain(node.callee);
        if (name === "Function") codegen += 1;
        if (BINARY_DECODE.includes(name)) binary += 0.5;
        if (name === "Image" || name === "WebSocket" || name === "XMLHttpRequest") { exfil += 0.5; exfilHits.add(name); }
      },
      MemberExpression(node: any) {
        const chain = memberChain(node);
        for (const probe of AUTOMATION_PROBES) if (chain.includes(probe)) { automation += 1; automationHits.add(probe); }
        if (/\.(innerHTML|outerHTML|textContent|innerText)$/.test(chain)) textInject += 0.5;
        if (chain.endsWith(".src") || chain.endsWith(".href")) exfil += 0.1;
      },
      Literal(node: any) {
        if (node.regex) {
          for (const probe of AUTOMATION_PROBES) if (node.regex.pattern.includes(probe)) { automation += 0.8; automationHits.add(probe); }
          return;
        }
        if (typeof node.value !== "string") return;
        for (const probe of AUTOMATION_PROBES) if (node.value.includes(probe)) { automation += 0.8; automationHits.add(probe); }
        if (/^(https?:)?\/\/[^/]+\/(collect|beacon|track|pixel|log|t\.gif|p\.gif|hook|webhook)/i.test(node.value)) { exfil += 0.8; exfilHits.add(node.value.slice(0, 60)); }
        if (/^https?:\/\/[^\s"']+$/.test(node.value)) urlLiterals.add(node.value.slice(0, 120));
      },
    });
  } else {
    // unparseable: treat lexical hits as structural
    for (const p of AUTOMATION_PROBES) if (src.includes(p)) { automation += 1; automationHits.add(p); }
    if (/\beval\s*\(|new\s+Function\s*\(/.test(src)) codegen += 1;
    obf += 0.2;
  }

  if (codegen >= 1) findings.push({
    pass: "script", kind: "script.runtime_codegen", confidence: Math.min(0.85, 0.4 + codegen * 0.15), severity: 0.6,
    message: `runtime code generation (${Math.round(codegen)} sites: eval / new Function / string timers)`, location: loc, action: "none",
  });
  if (automation >= 1) findings.push({
    pass: "script", kind: "script.automation_detection", confidence: Math.min(0.95, 0.45 + automation * 0.12), severity: 0.85,
    message: `probes for automation or AI crawlers: ${[...automationHits].slice(0, 6).join(", ")}`, excerpt: [...urlLiterals].slice(0, 5).join(" "), location: loc, action: "none",
  });
  if (textInject >= 2 && (codegen >= 1 || binary >= 2 || obf >= 0.3)) findings.push({
    pass: "script", kind: "script.post_load_text_injection", confidence: 0.6, severity: 0.7,
    message: `writes text into the document after load, combined with decoding or code generation`, location: loc, action: "none",
  });
  if (exfil >= 1.5 && (textInject >= 1 || binary >= 1 || automation >= 1)) findings.push({
    pass: "script", kind: "script.exfil_beacon", confidence: Math.min(0.8, 0.3 + exfil * 0.1), severity: 0.6,
    message: `outbound channels present: ${[...exfilHits].slice(0, 4).join(", ")}`, excerpt: [...urlLiterals].slice(0, 5).join(" "), location: loc, action: "none",
  });
  if (binary >= 3) findings.push({
    pass: "script", kind: "script.binary_decoding", confidence: Math.min(0.8, 0.3 + binary * 0.08), severity: 0.5,
    message: `typed-array / char-code decoding of embedded data (${Math.round(binary)} sites)`, location: loc, action: "none",
  });

  // suspicion for sandbox escalation: automation detection and codegen+textinject are the strongest tells
  const suspicion = Math.min(1,
    obf * 0.6 +
    (automation >= 1 ? 0.5 : 0) +
    (codegen >= 1 && textInject >= 1 ? 0.35 : 0) +
    (binary >= 3 ? 0.15 : 0),
  );
  return { findings, suspicion };
}

export function analyzeScripts(units: ScriptUnit[]): ScriptResult {
  const findings: Finding[] = [];
  let maxSuspicion = 0;
  for (const u of units) {
    const r = analyzeScript(u);
    findings.push(...r.findings);
    maxSuspicion = Math.max(maxSuspicion, r.suspicion);
  }
  return { findings, maxSuspicion };
}
