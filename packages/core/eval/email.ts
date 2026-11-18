#!/usr/bin/env node
/**
 * Score the email adapter on public email sets (tools/email-eval/fetch-email-sets.mjs).
 *
 *   npm run email-eval -- <dir>/*.jsonl [--trust=4] [--why]
 *
 * Prints counts only, never message text. For benign messages that were refused, `--why` adds a tally of the
 * finding kinds that refused them (kinds, not excerpts), which is what a precision fix needs to know.
 */
import { readFileSync } from "node:fs";
import { basename } from "node:path";
import { IngressEngine } from "../src/index.js";
import type { TrustLevel } from "../src/index.js";

const args = process.argv.slice(2);
const files = args.filter((a) => !a.startsWith("--"));
const trust = Number(args.find((a) => a.startsWith("--trust="))?.split("=")[1] ?? 4) as TrustLevel;
const why = args.includes("--why");
// --as=message reads each row as a text message from an unknown number (the strictest reading): rows with a
// "text" field as they are, and email rows by their body, to check that the same words are judged alike in a chat
const asMessage = args.includes("--as=message");
if (!files.length) { console.error("usage: email-eval <file.jsonl>... [--trust=4] [--why] [--as=message]"); process.exit(2); }

const engine = new IngressEngine({ cloakingCheck: false, cacheTtlSeconds: 0, sandbox: "off", fetchStylesheets: false, chainReceipts: false }, { log: () => {} });

interface Row { raw?: string; subject?: string; from?: string; to?: string; body?: string; text?: string; label: boolean | null; category: string; objectives?: string }
interface Tally { n: number; refused: number; hostile: number; ms: number; kinds: Map<string, number> }
const by = new Map<string, Tally & { label: boolean | null }>();

for (const f of files) {
  const rows = readFileSync(f, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as Row);
  for (const r of rows) {
    if (asMessage && r.raw !== undefined && r.text === undefined && r.body === undefined) continue; // a whole raw email has no single body to send as a text
    const content = asMessage
      ? JSON.stringify([{ is_from_me: 0, service: "SMS", sender: "+15550100", text: r.text ?? r.body ?? "" }])
      : r.raw ?? JSON.stringify({ subject: r.subject ?? "", from: r.from ?? "", to: r.to ?? "", text: r.body ?? r.text ?? "" });
    const t0 = performance.now();
    const res = await engine.scan(content, asMessage ? { kind: "message", source: { channel: "text message", trust } } : { kind: "email", source: { channel: "email", trust } });
    const t = by.get(r.category) ?? { n: 0, refused: 0, hostile: 0, ms: 0, kinds: new Map<string, number>(), label: r.label };
    t.n++; t.ms += performance.now() - t0;
    if (res.tier !== "clean") {
      t.refused++;
      if (res.tier === "hostile") t.hostile++;
      // the kinds that carried the verdict: anything scoring at or above the weakest that could matter
      for (const k of new Set(res.findings.filter((x) => x.confidence * x.severity >= 0.1).map((x) => `${x.kind}${x.inHidden ? " (hidden)" : ""}`))) t.kinds.set(k, (t.kinds.get(k) ?? 0) + 1);
    }
    by.set(r.category, t);
  }
  console.error(`scanned ${basename(f)}`);
}

const pct = (a: number, b: number) => (b ? `${((100 * a) / b).toFixed(1)}%` : "-");
console.log(`\nemail sets, source trust ${trust}\n`);
console.log(`${"set".padEnd(18)} ${"class".padEnd(8)} ${"n".padStart(6)} ${"refused".padStart(8)} ${"hostile".padStart(8)} ${"rate".padStart(7)} ${"ms/msg".padStart(7)}`);
let aN = 0, aHit = 0, bN = 0, bPass = 0;
for (const [cat, t] of [...by].sort()) {
  const cls = t.label === true ? "attack" : t.label === false ? "benign" : "other";
  console.log(`${cat.padEnd(18)} ${cls.padEnd(8)} ${String(t.n).padStart(6)} ${String(t.refused).padStart(8)} ${String(t.hostile).padStart(8)} ${pct(t.refused, t.n).padStart(7)} ${(t.ms / t.n).toFixed(1).padStart(7)}`);
  if (t.label === true) { aN += t.n; aHit += t.refused; } else if (t.label === false) { bN += t.n; bPass += t.n - t.refused; }
  if (why && t.refused && t.label !== true) for (const [k, n] of [...t.kinds].sort((x, y) => y[1] - x[1]).slice(0, 8)) console.log(`${"".padEnd(27)}${String(n).padStart(5)}  ${k}`);
}
if (aN && bN) console.log(`\nattacks caught ${aHit}/${aN} (${pct(aHit, aN)}), benign passed ${bPass}/${bN} (${pct(bPass, bN)}), balanced accuracy ${(50 * (aHit / aN + bPass / bN)).toFixed(1)}%`);
