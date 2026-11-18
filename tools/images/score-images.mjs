#!/usr/bin/env node
// Scan every image in a folder through the engine and print, for each one that is not clean, the verdict
// and the kinds of finding behind it. Never prints text read from an image.
//
//   npm run build && ingress vision build
//   node tools/images/score-images.mjs <folder> [--all]
//
// For a folder of ordinary images (tools/images/fetch-commons.mjs) every refusal is a false alarm.
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { IngressEngine } from "../../packages/core/dist/src/index.js";

const dir = process.argv[2];
if (!dir) { console.error("usage: score-images.mjs <folder> [--all]"); process.exit(2); }
const all = process.argv.includes("--all");
const engine = new IngressEngine({ cacheTtlSeconds: 0, sandbox: "off" }, { log: () => {} });
const tally = {}, kinds = {};
let n = 0, ms = 0, unread = 0, withText = 0, withCode = 0;
for (const f of readdirSync(dir).sort()) {
  if (f.startsWith(".")) continue;
  const t = performance.now();
  const r = await engine.scanImage(readFileSync(join(dir, f)), { url: `file:${f}` });
  ms += performance.now() - t; n++;
  tally[r.tier] = (tally[r.tier] ?? 0) + 1;
  if (!r.coverage?.image?.pixels) unread++;
  if (r.delivered.replace(/\[[^\]]*\]/g, "").trim().length > 20) withText++;
  if (r.findings.some((x) => x.kind === "image.code_payload" || x.kind === "image.code_action")) withCode++;
  const scored = r.findings.filter((x) => x.confidence * x.severity >= 0.05);
  if (r.tier !== "clean") for (const k of new Set(scored.map((x) => x.kind))) kinds[k] = (kinds[k] ?? 0) + 1;
  if (all || r.tier !== "clean") console.log(`${r.tier.padEnd(8)} ${String(r.score).padEnd(7)} ${f.slice(0, 40).padEnd(40)} ${scored.map((x) => `${x.kind}=${(x.confidence * x.severity).toFixed(2)}`).join(" ").slice(0, 150)}`);
}
console.log(`\n${n} images: ${Object.entries(tally).map(([k, v]) => `${v} ${k}`).join(", ")}; ${withText} with readable text, ${withCode} with a code, ${unread} whose pixels were not read; ${(ms / Math.max(1, n) / 1000).toFixed(1)} s each`);
if (Object.keys(kinds).length) console.log(`kinds behind the refusals: ${Object.entries(kinds).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${v} ${k}`).join(", ")}`);
