#!/usr/bin/env node
// How often do the drawn-interface checks (packages/core/src/screen.ts) fire on ordinary screenshots?
// Every picture in the set is an ordinary screen, so every finding is a false alarm to count.
//
//   npm run build && ingress vision build
//   node tools/images/fetch-screens.mjs <dir>
//   node tools/images/score-screens.mjs <dir> --half=dev        # choose rules and weights on this half
//   node tools/images/score-screens.mjs <dir> --half=holdout    # score once, at the end
//
// The helper's reading of each picture is kept in <dir>/reports, so a rule change is re-scored without
// reading the pictures again. Prints counts, never the text read from a picture.
//
// Three readings of every picture are scored:
//   as given           nothing said about how the picture was taken (what a caller without knowledge passes)
//   viewport           every picture declared a capture of a page's content area: the worst case, since desktop
//                      and phone screens are not, and real windows in them count against the rule
//   viewport + site    as above, and the page declared to be on a site no picture names
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";
import { IngressEngine, drawnElements, visionHelperPath } from "../../packages/core/dist/src/index.js";

const dir = process.argv[2];
const half = process.argv.find((a) => a.startsWith("--half="))?.split("=")[1];
const limit = Number(process.argv.find((a) => a.startsWith("--limit="))?.split("=")[1] ?? 0);
if (!dir || !["dev", "holdout"].includes(half)) { console.error("usage: score-screens.mjs <dir> --half=dev|holdout [--limit=N] [--read-only]"); process.exit(2); }
const helper = process.env.INGRESS_VISION_HELPER || visionHelperPath();
const reports = join(dir, "reports");
mkdirSync(reports, { recursive: true });

const group = new Map();
for (const g of ["web", "desktop", "mobile"]) {
  const file = join(dir, `screenspot_${g}_v2.json`);
  if (!existsSync(file)) continue;
  for (const row of JSON.parse(readFileSync(file, "utf8"))) if (row.img_filename) group.set(basename(row.img_filename), g);
}
const walk = (d) => readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(join(d, e.name)) : /\.(png|jpe?g|webp)$/i.test(e.name) && !e.name.startsWith(".") ? [join(d, e.name)] : []));
let files = walk(join(dir, "images")).filter((f) => (createHash("sha256").update(basename(f)).digest()[0] % 2 === 0 ? "dev" : "holdout") === half).sort();
if (limit) files = files.slice(0, limit);

const engine = new IngressEngine({ cacheTtlSeconds: 0, sandbox: "off" }, { log: () => {} });
const CONFIGS = [["as given", undefined], ["viewport", { capture: "viewport" }], ["viewport + site", { capture: "viewport", pageHost: "pages.example.org" }]];
const stats = {};
const bump = (g, k) => { stats[g] ??= {}; stats[g][k] = (stats[g][k] ?? 0) + 1; };
// --read-only: have the helper read the pictures and keep its readings, and score nothing. For reading the
// hold-out half ahead of time without looking at any result from it.
const readOnly = process.argv.includes("--read-only");
let unread = 0, read = 0;
for (const f of files) {
  const g = group.get(basename(f)) ?? "other";
  const cache = join(reports, `${createHash("sha256").update(basename(f)).digest("hex").slice(0, 24)}.json`);
  let report;
  if (existsSync(cache)) report = JSON.parse(readFileSync(cache, "utf8"));
  else {
    try { report = JSON.parse(execFileSync(helper, [f], { timeout: 120_000, maxBuffer: 64 * 1024 * 1024, encoding: "utf8" })); writeFileSync(cache, JSON.stringify(report)); }
    catch { unread++; continue; }
  }
  if (report.decoded === false) { unread++; continue; }
  if (readOnly) { read++; continue; }
  bump(g, "pictures");
  const { elements, topBarHost } = drawnElements(report.full, report.rects ?? []);
  if (topBarHost) bump(g, "address bar at the top");
  for (const e of elements) bump(g, `${e.what}${e.framed ? ", framed" : ""}`);
  const bytes = readFileSync(f);
  let base;
  for (const [name, screen] of CONFIGS) {
    const r = await engine.scanImage(bytes, { url: `file:${basename(f)}`, vision: async () => report, screen });
    if (name === "as given") base = r.tier;
    bump(g, `${name}: ${r.tier}`);
    if (name !== "as given" && r.tier !== base) bump(g, `${name}: changed from ${base} to ${r.tier}`);
    for (const k of new Set(r.findings.filter((x) => x.kind.startsWith("image.drawn_")).map((x) => x.kind))) bump(g, `${name}: ${k}`);
  }
}
if (readOnly) { console.log(`${half} half: ${read} pictures read and kept${unread ? `, ${unread} not read` : ""}; nothing was scored`); process.exit(0); }
console.log(`${half} half: ${files.length} pictures${unread ? `, ${unread} not read` : ""}`);
for (const [g, s] of Object.entries(stats).sort()) {
  console.log(`\n${g}`);
  for (const [k, v] of Object.entries(s).sort()) console.log(`  ${k.padEnd(58)} ${v}`);
}
