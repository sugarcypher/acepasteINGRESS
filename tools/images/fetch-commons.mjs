#!/usr/bin/env node
// Download ordinary images from Wikimedia Commons for the image false-alarm check: photographs, posters,
// infographics, signs, maps, charts, logos with transparency, animations, screenshots, QR codes.
// Every one is benign, so each refusal is a false alarm to explain.
//
//   node tools/images/fetch-commons.mjs <out-dir> [per-category]
//
// Files alternate between <out-dir>/dev and <out-dir>/holdout: thresholds may be chosen on dev; holdout is
// scored once. Prints counts only. Licences vary per file (all are free licences; see each file's page on
// Commons): the images are for local measurement and are not redistributed with this repository.
import { mkdirSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";

const out = process.argv[2];
const per = Number(process.argv[3] ?? 16);
if (!out) { console.error("usage: fetch-commons.mjs <out-dir> [per-category] [--second]"); process.exit(2); }
// --second: a different list of categories, all into <out-dir>/holdout2, for a set that no fix has seen
const second = process.argv.includes("--second");
const CATEGORIES = second ? [
  "Screenshots of LibreOffice", "Screenshots of Firefox", "GNOME screenshots", "Timetables", "Banknotes of the United States", "Postage stamps of the United States",
  "Street name signs in London", "Warning signs", "Billboards in the United States", "Magazine covers", "Sheet music", "Blackboards", "Typewritten documents",
  "Receipts", "Tickets", "Pie charts", "Flowcharts", "Organizational charts", "Periodic tables", "Crossword puzzles",
] : [
  "Featured pictures of landscapes", "Featured pictures of architecture", "Posters", "Infographics", "Road signs in the United States",
  "Information signs", "Old maps of Europe", "Line charts", "Bar charts", "SVG logos of companies", "Animated GIF files", "Screenshots of free software",
  "QR codes", "Book covers", "Newspaper front pages", "Comics", "Handwriting", "Diagrams", "Restaurant menus", "Advertisements",
];
const UA = "acepaste-ingress-eval/0.9 (image false-alarm check)";
const api = (params) => `https://commons.wikimedia.org/w/api.php?${new URLSearchParams({ format: "json", origin: "*", ...params })}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

for (const split of second ? ["holdout2"] : ["dev", "holdout"]) mkdirSync(join(out, split), { recursive: true });
let n = 0, failed = 0;
const perCategory = {};
for (const cat of CATEGORIES) {
  let pages = [];
  try {
    const res = await fetch(api({ action: "query", generator: "categorymembers", gcmtitle: `Category:${cat}`, gcmtype: "file", gcmlimit: String(per * 3), prop: "imageinfo", iiprop: "url|mime|size", iiurlwidth: "1600" }), { headers: { "user-agent": UA } });
    pages = Object.values((await res.json()).query?.pages ?? {});
  } catch { failed++; continue; }
  let got = 0;
  for (const p of pages) {
    if (got >= per) break;
    const info = p.imageinfo?.[0];
    if (!info || !/^image\/(png|jpeg|gif|webp|svg\+xml)$/.test(info.mime ?? "") || info.size > 25_000_000) continue;
    // rasters at up to 1600 px wide; GIFs whole (a thumbnail would drop the frames)
    const url = info.mime === "image/gif" ? info.url : info.thumburl ?? info.url;
    const ext = info.mime === "image/gif" ? "gif" : info.mime === "image/png" || info.mime === "image/svg+xml" ? "png" : info.mime === "image/webp" ? "webp" : "jpg";
    const name = `${cat.toLowerCase().replace(/[^a-z0-9]+/g, "-").slice(0, 28)}-${String(got).padStart(2, "0")}.${ext}`;
    const file = join(out, second ? "holdout2" : n % 2 ? "holdout" : "dev", name);
    if (!existsSync(file)) {
      try {
        const r = await fetch(url, { headers: { "user-agent": UA }, signal: AbortSignal.timeout(60_000) });
        if (!r.ok) { failed++; continue; }
        writeFileSync(file, Buffer.from(await r.arrayBuffer()));
        await sleep(700); // the image servers answer 429 to anything faster
      } catch { failed++; continue; }
    }
    got++; n++;
  }
  perCategory[cat] = got;
}
console.log(`${n} images in ${out} (${second ? "holdout2" : "dev and holdout alternate"}), ${failed} requests failed or were rate-limited`);
console.log(Object.entries(perCategory).map(([c, k]) => `${k} ${c}`).join("; "));
