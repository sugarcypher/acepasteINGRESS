#!/usr/bin/env node
// Download ordinary short videos to measure false alarms on: clips from NASA's Image and Video Library
// (images.nasa.gov). NASA's own material is generally not copyrighted (see
// https://www.nasa.gov/nasa-brand-center/images-and-media/); each clip's page says where it came from.
// The clips are for local measurement and are not redistributed here.
//
//   node tools/video/fetch-nasa.mjs <dir> [per-query=8] [--prefer=small,medium]
//
// Writes <dir>/dev and <dir>/holdout. Which half a clip goes to is decided by a hash of its id, before
// anything is scanned. Prints counts and ids, never what a clip shows or says.
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const dir = process.argv[2];
const perQuery = Number(process.argv[3] ?? 8);
if (!dir) { console.error("usage: fetch-nasa.mjs <dir> [per-query]"); process.exit(2); }
// kinds of footage that carry text: explainers, title cards, lower thirds, interviews, as well as plain footage
const QUERIES = ["explainer", "ScienceCast", "this week at NASA", "how it works", "animation", "interview", "launch highlights", "time lapse", "tutorial", "infographic", "mission overview", "press briefing"];
const MAX_BYTES = 80_000_000;
const PREFER = (process.argv.find((a) => a.startsWith("--prefer="))?.split("=")[1] ?? "small,medium").split(",");
const API = "https://images-api.nasa.gov";
const UA = { "user-agent": "ingress-eval/1.0" };

const json = async (url) => { const r = await fetch(url, { headers: UA, signal: AbortSignal.timeout(40_000) }); if (!r.ok) throw new Error(`${r.status}`); return r.json(); };
for (const half of ["dev", "holdout"]) mkdirSync(join(dir, half), { recursive: true });

const seen = new Set();
let fetched = 0, skipped = 0, bytes = 0;
const manifest = [];
for (const q of QUERIES) {
  let items = [];
  try { items = (await json(`${API}/search?q=${encodeURIComponent(q)}&media_type=video&page_size=${perQuery * 3}`)).collection?.items ?? []; }
  catch (e) { console.error(`query failed (${q}): ${e.message}`); continue; }
  let got = 0;
  for (const it of items) {
    if (got >= perQuery) break;
    const id = it?.data?.[0]?.nasa_id;
    if (!id || seen.has(id)) continue;
    seen.add(id);
    const half = createHash("sha256").update(id).digest()[0] % 2 === 0 ? "dev" : "holdout";
    const out = join(dir, half, `${id.replace(/[^A-Za-z0-9._-]/g, "_")}.mp4`);
    if (existsSync(out)) { got++; continue; }
    try {
      const files = ((await json(`${API}/asset/${encodeURIComponent(id)}`)).collection?.items ?? []).map((x) => String(x.href));
      // the library's sizes: "mobile" is 320 pixels wide, too small for the text on screen to be read at all;
      // "small" and "medium" are what a person would watch
      const pick = PREFER.map((size) => files.find((h) => new RegExp(`~${size}\\.mp4$`, "i").test(h))).find(Boolean);
      if (!pick) { skipped++; continue; }
      const res = await fetch(pick.replace(/^http:/, "https:").replace(/ /g, "%20"), { headers: UA, signal: AbortSignal.timeout(180_000) });
      const len = Number(res.headers.get("content-length") ?? 0);
      if (!res.ok || len > MAX_BYTES) { skipped++; continue; }
      const buf = Buffer.from(await res.arrayBuffer());
      if (buf.length > MAX_BYTES || buf.length < 50_000) { skipped++; continue; }
      writeFileSync(out, buf);
      manifest.push({ id, half, bytes: buf.length, query: q });
      fetched++; got++; bytes += buf.length;
    } catch { skipped++; }
  }
  console.log(`${q.padEnd(22)} ${got} clips`);
}
writeFileSync(join(dir, `manifest-${Date.now()}.json`), JSON.stringify(manifest, null, 1));
console.log(`fetched ${fetched} clips (${(bytes / 1e6).toFixed(0)} MB), skipped ${skipped}; dev ${manifest.filter((m) => m.half === "dev").length}, holdout ${manifest.filter((m) => m.half === "holdout").length}`);
