#!/usr/bin/env node
// Scan every video in a folder through the engine and print, for each, the verdict, the kinds of finding
// behind it and how much of it was read. Never prints text read from a video.
//
//   npm run build && ingress vision build
//   node tools/video/score-videos.mjs <folder> [--all] [--max-seconds=600] [--max-frames=240]
//
// For a folder of ordinary videos (tools/video/fetch-nasa.mjs) every refusal is a false alarm.
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { IngressEngine } from "../../packages/core/dist/src/index.js";

const dir = process.argv[2];
if (!dir) { console.error("usage: score-videos.mjs <folder> [--all] [--max-seconds=N] [--max-frames=N]"); process.exit(2); }
const all = process.argv.includes("--all");
const num = (name) => { const v = process.argv.find((a) => a.startsWith(`--${name}=`)); return v ? Number(v.split("=")[1]) : undefined; };
const engine = new IngressEngine({ cacheTtlSeconds: 0, sandbox: "off" }, { log: () => {} });
const tally = {}, kinds = {}, anyKinds = {};
let n = 0, ms = 0, unread = 0, seconds = 0, framesTotal = 0, framesRead = 0, withText = 0, partly = 0;
for (const f of readdirSync(dir).sort()) {
  if (f.startsWith(".") || !/\.(mp4|mov|m4v)$/i.test(f)) continue;
  const t = performance.now();
  const r = await engine.scanVideo(readFileSync(join(dir, f)), { url: `file:${f}`, maxSeconds: num("max-seconds"), maxFrames: num("max-frames") });
  const took = performance.now() - t;
  ms += took; n++;
  tally[r.tier] = (tally[r.tier] ?? 0) + 1;
  const c = r.coverage?.video;
  if (!c?.frames) unread++;
  seconds += c?.examinedSeconds ?? 0; framesTotal += c?.framesTotal ?? 0; framesRead += c?.framesRead ?? 0;
  if (r.delivered.replace(/\[[^\]]*\]/g, "").trim().length > 20) withText++;
  const scored = r.findings.filter((x) => x.confidence * x.severity >= 0.05);
  for (const k of new Set(r.findings.map((x) => x.kind))) anyKinds[k] = (anyKinds[k] ?? 0) + 1;
  if (r.findings.some((x) => x.kind === "video.partly_read")) partly++;
  if (r.tier !== "clean") for (const k of new Set(scored.map((x) => x.kind))) kinds[k] = (kinds[k] ?? 0) + 1;
  if (all || r.tier !== "clean") console.log(`${r.tier.padEnd(8)} ${String(r.score).padEnd(7)} ${f.slice(0, 36).padEnd(36)} ${c?.frames ? `${Math.round(c.seconds ?? 0)}s ${c.framesRead}/${c.framesTotal} ${c.sampling}` : `not read (${c?.framesReason})`} ${(took / 1000).toFixed(1)}s ${scored.map((x) => `${x.kind}=${(x.confidence * x.severity).toFixed(2)}`).join(" ")}`);
}
console.log(`\n${n} videos: ${Object.entries(tally).map(([k, v]) => `${v} ${k}`).join(", ")}`);
console.log(`frames not read: ${unread}; with text on screen: ${withText}; partly read: ${partly}`);
console.log(`${Math.round(seconds)} seconds examined, ${framesTotal} frames, ${framesRead} read for text; ${(ms / 1000 / Math.max(1, n)).toFixed(1)} s per video`);
console.log(`findings present in any video: ${Object.entries(anyKinds).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k} ${v}`).join(", ") || "none"}`);
if (Object.keys(kinds).length) console.log(`behind the refusals: ${Object.entries(kinds).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k} ${v}`).join(", ")}`);
