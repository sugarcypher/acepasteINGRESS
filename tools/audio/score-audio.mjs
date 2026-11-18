#!/usr/bin/env node
// Scan every recording in a folder through the engine and print, for each one that is not clean, the verdict
// and the kinds of finding behind it. Never prints a transcript.
//
//   export INGRESS_AUDIO_TRANSCRIBER="python tools/audio/transcribe.py"
//   node tools/audio/score-audio.mjs <folder> [--all]
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { IngressEngine } from "../../packages/core/dist/src/index.js";

const dir = process.argv[2];
if (!dir) { console.error("usage: score-audio.mjs <folder> [--all]"); process.exit(2); }
const all = process.argv.includes("--all");
const engine = new IngressEngine({ cacheTtlSeconds: 0, sandbox: "off" }, { log: () => {} });
const tally = {};
let n = 0, ms = 0, seconds = 0, untranscribed = 0, words = 0;
for (const f of readdirSync(dir).sort()) {
  if (f.startsWith(".") || !/\.(wav|mp3|m4a|flac|ogg|aiff?)$/i.test(f)) continue;
  const t = performance.now();
  const r = await engine.scanAudio(readFileSync(join(dir, f)), { url: `file:${f}` });
  ms += performance.now() - t; n++;
  tally[r.tier] = (tally[r.tier] ?? 0) + 1;
  if (!r.coverage?.audio?.transcribed) untranscribed++;
  seconds += r.coverage?.audio?.seconds ?? 0;
  words += r.delivered.split(/\s+/).filter(Boolean).length;
  const scored = r.findings.filter((x) => x.confidence * x.severity >= 0.05);
  if (all || r.tier !== "clean") console.log(`${r.tier.padEnd(8)} ${String(r.score).padEnd(7)} ${f.padEnd(24)} ${scored.map((x) => `${x.kind}=${(x.confidence * x.severity).toFixed(2)}`).join(" ").slice(0, 150)}`);
}
console.log(`\n${n} recordings (${Math.round(seconds)} s of audio, ${words} words delivered): ${Object.entries(tally).map(([k, v]) => `${v} ${k}`).join(", ")}; ${untranscribed} not transcribed; ${(ms / Math.max(1, n) / 1000).toFixed(1)} s each`);
