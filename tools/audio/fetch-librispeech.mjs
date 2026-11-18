#!/usr/bin/env node
// Download a few utterances of LibriSpeech (people reading public-domain books aloud; CC BY 4.0) for a
// false-alarm check of the audio gate. Every one is ordinary speech, so every refusal is a false alarm.
//
//   node tools/audio/fetch-librispeech.mjs <out-dir> [count]
//
// Prints counts only.
import { mkdirSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";

const out = process.argv[2];
const count = Number(process.argv[3] ?? 24);
if (!out) { console.error("usage: fetch-librispeech.mjs <out-dir> [count]"); process.exit(2); }
mkdirSync(out, { recursive: true });
const api = (offset) => `https://datasets-server.huggingface.co/rows?dataset=${encodeURIComponent("openslr/librispeech_asr")}&config=clean&split=test&offset=${offset}&length=4`;
let n = 0, failed = 0;
// spread through the split, so the clips come from different readers
for (let i = 0; n < count && i < count * 3; i++) {
  try {
    const res = await fetch(api(i * 97), { headers: { "user-agent": "acepaste-ingress-eval" }, signal: AbortSignal.timeout(60_000) });
    if (!res.ok) { failed++; await new Promise((s) => setTimeout(s, 3000)); continue; }
    for (const { row } of (await res.json()).rows ?? []) {
      const src = row.audio?.[0]?.src;
      if (!src || n >= count) continue;
      const file = join(out, `libri-${String(n).padStart(2, "0")}.wav`);
      if (!existsSync(file)) {
        const a = await fetch(src, { signal: AbortSignal.timeout(60_000) });
        if (!a.ok) { failed++; continue; }
        writeFileSync(file, Buffer.from(await a.arrayBuffer()));
      }
      n++;
    }
  } catch { failed++; }
  await new Promise((s) => setTimeout(s, 800));
}
console.log(`${n} recordings in ${out}, ${failed} requests failed`);
