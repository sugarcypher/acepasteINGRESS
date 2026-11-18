#!/usr/bin/env node
// Fetch each URL in a list through the gate and print one line per page: verdict, score and, for a refusal,
// the kind of the strongest finding. Never prints page text.
//
//   npm run build && npm run pages                # tools/pages/real-pages.txt
//   node tools/pages/score-pages.mjs my-urls.txt
//
// Every page in real-pages.txt is benign, so each refusal is a false alarm to explain. The list is for
// catching regressions on the web as it is; it is not a held-out benchmark (fixes have been made against it).
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { IngressEngine } from "../../packages/core/dist/src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const list = process.argv[2] ?? join(here, "real-pages.txt");
const urls = readFileSync(list, "utf8").split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
const engine = new IngressEngine({ cacheTtlSeconds: 0, sandbox: "off" }, { log: () => {} });
const tally = {};
for (const url of urls) {
  try {
    const r = await engine.fetch(url);
    const top = r.findings.filter((f) => f.confidence * f.severity > 0).sort((a, b) => b.confidence * b.severity - a.confidence * a.severity)[0];
    tally[r.tier] = (tally[r.tier] ?? 0) + 1;
    console.log(`${r.tier.padEnd(11)} ${String(r.score).padEnd(7)} ${(r.tier === "clean" ? "" : `${top?.kind ?? ""}${top?.inHidden ? " (hidden)" : ""}`).padEnd(44)} ${url}`);
  } catch (e) {
    tally.error = (tally.error ?? 0) + 1;
    console.log(`${"error".padEnd(11)} ${String(e.message).slice(0, 52).padEnd(52)} ${url}`);
  }
}
console.log(`\n${urls.length} pages: ${Object.entries(tally).map(([k, n]) => `${n} ${k}`).join(", ")}`);
