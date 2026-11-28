#!/usr/bin/env node
// Same scan as packages/core/eval/pint.ts (engine.scan(text, {isHtml:false}), static passes, cloaking off,
// sandbox off, no stylesheet fetch, default thresholds), but keeps hostile and suspect apart and times each set.
// Prints counts only, never input text.
//
//   node score-tiers.mjs [--json=out.json] <set.jsonl> ...
import { readFileSync, writeFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const repo = process.env.INGRESS_REPO ?? resolve(process.cwd());
const { IngressEngine } = await import(pathToFileURL(`${repo}/packages/core/dist/src/index.js`).href);
const { ENGINE_VERSION, RULESET_VERSION } = await import(pathToFileURL(`${repo}/packages/core/dist/src/types.js`).href);

const args = process.argv.slice(2);
const jsonOut = args.find((a) => a.startsWith("--json="))?.slice(7);
const files = args.filter((a) => !a.startsWith("--"));
const engine = new IngressEngine({ cloakingCheck: false, cacheTtlSeconds: 0, sandbox: "off", fetchStylesheets: false }, { log: () => {} });

const blank = () => ({ n: 0, hostile: 0, suspect: 0, clean: 0 });
const add = (t, tier) => { t.n++; t[tier]++; };
const pct = (a, b) => (b ? `${((100 * a) / b).toFixed(1)}%` : "-");
const results = { engine: ENGINE_VERSION, ruleset: RULESET_VERSION, node: process.version, sets: [] };

for (const f of files) {
  const rows = readFileSync(f, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
  const atk = blank(), ben = blank(), cats = {};
  const t0 = performance.now();
  for (const r of rows) {
    const res = await engine.scan(r.text, { isHtml: false });
    add(r.label ? atk : ben, res.tier);
    add((cats[r.category] ??= { label: r.label, ...blank() }), res.tier);
  }
  const seconds = (performance.now() - t0) / 1000;
  results.sets.push({ set: basename(f), n: rows.length, attacks: atk, benign: ben, categories: cats, seconds });
  console.log(`${basename(f)}  n=${rows.length}  ${seconds.toFixed(1)}s`);
  if (atk.n) console.log(`  attacks ${atk.n}: refused ${atk.hostile + atk.suspect} (${pct(atk.hostile + atk.suspect, atk.n)}) = hostile ${atk.hostile} (${pct(atk.hostile, atk.n)}) + suspect ${atk.suspect} (${pct(atk.suspect, atk.n)})`);
  if (ben.n) console.log(`  benign  ${ben.n}: refused ${ben.hostile + ben.suspect} (${pct(ben.hostile + ben.suspect, ben.n)}) = hostile ${ben.hostile} + suspect ${ben.suspect}`);
  for (const [c, t] of Object.entries(cats)) console.log(`    ${c.padEnd(40)} ${t.label ? "atk" : "ben"} n=${t.n} hostile=${t.hostile} suspect=${t.suspect} clean=${t.clean}`);
}
if (jsonOut) writeFileSync(jsonOut, JSON.stringify(results, null, 2));
