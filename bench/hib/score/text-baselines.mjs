#!/usr/bin/env node
// HIB text-only baselines: Ingress's text components applied to the naive extraction (data/<split>/flat.jsonl from
// flatten.py), with no rendering, no file reader and no cloaking check.
//
//   INGRESS_REPO=. node bench/hib/score/text-baselines.mjs --split public [--data bench/hib/data]
//
//   classifier-<split>.jsonl  classifyText(text) >= the model's own threshold (classifierInfo().threshold): the learned
//                             text classifier alone, at its shipped line.
//   textscan-<split>.jsonl    IngressEngine.scan(text, {isHtml:false}) with cloaking, sandbox and stylesheet fetch off:
//                             every text pass (rules, characters, classifier), as docs/EVAL-0.10.0.md scored plain-text sets.
import { readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const args = process.argv.slice(2);
const opt = (k, d) => { const i = args.indexOf(`--${k}`); return i >= 0 ? args[i + 1] : d; };
const repo = resolve(process.env.INGRESS_REPO ?? process.cwd());
const split = opt("split", "public");
const data = resolve(opt("data", join(import.meta.dirname, "..", "data")));
const { IngressEngine, classifyText, classifierInfo } = await import(pathToFileURL(`${repo}/packages/core/dist/src/index.js`).href);
const { ENGINE_VERSION } = await import(pathToFileURL(`${repo}/packages/core/dist/src/types.js`).href);
const engine = new IngressEngine({ cloakingCheck: false, cacheTtlSeconds: 0, sandbox: "off", fetchStylesheets: false }, { log: () => {} });
const { threshold } = classifierInfo();
const rows = readFileSync(join(data, split, "flat.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
const cls = [], scan = [];
for (const r of rows) {
  const p = r.text.trim() ? classifyText(r.text) : 0;
  cls.push(JSON.stringify({ id: r.id, defense: `naive extraction + Ingress ${ENGINE_VERSION} classifier only (threshold ${threshold})`, flagged: p >= threshold, score: +p.toFixed(4) }));
  const res = r.text.trim() ? await engine.scan(r.text, { isHtml: false }) : { tier: "clean", score: 0 };
  scan.push(JSON.stringify({ id: r.id, defense: `naive extraction + Ingress ${ENGINE_VERSION} text scan (isHtml:false)`, flagged: res.tier === "hostile" || res.tier === "suspect", tier: res.tier }));
}
const out = join(import.meta.dirname, "..", "results");
writeFileSync(join(out, `classifier-${split}.jsonl`), cls.join("\n") + "\n");
writeFileSync(join(out, `textscan-${split}.jsonl`), scan.join("\n") + "\n");
console.log(JSON.stringify({ split, items: rows.length, threshold }));
