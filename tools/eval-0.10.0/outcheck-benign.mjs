#!/usr/bin/env node
// False-alarm proxy for the 0.10.0 exfiltration check outcheck(): read benign markdown/text as if it were a model's
// reply (no session context, no allow-list) and count replies and addresses flagged. Counts only, never text.
//   INGRESS_REPO=<repo> node outcheck-benign.mjs <set.jsonl> ...   (rows with label=false are used)
import { readFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import { pathToFileURL } from "node:url";
const repo = process.env.INGRESS_REPO ?? resolve(process.cwd());
const { outcheck } = await import(pathToFileURL(`${repo}/packages/core/dist/src/index.js`).href);
let T = { replies: 0, withAddr: 0, addrs: 0, suspect: 0, hostile: 0, flaggedAddrs: 0 };
for (const f of process.argv.slice(2)) {
  const rows = readFileSync(f, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)).filter((r) => r.label === false);
  const t = { replies: 0, withAddr: 0, addrs: 0, suspect: 0, hostile: 0, flaggedAddrs: 0 };
  const reasons = {};
  const t0 = performance.now();
  for (const r of rows) {
    const o = outcheck(r.text);
    t.replies++; t.addrs += o.checked; if (o.checked) t.withAddr++;
    if (o.tier !== "clean") t[o.tier]++;
    t.flaggedAddrs += o.findings.length;
    for (const fd of o.findings) { const k = `${fd.severity}: ${String(fd.reasons?.[0] ?? "").replace(/\d+/g, "N").slice(0, 60)}`; reasons[k] = (reasons[k] ?? 0) + 1; }
  }
  for (const k of Object.keys(T)) T[k] += t[k];
  console.log(`${basename(f)}: ${t.replies} benign texts (${t.withAddr} with addresses, ${t.addrs} addresses) -> suspect ${t.suspect}, hostile ${t.hostile}; ${t.flaggedAddrs} addresses flagged; ${((performance.now() - t0) / 1000).toFixed(1)}s`);
  for (const [k, n] of Object.entries(reasons).sort((a, b) => b[1] - a[1])) console.log(`    ${n}  ${k}`);
}
console.log(`total: ${T.replies} texts, ${T.withAddr} with addresses, ${T.addrs} addresses; replies flagged ${T.suspect + T.hostile} (hostile ${T.hostile}, suspect ${T.suspect}); addresses flagged ${T.flaggedAddrs}`);
