/**
 * Evaluation harness. Runs every corpus case through the engine (static
 * passes only, so the numbers are deterministic and fast) and reports
 * detection rate on attacks and false-positive rate on benign cases.
 *
 *   node dist/eval/run.js            summary + misses
 *   node dist/eval/run.js --verbose  every case
 *   node dist/eval/run.js --json     machine-readable
 */
import { GateEngine } from "../src/index.js";
import { ATTACKS, ATTACKS_R2, BENIGN, SUPPLY, SUPPLY_BENIGN, COLOR, COLOR_BENIGN, type Case } from "./corpus.js";

const verbose = process.argv.includes("--verbose");
const json = process.argv.includes("--json");
const engine = new GateEngine({ cloakingCheck: false, cacheTtlSeconds: 0, sandbox: "off", fetchStylesheets: false }, { log: () => {} });

interface Row { id: string; label: Case["label"]; tier: string; score: number; ok: boolean; kinds: string[]; note: string; ms: number }

async function run(c: Case): Promise<Row> {
  const t = performance.now();
  const r = await engine.scan(c.content, { isHtml: c.kind === "html" ? true : c.kind === "text" ? false : undefined, contentType: c.kind === "markdown" ? "text/markdown" : c.kind === "json" ? "application/json" : undefined });
  const ok = c.label === "attack" ? r.tier !== "clean" : c.label === "ambiguous" ? r.tier === "suspect" : r.tier === "clean";
  return { id: c.id, label: c.label, tier: r.tier, score: r.score, ok, kinds: [...new Set(r.findings.map((f) => f.kind))], note: c.note, ms: performance.now() - t };
}

const rows: Row[] = [];
for (const c of [...ATTACKS, ...ATTACKS_R2, ...BENIGN, ...SUPPLY, ...SUPPLY_BENIGN, ...COLOR, ...COLOR_BENIGN]) rows.push(await run(c));

const attacks = rows.filter((r) => r.label === "attack");
const benign = rows.filter((r) => r.label === "benign");
const ambiguous = rows.filter((r) => r.label === "ambiguous");
const caught = attacks.filter((r) => r.ok).length;
const hostileCaught = attacks.filter((r) => r.tier === "hostile").length;
const fp = benign.filter((r) => !r.ok).length;
const summary = {
  attacks: attacks.length, caught, detectionRate: +(caught / attacks.length).toFixed(3), hostileRate: +(hostileCaught / attacks.length).toFixed(3),
  benign: benign.length, falsePositives: fp, falsePositiveRate: +(fp / benign.length).toFixed(3),
  medianMs: +[...rows].sort((a, b) => a.ms - b.ms)[Math.floor(rows.length / 2)].ms.toFixed(2),
};

if (json) { console.log(JSON.stringify({ summary, rows }, null, 2)); process.exit(fp > 0 || caught < attacks.length ? 1 : 0); }

console.log(`attacks: ${caught}/${attacks.length} refused (${(summary.detectionRate * 100).toFixed(1)}%), ${hostileCaught} hostile`);
console.log(`benign:  ${benign.length - fp}/${benign.length} passed clean (${((1 - summary.falsePositiveRate) * 100).toFixed(1)}%)`);
console.log(`ambiguous: ${ambiguous.filter((r) => r.ok).length}/${ambiguous.length} refused as suspect (overridable)`);
console.log(`median analysis time: ${summary.medianMs} ms`);
for (const r of rows) {
  if (verbose || !r.ok) console.log(`${r.ok ? "  ok  " : " MISS "} ${r.id.padEnd(24)} ${r.tier.padEnd(8)} ${r.score.toFixed(2)}  ${r.kinds.join(",") || "-"}   (${r.note})`);
}
process.exit(fp > 0 || caught < attacks.length || ambiguous.some((r) => !r.ok) ? 1 : 0);
