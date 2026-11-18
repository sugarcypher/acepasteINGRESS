/**
 * PINT-style scoring (Lakera PINT Benchmark, github.com/lakeraai/pint-benchmark) for Ingress on JSON Lines sets:
 *   {"text": "...", "label": true|false, "category": "...", "source": "..."}
 *
 *   node dist/eval/pint.js <set.jsonl> [more.jsonl ...]      per-set and pooled scores
 *   node dist/eval/pint.js --json <set.jsonl> ...             machine-readable
 *
 * Same rules as the PINT notebook: each input goes through the detector as a single string (here
 * engine.scan, plain text, static passes); flagged means the verdict is not clean (suspect or hostile:
 * both refuse); the score is balanced accuracy, the mean of accuracy on attacks and accuracy on benign
 * inputs. A score here is NOT a PINT score: PINT's 4,314 inputs are private and only Lakera can run them.
 * It prints numbers only, never input text.
 */
import { readFileSync } from "node:fs";
import { basename } from "node:path";
import { IngressEngine } from "../src/index.js";
import { ENGINE_VERSION, RULESET_VERSION } from "../src/types.js";

interface Row { text: string; label: boolean; category: string; source?: string }
interface Tally { tp: number; fn: number; tn: number; fp: number }

const json = process.argv.includes("--json");
const files = process.argv.slice(2).filter((a) => !a.startsWith("--"));
if (!files.length) { console.error("usage: pint.js [--json] <set.jsonl> ..."); process.exit(2); }

const engine = new IngressEngine({ cloakingCheck: false, cacheTtlSeconds: 0, sandbox: "off", fetchStylesheets: false }, { log: () => {} });
const empty = (): Tally => ({ tp: 0, fn: 0, tn: 0, fp: 0 });
const add = (t: Tally, label: boolean, flagged: boolean) => { if (label) flagged ? t.tp++ : t.fn++; else flagged ? t.fp++ : t.tn++; };
const tpr = (t: Tally) => (t.tp + t.fn ? t.tp / (t.tp + t.fn) : NaN);
const tnr = (t: Tally) => (t.tn + t.fp ? t.tn / (t.tn + t.fp) : NaN);
/** PINT balanced accuracy: mean of per-label accuracy over the labels present */
const pint = (t: Tally) => { const a = [tpr(t), tnr(t)].filter((x) => !Number.isNaN(x)); return a.reduce((s, x) => s + x, 0) / a.length; };

export async function flagged(text: string): Promise<boolean> {
  const r = await engine.scan(text, { isHtml: false });
  return r.tier !== "clean";
}

const pooled = empty();
const perCategory = new Map<string, Tally>();
const perSet: Array<{ set: string; n: number; tally: Tally; score: number }> = [];
for (const f of files) {
  const rows: Row[] = readFileSync(f, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
  const t = empty();
  for (const r of rows) {
    const fl = await flagged(r.text);
    add(t, r.label, fl); add(pooled, r.label, fl);
    const c = perCategory.get(r.category) ?? empty(); add(c, r.label, fl); perCategory.set(r.category, c);
  }
  perSet.push({ set: basename(f), n: rows.length, tally: t, score: pint(t) });
}

const pct = (x: number) => (Number.isNaN(x) ? "   -  " : `${(x * 100).toFixed(1).padStart(5)}%`);
if (json) {
  console.log(JSON.stringify({ engine: ENGINE_VERSION, ruleset: RULESET_VERSION, pooled: { ...pooled, score: pint(pooled) }, perSet, perCategory: Object.fromEntries(perCategory) }, null, 2));
} else {
  console.log(`Ingress ${ENGINE_VERSION} (ruleset ${RULESET_VERSION}), PINT-style balanced accuracy\n`);
  console.log("set                        n   attacks caught   benign passed   score");
  for (const s of perSet) console.log(`${s.set.padEnd(22)} ${String(s.n).padStart(5)}   ${pct(tpr(s.tally))} (${s.tally.tp}/${s.tally.tp + s.tally.fn})`.padEnd(54) + `${pct(tnr(s.tally))} (${s.tally.tn}/${s.tally.tn + s.tally.fp})`.padEnd(18) + pct(s.score));
  console.log("\nby category");
  for (const [c, t] of perCategory) console.log(`  ${c.padEnd(18)} ${t.tp + t.fn ? `caught ${pct(tpr(t))} of ${t.tp + t.fn}` : `passed ${pct(tnr(t))} of ${t.tn + t.fp}`}`);
  console.log(`\npooled: ${pooled.tp + pooled.fn + pooled.tn + pooled.fp} inputs, attacks caught ${pct(tpr(pooled))}, benign passed ${pct(tnr(pooled))}, score ${pct(pint(pooled))}`);
}
