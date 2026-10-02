#!/usr/bin/env node
/**
 * gate <url>              gate a URL
 * gate --text < file      gate text/HTML/markdown/JSON on stdin
 * gate --json ...         emit the full result as JSON
 * gate --override ...     deliver a suspect page the human asked for
 * gate --sandbox=always|escalate|off
 * gate --policy=file.json
 * gate --verify < receipt.json   verify a receipt's digest (and signature with GATE_SIGNING_KEY)
 */
import { GateEngine } from "./engine.js";
import { loadPolicyFile } from "./policyfile.js";
import type { GateConfig, TaintReceipt } from "./types.js";

const args = process.argv.slice(2);
const flag = (n: string) => args.includes(`--${n}`);
const opt = (n: string) => args.find((a) => a.startsWith(`--${n}=`))?.split("=")[1];
const url = args.find((a) => /^https?:\/\//.test(a));

async function main() {
  const chunksIn = async () => { const c: Buffer[] = []; for await (const x of process.stdin) c.push(x as Buffer); return Buffer.concat(c).toString("utf8"); };
  if (flag("verify")) {
    const r = JSON.parse(await chunksIn()) as TaintReceipt;
    console.log(JSON.stringify(GateEngine.verifyReceipt(r, process.env.GATE_SIGNING_KEY), null, 2));
    return;
  }
  const cfg: Partial<GateConfig> = opt("policy") ? loadPolicyFile(opt("policy")!) : {};
  if (flag("no-cloaking")) cfg.cloakingCheck = false;
  const sb = opt("sandbox"); if (sb === "always" || sb === "escalate" || sb === "off") cfg.sandbox = sb;
  if (process.env.GATE_SIGNING_KEY) cfg.signingKey = process.env.GATE_SIGNING_KEY;
  const engine = new GateEngine(cfg);
  const override = flag("override");

  let result;
  if (flag("text")) result = await engine.scan(await chunksIn(), { override });
  else if (url) result = await engine.fetch(url, { override });
  else { console.error("usage: gate <url> | gate --text < file   [--json] [--no-cloaking] [--override] [--sandbox=always|escalate|off] [--policy=file.json] | gate --verify < receipt.json"); process.exit(2); }

  if (flag("json")) { console.log(JSON.stringify(result, null, 2)); return; }
  console.log(result.envelope);
  console.error(`\n[timings] ${Object.entries(result.timings).map(([k, v]) => `${k}=${v!.toFixed(1)}ms`).join(" ")}`);
}
main().catch((e) => { console.error(e); process.exit(1); });
