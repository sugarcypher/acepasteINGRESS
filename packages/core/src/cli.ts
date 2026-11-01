#!/usr/bin/env node
/**
 * gate <url>              gate a URL
 * gate --text < file      gate text/HTML/markdown/JSON on stdin
 * gate --json ...         emit the full result as JSON
 * gate --override ...     deliver a suspect page the human asked for
 * gate --sandbox=always|escalate|off
 * gate --policy=file.json
 * gate --verify < receipt.json   verify a receipt's digest and signature (GATE_VERIFY_PUBLIC_KEY=file.pem for ECDSA, GATE_SIGNING_KEY for HMAC)
 * gate --keygen                  print a new ECDSA P-256 key pair for receipt signing
 */
import { readFileSync } from "node:fs";
import { GateEngine } from "./engine.js";
import { loadPolicyFile } from "./policyfile.js";
import type { GateConfig, TaintReceipt } from "./types.js";

const args = process.argv.slice(2);
const flag = (n: string) => args.includes(`--${n}`);
const opt = (n: string) => args.find((a) => a.startsWith(`--${n}=`))?.split("=")[1];
const url = args.find((a) => /^https?:\/\//.test(a));

async function main() {
  const chunksIn = async () => { const c: Buffer[] = []; for await (const x of process.stdin) c.push(x as Buffer); return Buffer.concat(c).toString("utf8"); };
  if (flag("keygen")) {
    const k = GateEngine.generateSigningKeys();
    console.log(`# keyId ${k.keyId}\n# private key: keep secret; set GATE_SIGNING_PRIVATE_KEY_FILE to its path\n${k.privateKeyPem}\n# public key: publish; anyone can verify receipts with it\n${k.publicKeyPem}`);
    return;
  }
  if (flag("verify")) {
    const r = JSON.parse(await chunksIn()) as TaintReceipt;
    const pub = process.env.GATE_VERIFY_PUBLIC_KEY;
    const key = r.signatureAlg === "ecdsa-p256-sha256" ? (pub && !pub.includes("BEGIN") ? readFileSync(pub, "utf8") : pub) : process.env.GATE_SIGNING_KEY;
    console.log(JSON.stringify(GateEngine.verifyReceipt(r, key), null, 2));
    return;
  }
  const cfg: Partial<GateConfig> = opt("policy") ? loadPolicyFile(opt("policy")!) : {};
  if (flag("no-cloaking")) cfg.cloakingCheck = false;
  const sb = opt("sandbox"); if (sb === "always" || sb === "escalate" || sb === "off") cfg.sandbox = sb;
  if (process.env.GATE_SIGNING_KEY) cfg.signingKey = process.env.GATE_SIGNING_KEY;
  const pk = process.env.GATE_SIGNING_PRIVATE_KEY_FILE ? readFileSync(process.env.GATE_SIGNING_PRIVATE_KEY_FILE, "utf8") : process.env.GATE_SIGNING_PRIVATE_KEY;
  if (pk) cfg.signingPrivateKey = pk;
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
