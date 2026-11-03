#!/usr/bin/env node
/**
 * ingress <url>              gate a URL
 * ingress --text < file      gate text/HTML/markdown/JSON on stdin
 * ingress --json ...         emit the full result as JSON
 * ingress --override ...     deliver a suspect page the human asked for
 * ingress --sandbox=always|escalate|off
 * ingress --policy=file.json
 * ingress --verify < receipt.json   verify a receipt's digest and signature (INGRESS_VERIFY_PUBLIC_KEY=file.pem for ECDSA, INGRESS_SIGNING_KEY for HMAC)
 * ingress --keygen                  print a new ECDSA P-256 key pair for receipt signing
 */
import { readFileSync } from "node:fs";
import { IngressEngine } from "./engine.js";
import { HONEST_USER_AGENT } from "./acquire.js";
import { summarize, cloakingConfigFromEnv } from "./summary.js";
import { loadPolicyFile } from "./policyfile.js";
import { checkInstructionFiles, approveInstructionFile, readInstructionBytes } from "./instructions.js";
import { macosDialogApprover } from "./approvers.js";
import { createInterface } from "node:readline/promises";
import { userInfo } from "node:os";
import type { IngressConfig, TaintReceipt } from "./types.js";

const args = process.argv.slice(2);
const flag = (n: string) => args.includes(`--${n}`);
const opt = (n: string) => args.find((a) => a.startsWith(`--${n}=`))?.split("=")[1];
const url = args.find((a) => /^https?:\/\//.test(a));

async function main() {
  const chunksIn = async () => { const c: Buffer[] = []; for await (const x of process.stdin) c.push(x as Buffer); return Buffer.concat(c).toString("utf8"); };
  if (args[0] === "instructions") return instructionsCommand(args.slice(1));
  if (flag("keygen")) {
    const k = IngressEngine.generateSigningKeys();
    console.log(`# keyId ${k.keyId}\n# private key: keep secret; set INGRESS_SIGNING_PRIVATE_KEY_FILE to its path\n${k.privateKeyPem}\n# public key: publish; anyone can verify receipts with it\n${k.publicKeyPem}`);
    return;
  }
  if (flag("verify")) {
    const r = JSON.parse(await chunksIn()) as TaintReceipt;
    const pub = process.env.INGRESS_VERIFY_PUBLIC_KEY;
    const key = r.signatureAlg === "ecdsa-p256-sha256" ? (pub && !pub.includes("BEGIN") ? readFileSync(pub, "utf8") : pub) : process.env.INGRESS_SIGNING_KEY;
    console.log(JSON.stringify(IngressEngine.verifyReceipt(r, key), null, 2));
    return;
  }
  const cfg: Partial<IngressConfig> = opt("policy") ? loadPolicyFile(opt("policy")!) : {};
  Object.assign(cfg, cloakingConfigFromEnv(process.env, HONEST_USER_AGENT));
  if (flag("no-cloaking")) cfg.cloakingCheck = false;
  const hf = opt("human-fetch"); if (hf === "browser" || hf === "http") cfg.humanFetch = hf;
  const sb = opt("sandbox"); if (sb === "always" || sb === "escalate" || sb === "off") cfg.sandbox = sb;
  if (process.env.INGRESS_SIGNING_KEY) cfg.signingKey = process.env.INGRESS_SIGNING_KEY;
  const pk = process.env.INGRESS_SIGNING_PRIVATE_KEY_FILE ? readFileSync(process.env.INGRESS_SIGNING_PRIVATE_KEY_FILE, "utf8") : process.env.INGRESS_SIGNING_PRIVATE_KEY;
  if (pk) cfg.signingPrivateKey = pk;
  const engine = new IngressEngine(cfg);
  const override = flag("override");

  let result;
  if (flag("text")) result = await engine.scan(await chunksIn(), { override });
  else if (url) result = await engine.fetch(url, { override });
  else { console.error("usage: ingress <url> | ingress --text < file   [--json | --summary] [--no-cloaking] [--human-fetch=http|browser] [--override] [--sandbox=always|escalate|off] [--policy=file.json] | ingress --verify < receipt.json"); process.exit(2); }

  if (flag("json")) { console.log(JSON.stringify(result, null, 2)); return; }
  if (flag("summary")) { console.log(JSON.stringify(summarize(result))); if (result.tier === "unreachable") process.exitCode = 1; return; }
  console.log(result.envelope);
  console.error(`\n[timings] ${Object.entries(result.timings).map(([k, v]) => `${k}=${v!.toFixed(1)}ms`).join(" ")}`);
}
main().catch((e) => { console.error(e); process.exit(1); });

/**
 *   ingress instructions [dir]                     list instruction files and their approval status
 *   ingress instructions approve <dir> <relPath>   approve one file's exact bytes (interactive terminal only)
 */
async function instructionsCommand(a: string[]) {
  if (a[0] === "approve") {
    const [dir, rel] = [a[1], a[2]];
    if (!dir || !rel) { console.error("usage: ingress instructions approve <dir> <relative path>"); process.exit(2); }
    if (!process.stdin.isTTY || !process.stdout.isTTY) { console.error("refused: approval needs an interactive terminal, typed by a person"); process.exit(3); }
    // read once: what is shown is what gets fingerprinted and approved
    let bytes;
    try { bytes = readInstructionBytes(dir, rel); } catch (e) { console.error((e as Error).message); process.exit(2); }
    const text = bytes.buf.toString("utf8");
    const MAX_SHOWN = 100_000;
    if (bytes.buf.length > MAX_SHOWN) { console.error(`refused: ${rel} is ${bytes.buf.length} bytes, more than can be shown for review (${MAX_SHOWN})`); process.exit(2); }
    const engine = new IngressEngine({ cloakingCheck: false, sandbox: "off" }, { log: () => {} });
    const r = await engine.scan(text, { url: `file:${rel}`, contentType: "text/markdown" });
    // terminal escape sequences and invisible characters are shown, never interpreted
    const shown = text.replace(/[\p{Cc}\p{Cf}\u2028\u2029]/gu, (c) => (c === "\n" || c === "\t" ? c : `<U+${c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}>`));
    const inDep = /(?:^|\/)(?:node_modules|vendor|\.venv|venv|site-packages|third_party)\//.test(rel);
    console.log(`\n${rel}  (${bytes.buf.length} bytes, fingerprint ${bytes.sha256.slice(0, 16)})${inDep ? "  INSIDE A DEPENDENCY" : ""}`);
    console.log(`gate verdict: ${r.tier}${r.findings.length ? " — " + [...new Set(r.findings.map((x) => x.kind))].join(", ") : ""}`);
    console.log(`\n----- file (complete) -----\n${shown}\n----- end -----\n`);
    let ok = false;
    if (process.platform === "darwin") {
      // confirmation through a native dialog: a pseudo-terminal driven by a program cannot click it
      const answer = await macosDialogApprover({ timeoutSec: 180 }).request({
        id: "instructions", runId: "instructions", tool: `approve instruction file ${rel}`, canonicalArgs: JSON.stringify({ file: rel, bytes: bytes.buf.length, fingerprint: bytes.sha256.slice(0, 16), verdict: r.tier }),
        digest: bytes.sha256, reasons: ["you are approving this exact version as project guidance for coding agents; the full text is in your terminal"], destinations: [], fields: [], sources: [], createdAt: Date.now(), expiresAt: Date.now() + 180_000,
      });
      ok = answer === "approved";
    } else {
      const rl = createInterface({ input: process.stdin, output: process.stdout });
      const typed = (await rl.question(`To approve this exact version, type the first 8 characters of its fingerprint: `)).trim();
      rl.close();
      ok = typed === bytes.sha256.slice(0, 8);
    }
    if (!ok) { console.log("not approved"); process.exit(1); }
    try {
      const e = approveInstructionFile(dir, rel, userInfo().username, bytes.sha256);
      console.log(`approved ${rel} at ${e.approvedAt}. Any change to the file needs approval again.`);
    } catch (e) { console.error((e as Error).message); process.exit(1); }
    return;
  }
  const dir = a[0] ?? ".";
  const files = checkInstructionFiles(dir);
  if (!files.length) { console.log("no instruction files found"); return; }
  for (const f of files) console.log(`${f.status.padEnd(9)} ${f.inDependency ? "[dependency] " : ""}${f.relPath}  ${f.sha256.slice(0, 12)}`);
}
