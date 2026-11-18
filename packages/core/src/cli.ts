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
import { auditEnvironment, formatAudit } from "./audit.js";
import { trackAudit, confirmAuditArea, formatAuditChanges, AUDIT_NEEDS_CONFIRMATION } from "./audit-changes.js";
import { confirmServerTools, describeServerTools } from "./tooldefs.js";
import { BaselineStore } from "./changes.js";
import { engageStop, clearStop, stopReason } from "./safeguards.js";
import { postToolUse, userPromptSubmit, preCompact, postCompact, sessionStart, remoteGate, type HookGate } from "./agent-hooks.js";
import { appendFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { AuditArea } from "./audit-parsers.js";
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
  if (args[0] === "hook") return hookCommand(args[1], await chunksIn());
  if (args[0] === "tools") return toolsCommand(args.slice(1));
  // ingress stop [reason]: every broker on this machine refuses every agent action until `ingress resume`.
  // Anyone may stop, an agent included. Only a person at a terminal may resume.
  if (args[0] === "stop") {
    const p = engageStop(args.slice(1).join(" "));
    console.log(`stopped: agent actions routed through AcePaste Ingress are refused until you run: ingress resume\n(${p})`);
    return;
  }
  if (args[0] === "resume") {
    const why = stopReason();
    if (!why) { console.log("not stopped"); return; }
    if (!process.stdin.isTTY || !process.stdout.isTTY) { console.error("refused: resuming needs an interactive terminal, typed by a person"); process.exit(3); }
    console.log(`stopped: ${why}`);
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    const typed = (await rl.question('Type "resume" to let agents act again: ')).trim();
    rl.close();
    if (typed !== "resume") { console.log("still stopped"); process.exit(1); }
    clearStop();
    console.log("resumed");
    return;
  }
  if (args[0] === "audit") {
    // read-only: what on this machine could change what agents receive (hosts, DNS, proxies, browsers, certificates, agent configs)
    const gateEngine = new IngressEngine({ cloakingCheck: false, sandbox: "off" }, { log: () => {} });
    const remoteBase = opt("remote");
    if (remoteBase && !process.env.INGRESS_API_KEY) { console.error("--remote needs INGRESS_API_KEY (an API key for that gate)"); process.exit(2); }
    const fetchEngine = new IngressEngine({ cloakingCheck: false, sandbox: "off", cacheTtlSeconds: 0 }, { log: () => {} });
    const r = await auditEnvironment({
      network: flag("network"),
      gate: (t, src) => gateEngine.scan(t, { url: src, contentType: "text/markdown" }),
      remote: remoteBase ? { base: remoteBase, key: process.env.INGRESS_API_KEY!, localFetch: (u) => fetchEngine.fetch(u) } : undefined,
    });
    // ingress audit confirm <area>: a person says the current items of that area are expected
    if (args[1] === "confirm") {
      const area = args[2] as AuditArea | undefined;
      if (!area || !AUDIT_NEEDS_CONFIRMATION.includes(area)) { console.error(`usage: ingress audit confirm <area>   areas: ${AUDIT_NEEDS_CONFIRMATION.join(", ")}`); process.exit(2); }
      if (!process.stdin.isTTY || !process.stdout.isTTY) { console.error("refused: confirmation needs an interactive terminal, typed by a person"); process.exit(3); }
      const items = r.findings.filter((f) => f.area === area);
      console.log(`\n${area}: ${items.length} item(s) found now\n`);
      for (const f of items) console.log(`  [${f.severity}] ${f.title}\n      ${f.detail}${f.where ? `\n      where: ${f.where}` : ""}\n`);
      const rl = createInterface({ input: process.stdin, output: process.stdout });
      const typed = (await rl.question(`Type "${area}" to confirm these are expected: `)).trim();
      rl.close();
      if (typed !== area) { console.log("not confirmed"); process.exit(1); }
      const c = confirmAuditArea(r, area);
      console.log(`confirmed ${c.items} item(s) in ${c.area}. Any addition or removal will ask for your attention again.`);
      return;
    }
    // --no-track looks without recording a snapshot (and without comparing)
    let changes: ReturnType<typeof trackAudit> | undefined;
    if (!flag("no-track")) { try { changes = trackAudit(r); } catch (e) { console.error(`change tracking unavailable: ${(e as Error).message}`); } }
    if (flag("json")) console.log(JSON.stringify(changes ? { ...r, changes } : r, null, 2));
    else console.log(`${changes ? formatAuditChanges(changes) + "\n\n" : ""}${formatAudit(r)}`);
    if (r.summary.high) process.exitCode = 1;
    return;
  }
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
 *   ingress hook <event>     reply to an agent harness hook: the event's JSON on stdin, the reply on stdout
 *       events: post-tool-use, user-prompt-submit, pre-compact, post-compact, session-start
 *   The engine runs in this process unless INGRESS_HOOK_SERVICE names a running Ingress service
 *   (http://127.0.0.1:8787), whose key is read from INGRESS_HOOK_KEY_FILE (default ~/.acepaste-ingress/local-api-key);
 *   then the service's receipts and audit trail record what the hooks gated.
 */
async function hookCommand(event: string | undefined, stdin: string) {
  let input: Record<string, unknown>;
  try { input = JSON.parse(stdin || "{}") as Record<string, unknown>; } catch { console.error("ingress hook: the event on stdin is not JSON"); process.exit(1); }
  const service = process.env.INGRESS_HOOK_SERVICE;
  let gate: HookGate;
  let ownPort: number | undefined;
  if (service) {
    const keyFile = process.env.INGRESS_HOOK_KEY_FILE ?? join(homedir(), ".acepaste-ingress", "local-api-key");
    let key = "";
    try { key = readFileSync(keyFile, "utf8").trim(); } catch { /* the gate reports it: a missing key fails closed in the handlers */ }
    gate = key ? remoteGate(service, key) : { fetch: async () => { throw new Error(`cannot read the Ingress API key at ${keyFile}`); }, scan: async () => { throw new Error(`cannot read the Ingress API key at ${keyFile}`); } };
    try { const u = new URL(service); if (u.port) ownPort = Number(u.port); } catch { /* not a URL: nothing is exempt */ }
  } else {
    const cfg: Partial<IngressConfig> = { ...(process.env.INGRESS_POLICY ? loadPolicyFile(process.env.INGRESS_POLICY) : {}), ...cloakingConfigFromEnv(process.env, HONEST_USER_AGENT) };
    const sb = process.env.INGRESS_SANDBOX; cfg.sandbox = sb === "always" || sb === "escalate" ? sb : "off";
    const pk = process.env.INGRESS_SIGNING_PRIVATE_KEY_FILE ? readFileSync(process.env.INGRESS_SIGNING_PRIVATE_KEY_FILE, "utf8") : process.env.INGRESS_SIGNING_PRIVATE_KEY;
    if (pk) cfg.signingPrivateKey = pk;
    const logPath = process.env.INGRESS_LOG;
    const engine = new IngressEngine(cfg, { log: (e) => { if (logPath) { try { appendFileSync(logPath, JSON.stringify(e) + "\n"); } catch { /* best effort */ } } } });
    gate = { fetch: (u) => engine.fetch(u), scan: (c, o) => engine.scan(c, o) };
  }
  const out = (v: unknown) => { if (v !== undefined) process.stdout.write(JSON.stringify(v) + "\n"); };
  switch (event) {
    case "post-tool-use": return out(await postToolUse(input, gate, { ownPort }));
    case "user-prompt-submit": return out(await userPromptSubmit(input, gate));
    case "pre-compact": process.stdout.write(preCompact() + "\n"); return;
    case "post-compact": await postCompact(input, gate); return;
    case "session-start": return out(sessionStart(input));
    default: console.error("usage: ingress hook post-tool-use|user-prompt-submit|pre-compact|post-compact|session-start   (event JSON on stdin)"); process.exit(2);
  }
}

/**
 *   ingress tools                      downstream MCP servers whose tools were recorded, and their state
 *   ingress tools confirm <server>     confirm the tools that server offered when the proxy last started (interactive terminal only)
 */
async function toolsCommand(a: string[]) {
  if (a[0] === "confirm") {
    const server = a[1];
    if (!server) { console.error("usage: ingress tools confirm <server>"); process.exit(2); }
    if (!process.stdin.isTTY || !process.stdout.isTTY) { console.error("refused: confirmation needs an interactive terminal, typed by a person"); process.exit(3); }
    const d = describeServerTools(server);
    if (!d) { console.error(`no reviewed tools for "${server}": start the Ingress proxy with that server once, then confirm`); process.exit(2); }
    console.log(`\n${server}: ${d.pending.length} tool(s) offered when the proxy last started`);
    if (d.state.state === "changed") {
      console.log(`changed since ${d.state.since}:`);
      for (const x of d.state.added) console.log(`  + ${x.label} (new, or its definition changed)`);
      for (const x of d.state.removed) console.log(`  - ${x.replace(/ @ [0-9a-f]{16}$/, "")} (previous definition)`);
    } else console.log(`state: ${d.state.state}`);
    console.log("Read the server's current tool descriptions before confirming; Ingress checked them for hidden instructions, not for what they do.");
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    const typed = (await rl.question(`Type "${server}" to confirm this set of tools: `)).trim();
    rl.close();
    if (typed !== server) { console.log("not confirmed"); process.exit(1); }
    const c = confirmServerTools(server);
    console.log(`confirmed ${c.tools} tool(s) of ${c.server} at ${c.at}. Restart the proxy; a later change will be held again.`);
    return;
  }
  const groups = new BaselineStore().groups().filter((g) => g.startsWith("mcp-tools:")).map((g) => g.slice("mcp-tools:".length));
  if (!groups.length) { console.log("no downstream servers recorded yet"); return; }
  for (const s of groups) {
    const d = describeServerTools(s);
    console.log(`${(d?.state.state ?? "unknown").padEnd(10)} ${s}${d ? `  (${d.pending.length} tools)` : ""}`);
  }
}

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
