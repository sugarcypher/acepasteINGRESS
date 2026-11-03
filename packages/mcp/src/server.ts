#!/usr/bin/env node
/**
 * AcePaste Ingress — Model Context Protocol server (stdio).
 *
 * Tools:
 *   ingress_fetch(url, override?)          gate a web page
 *   ingress_scan(content, ...)             gate text/HTML/markdown/JSON already in hand
 *   ingress_status()                       taint state of this session
 *   ingress_confirm()                      human confirmed a side-effect while tainted
 *   ingress_verify_receipt(receipt)        check a receipt's digest and signature
 *
 * Environment:
 *   INGRESS_SIGNING_PRIVATE_KEY_FILE  ECDSA P-256 key for publicly verifiable receipts (preferred; or INGRESS_SIGNING_PRIVATE_KEY as PEM)
 *   INGRESS_SIGNING_KEY       HMAC key for receipts (fallback: whoever can verify can also forge)
 *   INGRESS_VERIFY_PUBLIC_KEY PEM used by ingress_verify_receipt for receipts from another instance
 *   INGRESS_HOSTILE=0.7       hostile threshold
 *   INGRESS_SUSPECT=0.25      suspect threshold
 *   INGRESS_CLOAKING=1        set 0 to disable the second fetch
 *   INGRESS_SANDBOX=escalate  off | escalate | always
 *   INGRESS_POLICY=path       policy JSON (thresholds, net, domains)
 *   INGRESS_LOG=path          append attack log (JSON lines) to a file
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { appendFileSync, readFileSync } from "node:fs";
import { IngressEngine, createTaintGuard, loadPolicyFile, cloakingConfigFromEnv, HONEST_USER_AGENT, ENGINE_VERSION, type IngressConfig, type TaintReceipt } from "@acepaste/ingress";

const env = process.env;
const logPath = env.INGRESS_LOG;
const cfg: Partial<IngressConfig> = env.INGRESS_POLICY ? loadPolicyFile(env.INGRESS_POLICY) : {};
if (env.INGRESS_SIGNING_KEY) cfg.signingKey = env.INGRESS_SIGNING_KEY;
// ECDSA P-256 private key (PEM, or a path to one). Preferred: receipts become verifiable by anyone with the public key.
{
  const k = env.INGRESS_SIGNING_PRIVATE_KEY_FILE ? readFileSync(env.INGRESS_SIGNING_PRIVATE_KEY_FILE, "utf8") : env.INGRESS_SIGNING_PRIVATE_KEY;
  if (k) cfg.signingPrivateKey = k.includes("BEGIN") ? k.replace(/\\n/g, "\n") : readFileSync(k, "utf8");
}
if (env.INGRESS_HOSTILE) cfg.hostileThreshold = Number(env.INGRESS_HOSTILE);
if (env.INGRESS_SUSPECT) cfg.suspectThreshold = Number(env.INGRESS_SUSPECT);
Object.assign(cfg, cloakingConfigFromEnv(env, HONEST_USER_AGENT));
if (env.INGRESS_CLOAKING === "0") cfg.cloakingCheck = false;
if (env.INGRESS_SANDBOX === "off" || env.INGRESS_SANDBOX === "escalate" || env.INGRESS_SANDBOX === "always") cfg.sandbox = env.INGRESS_SANDBOX;

const engine = new IngressEngine(cfg, {
  log: (e: Record<string, unknown>) => {
    const line = JSON.stringify(e) + "\n";
    if (logPath) appendFileSync(logPath, line); else process.stderr.write(line);
  },
});
const guard = createTaintGuard();

const server = new McpServer({ name: "acepaste-ingress", version: ENGINE_VERSION });

const present = (r: Awaited<ReturnType<IngressEngine["fetch"]>>) => {
  const taint = guard.ingest(r);
  return {
    content: [{ type: "text" as const, text: r.envelope }],
    structuredContent: { tier: r.tier, score: r.score, contentKind: r.contentKind, overridden: r.overridden, receipt: r.receipt, findings: r.findings, taint, timings: r.timings },
    isError: r.tier !== "clean" && !r.overridden,
  };
};

server.registerTool(
  "ingress_fetch",
  {
    title: "Fetch a web page through AcePaste Ingress",
    description:
      "Fetches a URL and returns its text inside a provenance envelope. Clean pages pass. Suspect and hostile pages are refused and only the attack classification is returned. A suspect refusal may be overridden with override=true ONLY when the human has explicitly asked for that page anyway; hostile is never overridable. Use this instead of any raw fetch tool.",
    inputSchema: { url: z.string().url(), override: z.boolean().optional().describe("Set true only when the human explicitly asked to fetch a suspect page anyway") },
  },
  async ({ url, override }) => present(await engine.fetch(url, { override })),
);

server.registerTool(
  "ingress_scan",
  {
    title: "Scan content through AcePaste Ingress",
    description: "Gate content already in hand (a tool result, a pasted document, a file): HTML, markdown, JSON or plain text. Same verdict policy as ingress_fetch.",
    inputSchema: {
      content: z.string().max(5_000_000),
      source: z.string().optional().describe("where the content came from, for the receipt"),
      contentType: z.string().optional().describe("MIME type if known"),
      isHtml: z.boolean().optional(),
      override: z.boolean().optional(),
    },
  },
  async ({ content, source, contentType, isHtml, override }) => present(await engine.scan(content, { url: source, contentType, isHtml, override })),
);

server.registerTool(
  "ingress_status",
  { title: "Taint state of this session", description: "Whether untrusted content has been ingested and which sources caused it.", inputSchema: {} },
  async () => ({ content: [{ type: "text", text: JSON.stringify(guard.state) }], structuredContent: { ...guard.state } }),
);

server.registerTool(
  "ingress_confirm",
  { title: "Confirm a side-effect while tainted", description: "Call only after the human has explicitly approved the pending side-effecting action.", inputSchema: {} },
  async () => { guard.confirm(); return { content: [{ type: "text", text: "confirmed for 60 seconds" }] }; },
);

server.registerTool(
  "ingress_verify_receipt",
  { title: "Verify a gate receipt", description: "Checks a receipt's digest and, its signature against this server's public key (ECDSA) or shared secret (HMAC).", inputSchema: { receipt: z.record(z.string(), z.any()) } },
  async ({ receipt }) => {
    const v = IngressEngine.verifyReceipt(receipt as unknown as TaintReceipt, (receipt as unknown as TaintReceipt).signatureAlg === "ecdsa-p256-sha256" ? (env.INGRESS_VERIFY_PUBLIC_KEY ?? engine.publicKey()?.publicKeyPem) : env.INGRESS_SIGNING_KEY);
    return { content: [{ type: "text", text: JSON.stringify(v) }], structuredContent: v };
  },
);

const transport = new StdioServerTransport();
await server.connect(transport);
