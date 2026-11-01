#!/usr/bin/env node
/**
 * AcePaste Gate — Model Context Protocol server (stdio).
 *
 * Tools:
 *   gate_fetch(url, override?)          gate a web page
 *   gate_scan(content, ...)             gate text/HTML/markdown/JSON already in hand
 *   gate_status()                       taint state of this session
 *   gate_confirm()                      human confirmed a side-effect while tainted
 *   gate_verify_receipt(receipt)        check a receipt's digest and signature
 *
 * Environment:
 *   GATE_SIGNING_KEY       HMAC key for receipts
 *   GATE_HOSTILE=0.7       hostile threshold
 *   GATE_SUSPECT=0.25      suspect threshold
 *   GATE_CLOAKING=1        set 0 to disable the second fetch
 *   GATE_SANDBOX=escalate  off | escalate | always
 *   GATE_POLICY=path       policy JSON (thresholds, net, domains)
 *   GATE_LOG=path          append attack log (JSON lines) to a file
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { appendFileSync, readFileSync } from "node:fs";
import { GateEngine, createTaintGuard, loadPolicyFile, ENGINE_VERSION, type GateConfig, type TaintReceipt } from "@acepaste/gate-core";

const env = process.env;
const logPath = env.GATE_LOG;
const cfg: Partial<GateConfig> = env.GATE_POLICY ? loadPolicyFile(env.GATE_POLICY) : {};
if (env.GATE_SIGNING_KEY) cfg.signingKey = env.GATE_SIGNING_KEY;
// ECDSA P-256 private key (PEM, or a path to one). Preferred: receipts become verifiable by anyone with the public key.
{
  const k = env.GATE_SIGNING_PRIVATE_KEY_FILE ? readFileSync(env.GATE_SIGNING_PRIVATE_KEY_FILE, "utf8") : env.GATE_SIGNING_PRIVATE_KEY;
  if (k) cfg.signingPrivateKey = k.includes("BEGIN") ? k.replace(/\\n/g, "\n") : readFileSync(k, "utf8");
}
if (env.GATE_HOSTILE) cfg.hostileThreshold = Number(env.GATE_HOSTILE);
if (env.GATE_SUSPECT) cfg.suspectThreshold = Number(env.GATE_SUSPECT);
if (env.GATE_CLOAKING === "0") cfg.cloakingCheck = false;
if (env.GATE_SANDBOX === "off" || env.GATE_SANDBOX === "escalate" || env.GATE_SANDBOX === "always") cfg.sandbox = env.GATE_SANDBOX;

const engine = new GateEngine(cfg, {
  log: (e: Record<string, unknown>) => {
    const line = JSON.stringify(e) + "\n";
    if (logPath) appendFileSync(logPath, line); else process.stderr.write(line);
  },
});
const guard = createTaintGuard();

const server = new McpServer({ name: "acepaste-gate", version: ENGINE_VERSION });

const present = (r: Awaited<ReturnType<GateEngine["fetch"]>>) => {
  const taint = guard.ingest(r);
  return {
    content: [{ type: "text" as const, text: r.envelope }],
    structuredContent: { tier: r.tier, score: r.score, contentKind: r.contentKind, overridden: r.overridden, receipt: r.receipt, findings: r.findings, taint, timings: r.timings },
    isError: r.tier !== "clean" && !r.overridden,
  };
};

server.registerTool(
  "gate_fetch",
  {
    title: "Fetch a web page through AcePaste Gate",
    description:
      "Fetches a URL and returns its text inside a provenance envelope. Clean pages pass. Suspect and hostile pages are refused and only the attack classification is returned. A suspect refusal may be overridden with override=true ONLY when the human has explicitly asked for that page anyway; hostile is never overridable. Use this instead of any raw fetch tool.",
    inputSchema: { url: z.string().url(), override: z.boolean().optional().describe("Set true only when the human explicitly asked to fetch a suspect page anyway") },
  },
  async ({ url, override }) => present(await engine.fetch(url, { override })),
);

server.registerTool(
  "gate_scan",
  {
    title: "Scan content through AcePaste Gate",
    description: "Gate content already in hand (a tool result, a pasted document, a file): HTML, markdown, JSON or plain text. Same verdict policy as gate_fetch.",
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
  "gate_status",
  { title: "Taint state of this session", description: "Whether untrusted content has been ingested and which sources caused it.", inputSchema: {} },
  async () => ({ content: [{ type: "text", text: JSON.stringify(guard.state) }], structuredContent: { ...guard.state } }),
);

server.registerTool(
  "gate_confirm",
  { title: "Confirm a side-effect while tainted", description: "Call only after the human has explicitly approved the pending side-effecting action.", inputSchema: {} },
  async () => { guard.confirm(); return { content: [{ type: "text", text: "confirmed for 60 seconds" }] }; },
);

server.registerTool(
  "gate_verify_receipt",
  { title: "Verify a gate receipt", description: "Checks a receipt's digest and, when this server has the signing key, its signature.", inputSchema: { receipt: z.record(z.any()) } },
  async ({ receipt }) => {
    const v = GateEngine.verifyReceipt(receipt as unknown as TaintReceipt, (receipt as unknown as TaintReceipt).signatureAlg === "ecdsa-p256-sha256" ? (env.GATE_VERIFY_PUBLIC_KEY ?? engine.publicKey()?.publicKeyPem) : env.GATE_SIGNING_KEY);
    return { content: [{ type: "text", text: JSON.stringify(v) }], structuredContent: v };
  },
);

const transport = new StdioServerTransport();
await server.connect(transport);
