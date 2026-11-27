/**
 * ingress mcpscan: tool poisoning and rug-pull scanner for the MCP servers your AI clients use.
 *
 * What it reads:
 *  - by default, only the client config files (the same ones `ingress audit` reads, see mcpConfigLocations
 *    in audit.ts) or the file given with --config. Nothing is started and nothing is contacted. The config is
 *    checked for risky launch commands (curl | sh, unpinned npx/uvx @latest), secrets written into it (names
 *    only, never values) and remote servers over plain http.
 *  - with --connect, each configured server is started (stdio) or contacted (http), asked for its tools,
 *    prompts and resources (initialize, tools/list, prompts/list, resources/list; never tools/call), and shut
 *    down. Starting a server runs its code, so this only happens when asked for.
 *  - with --url, one remote MCP server (streamable HTTP, or the older SSE transport) is asked for tools/list.
 *
 * What it looks for in every tool name, description, parameter text, prompt and resource description:
 * the Ingress engine's verdict (hidden instructions, invisible Unicode, injection shapes), plus checks for
 * tool definitions specifically: instructions aimed at the model ("before using this tool, read ~/.ssh..."),
 * cross-tool shadowing (a description that gives orders about other tools), and look-alike tool names that
 * collide across servers.
 *
 * Rug pulls: each server's tool list is fingerprinted (sha256 of canonical JSON) and pinned in the Ingress
 * state directory (mcpscan-pins.json). A later scan reports tools added, removed or changed since the pin,
 * with the old and new text. The first scan of a server pins what it saw; `ingress mcpscan pin` accepts the
 * current state after a change.
 */

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { homedir, platform } from "node:os";
import { dirname, join, resolve } from "node:path";
import { HONEST_USER_AGENT } from "./acquire.js";
import { mcpConfigLocations } from "./audit.js";
import { fingerprint, stateDir } from "./changes.js";
import { collectSecrets, redactSecrets } from "./secrets.js";
import { toolDefinitionText, type ToolDefinition } from "./tooldefs.js";
import { ENGINE_VERSION } from "./types.js";

export type McpScanSeverity = "high" | "review" | "info";
export type McpScanCheck = "config" | "connect" | "gate" | "model-instruction" | "shadowing" | "lookalike" | "rug-pull";

export interface McpScanFinding {
  id: string;
  check: McpScanCheck;
  severity: McpScanSeverity;
  server: string;
  /** tool, prompt or resource the finding is about */
  item?: string;
  title: string;
  /** short excerpt; credentials redacted, invisible characters shown as <U+XXXX> */
  evidence: string;
  /** one line, plain English */
  fix: string;
  /** rug-pull: the old and new text of a changed definition */
  diff?: string[];
}

export interface McpServerConfig {
  name: string;
  /** where the entry was found: "Claude Desktop (/path)", "--config /path", "--url" */
  source: string;
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  cwd?: string;
  url?: string;
  headers?: Record<string, string>;
  type?: string;
}

export interface McpServerListing {
  tools: ToolDefinition[];
  prompts: Array<{ name: string; description?: string; arguments?: Array<{ name: string; description?: string }> }>;
  resources: Array<{ name?: string; uri?: string; description?: string }>;
  serverInfo?: { name?: string; version?: string };
}

export interface McpScanServerResult {
  name: string;
  source: string;
  launch: string;
  /** "config-only" unless the server was started or contacted */
  mode: "config-only" | "connected" | "failed";
  tools?: number;
  prompts?: number;
  resources?: number;
  fingerprint?: string;
  pin?: "first-seen" | "unchanged" | "changed" | "pinned";
  error?: string;
}

export interface McpScanReport {
  startedAt: string;
  connected: boolean;
  configsRead: string[];
  servers: McpScanServerResult[];
  findings: McpScanFinding[];
  summary: { high: number; review: number; info: number };
  notes: string[];
}

export type McpScanGate = (text: string, source: string) => Promise<{ tier: string; findings: ReadonlyArray<{ kind: string; message: string }> }>;

export interface McpScanOptions {
  /** read only these config files instead of the clients' usual locations */
  configs?: string[];
  /** start stdio servers and contact remote ones from the configs */
  connect?: boolean;
  /** scan one remote server (tools/list only) */
  url?: string;
  /** headers for --url ("Name: value") */
  headers?: string[];
  /** accept the current tool lists as the new pins */
  pin?: boolean;
  /** per server, default 20 s */
  timeoutMs?: number;
  /** state directory (pins); defaults to stateDir() */
  dir?: string;
  home?: string;
  gate?: McpScanGate;
  /** for tests: replaces starting/contacting a server */
  list?: (s: McpServerConfig, timeoutMs: number) => Promise<McpServerListing>;
}

export const MCPSCAN_CONNECT_NOTICE = "--connect starts each configured MCP server on this machine (it runs that server's code) and asks it for its tool list. Only connect to servers you would let your AI client start anyway.";
const PROTOCOL_VERSION = "2025-06-18";
const EVIDENCE_MAX = 220;

// ------------------------------------------------------------------ arguments

export function parseMcpscanArgs(argv: string[]): { json: boolean; opts: McpScanOptions; error?: string } {
  const opts: McpScanOptions = {};
  let json = false;
  let i = 0;
  if (argv[0] === "pin") { opts.pin = true; i = 1; }
  for (; i < argv.length; i++) {
    const a = argv[i];
    const take = (name: string): string | undefined => {
      if (a.startsWith(`--${name}=`)) return a.slice(name.length + 3);
      if (a === `--${name}`) return argv[++i];
      return undefined;
    };
    if (a === "--json") json = true;
    else if (a === "--connect") opts.connect = true;
    else if (a === "--config" || a.startsWith("--config=")) { const v = take("config"); if (!v) return { json, opts, error: "--config needs a file" }; (opts.configs ??= []).push(v); }
    else if (a === "--url" || a.startsWith("--url=")) opts.url = take("url");
    else if (a === "--header" || a.startsWith("--header=")) { const v = take("header"); if (!v || !/^[A-Za-z0-9-]+:\s*\S/.test(v)) return { json, opts, error: '--header must look like "Name: value"' }; (opts.headers ??= []).push(v); }
    else if (a === "--timeout" || a.startsWith("--timeout=")) {
      const n = Number(take("timeout"));
      if (!Number.isFinite(n) || n <= 0) return { json, opts, error: "--timeout needs a number of seconds" };
      opts.timeoutMs = n * 1000;
    } else return { json, opts, error: `unknown argument: ${a}` };
  }
  if (opts.url !== undefined && !/^https?:\/\//i.test(opts.url)) return { json, opts, error: "--url must start with http:// or https://" };
  if (opts.pin && !opts.connect && !opts.url) return { json, opts, error: "pin needs the current tool lists: add --connect (starts the configured servers) or --url" };
  return { json, opts };
}

// ------------------------------------------------------------------ config discovery

/** the MCP servers listed in one client config (Claude Desktop, Cursor, VS Code, Windsurf, Gemini, Claude Code incl. per-project) */
export function serversFromConfig(config: any, source: string): McpServerConfig[] {
  const out: McpServerConfig[] = [];
  const add = (servers: any, where: string) => {
    if (!servers || typeof servers !== "object") return;
    for (const [name, s] of Object.entries<any>(servers)) {
      if (!s || typeof s !== "object") continue;
      out.push({
        name, source: where,
        command: typeof s.command === "string" ? s.command : undefined,
        args: Array.isArray(s.args) ? s.args.map(String) : undefined,
        env: s.env && typeof s.env === "object" ? Object.fromEntries(Object.entries(s.env).map(([k, v]) => [k, String(v)])) : undefined,
        cwd: typeof s.cwd === "string" ? s.cwd : undefined,
        url: typeof (s.url ?? s.serverUrl ?? s.httpUrl) === "string" ? (s.url ?? s.serverUrl ?? s.httpUrl) : undefined,
        headers: s.headers && typeof s.headers === "object" ? Object.fromEntries(Object.entries(s.headers).map(([k, v]) => [k, String(v)])) : undefined,
        type: typeof s.type === "string" ? s.type : undefined,
      });
    }
  };
  add(config?.mcpServers ?? config?.servers ?? config?.mcp?.servers, source);
  // Claude Code keeps per-project servers in ~/.claude.json under projects[path].mcpServers
  if (config?.projects && typeof config.projects === "object") for (const [p, v] of Object.entries<any>(config.projects)) add(v?.mcpServers, `${source} project ${p}`);
  return out;
}

function readConfigs(o: McpScanOptions, notes: string[]): { servers: McpServerConfig[]; read: string[] } {
  const servers: McpServerConfig[] = [], read: string[] = [];
  const files: Array<[string, string]> = o.configs?.length
    ? o.configs.map((p) => ["--config", resolve(p)])
    : [...mcpConfigLocations(o.home ?? homedir(), platform()), ["project .mcp.json", resolve(".mcp.json")], ["project .cursor/mcp.json", resolve(".cursor/mcp.json")], ["project .vscode/mcp.json", resolve(".vscode/mcp.json")]];
  for (const [label, p] of files) {
    if (!existsSync(p)) { if (o.configs?.length) notes.push(`${p}: not found`); continue; }
    let j: unknown;
    try { j = JSON.parse(readFileSync(p, "utf8")); } catch { notes.push(`${p}: not valid JSON, skipped`); continue; }
    read.push(p);
    servers.push(...serversFromConfig(j, `${label} (${p})`));
  }
  return { servers, read };
}

// ------------------------------------------------------------------ config checks (nothing is started)

const SECRET_NAME = /(?:^|_)(?:API_?KEY|KEY|TOKEN|SECRET|PASSWORD|PASSWD|PASS|PAT|CREDENTIALS?|AUTH|PRIVATE_?KEY|ACCESS_?KEY|CLIENT_?SECRET|COOKIE|SESSION)(?:$|_)/i;
const isReference = (v: string) => /^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$|^\$\{(?:env|input):[^}]+\}$/.test(v.trim()) || v.trim() === "";
const isLoopbackUrl = (u: string) => { try { return /^(localhost|127\.\d+\.\d+\.\d+|\[::1\])$/i.test(new URL(u).hostname); } catch { return false; } };

export function launchLine(s: McpServerConfig): string {
  return s.url ? s.url : [s.command, ...(s.args ?? [])].filter(Boolean).join(" ");
}

export function checkServerConfig(s: McpServerConfig): McpScanFinding[] {
  const out: McpScanFinding[] = [];
  const cmd = launchLine(s);
  const f = (id: string, severity: McpScanSeverity, title: string, evidence: string, fix: string) => out.push({ id, check: "config", severity, server: s.name, title, evidence: excerpt(evidence), fix });
  if (s.command) {
    if (/\b(?:curl|wget|fetch|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^|;&]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|\|\s*(?:python3?|node|perl|ruby|iex)\b|\biex\s*\(|base64\s+(?:-d|--decode)[^|]*\|\s*(?:ba|z)?sh/i.test(cmd))
      f("config.pipe_to_shell", "high", "launch command downloads code and runs it straight away", cmd, "Install the server from a pinned package or a file you have read, instead of piping a download into a shell.");
    const runner = /(?:^|[\s/])(npx|uvx|bunx|pnpx|pipx\s+run|pnpm\s+dlx|yarn\s+dlx)\b/.exec(cmd)?.[1];
    if (runner) {
      const pkgArgs = (s.args ?? []).filter((a) => !a.startsWith("-"));
      const latest = (s.args ?? []).some((a) => /@latest$/i.test(a));
      const pinned = pkgArgs.some((a) => /@\d+\.\d+|==\d|@sha256:/.test(a));
      if (latest) f("config.unpinned_latest", "review", `runs ${runner} with @latest: whatever is published next is loaded on the next start`, cmd, "Pin an exact version (package@1.2.3), so an update or a hijacked package cannot change the server silently.");
      else if (!pinned) f("config.unpinned", "review", `runs ${runner} without a pinned version`, cmd, "Pin an exact version (package@1.2.3), so an update or a hijacked package cannot change the server silently.");
    }
    if (/\bdocker\b.*\b(?:--privileged|-v\s+\/:\/|--volume[= ]\/:\/|--network[= ]host)\b/.test(cmd)) f("config.docker_broad", "review", "container is started with broad access to this machine", cmd, "Drop --privileged, host networking and whole-disk mounts unless the server needs them.");
  }
  if (s.url) {
    if (/^http:\/\//i.test(s.url) && !isLoopbackUrl(s.url)) f("config.plain_http", "high", "remote MCP server over plain http", s.url, "Use https: over plain http anyone on the network path can read the traffic and rewrite the tool list.");
    else if (/^http:\/\//i.test(s.url)) f("config.local_http", "info", "local MCP server over http (loopback)", s.url, "Fine for a server on this machine.");
  }
  for (const [where, map] of [["env", s.env], ["header", s.headers]] as const) {
    if (!map) continue;
    const literal: string[] = [], named: string[] = [];
    for (const [k, v] of Object.entries(map)) {
      if (isReference(v)) continue;
      const looks = collectSecrets([v]).length > 0 || collectSecrets([`${k}=${v}`]).length > 0 || /^Bearer\s+\S{12,}/i.test(v);
      if (looks || (SECRET_NAME.test(k) || /^authorization$/i.test(k)) && v.length >= 8) (looks ? literal : named).push(k);
    }
    if (literal.length) f(`config.secret_in_${where}`, "review", `credential written into the config file (${where}: ${literal.join(", ")})`, `${where} keys: ${literal.join(", ")} (values not shown)`, "Keep the credential in your keychain or shell environment and reference it (${VAR}); anyone who can read this file can use it.");
    if (named.length) f(`config.secret_name_in_${where}`, "info", `${where} values that look like credentials (${named.join(", ")})`, `${where} keys: ${named.join(", ")} (values not shown)`, "If these are real credentials, reference them from the environment instead of writing them into the file.");
  }
  return out;
}

// ------------------------------------------------------------------ text checks on definitions

/** invisible and control characters shown, never passed through */
export function showInvisible(s: string): string {
  return s.replace(/[\p{Cc}\p{Cf}\u2028\u2029]|[\u{E0000}-\u{E007F}]/gu, (c) => (c === "\n" ? " ⏎ " : c === "\t" ? " " : `<U+${c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}>`));
}
function excerpt(s: string, at = 0): string {
  const start = Math.max(0, at - 60);
  const cut = s.slice(start, start + EVIDENCE_MAX);
  return showInvisible(redactSecrets(`${start > 0 ? "…" : ""}${cut}${start + EVIDENCE_MAX < s.length ? "…" : ""}`));
}

const SENSITIVE_PATH = /~\/\.ssh|\.ssh\/|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|\.aws\/credentials|\.config\/gcloud|\.kube\/config|\.netrc\b|\.npmrc\b|\.pypirc\b|\.git-credentials|\.docker\/config\.json|\/etc\/(?:passwd|shadow)|\bkeychain\b|mcp\.json\b|claude_desktop_config|\.env\b(?!ironment)|private key|seed phrase|wallet\.dat/i;
const READ_VERB = /\b(?:read|open|cat|load|include|attach|send|pass|upload|copy|fetch|get|collect|extract|forward|provide)\b/i;
const CONCEAL = /\b(?:do\s+not|don't|dont|never|without)\s+(?:tell(?:ing)?|mention(?:ing)?|inform(?:ing)?|reveal(?:ing)?|show(?:ing)?|notify(?:ing)?|alert(?:ing)?|disclos(?:e|ing))\b[^.\n]{0,40}\b(?:the\s+)?(?:user|human|person|operator)\b/i;
const HIDDEN_TAG = /<\s*\/?\s*(?:important|system|instructions?|secret|hidden|admin|critical|note\s+to\s+(?:ai|assistant|model))\b[^>]*>/i;
const BEFORE_USING = /\b(?:before|prior\s+to|after|instead\s+of|in\s+addition\s+to)\s+(?:using|calling|invoking|running)\s+(?:this|any|the|every|each)\b[^.\n]{0,40}\btools?\b/i;
const ADDRESSED_TO_MODEL = /\b(?:the\s+(?:assistant|model|ai|llm|agent)|you\s+\(the\s+(?:assistant|model|ai)\))\s+(?:must|should\s+always|is\s+required\s+to|needs\s+to\s+always|has\s+to)\b/i;
const ORDER_CUE = /\b(?:always|must|never|instead|before|after|whenever|do\s+not|don't|make\s+sure|ensure|override|ignore|replace|redirect|bcc|cc|copy)\b/i;
const OTHER_TOOLS = /\b(?:all|any|every|other)\s+(?:other\s+)?tools?\b|\bthe\s+[`'"]?[\w.-]+[`'"]?\s+tool\b/i;

export interface DefinitionItem { server: string; kind: "tool" | "prompt" | "resource"; name: string; text: string }

export function definitionItems(server: string, l: McpServerListing): DefinitionItem[] {
  return [
    ...l.tools.map((t) => ({ server, kind: "tool" as const, name: t.name, text: toolDefinitionText(t) })),
    ...l.prompts.map((p) => ({ server, kind: "prompt" as const, name: p.name, text: [p.name, p.description ?? "", ...(p.arguments ?? []).flatMap((a) => [a.name, a.description ?? ""])].filter(Boolean).join("\n") })),
    ...l.resources.map((r) => ({ server, kind: "resource" as const, name: r.name ?? r.uri ?? "(unnamed)", text: [r.name ?? "", r.description ?? ""].filter(Boolean).join("\n") })),
  ];
}

/** checks that need no engine: instructions aimed at the model, and orders about other tools */
export function checkDefinitionText(item: DefinitionItem, allToolNames: ReadonlyArray<{ server: string; name: string }>): McpScanFinding[] {
  const out: McpScanFinding[] = [];
  const t = item.text;
  const label = `${item.kind} ${item.name}`;
  const f = (id: string, check: McpScanCheck, severity: McpScanSeverity, title: string, at: number, fix: string) => out.push({ id, check, severity, server: item.server, item: label, title, evidence: excerpt(t, at), fix });
  const fixModel = "Do not use this server until its author removes the text; tool descriptions should say what a tool does, not give the model orders.";
  let m: RegExpExecArray | null;
  if ((m = SENSITIVE_PATH.exec(t)) && READ_VERB.test(t)) f("model.sensitive_file", "model-instruction", "high", `${item.kind} description points the model at credentials or private files (${m[0]})`, m.index, fixModel);
  if ((m = CONCEAL.exec(t))) f("model.conceal", "model-instruction", "high", `${item.kind} description tells the model to keep something from the user`, m.index, fixModel);
  if ((m = HIDDEN_TAG.exec(t))) f("model.hidden_tag", "model-instruction", "high", `${item.kind} description carries a pseudo-tag aimed at the model (${m[0].slice(0, 30)})`, m.index, fixModel);
  if ((m = BEFORE_USING.exec(t))) f("model.before_using", "model-instruction", out.length ? "high" : "review", `${item.kind} description tells the model what to do around its tool calls`, m.index, fixModel);
  else if ((m = ADDRESSED_TO_MODEL.exec(t))) f("model.addressed", "model-instruction", "review", `${item.kind} description gives the model orders`, m.index, "Read it: a description that says what the model must do can steer more than this one tool.");

  // cross-tool shadowing: orders about OTHER tools
  if (item.kind === "tool") {
    // a server's own tools often mention each other ("call list_dir before read_file"); only another server's tools count
    const others = allToolNames.filter((o) => o.server !== item.server && o.name.length >= 4 && o.name !== item.name);
    for (const o of others) {
      const re = new RegExp(`(?:^|[^\\w-])[\`'"]?${o.name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}[\`'"]?(?=$|[^\\w-])`, "i");
      // a plain English word (read, search) only counts when it is quoted or called a tool
      const plainWord = /^[a-z]+$/.test(o.name);
      const hit = re.exec(t.slice(item.name.length));
      if (!hit) continue;
      const idx = hit.index + item.name.length;
      const near = t.slice(Math.max(0, idx - 80), idx + o.name.length + 80);
      if (plainWord && !new RegExp(`[\`'"]${o.name}[\`'"]|${o.name}\\s+tool|${o.name}\\(`, "i").test(near)) continue;
      if (!ORDER_CUE.test(near)) continue;
      f("shadowing.names_other_tool", "shadowing", "high", `tool description gives orders about another server's tool (${o.name} on ${o.server})`, idx, "A tool should not tell the model how to use other tools; this is how one server hijacks another's calls. Remove the server or ask its author why.");
      break;
    }
    if (!out.some((x) => x.check === "shadowing") && (m = OTHER_TOOLS.exec(t.slice(item.name.length))) && !/\bthis\s+tool\b/i.test(m[0])) {
      const idx = m.index + item.name.length;
      const near = t.slice(Math.max(0, idx - 80), idx + 80);
      if (ORDER_CUE.test(near) && /\b(?:when|whenever|before|after|instead|always|every|all|any)\b/i.test(near)) f("shadowing.other_tools", "shadowing", "review", "tool description gives orders about other tools", idx, "A tool should describe itself only; read what it asks of other tools.");
    }
  }
  return out;
}

/** look-alike or duplicate tool names across servers */
export function checkToolNames(all: ReadonlyArray<{ server: string; name: string }>): McpScanFinding[] {
  const out: McpScanFinding[] = [];
  const CONFUSE: Record<string, string> = { "0": "o", "1": "l", "i": "l", "|": "l", "5": "s", "$": "s", "3": "e", "@": "a", "4": "a", "7": "t", "8": "b" };
  const norm = (n: string) => n.normalize("NFKC").toLowerCase().replace(/[\s_.\-:/]+/g, "").replace(/rn/g, "m").replace(/vv/g, "w").split("").map((c) => CONFUSE[c] ?? c).join("");
  for (const t of all) if (/[^\x20-\x7e]/.test(t.name)) out.push({ id: "lookalike.non_ascii", check: "lookalike", severity: "high", server: t.server, item: `tool ${showInvisible(t.name)}`, title: "tool name uses characters outside plain ASCII", evidence: showInvisible(t.name), fix: "A tool name with look-alike or invisible characters is made to be mistaken for another; remove the server." });
  const groups = new Map<string, Array<{ server: string; name: string }>>();
  for (const t of all) { const k = norm(t.name); groups.set(k, [...(groups.get(k) ?? []), t]); }
  for (const g of groups.values()) {
    const servers = new Set(g.map((t) => t.server));
    if (servers.size < 2) continue;
    const names = [...new Set(g.map((t) => t.name))];
    const exact = names.length === 1;
    out.push({ id: exact ? "lookalike.same_name" : "lookalike.collision", check: "lookalike", severity: exact ? "review" : "high", server: [...servers].join(", "), item: `tool ${showInvisible(names.join(" / "))}`, title: exact ? `two servers offer a tool with the same name (${names[0]})` : `tool names that look alike on different servers (${names.map(showInvisible).join(" vs ")})`, evidence: g.map((t) => `${t.server}: ${showInvisible(t.name)}`).join("; "), fix: exact ? "The model may call either one; turn one off or rename it in the client if it supports that." : "One of these is likely impersonating the other; check which server you meant to install." });
  }
  return out;
}

// ------------------------------------------------------------------ pins (rug-pull detection)

interface PinnedTool { fingerprint: string; text: string }
interface PinnedServer { fingerprint: string; pinnedAt: string; launch: string; tools: Record<string, PinnedTool> }
interface PinFile { version: 1; servers: Record<string, PinnedServer> }

export const pinsPath = (dir: string = stateDir()) => join(dir, "mcpscan-pins.json");

export function loadPins(dir?: string): PinFile {
  try { const j = JSON.parse(readFileSync(pinsPath(dir), "utf8")); if (j?.version === 1 && j.servers) return j; } catch { /* none yet */ }
  return { version: 1, servers: {} };
}
function savePins(p: PinFile, dir?: string) {
  const path = pinsPath(dir);
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(p, null, 2), { mode: 0o600 });
  renameSync(tmp, path);
}

const toolCanon = (t: ToolDefinition) => ({ name: t.name, title: t.title ?? null, description: t.description ?? null, inputSchema: t.inputSchema ?? null });
/** sha256 of the canonical JSON of a server's tool list (order-independent) */
export function toolListFingerprint(tools: readonly ToolDefinition[]): string {
  return fingerprint([...tools].map(toolCanon).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0)));
}
export function pinnedServerOf(tools: readonly ToolDefinition[], launch: string, at = new Date()): PinnedServer {
  return { fingerprint: toolListFingerprint(tools), pinnedAt: at.toISOString(), launch, tools: Object.fromEntries(tools.map((t) => [t.name, { fingerprint: fingerprint(toolCanon(t)), text: toolDefinitionText(t) }])) };
}

/** line diff of two short texts (LCS), "- old" / "+ new", unchanged lines left out */
export function textDiff(a: string, b: string): string[] {
  const split = (s: string) => s.split(/\n|(?<=[.!?])\s+/).map((x) => x.trim()).filter(Boolean);
  const A = split(a), B = split(b);
  const L = Array.from({ length: A.length + 1 }, () => new Array<number>(B.length + 1).fill(0));
  for (let i = A.length - 1; i >= 0; i--) for (let j = B.length - 1; j >= 0; j--) L[i][j] = A[i] === B[j] ? L[i + 1][j + 1] + 1 : Math.max(L[i + 1][j], L[i][j + 1]);
  const out: string[] = [];
  let i = 0, j = 0;
  while (i < A.length || j < B.length) {
    if (i < A.length && j < B.length && A[i] === B[j]) { i++; j++; }
    else if (j < B.length && (i === A.length || L[i][j + 1] >= L[i + 1][j])) out.push(`+ ${B[j++]}`);
    else out.push(`- ${A[i++]}`);
  }
  return out.slice(0, 40).map((l) => showInvisible(redactSecrets(l.length > 300 ? l.slice(0, 300) + "…" : l)));
}

export function comparePin(server: string, pinned: PinnedServer, now: PinnedServer): McpScanFinding[] {
  const out: McpScanFinding[] = [];
  if (pinned.fingerprint === now.fingerprint) return out;
  const fix = `If you expected this change, read the new text and accept it with: ingress mcpscan pin --connect (or --url). Otherwise remove the server.`;
  for (const [name, t] of Object.entries(now.tools)) {
    const was = pinned.tools[name];
    if (!was) out.push({ id: "rugpull.added", check: "rug-pull", severity: "review", server, item: `tool ${name}`, title: `tool added since it was pinned (${pinned.pinnedAt})`, evidence: excerpt(t.text), fix });
    else if (was.fingerprint !== t.fingerprint) {
      const diff = textDiff(was.text, t.text);
      out.push({ id: "rugpull.changed", check: "rug-pull", severity: "high", server, item: `tool ${name}`, title: `tool definition changed since it was pinned (${pinned.pinnedAt})`, evidence: diff.length ? diff.slice(0, 2).join(" ") : "the input schema changed (no wording change)", fix, diff: diff.length ? diff : ["(schema-only change: types, required fields or structure)"] });
    }
  }
  for (const name of Object.keys(pinned.tools)) if (!now.tools[name]) out.push({ id: "rugpull.removed", check: "rug-pull", severity: "info", server, item: `tool ${name}`, title: `tool removed since it was pinned (${pinned.pinnedAt})`, evidence: excerpt(pinned.tools[name].text), fix: "Usually harmless; re-pin when you are satisfied." });
  return out;
}

// ------------------------------------------------------------------ talking to servers (JSON-RPC, no SDK)

interface Rpc { request(method: string, params?: unknown): Promise<any>; notify(method: string, params?: unknown): Promise<void>; close(): Promise<void> }

const initParams = { protocolVersion: PROTOCOL_VERSION, capabilities: {}, clientInfo: { name: "acepaste-ingress-mcpscan", version: ENGINE_VERSION } };

/** a minimal environment for a started server, as MCP clients give (plus the server's own env from the config) */
function childEnv(extra?: Record<string, string>): NodeJS.ProcessEnv {
  const keys = process.platform === "win32"
    ? ["APPDATA", "HOMEDRIVE", "HOMEPATH", "LOCALAPPDATA", "PATH", "PROCESSOR_ARCHITECTURE", "SYSTEMDRIVE", "SYSTEMROOT", "TEMP", "USERNAME", "USERPROFILE", "PROGRAMFILES"]
    : ["HOME", "LOGNAME", "PATH", "SHELL", "TERM", "USER", "TMPDIR", "LANG"];
  const env: NodeJS.ProcessEnv = {};
  for (const k of keys) if (process.env[k] !== undefined && !process.env[k]!.startsWith("()")) env[k] = process.env[k];
  for (const [k, v] of Object.entries(extra ?? {})) env[k] = v.replace(/\$\{(?:env:)?([A-Za-z_][A-Za-z0-9_]*)\}/g, (_, n) => process.env[n] ?? "");
  return env;
}

function stdioRpc(s: McpServerConfig): Promise<Rpc> {
  return new Promise((res, rej) => {
    const child = spawn(s.command!, s.args ?? [], { env: childEnv(s.env), cwd: s.cwd, stdio: ["pipe", "pipe", "ignore"], shell: false, windowsHide: true });
    const pending = new Map<number, { ok: (v: any) => void; fail: (e: Error) => void }>();
    let next = 1, buf = "", exited = false;
    const failAll = (e: Error) => { for (const p of pending.values()) p.fail(e); pending.clear(); };
    child.on("error", (e) => { exited = true; failAll(e); rej(e); });
    child.on("exit", (code) => { exited = true; failAll(new Error(`server exited (code ${code})`)); });
    child.stdout!.setEncoding("utf8");
    child.stdout!.on("data", (d: string) => {
      buf += d;
      if (buf.length > 16 * 1024 * 1024) { child.kill("SIGKILL"); failAll(new Error("server sent more than 16 MB")); return; }
      let nl: number;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl).trim(); buf = buf.slice(nl + 1);
        if (!line) continue;
        let m: any; try { m = JSON.parse(line); } catch { continue; } // servers that log to stdout
        if (m && typeof m.id === "number" && pending.has(m.id) && !("method" in m)) {
          const p = pending.get(m.id)!; pending.delete(m.id);
          m.error ? p.fail(new Error(`${m.error.message ?? "error"} (${m.error.code})`)) : p.ok(m.result);
        } else if (m && m.method && m.id !== undefined) {
          // a request from the server (sampling, roots, elicitation): refused; the scanner offers nothing
          child.stdin!.write(JSON.stringify({ jsonrpc: "2.0", id: m.id, error: { code: -32601, message: "not supported by ingress mcpscan" } }) + "\n");
        }
      }
    });
    child.stdin!.on("error", () => { /* closed by the server */ });
    const write = (o: unknown) => { if (!exited) child.stdin!.write(JSON.stringify(o) + "\n"); };
    res({
      request: (method, params) => new Promise((ok, fail) => { if (exited) return fail(new Error("server is not running")); const id = next++; pending.set(id, { ok, fail }); write({ jsonrpc: "2.0", id, method, ...(params !== undefined ? { params } : {}) }); }),
      notify: async (method, params) => write({ jsonrpc: "2.0", method, ...(params !== undefined ? { params } : {}) }),
      close: () => new Promise<void>((done) => {
        if (exited) return done();
        const killer = setTimeout(() => child.kill("SIGKILL"), 2000);
        child.once("exit", () => { clearTimeout(killer); done(); });
        child.stdin!.end();
        setTimeout(() => { if (!exited) child.kill("SIGTERM"); }, 500);
      }),
    });
  });
}

function parseSse(text: string): any[] {
  const out: any[] = [];
  for (const block of text.split(/\r?\n\r?\n/)) {
    const data = block.split(/\r?\n/).filter((l) => l.startsWith("data:")).map((l) => l.slice(5).replace(/^ /, "")).join("\n");
    if (data) { try { out.push(JSON.parse(data)); } catch { /* not JSON */ } }
  }
  return out;
}

async function readCapped(r: Response, max = 8 * 1024 * 1024): Promise<string> {
  const reader = r.body?.getReader();
  if (!reader) return "";
  const chunks: Uint8Array[] = []; let n = 0;
  for (;;) { const { done, value } = await reader.read(); if (done) break; n += value.length; if (n > max) { await reader.cancel(); throw new Error("response larger than 8 MB"); } chunks.push(value); }
  return Buffer.concat(chunks).toString("utf8");
}

/** streamable HTTP (POST, JSON or SSE answer); falls back to the older SSE transport (GET stream + POST endpoint) */
async function httpRpc(url: string, headers: Record<string, string>, signal: AbortSignal): Promise<Rpc> {
  const base = { "user-agent": HONEST_USER_AGENT, ...headers };
  let session: string | undefined, next = 1;
  const post = async (body: unknown, wantReply: boolean) => {
    const r = await fetch(url, { method: "POST", redirect: "manual", signal, headers: { ...base, "content-type": "application/json", accept: "application/json, text/event-stream", "mcp-protocol-version": PROTOCOL_VERSION, ...(session ? { "mcp-session-id": session } : {}) }, body: JSON.stringify(body) });
    session = r.headers.get("mcp-session-id") ?? session;
    if (r.status >= 300 && r.status < 400) throw Object.assign(new Error(`redirected to ${r.headers.get("location")} (not followed)`), { status: r.status });
    if (!wantReply) { await r.body?.cancel(); if (r.status >= 400) throw Object.assign(new Error(`HTTP ${r.status}`), { status: r.status }); return undefined; }
    if (r.status >= 400) { await r.body?.cancel(); throw Object.assign(new Error(`HTTP ${r.status}`), { status: r.status }); }
    const text = await readCapped(r);
    const msgs = /text\/event-stream/i.test(r.headers.get("content-type") ?? "") ? parseSse(text) : [JSON.parse(text)].flat();
    return msgs;
  };
  const streamable: Rpc = {
    async request(method, params) {
      const id = next++;
      const msgs = (await post({ jsonrpc: "2.0", id, method, ...(params !== undefined ? { params } : {}) }, true)) ?? [];
      const m = msgs.find((x: any) => x && x.id === id);
      if (!m) throw new Error(`no answer to ${method}`);
      if (m.error) throw new Error(`${m.error.message ?? "error"} (${m.error.code})`);
      return m.result;
    },
    async notify(method, params) { try { await post({ jsonrpc: "2.0", method, ...(params !== undefined ? { params } : {}) }, false); } catch { /* best effort */ } },
    async close() { if (session) { try { await fetch(url, { method: "DELETE", signal, headers: { ...base, "mcp-session-id": session } }); } catch { /* best effort */ } } },
  };
  try {
    const init = await streamable.request("initialize", initParams);
    (streamable as any).init = init;
    return streamable;
  } catch (e) {
    const st = (e as any).status;
    if (st !== 404 && st !== 405 && st !== 400) throw e;
  }
  return legacySseRpc(url, base, signal);
}

async function legacySseRpc(url: string, base: Record<string, string>, signal: AbortSignal): Promise<Rpc> {
  const ctrl = new AbortController();
  signal.addEventListener("abort", () => ctrl.abort(), { once: true });
  const r = await fetch(url, { headers: { ...base, accept: "text/event-stream" }, signal: ctrl.signal, redirect: "manual" });
  if (r.status !== 200 || !r.body) throw new Error(`HTTP ${r.status} (neither streamable HTTP nor SSE)`);
  const reader = r.body.getReader();
  const dec = new TextDecoder();
  let buf = "", endpoint: string | undefined, next = 1, total = 0;
  const pending = new Map<number, { ok: (v: any) => void; fail: (e: Error) => void }>();
  let gotEndpoint: (u: string) => void = () => {};
  const endpointP = new Promise<string>((ok) => { gotEndpoint = ok; });
  (async () => {
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.length;
        if (total > 16 * 1024 * 1024) { ctrl.abort(); break; }
        buf += dec.decode(value, { stream: true });
        let k: number;
        while ((k = buf.search(/\r?\n\r?\n/)) >= 0) {
          const block = buf.slice(0, k); buf = buf.slice(k).replace(/^\r?\n\r?\n/, "");
          const ev = /^event:\s*(.*)$/m.exec(block)?.[1]?.trim() ?? "message";
          const data = block.split(/\r?\n/).filter((l) => l.startsWith("data:")).map((l) => l.slice(5).replace(/^ /, "")).join("\n");
          if (ev === "endpoint") { endpoint = new URL(data.trim(), url).href; gotEndpoint(endpoint); continue; }
          let m: any; try { m = JSON.parse(data); } catch { continue; }
          if (m && typeof m.id === "number" && pending.has(m.id)) { const p = pending.get(m.id)!; pending.delete(m.id); m.error ? p.fail(new Error(`${m.error.message ?? "error"} (${m.error.code})`)) : p.ok(m.result); }
        }
      }
    } catch { /* aborted */ }
    for (const p of pending.values()) p.fail(new Error("stream closed")); pending.clear();
  })();
  const ep = await endpointP;
  if (new URL(ep).origin !== new URL(url).origin) { ctrl.abort(); throw new Error(`SSE endpoint is on another origin (${new URL(ep).origin}); not contacted`); }
  const send = async (o: unknown) => { const x = await fetch(ep, { method: "POST", signal: ctrl.signal, headers: { ...base, "content-type": "application/json" }, body: JSON.stringify(o) }); await x.body?.cancel(); if (x.status >= 400) throw new Error(`HTTP ${x.status}`); };
  const rpc: Rpc = {
    request: (method, params) => new Promise((ok, fail) => { const id = next++; pending.set(id, { ok, fail }); send({ jsonrpc: "2.0", id, method, ...(params !== undefined ? { params } : {}) }).catch((e) => { pending.delete(id); fail(e); }); }),
    notify: async (method, params) => { try { await send({ jsonrpc: "2.0", method, ...(params !== undefined ? { params } : {}) }); } catch { /* best effort */ } },
    async close() { ctrl.abort(); },
  };
  (rpc as any).init = await rpc.request("initialize", initParams);
  return rpc;
}

async function listAll(rpc: Rpc, method: string, key: string, cap = 2000): Promise<any[]> {
  const out: any[] = [];
  let cursor: string | undefined;
  for (let page = 0; page < 50; page++) {
    const r = await rpc.request(method, cursor ? { cursor } : {});
    out.push(...(Array.isArray(r?.[key]) ? r[key] : []));
    cursor = typeof r?.nextCursor === "string" && r.nextCursor ? r.nextCursor : undefined;
    if (!cursor || out.length >= cap) break;
  }
  return out.slice(0, cap);
}

/** start or contact one server, list what it offers, shut it down. Never calls a tool. */
export async function listServer(s: McpServerConfig, timeoutMs = 20_000, toolsOnly = false): Promise<McpServerListing> {
  const ctrl = new AbortController();
  let rpc: Rpc | undefined;
  const timer = new Promise<never>((_, rej) => setTimeout(() => { ctrl.abort(); rej(new Error(`no answer within ${Math.round(timeoutMs / 1000)} s`)); }, timeoutMs).unref());
  const work = (async () => {
    let init: any;
    if (s.url) { rpc = await httpRpc(s.url, s.headers ?? {}, ctrl.signal); init = (rpc as any).init; }
    else if (s.command) { rpc = await stdioRpc(s); init = await rpc.request("initialize", initParams); }
    else throw new Error("no command or url in the config");
    await rpc.notify("notifications/initialized");
    const caps = init?.capabilities ?? {};
    const tools = (await listAll(rpc, "tools/list", "tools")).filter((t) => t && typeof t.name === "string") as ToolDefinition[];
    const prompts = !toolsOnly && caps.prompts ? await listAll(rpc, "prompts/list", "prompts").catch(() => []) : [];
    const resources = !toolsOnly && caps.resources ? await listAll(rpc, "resources/list", "resources").catch(() => []) : [];
    return { tools, prompts, resources, serverInfo: init?.serverInfo };
  })();
  try { return await Promise.race([work, timer]); }
  finally { try { await rpc?.close(); } catch { /* already gone */ } }
}

// ------------------------------------------------------------------ the scan

export async function mcpscan(o: McpScanOptions = {}): Promise<McpScanReport> {
  const notes: string[] = [];
  const findings: McpScanFinding[] = [];
  const results: McpScanServerResult[] = [];
  const dir = o.dir ?? stateDir();
  const timeoutMs = o.timeoutMs ?? 20_000;

  let servers: McpServerConfig[] = [], configsRead: string[] = [];
  if (o.url) {
    const headers = Object.fromEntries((o.headers ?? []).map((h) => { const i = h.indexOf(":"); return [h.slice(0, i).trim(), h.slice(i + 1).trim()]; }));
    let host = o.url; try { const u = new URL(o.url); host = `${u.host}${u.pathname.replace(/\/$/, "")}`; } catch { /* checked by the parser */ }
    servers = [{ name: host, source: "--url", url: o.url, headers }];
  } else {
    const c = readConfigs(o, notes);
    servers = c.servers; configsRead = c.read;
    if (!configsRead.length) notes.push(o.configs?.length ? "no config file could be read" : "no MCP client config found in the usual places (Claude Desktop, Claude Code, Cursor, Windsurf, VS Code, Gemini CLI, this folder's .mcp.json); use --config <file>");
  }

  // the same server listed by two clients is scanned once
  const seen = new Map<string, McpServerConfig>();
  for (const s of servers) {
    findings.push(...checkServerConfig(s).filter((f) => !findings.some((g) => g.id === f.id && g.server === f.server && g.evidence === f.evidence)));
    const key = `${s.name}\u0000${launchLine(s)}`;
    if (!seen.has(key)) seen.set(key, s);
  }
  const unique = [...seen.values()];
  // pin keys: the server's name, made distinct when two different servers share one
  const byName = new Map<string, number>();
  for (const s of unique) byName.set(s.name, (byName.get(s.name) ?? 0) + 1);
  const pinKey = (s: McpServerConfig) => (byName.get(s.name)! > 1 ? `${s.name} [${createHash("sha256").update(launchLine(s)).digest("hex").slice(0, 8)}]` : s.name);

  const connect = !!(o.connect || o.url);
  const listings: Array<{ s: McpServerConfig; l: McpServerListing }> = [];
  for (const s of unique) {
    const r: McpScanServerResult = { name: s.name, source: s.source, launch: redactSecrets(launchLine(s)), mode: "config-only" };
    results.push(r);
    if (!connect) continue;
    // a launch command that downloads and runs code is never started by the scanner
    if (findings.some((f) => f.id === "config.pipe_to_shell" && f.server === s.name && f.evidence === excerpt(launchLine(s)))) {
      notes.push(`${s.name}: not started, because its launch command downloads and runs code (see the high finding).`);
      continue;
    }
    try {
      const l = await (o.list ?? listServer)(s, timeoutMs);
      if (o.url) { l.prompts = []; l.resources = []; }
      r.mode = "connected"; r.tools = l.tools.length; r.prompts = l.prompts.length; r.resources = l.resources.length;
      r.fingerprint = toolListFingerprint(l.tools);
      listings.push({ s, l });
    } catch (e) {
      r.mode = "failed"; r.error = redactSecrets((e as Error).message);
      findings.push({ id: "connect.failed", check: "connect", severity: "info", server: s.name, title: "could not list this server's tools", evidence: r.error, fix: "Check that the server starts on its own (and that any login it needs is in place); its tools were not scanned." });
    }
  }
  if (!connect && unique.length) notes.push("Tool descriptions were not read: the servers were not started. Run again with --connect to start each one and scan what it tells the model (this runs their code).");

  // what every tool, prompt and resource says
  const gate = o.gate ?? (await defaultGate());
  const allTools = listings.flatMap(({ s, l }) => l.tools.map((t) => ({ server: s.name, name: t.name })));
  for (const { s, l } of listings) {
    for (const item of definitionItems(s.name, l)) {
      const own = checkDefinitionText(item, allTools);
      try {
        const v = await gate(item.text, `${item.kind}-definition:${s.name}/${item.name}`);
        if (v.tier !== "clean") {
          const kinds = [...new Set(v.findings.map((f) => f.kind))];
          const msgs = [...new Set(v.findings.map((f) => f.message))].slice(0, 3).join("; ");
          const strong = v.tier === "hostile" || kinds.some((k) => /^unicode\.(tag|bidi|zero_width)/.test(k)) || own.some((f) => f.severity === "high");
          // the learned classifier alone is a weak signal on short tool descriptions
          const weak = !strong && kinds.every((k) => k.startsWith("classifier."));
          findings.push({ id: `gate.${v.tier}`, check: "gate", severity: strong ? "high" : weak ? "info" : "review", server: s.name, item: `${item.kind} ${showInvisible(item.name)}`, title: `the Ingress engine rates this ${item.kind}'s text ${v.tier} (${kinds.slice(0, 4).join(", ")}${weak ? "; learned classifier only" : ""})`, evidence: `${msgs} | ${excerpt(item.text)}`, fix: strong ? "The proxy in @acepaste/ingress-mcp would withhold this definition from the model; do not use the server as it is." : "Read the text yourself: it may be harmless wording, but the proxy in @acepaste/ingress-mcp would withhold it until it reads clean." });
        }
      } catch (e) { notes.push(`Ingress scan failed on ${s.name}/${item.name}: ${(e as Error).message}`); }
      findings.push(...own);
    }
  }
  findings.push(...checkToolNames(allTools));

  // rug pulls
  const pins = loadPins(dir);
  let wrote = false;
  for (const { s, l } of listings) {
    const k = pinKey(s);
    const now = pinnedServerOf(l.tools, redactSecrets(launchLine(s)));
    const r = results.find((x) => x.name === s.name && x.launch === redactSecrets(launchLine(s)))!;
    const before = pins.servers[k];
    if (o.pin) { pins.servers[k] = now; wrote = true; r.pin = "pinned"; continue; }
    if (!before) { pins.servers[k] = now; wrote = true; r.pin = "first-seen"; continue; }
    const diff = comparePin(s.name, before, now);
    r.pin = diff.length ? "changed" : "unchanged";
    findings.push(...diff);
  }
  if (wrote) savePins(pins, dir);
  if (results.some((r) => r.pin === "first-seen")) notes.push(`First scan of some servers: their tool lists were pinned (${pinsPath(dir)}). Later scans report any change.`);

  const order: Record<McpScanSeverity, number> = { high: 0, review: 1, info: 2 };
  findings.sort((a, b) => order[a.severity] - order[b.severity]);
  return {
    startedAt: new Date().toISOString(), connected: connect, configsRead, servers: results, findings,
    summary: { high: findings.filter((f) => f.severity === "high").length, review: findings.filter((f) => f.severity === "review").length, info: findings.filter((f) => f.severity === "info").length },
    notes,
  };
}

async function defaultGate(): Promise<McpScanGate> {
  const { IngressEngine } = await import("./engine.js");
  const engine = new IngressEngine({ cloakingCheck: false, sandbox: "off", cacheTtlSeconds: 0, fetchStylesheets: false }, { log: () => {} });
  return async (text, source) => { const r = await engine.scan(text, { url: source, isHtml: false }); return { tier: r.tier, findings: r.findings }; };
}

/** the human report */
export function formatMcpscan(r: McpScanReport): string {
  const out: string[] = [`mcpscan: ${r.servers.length} MCP server(s)${r.configsRead.length ? ` from ${r.configsRead.length} config file(s)` : ""}${r.connected ? ", tool lists read" : ", config only"}`, ""];
  for (const s of r.servers) {
    const what = s.mode === "connected" ? `${s.tools} tools, ${s.prompts} prompts, ${s.resources} resources; pin: ${s.pin}` : s.mode === "failed" ? `not reached: ${s.error}` : "config only";
    out.push(`  ${s.name.padEnd(22)} ${what}`, `  ${"".padEnd(22)} ${s.launch.slice(0, 100)}`);
  }
  out.push("");
  const label: Record<McpScanSeverity, string> = { high: "HIGH", review: "REVIEW", info: "INFO" };
  for (const sev of ["high", "review", "info"] as const) {
    const fs = r.findings.filter((f) => f.severity === sev);
    if (!fs.length) continue;
    out.push(`${label[sev]} (${fs.length})`);
    for (const f of fs) {
      out.push(`  [${f.check}] ${f.server}${f.item ? ` / ${f.item}` : ""}: ${f.title}`);
      if (f.diff) for (const d of f.diff.slice(0, 12)) out.push(`      ${d}`);
      else out.push(`      saw: ${f.evidence}`);
      out.push(`      fix: ${f.fix}`);
    }
    out.push("");
  }
  if (!r.findings.length) out.push("No findings.", "");
  for (const n of r.notes) out.push(`note: ${n}`);
  out.push(`summary: ${r.summary.high} high, ${r.summary.review} review, ${r.summary.info} info`);
  return out.join("\n");
}
