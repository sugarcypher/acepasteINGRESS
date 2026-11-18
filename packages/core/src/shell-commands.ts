/**
 * Which shell commands bring outside content into an agent's context?
 *
 * A PostToolUse hook sees a command and its output. Output that came from the network (curl, wget, gh, a
 * script that calls fetch) or from a background task's output file is outside content and must be gated;
 * the output of `ls` or `npm test` is not. This module answers that question from the command text.
 *
 * It errs toward gating: a command it cannot parse is gated if a network program appears in it at all.
 */

import { existsSync, readFileSync, statSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import { isIP } from "node:net";

const NET_CLIENTS = new Set(["curl", "wget", "http", "https", "xh", "xhs", "aria2c", "lynx", "w3m", "links", "elinks", "gh", "nc", "ncat", "netcat", "telnet", "ftp", "sftp", "scp", "rsync", "dig", "nslookup", "host", "whois", "openssl"]);
const INTERPRETERS = new Set(["node", "python", "python3", "ruby", "perl", "php", "deno", "bun", "tsx", "ts-node", "npx", "bunx", "uvx", "pipx"]);
const WRAPPERS = new Set(["sudo", "env", "command", "time", "nohup", "exec", "nice", "caffeinate", "stdbuf", "unbuffer", "xargs", "watch"]);
const OPS = new Set([";", "&", "|", "(", ")", "`", "\n"]);

const NETWORK_CODE = /https?:\/\/|\bfetch\s*\(|urllib|\brequests\b|http\.client|aiohttp|httpx|axios|node:https?|require\(\s*['"]https?['"]\s*\)|net\/http|Net::HTTP|LWP::|WebSocket|curl_init|file_get_contents\s*\(\s*['"]https?|socket\.|XMLHttpRequest|undici|got\(|node-fetch/;

/** Split a command line into words and operators. Throws on an unterminated quote. */
export function shellTokens(command: string): string[] {
  const out: string[] = [];
  let cur = "", has = false;
  const push = () => { if (has) out.push(cur); cur = ""; has = false; };
  for (let i = 0; i < command.length; i++) {
    const c = command[i];
    if (c === "'") {
      const end = command.indexOf("'", i + 1);
      if (end < 0) throw new Error("unterminated single quote");
      cur += command.slice(i + 1, end); has = true; i = end;
    } else if (c === '"') {
      let j = i + 1, s = "";
      for (; j < command.length && command[j] !== '"'; j++) { if (command[j] === "\\" && j + 1 < command.length) j++; s += command[j]; }
      if (j >= command.length) throw new Error("unterminated double quote");
      cur += s; has = true; i = j;
    } else if (c === "\\" && i + 1 < command.length) { cur += command[++i]; has = true; }
    else if (c === " " || c === "\t" || c === "\r") push();
    else if (OPS.has(c)) { push(); let op = c; while (i + 1 < command.length && OPS.has(command[i + 1]) && command[i + 1] !== "\n") op += command[++i]; out.push(op); }
    else { cur += c; has = true; }
  }
  push();
  return out;
}

const isOp = (t: string) => [...t].every((c) => OPS.has(c));

/** Each simple command in command position: its program name (without a path) and its arguments. */
export function shellInvocations(command: string): Array<{ program: string; args: string[] }> {
  const toks = shellTokens(command);
  const out: Array<{ program: string; args: string[] }> = [];
  let i = 0, atCmd = true;
  while (i < toks.length) {
    const t = toks[i];
    if (isOp(t)) { atCmd = true; i++; continue; }
    if (atCmd) {
      const word = t.replace(/^[$(`]+/, "");
      if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(word)) { i++; continue; }
      const base = word.split("/").pop() ?? word;
      if (WRAPPERS.has(base)) { i++; continue; }
      if (base === "timeout") { i += 2; continue; }
      let j = i + 1;
      while (j < toks.length && !isOp(toks[j])) j++;
      out.push({ program: base, args: toks.slice(i + 1, j) });
      i = j; atCmd = false;
      continue;
    }
    i++;
  }
  return out;
}

function isLoopbackHost(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, "").toLowerCase().replace(/\.$/, "");
  if (h === "localhost" || h === "ip6-localhost" || h.endsWith(".localhost")) return true;
  if (isIP(h) === 4) return h.startsWith("127.") || h === "0.0.0.0";
  if (isIP(h) === 6) return h === "::1" || h === "::";
  return false;
}

/** (host, port) of each URL-like argument; port is undefined when not given. */
function argTargets(args: readonly string[]): Array<{ host: string; port?: number }> {
  const out: Array<{ host: string; port?: number }> = [];
  for (const a of args) {
    if (a.startsWith("-") || a.startsWith("@")) continue;
    if (a.includes("://")) {
      try { const u = new URL(a); out.push({ host: u.hostname, port: u.port ? Number(u.port) : undefined }); } catch { out.push({ host: "" }); }
      continue;
    }
    const m = a.match(/^(\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]+)(?::(\d+))?(?:[/?#].*)?$/);
    if (m && (m[1].includes(".") || m[1].toLowerCase() === "localhost" || m[1].startsWith("["))) out.push({ host: m[1], port: m[2] ? Number(m[2]) : undefined });
  }
  return out;
}

function scriptUsesNetwork(args: readonly string[], cwd: string | undefined): boolean {
  const code: string[] = [];
  let takeNext = false;
  for (const a of args) {
    if (takeNext) { code.push(a); takeNext = false; }
    else if (["-e", "-c", "--eval", "-p", "--print", "-r"].includes(a)) takeNext = true;
    else if (!a.startsWith("-") && /\.(m?js|cjs|ts|mts|py|rb|pl|php)$/.test(a)) {
      const path = isAbsolute(a) ? a : join(cwd ?? ".", a);
      try { if (existsSync(path) && statSync(path).size <= 2_000_000) code.push(readFileSync(path, "utf8")); } catch { /* unreadable: not evidence either way */ }
      break;
    }
  }
  return code.some((c) => NETWORK_CODE.test(c));
}

export interface ShellGateOptions {
  cwd?: string;
  /** a loopback port whose responses are already gated (the Ingress service itself); requests only to it are not gated again */
  ownPort?: number;
}

/**
 * A label for where this command's output came from if it must be gated, else undefined.
 * Loopback is not exempt: a dev server, a local model server and a tunnel all serve content someone else
 * wrote. Only requests addressed solely to `ownPort` are skipped.
 */
export function shellOutputSource(command: string, opts: ShellGateOptions = {}): string | undefined {
  if (/\/tasks\/[^\s'"]+\.output\b/.test(command)) return "background-task-output";
  let found: Array<{ program: string; args: string[] }>;
  try { found = shellInvocations(command); }
  catch {
    // unparseable (a heredoc, an odd quote): gate if a network program or interpreter appears in command position at all
    const names = [...NET_CLIENTS, ...INTERPRETERS].join("|");
    return new RegExp(`(?:^|[;&|(\`\\n])\\s*(?:\\S*/)?(${names})\\b`, "m").test(command) ? "bash:unparsed" : undefined;
  }
  for (const { program, args } of found) {
    if (NET_CLIENTS.has(program)) {
      if (program === "gh") return `gh:${args.slice(0, 2).join(" ")}`;
      const targets = argTargets(args);
      if (opts.ownPort !== undefined && targets.length && targets.every((t) => isLoopbackHost(t.host) && t.port === opts.ownPort)) continue;
      return args.find((a) => a.includes("://")) ?? `${program}:${args.join(" ").slice(0, 80)}`;
    }
    if (INTERPRETERS.has(program) && scriptUsesNetwork(args, opts.cwd)) return `${program}:network-code`;
  }
  return undefined;
}
