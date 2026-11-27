/**
 * ingress reposcan: a repo gate for coding agents.
 *
 * Reads a working tree the way a coding agent would (instruction files, READMEs, docs, MCP configs,
 * package.json scripts, source comments) and flags what a person reviewing the diff would not see or
 * would not expect an agent to obey:
 *  - invisible and bidirectional Unicode anywhere in text or code (Trojan Source, zero-width, tag characters,
 *    variation-selector smuggling), with script-aware exceptions so emoji, CJK, Indic, Arabic and accented
 *    names are left alone
 *  - hidden markdown (HTML comments, collapsed details, hidden inline styles, link titles, image alt text),
 *    each piece run through the Ingress engine
 *  - agent instruction files that tell the agent to run network commands, read secrets, disable safety or
 *    skip review, plus the engine's verdict on the whole file
 *  - lifecycle scripts (postinstall and friends) that download and run code
 *  - MCP server configs committed to the repo that pipe downloads into a shell, run unpinned packages or hold
 *    literal credentials
 *
 * Hard rules: local only. It reads files and runs `git` on your machine; it makes no network connection,
 * and the engine it uses is handed a fetch and a resolver that refuse. Symbolic links are never followed.
 * Evidence is cut short, credentials are redacted (secrets.ts) and invisible characters are shown as
 * ⟨U+XXXX⟩ so the report itself cannot reorder your terminal.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstatSync, readFileSync, readdirSync, realpathSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { INSTRUCTION_FILE_PATTERNS } from "./instructions.js";
import { redactSecrets } from "./secrets.js";
import { classifyStyle } from "./visibility.js";
import { ENGINE_VERSION, type Tier } from "./types.js";

export type RepoScanSeverity = "high" | "review" | "info";
export type RepoScanCheck = "unicode" | "hidden-markdown" | "agent-instructions" | "lifecycle-script" | "mcp-config" | "code-comment";
export type RepoFileRole = "agent-instructions" | "readme" | "docs" | "mcp-config" | "package-json" | "source" | "text";

export interface RepoScanFinding {
  /** stable rule id, e.g. "unicode.bidi-control" */
  id: string;
  check: RepoScanCheck;
  severity: RepoScanSeverity;
  title: string;
  /** path relative to the scanned directory, with forward slashes */
  file: string;
  /** 1-based */
  line: number;
  /** 1-based, in UTF-16 code units (what SARIF and editors count) */
  column?: number;
  /** truncated, credentials redacted, invisible characters shown as ⟨U+XXXX⟩ */
  evidence: string;
  /** one line, plain English */
  fix: string;
}

export interface RepoScanReport {
  root: string;
  mode: "full" | "diff";
  /** the git ref compared against, in diff mode */
  base?: string;
  startedAt: string;
  filesScanned: number;
  skipped: { binary: number; tooLarge: number; overCap: number; unreadable: number };
  findings: RepoScanFinding[];
  summary: { high: number; review: number; info: number };
  /** what was not checked, and why */
  notes: string[];
}

/** the text gate: the same scan `ingress --text` runs */
export type RepoScanGate = (text: string, label: string, kind: "markdown" | "text") => Promise<{ tier: Tier; findings: Array<{ kind: string; message: string }> }>;

export interface RepoScanOptions {
  /** scan only files changed since this git ref (a branch, tag or sha) */
  diff?: string;
  /** default 5000 */
  maxFiles?: number;
  /** default 1 MB; larger files are skipped and counted */
  maxFileBytes?: number;
  /** default 64 MB across all files */
  maxTotalBytes?: number;
  gate?: RepoScanGate;
}

export const REPOSCAN_DEFAULT_MAX_FILES = 5000;
export const REPOSCAN_DEFAULT_MAX_FILE_BYTES = 1_000_000;
const MAX_TOTAL_BYTES = 64 * 1024 * 1024;
const EVIDENCE_MAX = 160;
/** fragments shorter than this many words are not worth a verdict */
const MIN_FRAGMENT_WORDS = 4;

const ALWAYS_SKIP_DIRS = new Set([".git", ".hg", ".svn", "node_modules", "dist"]);
const BINARY_EXT = /\.(png|jpe?g|gif|bmp|ico|icns|webp|avif|tiff?|psd|pdf|zip|gz|tgz|bz2|xz|7z|rar|zst|jar|war|class|exe|dll|so|dylib|a|o|obj|lib|wasm|node|woff2?|ttf|otf|eot|mp[34]|m4a|mov|avi|mkv|webm|wav|flac|ogg|sqlite3?|db|bin|dat|pyc|pyo|DS_Store|keystore|p12|pfx|der)$/i;

const AGENT_FILE_EXTRA = [/(?:^|\/)\.cursor\/rules\//i, /(?:^|\/)\.windsurfrules$/i, /(?:^|\/)\.clinerules(?:\/|$)/i];
const MCP_FILE = /(?:^|\/)(?:\.mcp\.json|\.vscode\/mcp\.json|\.cursor\/mcp\.json)$/i;
const README_FILE = /(?:^|\/)README[^/]*$/i;
const DOCS_FILE = /(?:^|\/)docs\/(?:.*\/)?[^/]+\.(?:md|mdx|markdown)$/i;
const C_LIKE = /\.(?:[cm]?[jt]sx?|java|c|h|cc|cpp|cxx|hpp|hh|cs|go|rs|swift|kt|kts|scala|php|dart|groovy|gradle|m|mm|zig|sol|proto)$/i;
const HASH_LIKE = /\.(?:py|pyi|rb|sh|bash|zsh|fish|pl|pm|r|ps1|psm1|tf|nix|ex|exs|jl|cr)$/i;
const MARKDOWN = /\.(?:md|mdx|mdc|markdown)$/i;

/** what role a path plays for a coding agent */
export function classifyRepoFile(rel: string): RepoFileRole {
  if (INSTRUCTION_FILE_PATTERNS.some((p) => p.test(rel)) || AGENT_FILE_EXTRA.some((p) => p.test(rel))) return "agent-instructions";
  if (MCP_FILE.test(rel)) return "mcp-config";
  if (/(?:^|\/)package\.json$/i.test(rel)) return "package-json";
  if (README_FILE.test(rel)) return "readme";
  if (DOCS_FILE.test(rel)) return "docs";
  if (C_LIKE.test(rel) || HASH_LIKE.test(rel)) return "source";
  return "text";
}

/** parse argv after "reposcan": both --flag value and --flag=value */
export function parseReposcanArgs(argv: string[]): { dir: string; json: boolean; sarif?: string; opts: RepoScanOptions; error?: string } {
  const opts: RepoScanOptions = {};
  let dir: string | undefined, json = false, sarif: string | undefined;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const take = (name: string): string | undefined => {
      if (a.startsWith(`--${name}=`)) return a.slice(name.length + 3);
      if (a === `--${name}`) return argv[++i];
      return undefined;
    };
    if (a === "--json") json = true;
    else if (a === "--diff" || a.startsWith("--diff=")) {
      const v = take("diff");
      if (!v) return { dir: dir ?? ".", json, opts, error: "--diff needs a git ref (a branch, tag or commit sha)" };
      opts.diff = v;
    } else if (a === "--sarif" || a.startsWith("--sarif=")) {
      sarif = take("sarif");
      if (!sarif) return { dir: dir ?? ".", json, opts, error: "--sarif needs a file name (or - for stdout)" };
    } else if (a === "--max-files" || a.startsWith("--max-files=")) {
      const n = Number(take("max-files"));
      if (!Number.isInteger(n) || n < 1) return { dir: dir ?? ".", json, opts, error: "--max-files needs a whole number of 1 or more" };
      opts.maxFiles = n;
    } else if (!a.startsWith("-") && dir === undefined) dir = a;
    else return { dir: dir ?? ".", json, opts, error: `unknown argument: ${a}` };
  }
  // a ref that starts with a dash would be read by git as an option
  if (opts.diff !== undefined && (opts.diff.startsWith("-") || /[\0\s]/.test(opts.diff))) return { dir: dir ?? ".", json, sarif, opts, error: "--diff must be a git ref, not an option" };
  if (json && sarif === "-") return { dir: dir ?? ".", json, sarif, opts, error: "--json and --sarif - both want stdout; write the SARIF to a file instead" };
  return { dir: dir ?? ".", json, sarif, opts };
}

// ---------------------------------------------------------------- listing files

function git(root: string, args: string[]): string {
  return execFileSync("git", ["-C", root, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], maxBuffer: 64 * 1024 * 1024 });
}

function inGitWorkTree(root: string): boolean {
  try { return git(root, ["rev-parse", "--is-inside-work-tree"]).trim() === "true"; } catch { return false; }
}

/** a minimal .gitignore reader for directories that are not git work trees (no negation, no nesting) */
function gitignoreMatcher(root: string): (rel: string, isDir: boolean) => boolean {
  let lines: string[] = [];
  try { lines = readFileSync(join(root, ".gitignore"), "utf8").split(/\r?\n/); } catch { return () => false; }
  const rules = lines.map((l) => l.trim()).filter((l) => l && !l.startsWith("#") && !l.startsWith("!")).map((l) => {
    const dirOnly = l.endsWith("/");
    let p = l.replace(/\/$/, "");
    const anchored = p.includes("/");
    p = p.replace(/^\//, "");
    const rx = p.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*\*\/?/g, "\u0000").replace(/\*/g, "[^/]*").replace(/\?/g, "[^/]").replace(/\u0000/g, ".*");
    return { re: new RegExp(anchored ? `^${rx}(?:/|$)` : `(?:^|/)${rx}(?:/|$)`), dirOnly };
  });
  return (rel, isDir) => rules.some((r) => (!r.dirOnly || isDir) && r.re.test(rel));
}

function walk(root: string, cap: number): string[] {
  const ignored = gitignoreMatcher(root);
  const out: string[] = [];
  let entries = 0;
  const go = (dir: string, depth: number) => {
    if (depth > 24 || out.length > cap || entries > 500_000) return;
    let names: string[];
    try { names = readdirSync(dir).sort(); } catch { return; }
    for (const n of names) {
      entries++;
      const abs = join(dir, n);
      let st;
      try { st = lstatSync(abs); } catch { continue; }
      if (st.isSymbolicLink()) continue;
      const rel = relative(root, abs).split(sep).join("/");
      if (st.isDirectory()) { if (!ALWAYS_SKIP_DIRS.has(n) && !ignored(rel, true)) go(abs, depth + 1); continue; }
      if (st.isFile() && !ignored(rel, false)) out.push(rel);
    }
  };
  go(root, 0);
  return out;
}

/** the files to scan, relative to root. In diff mode, only those added, copied, modified, renamed or retyped since `base`. */
export function listRepoFiles(root: string, opts: { diff?: string; cap?: number } = {}): { files: string[]; usedGit: boolean } {
  const cap = opts.cap ?? REPOSCAN_DEFAULT_MAX_FILES;
  const isGit = inGitWorkTree(root);
  if (opts.diff !== undefined) {
    if (!isGit) throw new Error(`--diff needs a git work tree, and ${root} is not one`);
    try { git(root, ["rev-parse", "--verify", "--quiet", `${opts.diff}^{commit}`]); }
    catch { throw new Error(`git does not know the ref "${opts.diff}". In GitHub Actions, check out with fetch-depth: 0 so the base commit is present.`); }
    // compared with the working tree, so it also covers uncommitted and staged changes (pre-commit hooks)
    const out = git(root, ["diff", "--name-only", "-z", "--relative", "--no-renames", "--diff-filter=ACMRT", opts.diff, "--"]);
    return { files: out.split("\0").filter(Boolean), usedGit: true };
  }
  if (isGit) {
    // tracked plus untracked-but-not-ignored: .gitignore, .git/info/exclude and the global excludes all apply
    const out = git(root, ["ls-files", "-z", "--cached", "--others", "--exclude-standard"]);
    return { files: [...new Set(out.split("\0").filter(Boolean))], usedGit: true };
  }
  return { files: walk(root, cap), usedGit: false };
}

// ---------------------------------------------------------------- helpers

const INVISIBLE_FOR_DISPLAY = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180E\u200B-\u200F\u202A-\u202E\u2060-\u206F\u2800\u3164\uFE00-\uFE0F\uFEFF\uFFA0]|[\u{E0000}-\u{E007F}\u{E0100}-\u{E01EF}]/gu;

/** make text safe to print: invisible, bidi and control characters become ⟨U+XXXX⟩, credentials are redacted */
export function showInvisibles(s: string): string {
  const name = (c: string) => `U+${c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}`;
  return redactSecrets(s)
    // a run of tag characters is one hidden message: say how long it is rather than spelling it out
    .replace(/[\u{E0000}-\u{E007F}]{4,}/gu, (run) => `⟨${Array.from(run).length} tag characters⟩`)
    .replace(INVISIBLE_FOR_DISPLAY, (c) => `⟨${name(c)}⟩`)
    .replace(/(⟨U\+[0-9A-F]+⟩)\1{3,}/g, (run, one: string) => `${one.slice(0, -1)} ×${run.length / one.length}⟩`);
}

function excerpt(line: string, col = 1, max = EVIDENCE_MAX): string {
  // cut by code point, so a surrogate pair (an emoji, a tag character) is never split
  const cps = Array.from(line);
  let at = 0;
  for (let u = 0; at < cps.length && u < col - 1; at++) u += cps[at].length;
  const start = Math.max(0, at - Math.floor(max / 3));
  const cut = cps.slice(start, start + max).join("").trim();
  return (start > 0 ? "…" : "") + showInvisibles(cut) + (start + max < cps.length ? "…" : "");
}

/** 1-based line and column of a string offset */
function lineCol(text: string, offset: number): { line: number; column: number } {
  let line = 1, last = -1;
  for (let i = text.indexOf("\n"); i !== -1 && i < offset; i = text.indexOf("\n", i + 1)) { line++; last = i; }
  return { line, column: offset - last };
}

const words = (s: string) => s.trim().split(/\s+/).filter(Boolean).length;

// ---------------------------------------------------------------- Unicode

const EMOJI = /\p{Extended_Pictographic}|[\u{1F3FB}-\u{1F3FF}\u{1F1E6}-\u{1F1FF}\uFE0F\u20E3]/u;
const JOINING_SCRIPT = /[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF\u0900-\u0DFF\u1000-\u109F\u1780-\u17FF\uA8E0-\uA8FF\uFB50-\uFDFF\uFE70-\uFEFF]/u;
const RTL = /[\u0590-\u05FF\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF\uFB1D-\uFDFF\uFE70-\uFEFC]/u;
const HAN = /[\u3400-\u4DBF\u4E00-\u9FFF\uF900-\uFAFF\u{20000}-\u{3134F}]/u;
const SUSPECT_CHAR = /[\u202A-\u202E\u2066-\u2069\u200B-\u200F\u2060-\u2064\u206A-\u206F\u180E\uFEFF\u115F\u1160\u3164\uFFA0\u061C\uFE00-\uFE0F]|[\u{E0000}-\u{E007F}\u{E0100}-\u{E01EF}]/gu;

interface UnicodeHit { kind: "bidi" | "bidi-rtl" | "tag" | "zero-width" | "bidi-mark" | "variation-run"; line: number; column: number; count: number; decoded?: string }

/** suspicious invisible and bidi characters, line by line, with the legitimate uses left out */
export function findInvisibleUnicode(text: string): UnicodeHit[] {
  const hits: UnicodeHit[] = [];
  const lines = text.split("\n");
  for (let li = 0; li < lines.length; li++) {
    const ln = lines[li];
    const cps = Array.from(ln);
    // map code-point index to UTF-16 column
    let utf16 = 0;
    const col: number[] = [];
    for (const c of cps) { col.push(utf16 + 1); utf16 += c.length; }
    let tagRun: number[] = [], vsRun: number[] = [];
    const flushTags = () => {
      if (!tagRun.length) return;
      const decoded = tagRun.map((i) => { const cp = cps[i].codePointAt(0)!; return cp >= 0xe0020 && cp <= 0xe007e ? String.fromCodePoint(cp - 0xe0000) : ""; }).join("");
      hits.push({ kind: "tag", line: li + 1, column: col[tagRun[0]], count: tagRun.length, decoded });
      tagRun = [];
    };
    const flushVs = () => {
      // one selector after an emoji or a Han character is how those are written; a run of them can spell bytes
      if (vsRun.length >= 3) hits.push({ kind: "variation-run", line: li + 1, column: col[vsRun[0]], count: vsRun.length });
      vsRun = [];
    };
    let perLine: Partial<Record<UnicodeHit["kind"], UnicodeHit>> = {};
    const add = (kind: UnicodeHit["kind"], i: number) => {
      const h = perLine[kind];
      if (h) { h.count++; return; }
      perLine[kind] = { kind, line: li + 1, column: col[i], count: 1 };
      hits.push(perLine[kind]!);
    };
    for (let i = 0; i < cps.length; i++) {
      const c = cps[i];
      const cp = c.codePointAt(0)!;
      if (cp >= 0xe0000 && cp <= 0xe007f) { tagRun.push(i); continue; } else flushTags();
      if ((cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef)) { vsRun.push(i); continue; } else flushVs();
      SUSPECT_CHAR.lastIndex = 0;
      if (!SUSPECT_CHAR.test(c)) continue;
      const prev = cps[i - 1] ?? "", next = cps[i + 1] ?? "";
      // overrides (U+202D, U+202E) reorder characters and are the Trojan Source vector everywhere; embeddings and
      // isolates also have a real use, setting numbers and names inside right-to-left sentences
      if (cp === 0x202d || cp === 0x202e) { add("bidi", i); continue; }
      if ((cp >= 0x202a && cp <= 0x202c) || (cp >= 0x2066 && cp <= 0x2069)) { add(RTL.test(ln) ? "bidi-rtl" : "bidi", i); continue; }
      if (cp === 0x200e || cp === 0x200f || cp === 0x061c) { if (!RTL.test(ln)) add("bidi-mark", i); continue; }
      if (cp === 0x200d) {
        // zero-width joiner: legitimate inside emoji sequences and joining scripts
        if ((EMOJI.test(prev) || EMOJI.test(next)) || JOINING_SCRIPT.test(prev) || JOINING_SCRIPT.test(next)) continue;
      }
      if (cp === 0x200c && (JOINING_SCRIPT.test(prev) || JOINING_SCRIPT.test(next))) continue;
      if (cp === 0xfeff && li === 0 && i === 0) continue; // byte-order mark
      add("zero-width", i);
    }
    flushTags(); flushVs();
    perLine = {};
  }
  return hits;
}

function unicodeFindings(rel: string, role: RepoFileRole, text: string): RepoScanFinding[] {
  const out: RepoScanFinding[] = [];
  const lines = text.split("\n");
  const agentFacing = role === "agent-instructions" || role === "mcp-config";
  for (const h of findInvisibleUnicode(text).slice(0, 50)) {
    const ev = excerpt(lines[h.line - 1] ?? "", h.column);
    if (h.kind === "bidi") out.push({ id: "unicode.bidi-control", check: "unicode", severity: "high", title: `bidirectional control character${h.count > 1 ? `s (${h.count})` : ""}: the text a reviewer sees is not the order the compiler or the agent reads (Trojan Source)`, file: rel, line: h.line, column: h.column, evidence: ev, fix: "Remove the U+202A–202E / U+2066–2069 characters, or write them as escapes (\\u202E) if a string really needs one." });
    else if (h.kind === "bidi-rtl") out.push({ id: "unicode.bidi-isolate-in-rtl", check: "unicode", severity: "review", title: `bidirectional embedding or isolate${h.count > 1 ? `s (${h.count})` : ""} inside right-to-left text: usually legitimate, but a reviewer cannot see it`, file: rel, line: h.line, column: h.column, evidence: ev, fix: "Check that it only sets direction for a number or name in right-to-left prose; in code, write it as an escape." });
    else if (h.kind === "tag") out.push({ id: "unicode.tag-characters", check: "unicode", severity: "high", title: `${h.count} invisible Unicode tag character${h.count > 1 ? "s" : ""}${h.decoded ? ` spelling "${showInvisibles(h.decoded.slice(0, 80))}"` : ""}: text only a model reads`, file: rel, line: h.line, column: h.column, evidence: ev, fix: "Delete the U+E0000–E007F characters; nothing in a repository needs them." });
    else if (h.kind === "variation-run") out.push({ id: "unicode.variation-selector-run", check: "unicode", severity: "high", title: `${h.count} variation selectors in a row: a known way to hide bytes inside one visible character`, file: rel, line: h.line, column: h.column, evidence: ev, fix: "Delete the run of U+FE00–FE0F / U+E0100–E01EF characters." });
    else if (h.kind === "zero-width") out.push({ id: "unicode.zero-width", check: "unicode", severity: agentFacing ? "high" : "review", title: `zero-width character${h.count > 1 ? `s (${h.count})` : ""}${agentFacing ? " in a file coding agents load as instructions" : ""}: invisible to a reviewer, read by compilers and models`, file: rel, line: h.line, column: h.column, evidence: ev, fix: "Delete it, or write it as an escape if a string really needs one. Two identifiers that look the same may differ by it." });
    else out.push({ id: "unicode.stray-bidi-mark", check: "unicode", severity: "review", title: "left-to-right or right-to-left mark on a line with no right-to-left text", file: rel, line: h.line, column: h.column, evidence: ev, fix: "Delete the U+200E / U+200F / U+061C mark unless the line really mixes writing directions." });
  }
  return out;
}

// ---------------------------------------------------------------- agent-instruction rules

interface Rule { id: string; severity: RepoScanSeverity; title: string; fix: string; re: RegExp; negatable?: boolean }
const NEGATION = /\b(?:never|do not|don't|dont|must not|mustn't|should not|shouldn't|avoid|no need to|not allowed to|forbidden|prohibited)\b/i;
const REMOTE = String.raw`(?:https?|ftp)://(?!(?:localhost|127\.\d+\.\d+\.\d+|\[::1\]|0\.0\.0\.0)(?:[:/]|\b))`;

const PIPE_TO_SHELL = new RegExp(String.raw`\b(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|fetch)\b[^\n|]*\|\s*(?:sudo\s+)?(?:(?:ba|z|k|da|fi)?sh|python3?|node|perl|ruby|iex|Invoke-Expression|pwsh|powershell)\b|\b(?:ba|z)?sh\s+(?:-c\s+)?["']?\$?<\(\s*(?:curl|wget)\b|\bbase64\s+(?:-d|--decode)\b[^\n|]*\|\s*(?:ba|z)?sh\b|\biex\s*\(\s*(?:iwr|irm|New-Object\s+Net\.WebClient)`, "i");

const AGENT_RULES: Rule[] = [
  { id: "agent.pipe-to-shell", severity: "high", title: "tells the agent to download code and run it (pipe to a shell)", fix: "Remove the step. If setup needs a tool, pin it in package.json or a lockfile a person reviews.", re: PIPE_TO_SHELL },
  { id: "agent.upload-file", severity: "high", title: "tells the agent to send a file or data to a remote server", fix: "Remove it. An instruction file has no reason to make the agent upload anything.", re: new RegExp(String.raw`\b(?:curl|wget)\b[^\n]*(?:\s(?:-d|--data(?:-binary|-raw)?|-F|--form|-T|--upload-file)\s+["']?@|\s(?:-T|--upload-file)\s)[^\n]*${REMOTE}|\b(?:curl|wget)\b[^\n]*${REMOTE}[^\n]*\s(?:-d|--data(?:-binary|-raw)?|-F|--form|-T|--upload-file)\s+["']?@`, "i") },
  { id: "agent.read-secrets", severity: "high", title: "tells the agent to read, print or send secrets", fix: "Remove it. Agents should never handle keys, tokens or credential files on a repository's say-so.", negatable: true, re: /\b(?:read|cat|print|show|send|upload|include|copy|post|paste|exfiltrate|output|echo|dump|attach|base64|collect|grab|leak|forward|email|commit)\b[^\n]{0,80}(?:~\/\.ssh|\.ssh\/|\bid_(?:rsa|dsa|ecdsa|ed25519)\b|ssh keys?|\.aws\/credentials|aws credentials|\.env\b|\.npmrc|\.netrc|\.git-credentials|\.pypirc|\.docker\/config\.json|keychain|private keys?|secret keys?|api[_ -]?keys?|access tokens?|auth tokens?|credentials|passwords?|GITHUB_TOKEN|NPM_TOKEN|AWS_SECRET\w*|environment variables|env vars)/i },
  { id: "agent.dump-environment", severity: "high", title: "tells the agent to dump environment variables or credential stores", fix: "Remove it. The environment holds tokens the agent should not pass anywhere.", negatable: true, re: /`[^`\n]*\b(?:printenv|env\s*\||set\s*\||cat\s+[^`\n]*(?:\.env|credentials|\.npmrc|\.netrc|id_rsa)|security\s+find-(?:generic|internet)-password|gh\s+auth\s+token)\b[^`\n]*`/i },
  { id: "agent.disable-safety", severity: "high", title: "tells the agent to turn off its safety checks or permission prompts", fix: "Remove it. Permission prompts and hooks are the person's controls, not the repository's.", negatable: true, re: /--dangerously-skip-permissions|--dangerously-bypass\S*|--yolo\b|--no-verify\b|\bauto-?approve (?:all|every|everything)\b|approval[_ -]?policy\W{0,3}never|\b(?:disable|turn off|switch off|bypass|ignore|skip|circumvent|remove)\b[^\n]{0,40}\b(?:safety|security checks?|guardrails?|sandbox(?:ing)?|permission (?:checks?|prompts?)|content filters?|git hooks?|pre-commit hooks?|ingress|safeguards?|restrictions)\b/i },
  { id: "agent.hide-from-user", severity: "high", title: "tells the agent to keep something from the user", fix: "Remove it. Nothing a repository asks an agent to do should be hidden from the person running it.", re: /\b(?:do not|don't|never)\b[^\n]{0,25}\b(?:tell|inform|notify|mention|reveal|show|disclose|report)\b[^\n]{0,30}\b(?:the user|users|the human|anyone|maintainers?|the developer|reviewers?)\b|\b(?:hide|conceal|keep)\b[^\n]{0,30}\b(?:from|secret from) (?:the )?(?:user|human|developer|maintainers?|reviewers?)\b|\bsilently\b[^\n]{0,40}\b(?:run|execute|install|download|send|upload|push)\b/i },
  { id: "agent.skip-review", severity: "high", title: "tells the agent to skip code review or push straight to a protected branch", fix: "Remove it. Changes an agent makes should reach the default branch through review.", negatable: true, re: /\b(?:skip|bypass|avoid|circumvent)\b[^\n]{0,25}\b(?:code )?review\b|\bmerge\b[^\n]{0,20}\bwithout (?:a )?review\b|\bpush\b[^\n]{0,15}\b(?:directly|straight)\b[^\n]{0,10}\bto (?:main|master|production|prod)\b|\bgit push\b[^\n]*(?:-f\b|--force\b)[^\n]*\b(?:main|master)\b/i },
  { id: "agent.skip-confirmation", severity: "review", title: "tells the agent not to ask the user before acting", fix: "Check what it covers. Running tests without asking is fine; running installers, network commands or git pushes without asking is not.", re: /\b(?:do not|don't|never|no need to|without)\b[^\n]{0,15}\b(?:ask(?:ing)?|confirm(?:ing|ation)?|prompt(?:ing)?|check(?:ing)? (?:with|back))\b[^\n]{0,30}\b(?:the user|users|the human|me|permission|approval|first)\b/i },
  { id: "agent.network-command", severity: "review", title: "tells the agent to run a network command against an outside host", fix: "Check the host and why the agent needs it. Prefer pinned dependencies to fetching at run time.", re: new RegExp(String.raw`\b(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|nc|ncat|netcat|scp|rsync|sftp|ftp|telnet)\b[^\n]{0,120}?(?:${REMOTE}|\b\d{1,3}(?:\.\d{1,3}){3}\b(?<!127\.\d+\.\d+\.\d+))`, "i") },
];

function negatedBefore(line: string, index: number): boolean {
  return NEGATION.test(line.slice(Math.max(0, index - 60), index));
}

/** rule hits in instruction text, at most one per rule per line; the network rule is dropped where a stronger one hit */
export function agentInstructionHits(text: string): Array<{ rule: Rule; line: number; column: number; lineText: string }> {
  const out: Array<{ rule: Rule; line: number; column: number; lineText: string }> = [];
  text.split("\n").forEach((ln, i) => {
    const onLine: string[] = [];
    for (const rule of AGENT_RULES) {
      const m = rule.re.exec(ln);
      if (!m) continue;
      if (rule.negatable && negatedBefore(ln, m.index)) continue;
      if (rule.id === "agent.network-command" && onLine.some((id) => id === "agent.pipe-to-shell" || id === "agent.upload-file")) continue;
      onLine.push(rule.id);
      out.push({ rule, line: i + 1, column: m.index + 1, lineText: ln });
    }
  });
  return out;
}

// ---------------------------------------------------------------- hidden markdown

export interface HiddenFragment { where: string; text: string; offset: number }

/** the parts of a markdown file that do not render: comments, collapsed details, hidden inline HTML, link titles, alt text */
export function hiddenMarkdownFragments(md: string): HiddenFragment[] {
  const out: HiddenFragment[] = [];
  const push = (where: string, text: string, offset: number) => { const t = text.replace(/\s+/g, " ").trim(); if (t) out.push({ where, text: t, offset }); };
  for (const m of md.matchAll(/<!--([\s\S]*?)(?:-->|$)/g)) push("HTML comment", m[1], m.index!);
  for (const m of md.matchAll(/<details\b[^>]*>([\s\S]*?)<\/details>/gi)) push("collapsed <details> section", m[1].replace(/<summary\b[^>]*>[\s\S]*?<\/summary>/i, " ").replace(/<[^>]+>/g, " "), m.index!);
  for (const m of md.matchAll(/<([a-z][\w-]*)\b([^>]*)>([\s\S]*?)<\/\1\s*>/gi)) {
    const attrs = m[2];
    const style = attrs.match(/\bstyle\s*=\s*(?:"([^"]*)"|'([^']*)')/i);
    const how = style && classifyStyle(style[1] ?? style[2] ?? "") ? "inline style that hides it" : /\shidden(?:\s|=|$)|aria-hidden\s*=\s*["']?true/i.test(attrs) ? "hidden attribute" : undefined;
    if (how) push(`<${m[1].toLowerCase()}> with ${how}`, m[3].replace(/<[^>]+>/g, " "), m.index!);
  }
  for (const m of md.matchAll(/<(?:img|a|abbr|span|div)\b[^>]*?\b(alt|title|aria-label)\s*=\s*(?:"([^"]*)"|'([^']*)')/gi)) push(`HTML ${m[1].toLowerCase()} attribute`, m[2] ?? m[3] ?? "", m.index!);
  for (const m of md.matchAll(/!\[([^\]]*)\]\(/g)) push("image alt text", m[1], m.index!);
  for (const m of md.matchAll(/\]\(\s*<?[^)\s>]+>?\s+(?:"([^"]*)"|'([^']*)'|\(([^)]*)\))\s*\)/g)) push("link title", m[1] ?? m[2] ?? m[3] ?? "", m.index!);
  for (const m of md.matchAll(/^\s{0,3}\[[^\]]+\]:\s*\S+\s+(?:"([^"]*)"|'([^']*)'|\(([^)]*)\))\s*$/gm)) push("link definition title", m[1] ?? m[2] ?? m[3] ?? "", m.index!);
  return out;
}

// ---------------------------------------------------------------- source comments

/** comment blocks (consecutive comment lines join into one), with the offset of each block */
export function extractComments(text: string, style: "c" | "hash"): Array<{ text: string; offset: number }> {
  const blocks: Array<{ text: string; offset: number; endLine: number }> = [];
  let line = 1;
  const add = (t: string, offset: number, startLine: number, endLine: number) => {
    const last = blocks[blocks.length - 1];
    if (last && startLine <= last.endLine + 1) { last.text += "\n" + t; last.endLine = endLine; }
    else blocks.push({ text: t, offset, endLine });
  };
  let i = 0, quote: string | null = null;
  while (i < text.length) {
    const c = text[i];
    if (c === "\n") { line++; if (quote && quote !== "`" && quote !== '"""' && quote !== "'''") quote = null; i++; continue; }
    if (quote) {
      if (c === "\\") { i += 2; continue; }
      if (text.startsWith(quote, i)) { i += quote.length; quote = null; continue; }
      i++; continue;
    }
    if (style === "hash" && (text.startsWith('"""', i) || text.startsWith("'''", i))) { quote = text.slice(i, i + 3); i += 3; continue; }
    if (c === '"' || c === "'" || (style === "c" && c === "`")) { quote = c; i++; continue; }
    if (style === "c" && text.startsWith("//", i)) {
      const end = text.indexOf("\n", i); const stop = end === -1 ? text.length : end;
      add(text.slice(i + 2, stop), i, line, line); i = stop; continue;
    }
    if (style === "c" && text.startsWith("/*", i)) {
      const end = text.indexOf("*/", i + 2); const stop = end === -1 ? text.length : end;
      const body = text.slice(i + 2, stop);
      const startLine = line; line += (body.match(/\n/g) ?? []).length;
      add(body.replace(/^\s*\*+ ?/gm, ""), i, startLine, line); i = stop + 2; continue;
    }
    if (style === "hash" && c === "#" && (i === 0 || /[\s;]/.test(text[i - 1]))) {
      const end = text.indexOf("\n", i); const stop = end === -1 ? text.length : end;
      add(text.slice(i + 1, stop), i, line, line); i = stop; continue;
    }
    i++;
  }
  return blocks.map((b) => ({ text: b.text.trim(), offset: b.offset }));
}

// ---------------------------------------------------------------- package.json and MCP configs

const LIFECYCLE = new Set(["preinstall", "install", "postinstall", "preuninstall", "uninstall", "postuninstall", "prepublish", "preprepare", "prepare", "postprepare", "prepack", "postpack", "dependencies"]);
const FETCH_AND_RUN = new RegExp(PIPE_TO_SHELL.source + String.raw`|\b(?:curl|wget)\b[^\n;&|]*\s(?:-o|-O|--output)\s*\S+[^\n]*(?:&&|;)\s*(?:(?:ba|z)?sh|chmod\s+\+x|node|python3?)\b|\bnode\s+(?:-e|--eval|-p)\s+["'][^"']*(?:https?\.get|fetch\(|require\(["']https?["']\))|\beval\s*["'\`]?\$\((?:curl|wget)`, "i");
const NETWORK_TOOL = new RegExp(String.raw`\b(?:curl|wget|Invoke-WebRequest|iwr|nc|ncat)\b[^\n]*${REMOTE}`, "i");

function lineOf(raw: string, needle: string): number {
  const i = raw.indexOf(needle);
  return i < 0 ? 1 : lineCol(raw, i).line;
}

function packageJsonFindings(rel: string, raw: string): RepoScanFinding[] {
  let pkg: any;
  try { pkg = JSON.parse(raw); } catch { return []; }
  const scripts = pkg && typeof pkg.scripts === "object" && pkg.scripts ? pkg.scripts : {};
  const out: RepoScanFinding[] = [];
  for (const [name, cmd] of Object.entries<unknown>(scripts)) {
    if (typeof cmd !== "string") continue;
    const lifecycle = LIFECYCLE.has(name);
    const line = lineOf(raw, JSON.stringify(name) + ":") || lineOf(raw, JSON.stringify(name));
    if (FETCH_AND_RUN.test(cmd)) {
      out.push({ id: lifecycle ? "script.lifecycle-fetch-and-run" : "script.fetch-and-run", check: "lifecycle-script", severity: lifecycle ? "high" : "review", title: lifecycle ? `"${name}" runs on npm install and downloads code to execute it` : `script "${name}" downloads code and executes it; agents run npm scripts`, file: rel, line, evidence: excerpt(`"${name}": ${cmd}`), fix: lifecycle ? "Remove the download from the install hook. Ship the code in the package, or make it an explicit script a person runs." : "Pin what it downloads (a checksum or a dependency) instead of piping a URL into an interpreter." });
    } else if (lifecycle && NETWORK_TOOL.test(cmd)) {
      out.push({ id: "script.lifecycle-network", check: "lifecycle-script", severity: "review", title: `"${name}" contacts an outside host on npm install`, file: rel, line, evidence: excerpt(`"${name}": ${cmd}`), fix: "Check the host and what it sends; install hooks run on every machine and every agent that installs the project." });
    }
  }
  return out;
}

/** JSON with comments and trailing commas, as VS Code writes it */
function parseJsonc(raw: string): any {
  let out = "", i = 0, inStr = false;
  while (i < raw.length) {
    const c = raw[i];
    if (inStr) { out += c; if (c === "\\") { out += raw[i + 1] ?? ""; i += 2; continue; } if (c === '"') inStr = false; i++; continue; }
    if (c === '"') { inStr = true; out += c; i++; continue; }
    if (raw.startsWith("//", i)) { while (i < raw.length && raw[i] !== "\n") i++; continue; }
    if (raw.startsWith("/*", i)) { const e = raw.indexOf("*/", i + 2); i = e < 0 ? raw.length : e + 2; continue; }
    out += c; i++;
  }
  return JSON.parse(out.replace(/,(\s*[}\]])/g, "$1"));
}

const SECRETISH_KEY = /(?:token|secret|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key|auth)/i;

function mcpConfigFindings(rel: string, raw: string): RepoScanFinding[] {
  let doc: any;
  try { doc = parseJsonc(raw); } catch { return [{ id: "mcp.unreadable", check: "mcp-config", severity: "info", title: "MCP config is not valid JSON, so its servers were not checked", file: rel, line: 1, evidence: "", fix: "Fix the JSON so agents and this scan read the same thing." }]; }
  const servers = doc?.mcpServers ?? doc?.servers ?? doc?.mcp?.servers ?? {};
  const out: RepoScanFinding[] = [];
  for (const [name, s] of Object.entries<any>(servers && typeof servers === "object" ? servers : {})) {
    if (!s || typeof s !== "object") continue;
    const line = lineOf(raw, JSON.stringify(name));
    const cmd = [s.command, ...(Array.isArray(s.args) ? s.args : [])].filter((x) => typeof x === "string").join(" ");
    if (cmd && FETCH_AND_RUN.test(cmd)) out.push({ id: "mcp.fetch-and-run", check: "mcp-config", severity: "high", title: `MCP server "${name}" downloads code and runs it every time an agent starts`, file: rel, line, evidence: excerpt(cmd), fix: "Point the server at a pinned package or a local binary a person reviewed." });
    else if (/^(?:npx|bunx|pnpx|uvx|pipx)\b/.test(cmd)) {
      const pkg = (Array.isArray(s.args) ? s.args : []).find((a: unknown) => typeof a === "string" && !a.startsWith("-"));
      if (pkg && (!/@\d|==\d/.test(pkg.replace(/^@/, "")) || /@latest$/.test(pkg))) out.push({ id: "mcp.unpinned-package", check: "mcp-config", severity: "review", title: `MCP server "${name}" runs ${pkg} without a pinned version, so whatever is newest runs with the agent's access`, file: rel, line, evidence: excerpt(cmd), fix: `Pin an exact version (for example ${pkg.replace(/@latest$/, "")}@1.2.3) and update it on purpose.` });
    }
    if (typeof s.url === "string" && /^http:\/\//i.test(s.url) && !/^http:\/\/(?:localhost|127\.|\[::1\])/i.test(s.url)) out.push({ id: "mcp.plain-http", check: "mcp-config", severity: "review", title: `MCP server "${name}" is reached over plain HTTP`, file: rel, line, evidence: excerpt(s.url), fix: "Use https:// so the tools an agent receives cannot be swapped in transit." });
    const env = { ...(s.env && typeof s.env === "object" ? s.env : {}), ...(s.headers && typeof s.headers === "object" ? s.headers : {}) };
    for (const [k, v] of Object.entries<unknown>(env)) {
      if (typeof v !== "string" || !v || /^\$\{|^\$[A-Z_]|\$\{(?:env|input):/i.test(v) || /^<.*>$|^your[-_ ]|^x{4,}|^\*+$|^changeme$/i.test(v)) continue;
      if (SECRETISH_KEY.test(k) || redactSecrets(v) !== v) out.push({ id: "mcp.literal-credential", check: "mcp-config", severity: "high", title: `MCP server "${name}" has a literal credential (${k}) committed to the repository`, file: rel, line: lineOf(raw, JSON.stringify(k)), evidence: `${k}: ${redactSecrets(v) !== v ? redactSecrets(v) : "[redacted]"}`, fix: "Revoke the credential, then read it from the environment (${env:NAME} or ${input:...}) instead of the file." });
    }
  }
  return out;
}

// ---------------------------------------------------------------- the scan

function verdictSeverity(tier: Tier): RepoScanSeverity | undefined {
  return tier === "hostile" ? "high" : tier === "suspect" ? "review" : undefined;
}

/** scan a working tree. Local only: reads files and runs git, never contacts the network. */
export async function reposcan(dir: string, o: RepoScanOptions = {}): Promise<RepoScanReport> {
  const startedAt = new Date().toISOString();
  const root = realpathSync(dir);
  const maxFiles = o.maxFiles ?? REPOSCAN_DEFAULT_MAX_FILES;
  const maxFileBytes = o.maxFileBytes ?? REPOSCAN_DEFAULT_MAX_FILE_BYTES;
  const maxTotal = o.maxTotalBytes ?? MAX_TOTAL_BYTES;
  const gate = o.gate ?? (await defaultGate());
  const notes: string[] = [];
  const skipped = { binary: 0, tooLarge: 0, overCap: 0, unreadable: 0 };
  const { files: listed, usedGit } = listRepoFiles(root, { diff: o.diff, cap: maxFiles });
  if (!usedGit) notes.push("not a git work tree: files were found by walking the directory, with a simple reading of the top-level .gitignore");
  const files = listed.filter((f) => !f.split("/").some((seg) => ALWAYS_SKIP_DIRS.has(seg))).sort();
  const findings: RepoScanFinding[] = [];
  let scanned = 0, total = 0;
  const verdictCache = new Map<string, Awaited<ReturnType<RepoScanGate>>>();
  const verdict = async (text: string, label: string, kind: "markdown" | "text") => {
    const key = kind + "\0" + text;
    let v = verdictCache.get(key);
    if (!v) { v = await gate(text, label, kind); verdictCache.set(key, v); }
    return v;
  };

  for (const rel of files) {
    if (scanned >= maxFiles) { skipped.overCap++; continue; }
    if (BINARY_EXT.test(rel)) { skipped.binary++; continue; }
    const abs = join(root, rel);
    let st;
    try { st = lstatSync(abs); } catch { skipped.unreadable++; continue; }
    if (st.isSymbolicLink() || !st.isFile()) continue;
    if (st.size > maxFileBytes) { skipped.tooLarge++; continue; }
    if (total + st.size > maxTotal) { skipped.overCap++; continue; }
    let buf: Buffer;
    try { buf = readFileSync(abs); } catch { skipped.unreadable++; continue; }
    if (buf.subarray(0, 8000).includes(0)) { skipped.binary++; continue; }
    total += buf.length; scanned++;
    const text = buf.toString("utf8").replace(/\r\n/g, "\n");
    const role = classifyRepoFile(rel);
    findings.push(...unicodeFindings(rel, role, text));

    const isMd = MARKDOWN.test(rel);
    if ((role === "agent-instructions" || role === "readme" || role === "docs") && isMd) {
      // hidden parts first: each is judged on its own, where the text around it cannot dilute it
      let hiddenHigh = false;
      const seenLines = new Set<number>();
      for (const f of hiddenMarkdownFragments(text)) {
        if (words(f.text) < MIN_FRAGMENT_WORDS) continue;
        const { line, column } = lineCol(text, f.offset);
        const ruleHits = agentInstructionHits(f.text).filter((h) => h.rule.severity === "high");
        const v = await verdict(f.text, `${rel}:${line}`, "text");
        const sev: RepoScanSeverity | undefined = ruleHits.length ? "high" : verdictSeverity(v.tier);
        if (!sev || seenLines.has(line)) continue;
        seenLines.add(line);
        if (sev === "high") hiddenHigh = true;
        const why = ruleHits.length ? ruleHits[0].rule.title.replace(/^tells the agent to /, "") : `Ingress verdict ${v.tier}: ${[...new Set(v.findings.map((x) => x.kind))].slice(0, 4).join(", ")}`;
        findings.push({ id: "markdown.hidden-instructions", check: "hidden-markdown", severity: sev, title: `instructions hidden in ${/^(?:HTML|image)/.test(f.where) ? "an" : "a"} ${f.where}, which does not render for a reviewer (${why})`, file: rel, line, column, evidence: excerpt(f.text), fix: "Delete the hidden text, or move it into visible prose if it is legitimate." });
      }
      if (role === "agent-instructions") {
        const ruleLines = new Set<string>();
        for (const h of agentInstructionHits(text)) {
          const k = `${h.line}:${h.rule.id}`;
          if (ruleLines.has(k)) continue;
          ruleLines.add(k);
          findings.push({ id: h.rule.id, check: "agent-instructions", severity: h.rule.severity, title: h.rule.title, file: rel, line: h.line, column: h.column, evidence: excerpt(h.lineText, h.column), fix: h.rule.fix });
        }
        const v = await verdict(text, rel, "markdown");
        const sev = verdictSeverity(v.tier);
        if (sev && !(hiddenHigh && sev !== "high")) {
          const kinds = [...new Set(v.findings.filter((x) => !x.kind.startsWith("classifier.") || v.findings.length === 1).map((x) => x.kind))].slice(0, 5).join(", ");
          findings.push({ id: `agent-file.${v.tier}`, check: "agent-instructions", severity: sev, title: `the Ingress engine rates this agent instruction file ${v.tier}${kinds ? ` (${kinds})` : ""}`, file: rel, line: 1, evidence: excerpt(v.findings[0]?.message ?? ""), fix: "Read the file as an agent would. Remove anything that steers the agent away from the task the person gave it." });
        }
      }
    } else if (role === "agent-instructions") {
      // .cursorrules, .windsurfrules and other plain-text instruction files
      for (const h of agentInstructionHits(text)) findings.push({ id: h.rule.id, check: "agent-instructions", severity: h.rule.severity, title: h.rule.title, file: rel, line: h.line, column: h.column, evidence: excerpt(h.lineText, h.column), fix: h.rule.fix });
      const v = await verdict(text, rel, "text");
      const sev = verdictSeverity(v.tier);
      if (sev) findings.push({ id: `agent-file.${v.tier}`, check: "agent-instructions", severity: sev, title: `the Ingress engine rates this agent instruction file ${v.tier}`, file: rel, line: 1, evidence: excerpt(v.findings[0]?.message ?? ""), fix: "Read the file as an agent would. Remove anything that steers the agent away from the task the person gave it." });
    } else if (role === "package-json") findings.push(...packageJsonFindings(rel, text));
    else if (role === "mcp-config") findings.push(...mcpConfigFindings(rel, text));
    else if (role === "source") {
      const style = C_LIKE.test(rel) ? "c" : "hash";
      for (const c of extractComments(text, style)) {
        if (words(c.text) < 8) continue;
        const v = await verdict(c.text, rel, "text");
        // a comment that only resembles an attack is common in security code; only a hostile verdict is reported
        if (v.tier !== "hostile") continue;
        const { line, column } = lineCol(text, c.offset);
        findings.push({ id: "comment.instructions-for-agents", check: "code-comment", severity: "high", title: `a code comment an agent would read as instructions (Ingress verdict hostile: ${[...new Set(v.findings.map((x) => x.kind))].slice(0, 3).join(", ")})`, file: rel, line, column, evidence: excerpt(c.text), fix: "Delete the comment. Comments are read by coding agents as context, and this one tries to steer them." });
      }
    }
  }

  if (skipped.overCap) notes.push(`${skipped.overCap} file(s) not scanned: over the cap of ${maxFiles} files or ${Math.round(maxTotal / 1048576)} MB in total (--max-files raises the first)`);
  if (skipped.tooLarge) notes.push(`${skipped.tooLarge} file(s) over ${maxFileBytes} bytes not scanned`);
  notes.push("node_modules, dist and binary files are skipped; dependencies are not scanned");
  const order: Record<RepoScanSeverity, number> = { high: 0, review: 1, info: 2 };
  findings.sort((a, b) => order[a.severity] - order[b.severity] || a.file.localeCompare(b.file) || a.line - b.line);
  const summary = { high: 0, review: 0, info: 0 };
  for (const f of findings) summary[f.severity]++;
  return { root, mode: o.diff !== undefined ? "diff" : "full", ...(o.diff !== undefined ? { base: o.diff } : {}), startedAt, filesScanned: scanned, skipped, findings, summary, notes };
}

/** the engine, with a fetch and a resolver that refuse: reposcan never touches the network */
async function defaultGate(): Promise<RepoScanGate> {
  const { IngressEngine } = await import("./engine.js");
  const refuse = async (): Promise<never> => { throw new Error("reposcan makes no network connections"); };
  const engine = new IngressEngine({ cloakingCheck: false, sandbox: "off", fetchStylesheets: false }, { log: () => {}, fetchImpl: refuse, resolver: refuse });
  return async (text, label, kind) => {
    const r = await engine.scan(text, { url: `inline:${label}`, kind });
    return { tier: r.tier, findings: r.findings };
  };
}

// ---------------------------------------------------------------- output

export function formatReposcan(r: RepoScanReport): string {
  const lines: string[] = [];
  lines.push(`ingress reposcan ${r.root}${r.mode === "diff" ? ` (files changed since ${r.base})` : ""}`);
  lines.push(`${r.filesScanned} file(s) scanned`);
  if (!r.findings.length) lines.push("", "nothing found");
  for (const sev of ["high", "review", "info"] as const) {
    const group = r.findings.filter((f) => f.severity === sev);
    if (!group.length) continue;
    lines.push("", `${sev.toUpperCase()} (${group.length})`);
    for (const f of group) {
      lines.push(`  ${f.file}:${f.line}${f.column ? `:${f.column}` : ""}  ${f.title}  [${f.id}]`);
      if (f.evidence) lines.push(`      ${f.evidence}`);
      lines.push(`      fix: ${f.fix}`);
    }
  }
  lines.push("", `${r.summary.high} high, ${r.summary.review} to review, ${r.summary.info} info`);
  for (const n of r.notes) lines.push(`note: ${n}`);
  return lines.join("\n");
}

const SARIF_LEVEL: Record<RepoScanSeverity, "error" | "warning" | "note"> = { high: "error", review: "warning", info: "note" };
const SECURITY_SEVERITY: Record<RepoScanSeverity, string> = { high: "8.0", review: "5.0", info: "2.0" };

/** SARIF 2.1.0, the format GitHub code scanning reads */
export function toSarif(r: RepoScanReport): Record<string, unknown> {
  const rules: Array<Record<string, unknown>> = [];
  const index = new Map<string, number>();
  for (const f of r.findings) {
    if (index.has(f.id)) continue;
    index.set(f.id, rules.length);
    rules.push({
      id: f.id, name: f.id.replace(/[^A-Za-z0-9]+(.)?/g, (_, c: string | undefined) => (c ?? "").toUpperCase()),
      shortDescription: { text: f.title.replace(/"[^"]*"/g, "…").slice(0, 200) }, help: { text: f.fix },
      defaultConfiguration: { level: SARIF_LEVEL[f.severity] },
      properties: { tags: ["security", "ai-agents", f.check], "security-severity": SECURITY_SEVERITY[f.severity], precision: f.severity === "high" ? "high" : "medium" },
    });
  }
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: { driver: { name: "AcePaste Ingress reposcan", semanticVersion: ENGINE_VERSION, informationUri: "https://github.com/sugarcypher/acepasteINGRESS/blob/main/docs/REPOSCAN.md", rules } },
      columnKind: "utf16CodeUnits",
      results: r.findings.map((f) => ({
        ruleId: f.id, ruleIndex: index.get(f.id), level: SARIF_LEVEL[f.severity],
        message: { text: `${f.title}${f.evidence ? `\nEvidence: ${f.evidence}` : ""}\nFix: ${f.fix}` },
        locations: [{ physicalLocation: { artifactLocation: { uri: f.file.split("/").map(encodeURIComponent).join("/"), uriBaseId: "%SRCROOT%" }, region: { startLine: f.line, ...(f.column ? { startColumn: f.column } : {}) } } }],
        partialFingerprints: { "ingressReposcan/v1": createHash("sha256").update(`${f.id}\0${f.file}\0${f.evidence}`).digest("hex").slice(0, 32) },
      })),
    }],
  };
}
