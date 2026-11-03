/**
 * Code behavior pass.
 *
 * Code an agent receives (a fenced block in a README, a <pre> in a page, a script file,
 * a decoded payload) is judged by what it would DO, with comments separated from code
 * and string literals held apart, so "exec" in a comment or a tutorial sentence is not a
 * call. Behaviors: download then execute, encoded payload executed, reverse shell,
 * secrets sent out, persistence. Languages: JavaScript/TypeScript, Python, shell,
 * PowerShell, Go. This is lexical analysis, not data flow: it sees one code unit at a
 * time and does not follow values across files. The coverage report says exactly which
 * units and languages were inspected.
 *
 * Weighting: visible code is documentation and scores low on its own (security posts
 * show reverse shells); hidden or decoded code carries full weight. The supply-chain pass
 * already covers install commands (pipe-to-shell, URL installs); this pass does not
 * double-count those.
 */

import type { Finding, TextSegment } from "./types.js";

export type CodeLang = "javascript" | "python" | "shell" | "powershell" | "go";
export interface CodeUnit { lang: CodeLang | "unknown"; source: string; where: string; hidden: boolean }
export interface CodeCoverage {
  units: number;
  inspected: Partial<Record<CodeLang, number>>;
  /** code-like units whose language could not be told, so not inspected */
  unknown: number;
  /** units over the size limit, skipped */
  skipped: number;
  depth: "lexical";
}

const MAX_UNIT = 200_000;
const FENCE = /```([A-Za-z0-9_+-]*)[^\n]*\n([\s\S]*?)```/g;

const TAGS: Record<string, CodeLang> = {
  js: "javascript", javascript: "javascript", jsx: "javascript", ts: "javascript", typescript: "javascript", tsx: "javascript", node: "javascript", mjs: "javascript", cjs: "javascript",
  py: "python", python: "python", python3: "python",
  sh: "shell", bash: "shell", zsh: "shell", shell: "shell", console: "shell", terminal: "shell", fish: "shell",
  ps: "powershell", ps1: "powershell", powershell: "powershell", pwsh: "powershell",
  go: "go", golang: "go",
};

export function guessLang(src: string): CodeLang | "unknown" {
  const head = src.slice(0, 200);
  if (/^#!.*\b(?:ba|z|k)?sh\b/.test(head)) return "shell";
  if (/^#!.*\bpython/.test(head)) return "python";
  if (/^#!.*\bnode\b/.test(head)) return "javascript";
  if (/^\s*package\s+\w+\s*$/m.test(src) && /\bfunc\s+\w*\s*\(/.test(src)) return "go";
  if (/\b(?:Invoke-Expression|IEX|New-Object\s+Net\.WebClient|Write-Host|Get-ChildItem|\$env:)/i.test(src)) return "powershell";
  if (/^\s*(?:>>>\s+)?(?:import\s+[\w.]+|from\s+[\w.]+\s+import|def\s+\w+\s*\(|print\()/m.test(src)) return "python";
  if (/\b(?:const|let|var)\s+\w+\s*=|\brequire\(|\bfunction\s*\w*\s*\(|=>\s*[{(]|\bawait\s+fetch\(/.test(src)) return "javascript";
  if (/^\s*(?:\$\s+)?(?:sudo\s+)?(?:curl|wget|echo|export|chmod|cd|cat|nc|bash|sh)\b/m.test(src)) return "shell";
  return "unknown";
}

/** split source into code (comments removed, string literals replaced by STR) and the list of string literals */
export function lex(src: string, lang: CodeLang): { code: string; strings: string[]; comments: string } {
  let code = "", comments = "";
  const strings: string[] = [];
  const lineComment = lang === "python" || lang === "shell" || lang === "powershell" ? "#" : "//";
  const block = lang === "javascript" || lang === "go" ? ["/*", "*/"] : lang === "powershell" ? ["<#", "#>"] : null;
  const quotes = lang === "go" ? ['"', "`"] : lang === "javascript" ? ['"', "'", "`"] : ['"', "'"];
  let i = 0;
  const n = src.length;
  while (i < n) {
    if (lang === "python" && (src.startsWith('"""', i) || src.startsWith("'''", i))) {
      const q = src.slice(i, i + 3); const end = src.indexOf(q, i + 3); const j = end < 0 ? n : end + 3;
      strings.push(src.slice(i + 3, end < 0 ? n : end)); code += " STR "; i = j; continue;
    }
    if (block && src.startsWith(block[0], i)) {
      const end = src.indexOf(block[1], i + block[0].length); const j = end < 0 ? n : end + block[1].length;
      comments += src.slice(i, j) + "\n"; code += " "; i = j; continue;
    }
    // shell: "#" starts a comment only at a word boundary (not in ${#var} or a URL fragment)
    if (src.startsWith(lineComment, i) && (lineComment !== "#" || i === 0 || /\s/.test(src[i - 1]))) {
      const end = src.indexOf("\n", i); const j = end < 0 ? n : end;
      comments += src.slice(i, j) + "\n"; i = j; continue;
    }
    const c = src[i];
    if (quotes.includes(c)) {
      let j = i + 1, s = "";
      while (j < n && src[j] !== c) {
        if (src[j] === "\\" && j + 1 < n && !(lang === "shell" && c === "'")) { s += src[j + 1]; j += 2; continue; }
        if (src[j] === "\n" && c !== "`" && lang !== "shell") break;
        s += src[j]; j++;
      }
      strings.push(s); code += ` STR `; i = j + 1;
      // shell strings are still commands when evaluated; keep their text in the code view too
      if (lang === "shell") code += ` ${s} `;
      continue;
    }
    code += c; i++;
  }
  return { code, strings, comments };
}

const PIPE_TO_INTERPRETER = /\b(?:curl|wget|iwr|Invoke-WebRequest)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b|\b(?:curl|wget)\b[^|\n]*\|\s*(?:python3?|node|perl|ruby)\b/i;
const SECRET_PATHS = /(?:~|\$HOME|\/home\/\w+|\/Users\/\w+|%USERPROFILE%|\$env:USERPROFILE)[\\/](?:\.ssh[\\/]|\.aws[\\/]credentials|\.npmrc|\.netrc|\.docker[\\/]config\.json|\.kube[\\/]config|\.config[\\/]gcloud|\.gnupg)|\bid_(?:rsa|ed25519)\b|\/etc\/shadow/i;
const SECRET_ENV = /(?:process\.env\.?|os\.environ|os\.Getenv\(?|os\.getenv\(?|\$env:|\$\{?)(?:\[?["']?)?(?:AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|SLACK_TOKEN|STRIPE_SECRET_KEY|DATABASE_URL|[A-Z_]*(?:SECRET|TOKEN|PASSWORD|API_KEY))\b/;
const NETWORK_OUT: Record<CodeLang, RegExp> = {
  javascript: /\b(?:fetch|axios(?:\.\w+)?|https?\.request|XMLHttpRequest|navigator\.sendBeacon|got|request)\s*\(/,
  python: /\b(?:requests\.(?:post|put|get)|urllib\.request\.urlopen|httpx\.(?:post|put|get)|http\.client|socket\.socket|smtplib)\b/,
  shell: /\b(?:curl|wget|nc|ncat|scp|rsync|ftp)\b/,
  powershell: /\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm|Net\.WebClient|UploadString|UploadFile)\b/i,
  go: /\bhttp\.(?:Post|Get|NewRequest|PostForm)\b|\bnet\.Dial\b/,
};

interface Hit { kind: Finding["kind"]; what: string; strength: number }

function behaviors(lang: CodeLang, src: string): Hit[] {
  const { code, strings } = lex(src, lang);
  const strs = strings.join("\n");
  const hits: Hit[] = [];
  const add = (kind: Finding["kind"], what: string, strength = 1) => { if (!hits.some((h) => h.kind === kind)) hits.push({ kind, what, strength }); };

  if (lang === "python") {
    if (/\b(?:exec|eval)\s*\(\s*(?:requests\.get|urllib\.request\.urlopen|httpx\.get|urlopen)\s*\(/.test(code) || (/\b(?:exec|eval)\s*\(/.test(code) && /\.(?:text|content|read\(\))/.test(code) && /\b(?:requests|urllib|httpx)\b/.test(code)))
      add("code.download_execute", "Python runs code it downloads (exec/eval of a fetched response)");
    if (/\b(?:exec|eval)\s*\(\s*(?:base64\.b64decode|codecs\.decode|bytes\.fromhex|zlib\.decompress|marshal\.loads)/.test(code))
      add("code.encoded_execution", "Python decodes and executes a hidden payload");
    if (/\bsocket\.socket\b/.test(code) && /\b(?:os\.dup2|subprocess\.(?:call|Popen|run))\b/.test(code) && /\bconnect\s*\(/.test(code))
      add("code.reverse_shell", "Python reverse shell (socket connected back, process attached to it)");
    if (/\b(?:os\.system|subprocess\.(?:call|run|Popen|check_output))\s*\(/.test(code) && PIPE_TO_INTERPRETER.test(strs))
      add("code.download_execute", "Python shells out to download-and-run");
  }
  if (lang === "javascript") {
    if (/\b(?:eval|new\s+Function|Function)\s*\(/.test(code) && /\b(?:fetch|axios|https?\.get|request)\b/.test(code) && /\.(?:text|data)\b|\bres(?:ponse)?\b/.test(code))
      add("code.download_execute", "JavaScript evaluates code it downloads (eval/new Function on a fetched response)");
    if (/\b(?:eval|new\s+Function)\s*\(\s*(?:atob|Buffer\.from)\s*\(/.test(code))
      add("code.encoded_execution", "JavaScript decodes and evaluates a hidden payload");
    if (/\bchild_process\b|\b(?:exec|execSync|spawn|spawnSync)\s*\(/.test(code) && PIPE_TO_INTERPRETER.test(strs))
      add("code.download_execute", "Node shells out to download-and-run");
    if (/\bnet\.(?:connect|Socket)\b|\bnew\s+net\.Socket\b/.test(code) && /\b(?:spawn|exec)\s*\(\s*STR/.test(code) && /(?:\/bin\/(?:ba)?sh|cmd\.exe)\b/.test(strs))
      add("code.reverse_shell", "Node reverse shell (socket piped to a shell)");
  }
  if (lang === "shell") {
    if (/\/dev\/tcp\/[^\s/]+\/\d+/.test(code) || /\b(?:nc|ncat|netcat)\b[^\n]*\s-(?:e|c)\s/.test(code) || /\bbash\s+-i\b[^\n]*>&/.test(code) || /\bmkfifo\b[^\n]*\|\s*(?:nc|ncat)\b/.test(code))
      add("code.reverse_shell", "shell reverse shell (interactive shell connected to a remote host)");
    if (/\bbase64\s+(?:-d|--decode|-D)\b[^\n]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b|\becho\s+[A-Za-z0-9+/=]{40,}\s*\|\s*base64\s+(?:-d|--decode)/.test(code))
      add("code.encoded_execution", "shell decodes base64 and runs it");
    if (/\b(?:crontab\s+-|launchctl\s+(?:load|bootstrap)|systemctl\s+enable)\b/.test(code) || /(?:>>|tee\s+-a)\s*~?\/?[^\s]*(?:\.bashrc|\.zshrc|\.profile|\.bash_profile)\b/.test(code) && NETWORK_OUT.shell.test(code))
      add("code.persistence", "shell sets up persistence (cron, launch agent, service, shell profile)", 0.8);
  }
  if (lang === "powershell") {
    if (/\b(?:IEX|Invoke-Expression)\b[^\n]*(?:DownloadString|Invoke-WebRequest|iwr|irm|Invoke-RestMethod)/i.test(code) || /(?:DownloadString|irm|iwr)[^\n]*\|\s*(?:IEX|Invoke-Expression)\b/i.test(code))
      add("code.download_execute", "PowerShell downloads and runs a script (IEX of a download)");
    if (/-(?:e|enc|EncodedCommand)\s+[A-Za-z0-9+/=]{40,}/i.test(src) || /FromBase64String[^\n]*(?:IEX|Invoke-Expression)|(?:IEX|Invoke-Expression)[^\n]*FromBase64String/i.test(code))
      add("code.encoded_execution", "PowerShell runs an encoded command");
  }
  if (lang === "go") {
    if (/\bexec\.Command\s*\(/.test(code) && /\bhttp\.Get\b/.test(code) && /\b(?:sh|bash)\b/.test(strs))
      add("code.download_execute", "Go fetches and runs a shell command");
    if (/\bnet\.Dial\b/.test(code) && /\bexec\.Command\b/.test(code) && /\/bin\/(?:ba)?sh/.test(strs))
      add("code.reverse_shell", "Go reverse shell (connection attached to a shell)");
  }
  // any language: a secret read and a network send in the same unit
  const readsSecret = SECRET_PATHS.test(src) || SECRET_ENV.test(code) || SECRET_ENV.test(src);
  if (readsSecret && NETWORK_OUT[lang].test(code)) add("code.secret_exfiltration", "reads credentials (key files, cloud or API tokens) and sends data over the network", 1);
  return hits;
}

/** code units in what the model will receive: fenced blocks, <pre>/<code> text, whole files, decoded payloads */
export function extractCodeUnits(input: { kind: string; raw: string; segments: TextSegment[]; decodedPayloads: readonly string[] }): CodeUnit[] {
  const units: CodeUnit[] = [];
  if (input.kind === "javascript") units.push({ lang: "javascript", source: input.raw, where: "file", hidden: false });
  // syntax highlighting splits one <pre> block into many text nodes: join consecutive nodes of the same block
  const merged: TextSegment[] = [];
  const blockOf = (path: string) => { const i = path.search(/\/pre(?:\/|$|\[)/i); return i < 0 ? null : path.slice(0, i + 4); };
  for (const s of input.segments) {
    const k = blockOf(s.path);
    const last = merged[merged.length - 1];
    if (k && last && blockOf(last.path) === k && last.visibility === s.visibility) { merged[merged.length - 1] = { ...last, text: last.text + s.text }; continue; }
    merged.push(s);
  }
  for (const s of merged) {
    const hidden = !(s.visibility === "visible");
    for (const m of s.text.matchAll(FENCE)) {
      const tag = m[1].toLowerCase();
      units.push({ lang: TAGS[tag] ?? guessLang(m[2]), source: m[2], where: `${s.path} (fenced ${tag || "block"})`, hidden });
    }
    // a <pre> block, or a multi-line <code>; inline <code> spans are words in a sentence, not programs
    const isBlock = /\/pre(?:\/|$|\[)/i.test(s.path) || (/\/code(?:\/|$|\[)/i.test(s.path) && s.text.includes("\n") && s.text.length >= 40);
    if (isBlock || /^#!/.test(s.text)) units.push({ lang: guessLang(s.text), source: s.text, where: s.path, hidden });
    else if (hidden && s.text.length > 30 && guessLang(s.text) !== "unknown" && !s.text.includes("```")) units.push({ lang: guessLang(s.text), source: s.text, where: s.path, hidden });
  }
  if (input.kind === "text" && /^#!/.test(input.raw)) units.push({ lang: guessLang(input.raw), source: input.raw, where: "file", hidden: false });
  for (const p of input.decodedPayloads) { const l = guessLang(p); if (l !== "unknown") units.push({ lang: l, source: p, where: "decoded payload", hidden: true }); }
  return units;
}

export function scanCode(input: { kind: string; raw: string; segments: TextSegment[]; decodedPayloads: readonly string[] }): { findings: Finding[]; coverage: CodeCoverage } {
  const units = extractCodeUnits(input);
  const coverage: CodeCoverage = { units: units.length, inspected: {}, unknown: 0, skipped: 0, depth: "lexical" };
  const findings: Finding[] = [];
  const seen = new Set<string>();
  for (const u of units) {
    if (u.source.length > MAX_UNIT) { coverage.skipped++; continue; }
    if (u.lang === "unknown") { coverage.unknown++; continue; }
    coverage.inspected[u.lang] = (coverage.inspected[u.lang] ?? 0) + 1;
    for (const h of behaviors(u.lang, u.source)) {
      const key = `${h.kind}|${u.where}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({
        pass: "code", kind: h.kind,
        // visible code is documentation (cheat sheets, security posts): recorded, far below a refusal on its own
        confidence: (u.hidden ? 0.85 : 0.2) * h.strength, severity: u.hidden ? 0.9 : 0.4,
        message: `${h.what} (${u.lang}${u.hidden ? ", in code a human would not see" : ", visible code: documentation unless other evidence"})`,
        excerpt: u.source.replace(/\s+/g, " ").slice(0, 120), location: u.where, inHidden: u.hidden, action: "none",
      });
    }
  }
  return { findings, coverage };
}
