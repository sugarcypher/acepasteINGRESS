/**
 * Supply-chain pass (underlight lineage, ported 2026-10-31).
 *
 * underlight inventories JavaScript that can execute on a machine. The part
 * of it that sits on the gate's boundary is the moment an agent reads
 * something that would make it install or run code: a package manifest, a
 * lockfile, or an install command in a README. This pass ports underlight's
 * manifest detectors (lifecycle scripts, URL-valued dependency specifiers,
 * off-registry lockfile resolutions; same patterns as underlight.py 0.2.2)
 * and adds one the gate needs: install commands in text, graded by whether a
 * human reading the page would see them.
 *
 * Visible install commands are documentation (rustup, Homebrew) and score
 * low. The same command in hidden text, a decoded payload, or reaching for
 * credentials is the attack.
 */

import type { ContentKind, Finding, TextSegment } from "./types.js";

/** scripts that run when a package is installed as a dependency (underlight CONSUMER_LIFECYCLE) */
const CONSUMER_LIFECYCLE = ["preinstall", "install", "postinstall", "prepare"] as const;

/**
 * underlight SUSPICIOUS_SCRIPT_RE, split three ways after adversarial review (2026-11-01):
 *   strong  — fetches, opens a socket, or runs decoded or generated code: flags on its own
 *   weak    — inline interpreters, shells and URLs: common in harmless scripts ("node -e" feature checks,
 *             husky recipes, an echoed docs link), so they flag only in combination
 *   cred    — reaches for credentials
 */
const STRONG_RE = /(\bcurl\b|\bwget\b|\/dev\/(tcp|udp)\/|\bnc(at)?\s|\bsocat\b|\bnslookup\b|\bdig\s|\bfetch\(|child_process|\bexec(Sync)?\(|\bspawn(Sync)?\(|powershell|Invoke-WebRequest|\biwr\b|certutil|\beval\(|\bFunction\(|\batob\(|base64\s+(-d|--decode|-D)\b|\b(perl|ruby)\s+-e\b|\bphp\s+-r\b|\\x[0-9a-fA-F]{2}|require\(\s*["'](https?|net|dgram|dns|tls)["']\s*\))/i;
/** unambiguous on install: a socket back to a host, a decoded or downloaded payload handed straight to a shell */
const CRITICAL_RE = /(\/dev\/(tcp|udp)\/|\bnc(at)?\s[^\n]{0,120}\s-(e|c)\s|\bsocat\b[^\n]{0,120}exec|\b(curl|wget)\b[^\n|]{0,300}\|\s*(sudo\s+)?(ba|z)?sh\b|base64\s+(-d|--decode|-D)\b[^\n]{0,80}\|\s*(ba|z)?sh\b|\\x[0-9a-fA-F]{2}[^\n]{0,200}\|\s*(ba|z)?sh\b)/i;
const WEAK_RE = /(\bnode\s+-e\b|\b(ba|z)?sh\s+-c\b|\bpython[23]?\s+-c\b|https?:\/\/|\$\()/gi;
const CRED_RE = /(\$\{?HOME\b|~\/\.ssh|\.ssh\/id_|\.npmrc|\.aws\/|\.config\/gh|\.git-credentials|\bAWS_[A-Z_]+|GITHUB_TOKEN|NPM_TOKEN|\bprintenv\b|\benv\s*\|)/i;

function execSignal(script: string): boolean {
  if (STRONG_RE.test(script)) return true;
  const weak = new Set((script.match(WEAK_RE) ?? []).map((w) => w.toLowerCase().replace(/\s+/g, " ").replace(/^(ba|z)sh/, "sh")));
  // a URL inside an echo or a comment is a message to the installer, not an action
  if (weak.size === 1 && [...weak][0].startsWith("http") && /\becho\b|^\s*#/.test(script)) return false;
  return weak.size >= 2;
}

/** underlight URL_SPEC_RE */
const URL_SPEC_RE = /^(https?:\/\/|git\+|git:\/\/|ssh:\/\/|github:|gitlab:|bitbucket:|gist:|[\w.-]+\/[\w.-]+(#.*)?$|.*\.tgz$|.*\.tar\.gz$)/i;

const REGISTRY_HOSTS = new Set(["registry.npmjs.org", "registry.yarnpkg.com", "registry.npmjs.com", "registry.npmmirror.com"]);

/** install / execute commands an agent might be talked into running */
const SUDO = String.raw`(sudo(\s+-[A-Za-z]+)*\s+)?`;
const INSTALL_PATTERNS: Array<{ re: RegExp; what: string }> = [
  { re: new RegExp(String.raw`\b(curl|wget|fetch)\b[^\n|;]{0,300}\|\s*` + SUDO + String.raw`(ba|z|da|k|fi)?sh\b`, "i"), what: "download piped to a shell" },
  { re: new RegExp(String.raw`\b(curl|wget)\b[^\n|;]{0,300}\|\s*` + SUDO + String.raw`(python[23]?|node|perl|ruby|php|deno|bun)\b`, "i"), what: "download piped to an interpreter" },
  { re: /\b(ba|z)?sh\s{1,4}<\(\s{0,4}(curl|wget)\b/i, what: "download run through process substitution" },
  { re: /\b(ba|z)?sh\s{1,4}-c\s{1,4}["']?\$\(\s{0,4}(curl|wget)\b/i, what: "download run through command substitution" },
  { re: /\b(curl|wget)\b[^\n;&|]{0,200}\s(-o|-O|--output)\s{0,3}\S{1,200}[^\n]{0,60}(&&|;)\s{0,4}(sudo\s+)?((ba|z)?sh|chmod\s+\+x|\.\/)/i, what: "download saved and then run" },
  { re: /\b(iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|]{0,300}\|\s*(iex|Invoke-Expression)\b/i, what: "PowerShell download piped to Invoke-Expression" },
  { re: /\b(iex|Invoke-Expression)\s{0,4}\(\s{0,4}(iwr|irm|Invoke-WebRequest|Invoke-RestMethod|\(?\s{0,4}New-Object\s+Net\.WebClient)/i, what: "PowerShell expression evaluating a download" },
  { re: /\.DownloadString\s{0,3}\(/i, what: "PowerShell DownloadString" },
  { re: /\bbase64\s+(-d|--decode|-D)\b[^\n]{0,80}\|\s*(ba|z)?sh\b/i, what: "base64-decoded payload piped to a shell" },
  { re: /\b(npm|pnpm|yarn|bun)\s+(i|install|add)\s+[^\n]{0,80}(https?:\/\/|git\+|github:|gist:|\.tgz\b)/i, what: "package install from a URL instead of a registry" },
  { re: /\bnpx\s+(-y\s+|--yes\s+)?(https?:\/\/|github:|gist:)/i, what: "npx executing code from a URL" },
  { re: /\bdeno\s+run\s+(-A|--allow-all)\b[^\n]{0,60}https?:\/\//i, what: "deno running remote code with all permissions" },
  { re: /\b(uvx|pipx\s+run)\s+(--from|--spec)\s+(git\+|https?:\/\/)/i, what: "Python tool run from a URL" },
  { re: /\bpip3?\s+install\s+[^\n]{0,80}(git\+|https?:\/\/)/i, what: "pip install from a URL" },
  { re: /\b(env|printenv|set)\s*\|\s*(curl|wget|nc|ncat)\b/i, what: "environment variables piped to the network" },
  { re: /\b(cat|tar|zip)\b[^\n|]{0,120}(\.ssh|\.npmrc|\.aws|\.git-credentials|\.config\/gh|id_rsa|id_ed25519)[^\n|]{0,80}\|\s*(curl|wget|nc|ncat)\b/i, what: "credential files piped to the network" },
  { re: /\b(curl|wget)\b[^\n]{0,200}\s(-d|--data(-binary|-raw|-urlencode)?|-F|--form|-T|--upload-file|--post-file)[=\s]{1,3}["']?@?[^\s"']{0,200}(\.ssh|\.npmrc|\.aws|\.git-credentials|id_rsa|id_ed25519|\.env\b|@-)/i, what: "upload of local secrets or stdin to a remote host" },
  { re: /\/dev\/(tcp|udp)\/[\w.-]{1,253}\/\d{1,5}/i, what: "shell socket to a remote host (reverse shell)" },
  { re: /\bpython3?\s+-c\s+["'][^\n]{0,200}(urllib|requests|socket|exec\()/i, what: "inline Python that fetches or executes" },
  { re: /\bnode\s+-e\s+["'][^\n]{0,200}(child_process|https?\.get|fetch\(|eval\()/i, what: "inline Node that fetches or executes" },
];

export interface SupplyChainInput {
  kind: ContentKind;
  raw: string;
  segments: ReadonlyArray<TextSegment>;
  decodedPayloads: ReadonlyArray<string>;
}

const clip = (s: string, n = 200) => (s.length > n ? s.slice(0, n) + "…" : s);

function hostOf(u: string): string | null {
  const m = /^[a-z][a-z0-9+.-]*:\/\/([^/@]+@)?([^/:]+)/i.exec(u);
  return m ? m[2].toLowerCase() : null;
}

function isManifest(doc: any): boolean {
  return !!doc && typeof doc === "object" && !Array.isArray(doc) && typeof doc.name === "string" &&
    (typeof doc.version === "string" || typeof doc.scripts === "object" || typeof doc.dependencies === "object");
}

function manifestFindings(doc: any): Finding[] {
  const out: Finding[] = [];
  const scripts = doc.scripts && typeof doc.scripts === "object" ? doc.scripts : {};
  for (const k of CONSUMER_LIFECYCLE) {
    const v = scripts[k];
    if (typeof v !== "string" || !v.trim()) continue;
    const cred = CRED_RE.test(v), critical = CRITICAL_RE.test(v), exec = critical || execSignal(v);
    if (!cred && !exec) continue;
    out.push({
      pass: "supplychain", kind: "supplychain.lifecycle_script",
      confidence: cred && exec ? 0.95 : cred || critical ? 0.9 : 0.65,
      severity: cred || critical ? 0.95 : 0.6,
      message: `${k} script runs on install and ${cred ? "reaches for credentials" : critical ? "opens a shell to a remote host or pipes a payload into a shell" : "fetches or executes code"}`,
      excerpt: clip(v), location: `$.scripts.${k}`, action: "none",
    });
  }
  const url: string[] = [];
  for (const field of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
    const deps = doc[field];
    if (!deps || typeof deps !== "object") continue;
    for (const [name, spec] of Object.entries(deps)) if (typeof spec === "string" && URL_SPEC_RE.test(spec.trim())) url.push(`${name}@${spec}`);
  }
  if (url.length) out.push({
    pass: "supplychain", kind: "supplychain.url_dependency", confidence: 0.45, severity: 0.5,
    message: `${url.length} dependenc${url.length === 1 ? "y resolves" : "ies resolve"} to a network location instead of a registry; registry scanners see none of them`,
    excerpt: clip(url.slice(0, 5).join(", ")), location: "$.dependencies", action: "none",
  });
  return out;
}

function lockfileFindings(raw: string, doc: any): Finding[] {
  const hosts = new Map<string, number>();
  const note = (u: string) => { const h = hostOf(u); if (h && !REGISTRY_HOSTS.has(h)) hosts.set(h, (hosts.get(h) ?? 0) + 1); };
  if (doc && typeof doc === "object" && ("lockfileVersion" in doc)) {
    for (const group of [doc.packages, doc.dependencies]) if (group && typeof group === "object") for (const v of Object.values<any>(group)) if (v && typeof v.resolved === "string") note(v.resolved);
  } else if (/^# (yarn lockfile|THIS IS AN AUTOGENERATED FILE)/m.test(raw) || /^lockfileVersion:/m.test(raw)) {
    for (const m of raw.matchAll(/(?:resolved|tarball)[:\s]+["']?(https?:\/\/[^\s"'}]+)/g)) note(m[1]);
  } else return [];
  if (!hosts.size) return [];
  const list = [...hosts.entries()].sort((a, b) => b[1] - a[1]);
  return [{
    pass: "supplychain", kind: "supplychain.offregistry_resolution", confidence: 0.4, severity: 0.5,
    message: `lockfile resolves packages from ${list.length} host${list.length === 1 ? "" : "s"} outside the public registries (a private registry is legitimate; an unknown one is not)`,
    excerpt: clip(list.slice(0, 5).map(([h, n]) => `${h} (${n})`).join(", ")), action: "none",
  }];
}

function installFindings(text: string, hidden: boolean, where: string): Finding[] {
  const out: Finding[] = [];
  for (const p of INSTALL_PATTERNS) {
    const m = p.re.exec(text);
    if (!m) continue;
    const start = Math.max(0, m.index - 40);
    const ctx = text.slice(start, m.index + m[0].length + 80);
    const cred = CRED_RE.test(ctx);
    out.push({
      pass: "supplychain", kind: "supplychain.install_instruction",
      // a visible curl|sh is ordinary documentation; hidden, decoded, or credential-reaching is not
      confidence: hidden ? 0.92 : cred ? 0.75 : 0.3,
      severity: hidden ? 0.9 : cred ? 0.8 : 0.4,
      message: `${hidden ? "hidden " : ""}${p.what}${cred ? ", reaching for credentials" : ""}${hidden ? " (a human reading the page would not see this command)" : ""}`,
      excerpt: clip(m[0]), location: where, action: "none",
    });
  }
  return out;
}

export function scanSupplyChain(input: SupplyChainInput): Finding[] {
  const findings: Finding[] = [];
  let doc: any;
  if (input.kind === "json") { try { doc = JSON.parse(input.raw); } catch { doc = undefined; } }
  if (doc !== undefined && isManifest(doc)) findings.push(...manifestFindings(doc));
  if (input.kind === "json" || input.kind === "text") findings.push(...lockfileFindings(input.raw, doc));
  // manifests carry their scripts as JSON strings; those were judged above, so skip segment scanning of $.scripts
  for (const s of input.segments) {
    if (s.path.startsWith("$.scripts.")) continue;
    // collapsed <details> and hidden tab panels are revealed by one click: install docs live there, so weigh them as visible
    findings.push(...installFindings(s.text, s.visibility !== "visible" && !s.path.includes("~revealable"), s.path));
  }
  for (const p of input.decodedPayloads) findings.push(...installFindings(p, true, "decoded payload"));
  return findings;
}
