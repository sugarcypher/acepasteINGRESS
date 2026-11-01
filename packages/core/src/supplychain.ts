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

/** underlight SUSPICIOUS_SCRIPT_RE, split into execution/network and credential reach */
const EXEC_RE = /(curl\b|wget\b|fetch\(|https?:\/\/|child_process|\bexec\(|\bspawn\(|node\s+-e\b|base64|\batob\(|\beval\(|\bFunction\(|powershell|\/bin\/sh|bash\s+-c|python[23]?\s+-c|Invoke-WebRequest|certutil)/i;
const CRED_RE = /(\$\{?HOME\b|~\/\.ssh|\.ssh\/id_|\.npmrc|\.aws\/|\.config\/gh|\.git-credentials|\bAWS_[A-Z_]+|GITHUB_TOKEN|NPM_TOKEN|\bprintenv\b|\benv\s*\|)/i;

/** underlight URL_SPEC_RE */
const URL_SPEC_RE = /^(https?:\/\/|git\+|git:\/\/|ssh:\/\/|github:|gitlab:|bitbucket:|gist:|[\w.-]+\/[\w.-]+(#.*)?$|.*\.tgz$|.*\.tar\.gz$)/i;

const REGISTRY_HOSTS = new Set(["registry.npmjs.org", "registry.yarnpkg.com", "registry.npmjs.com", "registry.npmmirror.com"]);

/** install / execute commands an agent might be talked into running */
const INSTALL_PATTERNS: Array<{ re: RegExp; what: string }> = [
  { re: /\b(curl|wget)\b[^\n|;]{0,300}\|\s*(sudo\s+)?(ba|z|da|k)?sh\b/i, what: "download piped to a shell" },
  { re: /\b(iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|]{0,300}\|\s*(iex|Invoke-Expression)\b/i, what: "PowerShell download piped to Invoke-Expression" },
  { re: /\bbase64\s+(-d|--decode|-D)\b[^\n]{0,80}\|\s*(ba|z)?sh\b/i, what: "base64-decoded payload piped to a shell" },
  { re: /\b(npm|pnpm|yarn|bun)\s+(i|install|add)\s+[^\n]{0,80}(https?:\/\/|git\+|github:|gist:|\.tgz\b)/i, what: "package install from a URL instead of a registry" },
  { re: /\bnpx\s+(-y\s+|--yes\s+)?(https?:\/\/|github:|gist:)/i, what: "npx executing code from a URL" },
  { re: /\bpip3?\s+install\s+[^\n]{0,80}(git\+|https?:\/\/)/i, what: "pip install from a URL" },
  { re: /\bpython3?\s+-c\s+["'][^\n]{0,200}(urllib|requests|socket|exec\()/i, what: "inline Python that fetches or executes" },
  { re: /\b(env|printenv|set)\s*\|\s*(curl|wget|nc|ncat)\b/i, what: "environment variables piped to the network" },
  { re: /\b(cat|tar|zip)\b[^\n|]{0,120}(\.ssh|\.npmrc|\.aws|\.git-credentials|\.config\/gh|id_rsa|id_ed25519)[^\n|]{0,80}\|\s*(curl|wget|nc|ncat)\b/i, what: "credential files piped to the network" },
  { re: /\b(curl|wget)\b[^\n]{0,200}(-d|--data(-binary|-raw|-urlencode)?|-F|--form|-T|--upload-file|--post-file)[=\s]+["']?@?[^\s"']*(\.ssh|\.npmrc|\.aws|\.git-credentials|id_rsa|id_ed25519|\.env\b|@-)/i, what: "upload of local secrets or stdin to a remote host" },
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
    const cred = CRED_RE.test(v), exec = EXEC_RE.test(v);
    if (!cred && !exec) continue;
    out.push({
      pass: "supplychain", kind: "supplychain.lifecycle_script",
      confidence: cred && exec ? 0.95 : cred ? 0.85 : 0.65,
      severity: cred ? 0.95 : 0.6,
      message: `${k} script runs on install and ${cred ? "reaches for credentials" : "fetches or executes code"}`,
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
    findings.push(...installFindings(s.text, s.visibility !== "visible", s.path));
  }
  for (const p of input.decodedPayloads) findings.push(...installFindings(p, true, "decoded payload"));
  return findings;
}
