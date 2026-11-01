/**
 * Secrets pass (Kith & Revere lineage, ported 2026-10-31).
 *
 * Kith & Revere's rule for credentials: name the kind of secret and where it
 * is, never print the secret itself. The gate applies the same rule at the
 * ingestion boundary. A credential in fetched content is either a leak (it
 * should not land in a model's context, logs or training data) or bait (a
 * planted key with instructions to use it). Either way the gate redacts it
 * from everything it emits: delivered text, finding excerpts, the attack log
 * and the public feed. Detection alone does not refuse a page; a credential
 * in hidden text does count against it.
 */

import type { Finding, TextSegment } from "./types.js";

interface SecretPattern { name: string; re: RegExp; pre: RegExp }

// Every quantifier is bounded and every pattern has a cheap literal pre-filter: this pass runs on attacker-supplied
// text, so no pattern may be able to scan quadratically ("a.a.a.…", "sk-sk-sk-…", an unterminated key block).
// A token ends at the first character that cannot continue it, not at a word boundary ("ghp_…_backup" still matches).
const END = String.raw`(?![A-Za-z0-9])`;
const PATTERNS: SecretPattern[] = [
  { name: "AWS access key id", pre: /A[KSBC][IC]A/, re: new RegExp(String.raw`(?<![A-Za-z0-9])(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}` + END, "g") },
  { name: "AWS secret access key", pre: /secret_?access_?key/i, re: /(aws_secret_access_key\s{0,3}[=:]\s{0,3}["']?|"SecretAccessKey"\s{0,3}:\s{0,3}")[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/gi },
  { name: "GitHub token", pre: /gh[pousr]_|github_pat_/, re: new RegExp(String.raw`(?<![A-Za-z0-9])((ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,80}|github_pat_[A-Za-z0-9_]{60,120})` + END, "g") },
  { name: "GitLab token", pre: /glpat-/, re: new RegExp(String.raw`glpat-[A-Za-z0-9_-]{20,64}` + END, "g") },
  { name: "Slack token", pre: /xox[abposr]-/, re: new RegExp(String.raw`xox[abposr]-[A-Za-z0-9-]{10,120}` + END, "g") },
  { name: "Stripe secret key", pre: /[sr]k_live_/, re: new RegExp(String.raw`(sk|rk)_live_[A-Za-z0-9]{20,120}` + END, "g") },
  { name: "npm token", pre: /npm_|_authToken/, re: /(?<![A-Za-z0-9])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])|_authToken\s{0,3}=\s{0,3}[^\s"']{20,200}/g },
  { name: "Anthropic API key", pre: /sk-ant-/, re: new RegExp(String.raw`sk-ant-[A-Za-z0-9_-]{30,200}` + END, "g") },
  { name: "OpenAI API key", pre: /sk-/, re: new RegExp(String.raw`(?<![A-Za-z0-9-])sk-(proj-|svcacct-)?[A-Za-z0-9_-]{40,200}` + END, "g") },
  { name: "Hugging Face token", pre: /hf_/, re: new RegExp(String.raw`(?<![A-Za-z0-9])hf_[A-Za-z0-9]{34,40}` + END, "g") },
  { name: "SendGrid key", pre: /SG\./, re: /(?<![A-Za-z0-9])SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])/g },
  { name: "Google API key", pre: /AIza/, re: new RegExp(String.raw`AIza[0-9A-Za-z_-]{35}` + END, "g") },
  { name: "private key block", pre: /PRIVATE KEY/, re: /-----BEGIN (RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----[\s\S]{20,16000}?-----END (RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----/g },
  { name: "credential in URL", pre: /:\/\/[^\s/@]{0,200}:[^\s/@]{0,200}@/, re: /(?<![A-Za-z0-9+.-])[a-z][a-z0-9+.-]{0,20}:\/\/([^\s:/@]{2,64}):([^\s:/@]{6,128})@([^\s/:]{1,253})/gi },
  { name: "Kubernetes credential", pre: /client-(key|certificate)-data/, re: /(client-key-data|client-certificate-data):\s{0,3}[A-Za-z0-9+/=]{40,20000}/g },
];

/** documentation placeholders are not secrets */
const PLACEHOLDER = /EXAMPLE|example|xxxx|XXXX|your[_-]?(key|token)|placeholder|dummy|redacted|\*{4,}|<[^>]+>|\.\.\.|0{12,}|1234567890/;
/** well-known development defaults are not credentials worth redacting */
const DEFAULT_PASSWORDS = /^(password|passwd|postgres|secret|changeme|root|admin|example|test|guest|pass|mysql|redis)$/i;
const LOCAL_HOST = /^(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[::1\]|db|postgres|mysql|redis|.*\.(local|localhost|internal|test|example))$/i;

function entropy(s: string): number {
  const f = new Map<string, number>();
  for (const c of s) f.set(c, (f.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of f.values()) { const p = n / s.length; h -= p * Math.log2(p); }
  return h;
}

interface Hit { name: string; start: number; end: number; value: string }

function plausible(p: SecretPattern, m: RegExpMatchArray): boolean {
  const v = m[0];
  if (PLACEHOLDER.test(v)) return false;
  if (p.name === "private key block" || p.name === "Kubernetes credential") return true;
  if (p.name === "credential in URL") {
    const [, user, pass, host] = m;
    if (LOCAL_HOST.test(host) || DEFAULT_PASSWORDS.test(pass) || user === pass) return false;
    return true;
  }
  const body = v.replace(/^[a-z_]+[-_]/i, "");
  if (entropy(body) < 3.0) return false;
  if (p.name === "OpenAI API key") {
    // a key mixes case and digits and has at most a few hyphens; a URL slug like "sk-hynix-posts-record-…" does not
    const b = v.replace(/^sk-(proj-|svcacct-)?/, "");
    if (!(/[a-z]/.test(b) && /[A-Z]/.test(b) && /\d/.test(b)) || (b.match(/-/g) ?? []).length > 4) return false;
  }
  return true;
}

function findSecrets(text: string): Hit[] {
  const hits: Hit[] = [];
  if (!text || text.length < 16) return hits;
  // private key blocks: a linear scan (each BEGIN is paired with the next END by index, never by backtracking)
  if (text.includes("PRIVATE KEY-----")) {
    const begin = /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g;
    let m: RegExpExecArray | null;
    let after = 0, cachedEnd = -2;
    while ((m = begin.exec(text)) && hits.length < 500) {
      if (m.index < after) continue;
      if (cachedEnd < m.index + m[0].length && cachedEnd !== -1) cachedEnd = text.indexOf("-----END ", m.index + m[0].length);
      const endAt = cachedEnd;
      if (endAt < 0) break;
      const close = text.indexOf("-----", endAt + 9);
      if (close < 0) break;
      const stop = close + 5;
      const body = text.slice(m.index + m[0].length, endAt);
      if (body.length >= 20 && body.length <= 16000 && !PLACEHOLDER.test(body) && !/-----BEGIN /.test(body)) {
        hits.push({ name: "private key block", start: m.index, end: stop, value: text.slice(m.index, stop) });
        after = stop;
      }
      begin.lastIndex = Math.max(begin.lastIndex, m.index + m[0].length);
    }
  }
  for (const p of PATTERNS) {
    if (p.name === "private key block") continue;
    if (!p.pre.test(text)) continue;
    p.re.lastIndex = 0;
    for (const m of text.matchAll(p.re)) {
      if (!plausible(p, m)) continue;
      hits.push({ name: p.name, start: m.index!, end: m.index! + m[0].length, value: m[0] });
      if (hits.length > 500) break;
    }
  }
  return hits.sort((a, b) => a.start - b.start).filter((h, i, arr) => i === 0 || h.start >= arr[i - 1].end);
}

/** The literal credential values present in these texts, for scrubbing excerpts that were cut or altered before redaction. */
export function collectSecrets(texts: ReadonlyArray<string>): string[] {
  const out = new Set<string>();
  for (const t of texts) for (const h of findSecrets(t)) out.add(h.value);
  return [...out];
}

const INVISIBLE_OR_REPLACEMENT = /[\u200B-\u200F\u2060-\u2064\uFEFF\u00AD\uFFFD\u{E0000}-\u{E007F}]/gu;

/**
 * Make an excerpt safe to log or publish. Redacts detected credentials, then removes any fragment of a known
 * credential (an excerpt cut mid-token, or with an invisible character swapped for a marker, can no longer match
 * a pattern on its own). Works on a copy with invisible characters and replacement markers removed.
 */
export function scrubExcerpt(text: string, known: ReadonlyArray<string>): string {
  if (!text) return text;
  let out = redactSecrets(text);
  const flat = out.replace(INVISIBLE_OR_REPLACEMENT, "");
  let scrubbed = redactSecrets(flat);
  for (const k of known) {
    const plain = k.replace(INVISIBLE_OR_REPLACEMENT, "");
    // any run of 10+ characters of the credential, which also covers a truncated head or tail
    for (let len = Math.min(plain.length, 400); len >= 10; len = len > 40 ? len - 20 : len - 1) {
      let changed = false;
      for (let i = 0; i + len <= plain.length; i += Math.max(1, Math.floor(len / 2))) {
        const frag = plain.slice(i, i + len);
        if (scrubbed.includes(frag)) { scrubbed = scrubbed.split(frag).join("[redacted]"); changed = true; }
      }
      if (changed) break;
    }
  }
  return scrubbed !== flat ? scrubbed : out;
}

/** Replace every detected credential with a label naming its kind. Never reversible. */
export function redactSecrets(text: string): string {
  if (!text) return text;
  const hits = findSecrets(text);
  if (!hits.length) return text;
  let out = "", i = 0;
  for (const h of hits) { out += text.slice(i, h.start) + `[redacted: ${h.name}]`; i = h.end; }
  return out + text.slice(i);
}

export function scanSecrets(segments: ReadonlyArray<TextSegment>, decodedPayloads: ReadonlyArray<string>): Finding[] {
  const byKind = new Map<string, { n: number; hidden: boolean; where: string }>();
  const visit = (text: string, hidden: boolean, where: string) => {
    for (const h of findSecrets(text)) {
      const e = byKind.get(h.name) ?? { n: 0, hidden: false, where };
      e.n++; e.hidden ||= hidden;
      byKind.set(h.name, e);
    }
  };
  for (const s of segments) visit(s.text, s.visibility !== "visible", s.path);
  for (const p of decodedPayloads) visit(p, true, "decoded payload");
  return [...byKind.entries()].map(([name, e]) => ({
    pass: "secrets" as const, kind: "secrets.credential_in_content" as const,
    confidence: 0.8,
    // a visible leaked key is not an attack on the model; a hidden one is bait or a planted channel
    severity: e.hidden ? 0.6 : 0.25,
    message: `${e.n} ${name}${e.n === 1 ? "" : "s"} in ${e.hidden ? "hidden " : ""}content; redacted from everything the gate emits (the value is never logged)`,
    excerpt: `[redacted: ${name}]`, location: e.where, action: "neutralized" as const,
  }));
}
