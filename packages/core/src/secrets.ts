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

interface SecretPattern { name: string; re: RegExp }

/** token formats with a fixed, documented prefix; low false-positive rate */
const PATTERNS: SecretPattern[] = [
  { name: "AWS access key id", re: /\b(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g },
  { name: "AWS secret access key", re: /\baws_secret_access_key\s*[=:]\s*["']?[A-Za-z0-9/+=]{40}["']?/gi },
  { name: "GitHub token", re: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b/g },
  { name: "GitLab token", re: /\bglpat-[A-Za-z0-9_-]{20,}\b/g },
  { name: "Slack token", re: /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/g },
  { name: "Stripe secret key", re: /\b(sk|rk)_live_[A-Za-z0-9]{20,}\b/g },
  { name: "npm token", re: /\bnpm_[A-Za-z0-9]{36}\b|_authToken\s*=\s*[^\s"']{20,}/g },
  { name: "Anthropic API key", re: /\bsk-ant-[A-Za-z0-9_-]{30,}\b/g },
  { name: "OpenAI API key", re: /\bsk-(proj-)?[A-Za-z0-9_-]{40,}\b/g },
  { name: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { name: "private key block", re: /-----BEGIN (RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----[\s\S]{20,}?-----END (RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----/g },
  { name: "credential in URL", re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@]{2,}:[^\s:/@]{6,}@[^\s/]+/gi },
  { name: "Kubernetes credential", re: /\b(client-key-data|client-certificate-data):\s*[A-Za-z0-9+/=]{40,}/g },
];

/** documentation placeholders are not secrets */
const PLACEHOLDER = /EXAMPLE|example|xxxx|XXXX|your[_-]?(key|token)|placeholder|dummy|redacted|\*{4,}|<[^>]+>|\.\.\.|0{12,}|1234567890/;

function entropy(s: string): number {
  const f = new Map<string, number>();
  for (const c of s) f.set(c, (f.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of f.values()) { const p = n / s.length; h -= p * Math.log2(p); }
  return h;
}

interface Hit { name: string; start: number; end: number }

function findSecrets(text: string): Hit[] {
  const hits: Hit[] = [];
  for (const p of PATTERNS) {
    p.re.lastIndex = 0;
    for (const m of text.matchAll(p.re)) {
      const v = m[0];
      if (PLACEHOLDER.test(v)) continue;
      // a credential URL with an obvious demo user, or a token of one repeated character, is documentation
      if (p.name !== "private key block" && entropy(v.replace(/^[a-z_]+[-_]/i, "")) < 3.0) continue;
      hits.push({ name: p.name, start: m.index!, end: m.index! + v.length });
    }
  }
  return hits.sort((a, b) => a.start - b.start).filter((h, i, arr) => i === 0 || h.start >= arr[i - 1].end);
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
