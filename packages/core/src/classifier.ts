/**
 * The learned pass: a small classifier that reads text the way the rules cannot, by resemblance.
 *
 * The rules are precise and miss rewording: on public sets they catch about one attack in nine. This pass is
 * a logistic regression over two hashed bags (word 1-2-grams, and character 3-5-grams inside word
 * boundaries), trained on public attack and benign text (tools/classifier). It has no dependencies, runs on
 * the machine, and scores a text in well under a millisecond.
 *
 * What it is allowed to decide:
 *   - On its own it can make content suspect (refused, and a person may override). It cannot make content
 *     hostile: that needs a rule, hidden placement or another signal to agree. A statistical resemblance is
 *     not proof.
 *   - It judges what would be delivered (the visible text, by its opening) and every piece of hidden text.
 *     Later stretches of a long document are judged at a stricter line, because a long page gives it many
 *     chances to be wrong.
 *
 * The featurizer below must match tools/classifier/train.py exactly (scikit-learn's HashingVectorizer with
 * the `word` and `char_wb` analyzers). The model carries "parity" vectors scored by the trainer; the tests
 * check this implementation against them.
 */

import { CLASSIFIER_MODEL } from "./classifier-model.js";
import type { Finding, TextSegment } from "./types.js";

interface Block { scale: number; weights: Int8Array; ngram: readonly [number, number] }
interface Model { nFeatures: number; maxChars: number; bias: number; threshold: number; word: Block; char: Block; trainedAt: string }

let cached: Model | undefined;
function model(): Model {
  if (cached) return cached;
  const m = CLASSIFIER_MODEL as unknown as { nFeatures: number; maxChars: number; bias: number; threshold: number; trainedAt: string; word: { scale: number; int8: string; ngram: [number, number] }; char: { scale: number; int8: string; ngram: [number, number] } };
  const unpack = (b: { scale: number; int8: string; ngram: [number, number] }): Block => {
    const buf = Buffer.from(b.int8, "base64");
    return { scale: b.scale, weights: new Int8Array(buf.buffer, buf.byteOffset, buf.byteLength), ngram: b.ngram };
  };
  cached = { nFeatures: m.nFeatures, maxChars: m.maxChars, bias: m.bias, threshold: m.threshold, trainedAt: m.trainedAt, word: unpack(m.word), char: unpack(m.char) };
  return cached;
}

/** MurmurHash3 (x86, 32-bit), seed 0, as a signed integer: the hash scikit-learn's FeatureHasher uses. */
function murmur3(bytes: Uint8Array): number {
  let h = 0;
  const c1 = 0xcc9e2d51, c2 = 0x1b873593;
  const n = bytes.length, blocks = n >>> 2;
  for (let i = 0; i < blocks; i++) {
    let k = bytes[i * 4] | (bytes[i * 4 + 1] << 8) | (bytes[i * 4 + 2] << 16) | (bytes[i * 4 + 3] << 24);
    k = Math.imul(k, c1); k = (k << 15) | (k >>> 17); k = Math.imul(k, c2);
    h ^= k; h = (h << 13) | (h >>> 19); h = (Math.imul(h, 5) + 0xe6546b64) | 0;
  }
  let k = 0;
  const tail = blocks * 4;
  switch (n & 3) {
    case 3: k ^= bytes[tail + 2] << 16; // falls through
    case 2: k ^= bytes[tail + 1] << 8; // falls through
    case 1: k ^= bytes[tail];
      k = Math.imul(k, c1); k = (k << 15) | (k >>> 17); k = Math.imul(k, c2); h ^= k;
  }
  h ^= n;
  h ^= h >>> 16; h = Math.imul(h, 0x85ebca6b); h ^= h >>> 13; h = Math.imul(h, 0xc2b2ae35); h ^= h >>> 16;
  return h | 0;
}

const enc = new TextEncoder();
function column(token: string, nFeatures: number): number {
  const h = murmur3(enc.encode(token));
  // scikit-learn's own special case: abs() of the most negative int32 does not exist
  return h === -2147483648 ? (2147483647 - (nFeatures - 1)) % nFeatures : Math.abs(h) % nFeatures;
}

/** the characters Python's str.split() and \s treat as whitespace */
const PY_SPACE = "\\t\\n\\v\\f\\r \\x1c-\\x1f\\x85\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000";
const SPACE_RUN = new RegExp(`[${PY_SPACE}]{2,}`, "g");
const SPLIT = new RegExp(`[${PY_SPACE}]+`);
const WORD = /[\p{L}\p{N}_]{2,}/gu;

/** counts -> 1 + ln(count), L2-normalised, dotted with the weights */
function dot(counts: Map<number, number>, b: Block): number {
  let sumSq = 0, acc = 0;
  for (const [i, c] of counts) { const tf = 1 + Math.log(c); sumSq += tf * tf; acc += tf * b.weights[i]; }
  return sumSq ? (acc * b.scale) / Math.sqrt(sumSq) : 0;
}

/** Probability that this text is an injection or jailbreak, 0..1. */
export function classifyText(text: string): number {
  const m = model();
  const doc = Array.from(text.normalize("NFKC")).slice(0, m.maxChars).join("").toLowerCase();

  // word 1-2-grams: maximal runs of two or more word characters
  const words = new Map<number, number>();
  const toks = doc.match(WORD) ?? [];
  const bump = (map: Map<number, number>, t: string) => { const i = column(t, m.nFeatures); map.set(i, (map.get(i) ?? 0) + 1); };
  for (const t of toks) bump(words, t);
  for (let n = 2; n <= Math.min(m.word.ngram[1], toks.length); n++) for (let i = 0; i + n <= toks.length; i++) bump(words, toks.slice(i, i + n).join(" "));

  // character n-grams inside word boundaries: each whitespace-separated word, padded with one space each side
  const chars = new Map<number, number>();
  for (const raw of doc.replace(SPACE_RUN, " ").split(SPLIT)) {
    if (!raw) continue;
    const w = Array.from(` ${raw} `);
    for (let n = m.char.ngram[0]; n <= m.char.ngram[1]; n++) {
      let offset = 0;
      bump(chars, w.slice(0, n).join(""));
      while (offset + n < w.length) { offset++; bump(chars, w.slice(offset, offset + n).join("")); }
      if (offset === 0) break; // a word shorter than n is counted once
    }
  }

  const z = dot(words, m.word) + dot(chars, m.char) + m.bias;
  return 1 / (1 + Math.exp(-z));
}

export function classifierInfo(): { threshold: number; trainedAt: string; maxChars: number } {
  const m = model();
  return { threshold: m.threshold, trainedAt: m.trainedAt, maxChars: m.maxChars };
}

const WINDOW = 3000, STEP = 2400, MAX_WINDOWS = 80;

/**
 * How much the classifier may decide depends on what it is reading, because what it gets wrong depends on
 * that. It is a bag of words: it knows a text is ABOUT instructions to an assistant, not whether the text
 * issues them. Measured on public sets it makes nine mistakes in 7,855 benign texts at its own line and
 * none at 0.9; and it scores a news article that quotes an attack at 0.99.
 *
 *   message   Something addressed to a reader: an email, a chat message, a notification, an event. Reworded
 *             attacks live here, and ordinary messages rarely discuss prompts. A moderate line.
 *   text      Plain text of unknown kind. A strict line.
 *   document  The visible text of a page or a document, where writing about prompts is common. The score is
 *             recorded and decides nothing.
 * Hidden text is judged at the model's own line whatever it sits in: there is no reporting in text nobody
 * is shown.
 */
type Authority = "message" | "text" | "document";
const AUTHORITY: Record<string, Authority> = { email: "message", message: "message", notification: "message", calendar: "message", nearby: "message", html: "document", markdown: "document", javascript: "document", json: "text", text: "text", log: "text", automation: "text", captions: "text" };
// chosen on the development samples (tools/pint, tools/email-eval): at 0.85 the public benign sets give 3
// false alarms in 7,855 texts; at 0.8 the development emails give 1 in 3,000
const VISIBLE_LINE: Record<Authority, number> = { message: 0.8, text: 0.85, document: 2 /* never */ };
const HIDDEN_LINE = 0.9;

/**
 * The same text with what it quotes taken out: quotation marks, block quotes, code. An article that reports
 * an attack reads like one until the quotation is removed; an attack does not sit inside quotation marks.
 * (The rules make the same allowance.) Returns undefined when too little is left to judge.
 */
function withoutQuotations(text: string): string | undefined {
  const stripped = text
    .replace(/```[\s\S]*?```|~~~[\s\S]*?~~~/g, " ")
    .replace(/^\s{0,3}>.*$/gm, " ")
    .replace(/“[^”]{1,800}”|‘[^’]{12,800}’|«[^»]{1,800}»|"[^"\n]{12,800}"/g, " ");
  return stripped.trim().split(/\s+/).length >= 20 ? stripped : undefined;
}

/** the classifier's score for visible text, after the allowance for quotation */
function visibleScore(text: string): number {
  const p = classifyText(text);
  if (p < 0.5) return p;
  const rest = withoutQuotations(text);
  return rest === undefined || rest.length === text.length ? p : Math.min(p, classifyText(rest));
}

export interface ClassifierInput {
  /** the text that would be delivered */
  visible: string;
  /** every segment, so hidden text can be judged piece by piece */
  segments: ReadonlyArray<TextSegment>;
  /** the content kind: sets how much the visible score may decide */
  kind?: string;
}

/**
 * The classifier pass. A finding from here scores between the suspect line and well under the hostile line,
 * so on its own it refuses with an override and never more.
 */
export function scanClassifier(input: ClassifierInput): Finding[] {
  const { threshold, maxChars } = classifierInfo();
  const out: Finding[] = [];
  const authority = AUTHORITY[input.kind ?? "text"] ?? "text";
  const line = VISIBLE_LINE[authority];
  const finding = (p: number, at: number, where: string, hidden: boolean): Finding => ({
    pass: "classifier", kind: "classifier.injection_likely",
    // from just over the suspect line at the threshold to 0.62 at certainty: never hostile alone
    confidence: Math.min(0.95, 0.45 + 0.5 * ((p - at) / Math.max(1e-6, 1 - at)) + (hidden ? 0.1 : 0)), severity: 0.65,
    message: `reads like an injection or jailbreak attempt (learned classifier, ${(p * 100).toFixed(0)}%)${hidden ? ", in text a human would not see" : ""}`,
    location: where, inHidden: hidden || undefined, action: "none",
  });
  /** recorded on the receipt, deciding nothing */
  const note = (p: number, where: string): Finding => ({ pass: "classifier", kind: "classifier.injection_likely", confidence: 0, severity: 0, message: `resembles an injection or jailbreak attempt (learned classifier, ${(p * 100).toFixed(0)}%); not decisive for visible ${authority} text`, location: where, action: "none" });

  const visible = input.visible.trim();
  if (visible.length >= 20) {
    const cps = Array.from(visible);
    let best = visibleScore(cps.slice(0, maxChars).join("")), where = "visible text";
    // the rest of a long text, in overlapping windows
    for (let s = STEP, n = 0; s < cps.length - 200 && n < MAX_WINDOWS && cps.length > maxChars; s += STEP, n++) {
      const p = visibleScore(cps.slice(s, s + WINDOW).join(""));
      if (p > best) { best = p; where = "visible text (past the opening)"; }
    }
    if (best >= line) out.push(finding(best, line, where, false));
    else if (best >= Math.max(threshold, 0.9)) out.push(note(best, where));
  }
  // Hidden text, piece by piece: a hidden passage that reads like an attack is the strongest thing this pass
  // can say. A page has hundreds of hidden pieces (menus, labels, preheaders, descriptions), each a chance to
  // be wrong, so the line is strict and one-line furniture is not judged at all.
  let bestHidden = 0, where = "";
  for (const s of input.segments) {
    if (s.visibility === "visible" || (s.visibility === "attribute" && s.path.endsWith("@alt"))) continue;
    const t = s.text.trim();
    if (t.length < 60 || t.split(/\s+/).length < 9) continue;
    const p = classifyText(t);
    if (p > bestHidden) { bestHidden = p; where = s.path; }
  }
  if (bestHidden >= HIDDEN_LINE) out.push(finding(bestHidden, HIDDEN_LINE, where, true));
  return out;
}
