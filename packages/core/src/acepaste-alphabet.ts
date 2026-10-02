/**
 * The AcePaste invisible-character alphabet — ported verbatim from the
 * production tool (sugarcypher/ACE-ASTE-PRO, AcePasteBrowserExtension/
 * cleaner.js, INVISIBLE_RE and INVISIBLE_SUPPL_RE). This is the authoritative
 * definition of "hostile invisible character" shared by the web tool, the
 * Chrome extension, and this gate, so a verdict here matches what AcePaste
 * itself would strip. Keep it in sync with cleaner.js; do not fork it.
 *
 * Provenance: these ranges are AcePaste's, not Claude's reconstruction.
 * The gate's script-aware exceptions (emoji/Indic/Arabic context for joiners,
 * bidi marks inside right-to-left runs) live in character.ts and are applied
 * on top of this set.
 */

/** Basic-plane hostile invisibles (cleaner.js INVISIBLE_RE). */
export const ACEPASTE_INVISIBLE_SOURCE =
  "[" +
  "\\u00AD" + // SOFT HYPHEN
  "\\u034F" + // COMBINING GRAPHEME JOINER
  "\\u061C" + // ARABIC LETTER MARK
  "\\u115F\\u1160" + // HANGUL FILLERS
  "\\u17B4\\u17B5" + // KHMER INHERENT VOWELS
  "\\u180E" + // MONGOLIAN VOWEL SEPARATOR
  "\\u200B-\\u200F" + // ZERO WIDTH SPACE/NJ/J + LRM/RLM
  "\\u202A-\\u202E" + // BIDI EMBEDDINGS / OVERRIDES (Trojan Source)
  "\\u2060-\\u206F" + // WORD JOINER + general format chars
  "\\u2800" + // BRAILLE PATTERN BLANK (looks like a space)
  "\\u3164" + // HANGUL FILLER
  "\\uFE00-\\uFE0F" + // VARIATION SELECTORS 1-16
  "\\uFEFF" + // ZERO WIDTH NO-BREAK SPACE / BOM
  "\\uFFA0" + // HALFWIDTH HANGUL FILLER
  "]";

/** Supplementary-plane hostile invisibles (cleaner.js INVISIBLE_SUPPL_RE): tag chars + variation selectors supplement. */
export const ACEPASTE_INVISIBLE_SUPPL_SOURCE = "[\\u{E0000}-\\u{E007F}\\u{E0100}-\\u{E01EF}]";

export const acepasteInvisible = () => new RegExp(ACEPASTE_INVISIBLE_SOURCE, "g");
export const acepasteInvisibleSuppl = () => new RegExp(ACEPASTE_INVISIBLE_SUPPL_SOURCE, "gu");

/**
 * Count hostile invisibles the way the AcePaste extension's page scanner does
 * (scanner.js countHostile): the sum of matches of both sets. The gate uses
 * this only for the receipt's parity note; its own findings come from the
 * script-aware passes in character.ts.
 */
export function countHostileInvisibles(str: string): number {
  if (!str) return 0;
  const a = str.match(acepasteInvisible());
  const b = str.match(acepasteInvisibleSuppl());
  return (a ? a.length : 0) + (b ? b.length : 0);
}
