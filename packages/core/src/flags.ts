/**
 * Subdivision flag emoji (England, Scotland, Wales) are the one legitimate use of Unicode tag characters in text:
 * U+1F3F4 WAVING BLACK FLAG, then tag letters spelling the region code, then U+E007F CANCEL TAG. Unicode's RGI
 * emoji list (emoji-test.txt) has exactly three of them: gbeng, gbsct and gbwls.
 * Only those exact sequences are accepted (HIB v1, 2026-11-28: 48 of 49 false positives were these flags).
 * Everything else stays hostile: a tag run with no flag, a flag followed by more tags, a run that starts like a
 * flag but spells anything other than those three codes (a tag payload pretending to be a flag), a run without the
 * cancel tag, and the deprecated U+E0001 LANGUAGE TAG.
 */
export const RGI_SUBDIVISION_FLAG_SOURCE = "\\u{1F3F4}\\u{E0067}\\u{E0062}(?:\\u{E0065}\\u{E006E}\\u{E0067}|\\u{E0073}\\u{E0063}\\u{E0074}|\\u{E0077}\\u{E006C}\\u{E0073})\\u{E007F}";
const FLAG_OR_TAG = new RegExp(`${RGI_SUBDIVISION_FLAG_SOURCE}|[\\u{E0000}-\\u{E007F}]`, "gu");

/** Is this exact string one RGI subdivision flag? */
export function isRgiSubdivisionFlag(s: string): boolean {
  return new RegExp(`^${RGI_SUBDIVISION_FLAG_SOURCE}$`, "u").test(s);
}

/** Replace every tag character that is not part of an RGI subdivision flag; the flags themselves are kept intact. */
export function replaceStrayTags(text: string, by: (tag: string, index: number) => string = () => ""): string {
  return text.replace(FLAG_OR_TAG, (m, index: number) => (m.length > 2 ? m : by(m, index)));
}

/** The tag characters that are not part of an RGI subdivision flag, with their UTF-16 offsets. */
export function strayTags(text: string): Array<{ ch: string; index: number }> {
  const out: Array<{ ch: string; index: number }> = [];
  for (const m of text.matchAll(FLAG_OR_TAG)) if (m[0].length <= 2) out.push({ ch: m[0], index: m.index! });
  return out;
}

/** How many RGI subdivision flags the text holds. */
export function countRgiSubdivisionFlags(text: string): number {
  let n = 0;
  for (const m of text.matchAll(FLAG_OR_TAG)) if (m[0].length > 2) n++;
  return n;
}
