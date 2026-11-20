/**
 * Comparing two copies of "the same" content by their words: the page served to an AI fetcher and to a
 * browser, an email's plain part and its HTML part, a video's captions and its speech.
 * The question is always whether one reader was told something the other was not.
 */

/** words of served text with markup, link targets and bare URLs removed, so Markdown and HTML of the same page compare equal */
export function servedWords(text: string): string[] {
  const t = text
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g, " $1 ")          // [label](target) and ![alt](src) -> label
    .replace(/<\/?[a-z][^>]*>/gi, " ")                         // stray tags
    .replace(/\b(?:https?:\/\/|www\.)\S+/gi, " ")            // bare URLs
    .replace(/[#>*_`~|\-]{1,}/g, " ");                         // markdown syntax
  return t.toLowerCase().split(/[^\p{L}\p{N}']+/u).filter((w) => w.length > 2);
}

/** how much of what the agent received is absent from what the browser received (word occurrences, not distinct words) */
export function compareServed(agentText: string, humanText: string): { agentWords: number; agentOnlyWords: number; agentOnlyShare: number; longestAgentOnlyRun: number; sample: string } {
  const A = servedWords(agentText);
  const H = new Set(servedWords(humanText));
  const only = A.filter((w) => !H.has(w));
  let run = 0, longestAgentOnlyRun = 0;
  for (const w of A) { run = H.has(w) ? 0 : run + 1; if (run > longestAgentOnlyRun) longestAgentOnlyRun = run; }
  const sampleSeen = new Set<string>();
  const sample = only.filter((w) => (sampleSeen.has(w) ? false : (sampleSeen.add(w), true))).slice(0, 30).join(" ");
  return { agentWords: A.length, agentOnlyWords: only.length, agentOnlyShare: A.length ? only.length / A.length : 0, longestAgentOnlyRun, sample };
}

/**
 * A page that stands in for the page: a bot challenge, a block or rate-limit notice, an error page, a "turn on
 * JavaScript" stub. Sites hand these to anything that does not look like a browser. Recognised by being short
 * and saying what such pages say; no site is named here.
 */
const INTERSTITIAL = new RegExp([
  String.raw`\bcaptcha\b`,
  String.raw`\b(?:are you|you are|you're|i am|i'm) (?:a |not a )?(?:human|robot)\b`,
  String.raw`\bnot a robot\b`,
  String.raw`\bverif(?:y|ying|ication)\b[^.]{0,40}\bhuman\b`,
  String.raw`\b(?:made|sent) by a human\b`,
  String.raw`\bcomplete (?:the|this) (?:following )?(?:challenge|puzzle)\b`,
  String.raw`\bsecurity (?:check|challenge)\b`,
  String.raw`\bchecking (?:your|the) browser\b`,
  String.raw`\bjust a moment\b`,
  String.raw`\bunusual (?:traffic|activity)\b`,
  String.raw`\bautomated (?:queries|requests|access|traffic)\b`,
  String.raw`\bbots? (?:use|detected|detection)\b`,
  String.raw`\baccess (?:is |has been |to this (?:page|site) (?:is |has been ))?(?:denied|forbidden|restricted|blocked)\b`,
  String.raw`\b(?:you have|you've) been blocked\b`,
  String.raw`\brequest (?:was |has been )?blocked\b`,
  String.raw`\btoo many requests\b`,
  String.raw`\brate limit(?:ed)?\b`,
  String.raw`\btry again later\b`,
  String.raw`\b(?:temporarily|currently) unavailable\b`,
  String.raw`\b(?:page|site) (?:not found|can(?:'|no)t be (?:found|reached))\b`,
  String.raw`\bsomething went wrong\b`,
  String.raw`\ban error (?:has )?occurred\b`,
  String.raw`\b(?:enable|requires?|turn on) (?:javascript|cookies)\b`,
  String.raw`\bjavascript is (?:required|disabled|not enabled)\b`,
].join("|"), "i");
/** a page with more words than this is content, whatever it says about robots */
export const INTERSTITIAL_MAX_WORDS = 150;

export function looksLikeInterstitial(text: string): boolean {
  return servedWords(text).length <= INTERSTITIAL_MAX_WORDS && INTERSTITIAL.test(text.replace(/\s+/g, " "));
}

/**
 * The passages of `text` that `reference` does not contain: runs of at least `minRun` words in a row that
 * appear nowhere in the reference. Returned as the original text of each run, for scanning.
 */
export function passagesOnlyIn(text: string, reference: string, minRun = 8): string[] {
  const H = new Set(servedWords(reference));
  const out: string[] = [];
  // walk the original text sentence by sentence so the passages read as written
  for (const sentence of text.split(/(?<=[.!?])\s+|\n{2,}/)) {
    const words = servedWords(sentence);
    if (words.length < minRun) continue;
    let run = 0, longest = 0;
    for (const w of words) { run = H.has(w) ? 0 : run + 1; if (run > longest) longest = run; }
    const missing = words.filter((w) => !H.has(w)).length;
    if (longest >= minRun || (missing >= minRun && missing / words.length >= 0.7)) out.push(sentence.trim());
  }
  return out;
}
