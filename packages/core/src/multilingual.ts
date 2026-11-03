/**
 * Multilingual instruction pass (seed ruleset).
 *
 * Narrow on purpose: the instruction shapes that matter most (drop prior instructions,
 * hide something from the user, reveal the system prompt) in eleven languages besides
 * English, matched on the original text and on an NFKC-normalized copy (full-width and
 * compatibility forms fold; the original is never altered or delivered changed).
 *
 * Weighting follows the 2026-10-01 boundary: in VISIBLE text a foreign-language
 * instruction is recorded but does not refuse the page on its own (the model resists
 * visible instructions in any language, and foreign-language pages would false-alarm);
 * in HIDDEN text or decoded payloads it carries full weight, because there the model
 * cannot see the attack.
 *
 * Status: written by Claude as a seed, not yet reviewed by native speakers. The rule
 * set id says so on every finding. Paraphrases, transliteration and most languages are
 * not covered; the coverage line on each finding states what ran.
 */

import type { Finding } from "./types.js";

export const MULTILINGUAL_RULESET = "multilingual-seed-v1 (unreviewed)";

interface Rule { id: string; lang: string; kind: "override" | "conceal" | "extract"; re: RegExp }

const R = (id: string, lang: string, kind: Rule["kind"], re: RegExp): Rule => ({ id, lang, kind, re });

export const MULTILINGUAL_RULES: Rule[] = [
  // Spanish
  R("override.es", "es", "override", /\b(?:ignora|ignore|olvida|olvide|descarta)\s+(?:todas\s+)?las\s+instrucciones\s+(?:anteriores|previas)\b/iu),
  R("conceal.es", "es", "conceal", /\bno\s+(?:le\s+)?(?:digas|diga|menciones|mencione|reveles)\s+(?:nada\s+)?al\s+usuario\b/iu),
  // Portuguese
  R("override.pt", "pt", "override", /\b(?:ignore|ignora|esqueça|esqueca|desconsidere)\s+(?:todas\s+)?as\s+instruções\s+(?:anteriores|prévias|previas)\b/iu),
  R("conceal.pt", "pt", "conceal", /\bnão\s+(?:conte|diga|mencione|revele)\s+(?:nada\s+)?ao\s+usuário\b/iu),
  // French
  R("override.fr", "fr", "override", /\b(?:ignore[rz]?|oublie[rz]?)\s+(?:toutes\s+)?les\s+instructions\s+(?:précédentes|antérieures)\b/iu),
  R("conceal.fr", "fr", "conceal", /\bne\s+(?:le\s+)?(?:dis|dites|mentionne[sz]?|révèle[sz]?)\s+(?:rien\s+|pas\s+)?(?:cela\s+)?à\s+l['’]utilisateur\b/iu),
  // German
  R("override.de", "de", "override", /\b(?:ignorier(?:e|en)?|vergiss|vergessen\s+sie)\s+(?:alle\s+)?(?:vorherigen|bisherigen|früheren|vorangegangenen)\s+(?:anweisungen|instruktionen)\b/iu),
  R("conceal.de", "de", "conceal", /\b(?:sag|sage|sagen\s+sie)\s+dem\s+(?:benutzer|nutzer|anwender)\s+nichts\b/iu),
  // Italian
  R("override.it", "it", "override", /\b(?:ignora|ignorate|dimentica|dimenticate)\s+(?:tutte\s+)?le\s+istruzioni\s+(?:precedenti|anteriori)\b/iu),
  R("conceal.it", "it", "conceal", /\bnon\s+dire\s+(?:nulla\s+|niente\s+)?all['’]utente\b/iu),
  // Russian
  R("override.ru", "ru", "override", /(?:игнорируй(?:те)?|забудь(?:те)?)\s+(?:все\s+)?(?:предыдущие|прошлые|прежние)\s+(?:инструкции|указания)/iu),
  R("conceal.ru", "ru", "conceal", /не\s+(?:говори(?:те)?|сообщай(?:те)?)\s+пользователю/iu),
  // Turkish
  R("override.tr", "tr", "override", /önceki\s+(?:tüm\s+)?talimatları\s+(?:yok\s+say|görmezden\s+gel|unut)/iu),
  // Arabic
  R("override.ar", "ar", "override", /(?:تجاهل|انس[َى]?)\s+(?:جميع\s+|كل\s+)?التعليمات\s+السابقة/u),
  R("conceal.ar", "ar", "conceal", /لا\s+تخبر\s+المستخدم/u),
  // Japanese
  R("override.ja", "ja", "override", /(?:以前|前|これまで|先ほど)の指示を(?:すべて|全て)?無視/u),
  R("conceal.ja", "ja", "conceal", /ユーザー(?:に|には)(?:言わ|伝え|知らせ|教え)ないで/u),
  // Chinese (simplified and traditional)
  R("override.zh", "zh", "override", /(?:忽略|无视|無視|忘记|忘記)(?:之前|以前|先前|上述|上面)?(?:的)?(?:所有|全部)?(?:之前|先前)?(?:的)?(?:指令|指示|说明|說明)/u),
  R("conceal.zh", "zh", "conceal", /不要(?:告诉|告訴)(?:用户|用戶|使用者)/u),
  R("extract.zh", "zh", "extract", /(?:输出|輸出|显示|顯示|透露)(?:你的)?(?:系统|系統)(?:提示|提示词|提示詞)/u),
  // Korean
  R("override.ko", "ko", "override", /이전\s*(?:의\s*)?(?:모든\s*)?(?:지시|지침|명령)(?:사항)?(?:을|를)?\s*(?:모두\s*)?무시/u),
  // Hindi
  R("override.hi", "hi", "override", /पिछले\s+(?:सभी\s+)?निर्देशों\s+को\s+(?:अनदेखा|नज़रअंदाज़|नजरअंदाज)\s+कर/u),
];

const KIND_LABEL: Record<Rule["kind"], string> = {
  override: "instruction to drop prior instructions",
  conceal: "instruction to hide something from the user",
  extract: "instruction to reveal the system prompt",
};

/**
 * Scan one piece of text. `hidden` = a human reading the page would not see it (or it was
 * decoded from an encoding). Returns at most one finding per rule.
 */
export function scanMultilingual(text: string, hidden: boolean, where: string): Finding[] {
  if (!text || text.length > 2_000_000) return [];
  const views: Array<[string, string]> = [["original", text]];
  const nf = text.normalize("NFKC");
  if (nf !== text) views.push(["nfkc", nf]);
  const out: Finding[] = [];
  for (const rule of MULTILINGUAL_RULES) {
    for (const [view, t] of views) {
      const m = t.match(rule.re);
      if (!m) continue;
      out.push({
        pass: "meaning", kind: rule.kind === "extract" ? "meaning.system_prompt_imitation" : "meaning.instruction_shaped",
        confidence: hidden ? 0.85 : 0.2, severity: hidden ? 0.9 : 0.45,
        message: `${KIND_LABEL[rule.kind]} (${rule.lang}, rule ${rule.id}, ${view} view; ${MULTILINGUAL_RULESET})${hidden ? ", in text a human would not see" : ", visible: recorded, not refused on its own"}`,
        excerpt: m[0].slice(0, 120), location: where, inHidden: hidden, action: hidden ? "quarantined" : "none",
      });
      break;
    }
  }
  return out;
}
