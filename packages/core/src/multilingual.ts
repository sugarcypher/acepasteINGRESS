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
import { composeHangul, despaceCJK, foldArabicScript, foldIndic, hangulInitials, latinKeysToPersian, stripLatinAccents } from "./normalize.js";

export const MULTILINGUAL_RULESET = "multilingual-seed-v1 (unreviewed)";

interface Rule { id: string; lang: string; kind: "override" | "conceal" | "extract"; re: RegExp; folded?: RegExp; plain?: RegExp; initialsOnly?: boolean }

const R = (id: string, lang: string, kind: Rule["kind"], re: RegExp): Rule => ({ id, lang, kind, re });
/** a rule matched only against the initial-consonant view (초성 shorthand) */
const RI = (id: string, kind: Rule["kind"], re: RegExp): Rule => ({ id, lang: "ko", kind, re, initialsOnly: true });

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
  // added 2026-11-17 (AgentShield misses): word-order and pronoun variants, and system-prompt extraction
  R("override.es2", "es", "override", /\b(?:ignora|olvida|descarta|olvide)\s+(?:todas\s+)?(?:tus|sus|las)\s+instrucciones\s+(?:anteriores|previas)\b/iu),
  R("override.de2", "de", "override", /\b(?:ignorieren|vergessen)\s+sie\s+(?:alle\s+)?(?:vorherigen|bisherigen|früheren)\s+(?:anweisungen|instruktionen)\b/iu),
  R("override.tr2", "tr", "override", /(?:tüm\s+)?önceki\s+(?:tüm\s+)?talimatları\s+(?:unutun|unut|yok\s+sayın|görmezden\s+gelin)/iu),
  R("override.ja2", "ja", "override", /(?:以前|前|これまで)の(?:すべて|全て)の指示を無視/u),
  R("extract.ru", "ru", "extract", /(?:выведи|покажи|раскрой|выведите|покажите)[^.\n]{0,30}(?:системн\S*\s+(?:промпт|подсказк|инструкци))/iu),
  R("extract.fr", "fr", "extract", /\b(?:affiche[rz]?|montre[rz]?|révèle[rz]?)\b[^.\n]{0,30}\b(?:prompt|invite|message)\s+(?:système|systeme)/iu),
  R("extract.ja", "ja", "extract", /システムプロンプト(?:を|全体を)?(?:完全に)?(?:出力|表示|教え)/u),
  R("extract.ko", "ko", "extract", /시스템\s*프롬프트(?:를|을)?\s*(?:출력|보여|공개)/u),
  R("extract.ar", "ar", "extract", /(?:اعرض|أظهر|اكشف)\s+(?:رسالة|تعليمات)\s+النظام/u),
  R("unrestricted.multi", "multi", "override", /(?:sans\s+aucune\s+restriction|sin\s+restricciones|ohne\s+einschränkungen|без\s+ограничений|制限のない|没有任何限制|بدون\s+أي\s+قيود|kısıtlaması\s+olmayan|mode\s+développeur|modo\s+desarrollador|entwicklermodus|وضع\s+المطور)/iu),
  // added 2026-11-18 (0.9.3). Persian, written in the folded view's letters (ی ک, no ZWNJ): it also matches Arabic-keyboard spellings.
  R("override.fa", "fa", "override", /(?:همه\s*(?:ی\s*)?)?(?:دستورالعمل|دستور|دستورات|راهنمایی|آموزه)(?:ها|های)?\s*(?:ی\s*)?(?:قبلی|پیشین|قبل|بالا)\s*(?:را\s*)?(?:نادیده\s*(?:بگیر|بگیرید|گرفته)|فراموش\s*(?:کن|کنید)|کنار\s*(?:بگذار|بگذارید))/u),
  R("conceal.fa", "fa", "conceal", /به\s*کاربر\s*(?:چیزی\s*|هیچ\s*چیز\s*)?(?:نگو|نگویید|اطلاع\s*نده|اطلاع\s*ندهید)/u),
  R("extract.fa", "fa", "extract", /(?:پرامپت|دستور|دستورالعمل|پیام)(?:ها|های)?\s*(?:ی\s*)?سیستم(?:ی)?\s*(?:خود\s*|ات\s*)?(?:را\s*)?(?:نشان\s*(?:بده|دهید)|فاش\s*(?:کن|کنید)|بنویس|چاپ\s*(?:کن|کنید)|بازگو\s*کن)/u),
  // Korean initial-consonant shorthand (초성): 이전 지시 무시 -> ㅇㅈ ㅈㅅ ㅁㅅ; 시스템 프롬프트 -> ㅅㅅㅌ ㅍㄹㅍㅌ
  RI("override.ko.initials", "override", /ㅇㅈ\s*(?:ㅇ\s*)?(?:ㅁㄷ\s*)?(?:ㅈㅅ|ㅈㅊ|ㅁㄹ)(?:ㅅㅎ)?\s*(?:ㄹ|ㅇ)?\s*(?:ㅁㄷ\s*)?ㅁㅅ/u),
  RI("extract.ko.initials", "extract", /ㅅㅅㅌ\s*ㅍㄹㅍㅌ\s*(?:ㄹ|ㅇ)?\s*(?:ㅊㄹ|ㅂㅇ|ㄱㄱ)/u),
  // fake notices in CJK brackets (【システム】, 【系统】, 【시스템】) that go on to give an order. A bracket alone is an
  // ordinary announcement header on Japanese and Chinese sites ("【システム】メンテナンスのお知らせ").
  R("header.cjk", "multi", "override", /[【［〔〖]\s*(?:システム(?:通知|メッセージ)?|管理者|運営|系统(?:通知|消息)?|系統|管理员|管理員|시스템|관리자|운영자)\s*[】］〕〗][^\n]{0,120}?(?:指示|命令|無視|従って|従え|忽略|无视|指令|遵守|服从|무시|지시|따르|따라)/u),

  // ---- added 2026-11-18 (0.9.5). Seed rules, unreviewed by native speakers like the rest. ----
  // Turkish: the word endings that change with case and possession (talimatları / talimatlarını / yönergeleri ...)
  R("override.tr3", "tr", "override", /(?:önceki|daha\s+önceki|yukarıdaki|eski)\s+(?:tüm\s+|bütün\s+)?(?:talimat|yönerge|komut|kural|direktif|yönlendirme)(?:lar|ler)?(?:ı|i|ını|ini|ları|leri|larını|lerini|ın|in)?\s+(?:yok\s+say|görmezden\s+gel|unut|dikkate\s+alma|boş\s*ver|geçersiz\s+say|iptal\s+et|umursama)/iu),
  // the target must be the reader's own prompt, as in English ("your system prompt"): "istemini" is ambiguous between
  // "your" and "its", so this needs senin / kendi or the formal possessive (-inizi). A bare "show the system prompt"
  // in a Turkish chat about prompt writing is a question, and it refused 7 benign chats in the first version.
  R("extract.tr", "tr", "extract", /(?:senin|kendi|sizin)\s+sistem\s+(?:istem|komut|talimat|prompt|mesaj|yönerge)\S*\s+(?:göster|yaz|söyle|paylaş|açıkla|ver|ifşa\s+et|dök)|sistem\s+(?:istem|komut|talimat|prompt|mesaj|yönerge)(?:in|ın|un|ün|ler|lar)?(?:iniz|ınız|unuz|ünüz)(?:i|ı|u|ü)\s+(?:göster|yaz|söyle|paylaş|açıkla|ver|ifşa\s+et|dök)/iu),
  // Dutch, Swedish, Danish/Norwegian, Polish, Romanian, Ukrainian, Czech/Slovak, Serbian, Indonesian/Malay
  R("override.nl", "nl", "override", /\b(?:negeer|vergeet)\s+(?:alle\s+)?(?:vorige|eerdere|voorgaande)\s+(?:instructies|aanwijzingen|opdrachten)\b/iu),
  R("extract.nl", "nl", "extract", /\b(?:toon|geef|laat)\s+(?:me\s+)?(?:je|jouw|de)\s+systeem(?:prompt|instructies)\b/iu),
  R("override.sv", "sv", "override", /\b(?:ignorera|glöm)\s+(?:alla\s+)?(?:tidigare|föregående)\s+(?:instruktioner|anvisningar)\b/iu),
  R("override.da-no", "da", "override", /\b(?:ignorer|glem)\s+(?:alle\s+)?(?:tidligere|forrige|foregående)\s+(?:instruktioner|instruksjoner|instrukser|anvisninger)\b/iu),
  R("override.pl", "pl", "override", /\b(?:zignoruj|ignoruj|zapomnij(?:\s+o)?)\s+(?:wszystkie\s+|wszystkich\s+)?(?:poprzednie|poprzednich|wcześniejsze|wcześniejszych)\s+(?:instrukcje|instrukcjach|polecenia|poleceniach)\b/iu),
  R("override.ro", "ro", "override", /\b(?:ignoră|ignora|uită)\s+(?:toate\s+)?instrucțiunile\s+(?:anterioare|precedente)\b/iu),
  R("override.uk", "uk", "override", /(?:ігноруй(?:те)?|забудь(?:те)?)\s+(?:всі\s+|усі\s+)?попередні\s+(?:інструкції|вказівки)/iu),
  R("override.cs-sk", "cs", "override", /\b(?:ignoruj(?:te)?|zapomeň(?:te)?|zabudni)\s+(?:na\s+)?(?:všechny\s+|všetky\s+)?(?:předchozí|predchádzajúce|predošlé)\s+(?:instrukce|pokyny|inštrukcie)\b/iu),
  R("override.sr", "sr", "override", /\b(?:ignoriši|zaboravi)\s+(?:sve\s+)?prethodne\s+(?:instrukcije|uputstva|naredbe)\b|(?:игнориши|заборави)\s+(?:све\s+)?претходне\s+(?:инструкције|упутства|наредбе)/iu),
  R("override.id", "id", "override", /\b(?:abaikan|lupakan|acuhkan)\s+(?:semua\s+|seluruh\s+)?(?:instruksi|perintah|petunjuk|arahan)\s+(?:sebelumnya|terdahulu|sebelum\s+ini|di\s+atas)\b/iu),
  R("extract.id", "id", "extract", /\b(?:tunjukkan|tampilkan|beritahu|bocorkan)\s+(?:prompt|instruksi|pesan)\s+sistem(?:mu|\s+anda)?\b/iu),
  // Vietnamese, written without accents: it is matched on the accent-stripped view, so "bỏ qua" and "bo qua" both hit
  R("override.vi", "vi", "override", /\b(?:bo\s+qua|lo\s+di|quen\s+(?:di\s+)?|khong\s+can\s+quan\s+tam(?:\s+den)?|ko\s+can\s+quan\s+tam(?:\s+den)?)\s+(?:het\s+|tat\s+ca\s+|moi\s+|toan\s+bo\s+)?(?:cac\s+|nhung\s+)?(?:huong\s+dan|chi\s+dan|chi\s+thi|lenh|yeu\s+cau|quy\s+tac)\s+(?:truoc(?:\s+do|\s+day)?|o\s+tren|ban\s+dau)\b/iu),
  R("extract.vi", "vi", "extract", /\b(?:hien\s+thi|in\s+ra|cho\s+(?:toi|minh)\s+xem|tiet\s+lo)\s+(?:loi\s+nhac|prompt|chi\s+dan|huong\s+dan)\s+(?:he\s+thong|system)\b/iu),
  // Thai has no spaces between words, so no word boundaries here
  R("override.th", "th", "override", /(?:ละเว้น|เพิกเฉย(?:ต่อ)?|ไม่ต้องสนใจ|ลืม|ข้าม)\s*(?:คำสั่ง|คำแนะนำ|ข้อกำหนด)(?:ทั้งหมด)?\s*(?:ที่ผ่านมา|ก่อนหน้า(?:นี้)?|ข้างต้น|เดิม)/u),
  R("extract.th", "th", "extract", /(?:แสดง|บอก|เปิดเผย)\s*(?:พรอมต์|คำสั่ง)\s*(?:ของ)?\s*ระบบ/u),
  // Tagalog, Finnish, Hungarian, Hebrew, Greek
  R("override.tl", "tl", "override", /\b(?:huwag\s+(?:pansinin|sundin|intindihin)|kalimutan|balewalain)\s+(?:ang\s+)?(?:lahat\s+ng\s+)?(?:mga\s+)?(?:naunang|nakaraang|dating)\s+(?:tagubilin|utos|instruksyon|instruksiyon|panuto)\b/iu),
  R("override.fi", "fi", "override", /\b(?:ohita|unohda|sivuuta)\s+(?:kaikki\s+)?(?:aiemmat|edelliset|aikaisemmat)\s+(?:ohjeet|käskyt|ohjeesi)\b/iu),
  R("override.hu", "hu", "override", /\b(?:hagyd\s+figyelmen\s+kívül|felejtsd\s+el|ne\s+vedd\s+figyelembe)\s+(?:az\s+)?(?:összes\s+)?(?:korábbi|előző|eddigi)\s+(?:utasítást|utasításokat|utasítás)\b/iu),
  R("override.he", "he", "override", /(?:התעלם|תתעלם|התעלמו|שכח|תשכח)\s+(?:מ)?(?:כל\s+)?(?:ה)?(?:הוראות|הנחיות)\s+(?:ה)?קודמות/u),
  R("override.el", "el", "override", /(?:αγνόησε|αγνοήστε|ξέχασε|ξεχάστε)\s+(?:όλες\s+)?(?:τις\s+)?προηγούμενες\s+(?:οδηγίες|εντολές)/iu),
  // Hindi: more word orders, and English written in Devanagari (इग्नोर ... इंस्ट्रक्शंस). Matched on the Indic fold, which
  // drops the nukta, so these are written without it.
  R("override.hi2", "hi", "override", /(?:सभी\s*|सारे\s*)?(?:पिछले|पिछली|पहले\s*के|पुराने)\s*(?:सभी\s*|सारे\s*)?(?:निर्देश|निर्देशों|आदेश|आदेशों|इंस्ट्रक्श\S*|इन्स्ट्रक्श\S*)\s*(?:को\s*)?(?:भूल\s*जा\S*|इग्नोर\s*कर\S*|अनदेखा\s*कर\S*|नजरअंदाज\s*कर\S*)/u),
  R("override.hi-translit", "hi", "override", /इग्नोर\s*(?:कर\S*\s*)?(?:ऑल|सभी|सारे|सब)?\s*(?:प्रीवियस|पिछले|पिछली|पहले\s*के|पुराने)\s*(?:इंस्ट्रक्श\S*|इन्स्ट्रक्श\S*|निर्देश\S*|आदेश\S*)/u),
  R("extract.hi", "hi", "extract", /(?:सिस्टम\s*प्रॉम्प्ट|सिस्टम\s*प्रोम्प्ट|सिस्टम\s*निर्देश)\s*(?:को\s*)?(?:दिखाओ|दिखाइए|दिखा\s*दो|बताओ|बताइए|बता\s*दो|लिखो|प्रकट\s*कर\S*)/u),
  // Hinglish (Hindi in Latin letters), both word orders
  R("override.hinglish", "hi-Latn", "override", /\b(?:pichl[ea]|pichhl[ea]|pehl[ea]\s+(?:ke|wale)|purane|upar\s+(?:ke|wale))\s+(?:sab(?:hi)?\s+|saar[ea]\s+)?(?:instructions?|nirdesh|hidayat(?:ein|en)?|rules)\s+(?:ko\s+)?(?:ignore|bhool|bhul|nazarandaz|andekha)\s*(?:karo|kar\s*do|kariye|karein|jao|ja|jaao)\b|\b(?:ignore|bhool|bhul)\s+(?:karo|kar\s*do|jao)\s+(?:sab(?:hi)?\s+|saar[ea]\s+)?(?:pichl[ea]|pichhl[ea]|pehl[ea]\s+ke|purane)\s+(?:instructions?|nirdesh|rules)\b/iu),
  R("extract.hinglish", "hi-Latn", "extract", /\b(?:system\s+prompt|apn[ea]\s+(?:instructions|nirdesh))\s+(?:ko\s+)?(?:dikhao|batao|likho|bata\s+do|dikha\s+do)\b/iu),
  // Finglish (Persian in Latin letters) and Arabizi (Arabic chat-speak with 3 7 5 2 for sounds)
  R("override.finglish", "fa-Latn", "override", /\b(?:dastur|dastoor)(?:at|olamal|ol[ae]mal|ha(?:ye?)?)?\s*(?:e\s*)?(?:ghabli|qabli|ghabl|pishin)\s*(?:ro|ra)?\s*(?:nadide|nadideh|faramush|faramoosh)\s*(?:begir|begirid|kon|konid)\b/iu),
  R("extract.finglish", "fa-Latn", "extract", /\b(?:prompt|payam|dastur(?:at)?)\s*(?:e\s*)?system(?:i)?\s*(?:et|eto|ro|ra)?\s*(?:neshun|neshoon|neshan)\s*(?:bede|bedid|bedin)\b/iu),
  R("override.arabizi", "ar-Latn", "override", /\b(?:t[ae]?[jg]a?h[ae]l|t2[ae]hal|insa|ensa|9arf\s+nazar\s+3n)\s+(?:kol|kul|kel|gami3|jami3)?\s*(?:el|al|l)[- ]?(?:ta3l[ie]?ma?t|t3limat|awamer|2awamer)\s+(?:el|al|l)?[- ]?(?:sab[2']?[ae]?|sab9a|2adeema|qadima|adima|ola)\b/iu),
  // Japanese politeness hides the order ("これまでのご指示はお忘れください"); Korean polite and alternative verbs
  R("override.ja-polite", "ja", "override", /(?:これまで|以前|先ほど|前|上記)の(?:ご)?(?:指示|命令|設定|指図)(?:内容)?(?:は|を)(?:すべて|全て|一旦|いったん)?(?:お忘れ(?:ください|いただ|になって)|ご放念|破棄|取り消|無かったことに|なかったことに|リセット)/u),
  R("extract.ja-polite", "ja", "extract", /(?:システムプロンプト|初期設定|内部の?指示)(?:の内容)?を(?:お教え|ご教示|開示|教えて|表示して)/u),
  R("override.ko2", "ko", "override", /(?:이전|앞선|위의|기존)\s*(?:의\s*)?(?:모든\s*)?(?:지시|지침|명령|설정|규칙)(?:사항)?(?:은|는|을|를)?\s*(?:모두\s*|전부\s*)?(?:잊어|무효|따르지\s*마|폐기|취소)/u),
];

/** JavaScript's \b is ASCII-only even with /u: it never fires beside é, ş, Cyrillic or Thai. A Unicode-aware boundary. */
const UNICODE_BOUNDARY = String.raw`(?:(?<=[\p{L}\p{N}\p{M}_])(?![\p{L}\p{N}\p{M}_])|(?<![\p{L}\p{N}\p{M}_])(?=[\p{L}\p{N}\p{M}_]))`;
const compile = (src: string, flags: string) => new RegExp(src.replace(/\\b/g, UNICODE_BOUNDARY), flags.includes("u") ? flags : flags + "u");
const scriptFold = (s: string) => foldIndic(foldArabicScript(s));
for (const r of MULTILINGUAL_RULES) {
  const src = r.re.source;
  r.re = compile(src, r.re.flags);
  const f = scriptFold(src);
  if (f !== src) r.folded = compile(f, r.re.flags);
  const p = stripLatinAccents(src);
  if (p !== src) r.plain = compile(p, r.re.flags);
}

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
  // matching-only views (0.9.3): script fold (Arabic, and Devanagari since 0.9.5), rejoined CJK spacing, composed Hangul
  const folded = foldIndic(foldArabicScript(nf));
  if (folded !== nf) views.push(["script-fold", folded]);
  // 0.9.5: accents off Latin letters (Vietnamese, Romanian, Turkish typed without them); Turkish casing, where İ
  // lowercases to i and I to ı (JavaScript's /i never folds İ to i); Persian typed on a Latin keyboard layout
  const plain = stripLatinAccents(nf);
  if (plain !== nf) views.push(["no-accents", plain]);
  if (/[İıĞŞ]/.test(nf)) views.push(["turkish-case", nf.toLocaleLowerCase("tr-TR")]);
  if (!/[؀-ۿ]/.test(nf)) {
    const fa = latinKeysToPersian(nf);
    if (fa !== nf) views.push(["persian-keyboard", foldArabicScript(fa)]);
  }
  // compose before NFKC: NFKC turns loose Hangul letters into conjoining initials, which no longer compose
  const composed = composeHangul(despaceCJK(text));
  const joined = composed.normalize("NFKC");
  if (joined !== nf) views.push(["cjk-rejoin", joined]);
  // initials are compatibility letters (ㅇㅈ): taken before NFKC, which would turn them into conjoining jamo
  const initials = /[가-힣ㄱ-ㅎ]/.test(composed) ? hangulInitials(composed) : "";
  const out: Finding[] = [];
  for (const rule of MULTILINGUAL_RULES) {
    for (const [view, t] of rule.initialsOnly ? (initials ? [["hangul-initials", initials] as [string, string]] : []) : views) {
      const re = (view === "script-fold" || view === "persian-keyboard") && rule.folded ? rule.folded : view === "no-accents" && rule.plain ? rule.plain : rule.re;
      const m = t.match(re);
      if (!m) continue;
      // two rules on the same words are one instruction
      if (out.some((f) => f.excerpt && (f.excerpt.includes(m[0].slice(0, 120)) || m[0].includes(f.excerpt)))) break;
      out.push({
        pass: "meaning", kind: rule.kind === "extract" ? "meaning.system_prompt_imitation" : "meaning.instruction_shaped",
        confidence: hidden ? 0.85 : 0.675, severity: hidden ? 0.9 : 0.6,
        message: `${KIND_LABEL[rule.kind]} (${rule.lang}, rule ${rule.id}, ${view} view; ${MULTILINGUAL_RULESET})${hidden ? ", in text a human would not see" : ", visible: same weight as the English shape"}`,
        excerpt: m[0].slice(0, 120), location: where, inHidden: hidden, action: hidden ? "quarantined" : "neutralized",
      });
      break;
    }
  }
  return out;
}
