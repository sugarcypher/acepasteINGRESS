/**
 * Meaning pass.
 *
 * Pattern-based detection of instruction-shaped and exfiltration-shaped
 * text. This is the weakest pass by design: attackers evade classifiers.
 * Its job is to catch commodity payloads in the forms they ship (also
 * spaced, leet, reversed, rot13, homoglyph-spelled: see normalize.ts),
 * and to score hidden text harder than visible text. Hidden instruction-
 * shaped text is nearly always an attack; visible instruction-shaped text
 * may be an article, a support macro, or a runbook, so one visible shape
 * stays below the suspect threshold and two or more cross it. Text inside
 * code blocks is documentation by default and is discounted.
 *
 * Known gap (2026-10-01): patterns are English. Non-English instructions
 * reach the model unless they are hidden (visibility pass) or encoded
 * (character pass). Multilingual coverage needs native-speaker review and
 * is tracked as an open item, not shipped as Claude-generated translations.
 */

import type { Finding, TextSegment } from "./types.js";
import { variants } from "./normalize.js";

export interface MeaningInput {
  /** segments from the visibility pass (or a single visible segment for plain text) */
  segments: TextSegment[];
  /** payloads decoded by the character pass */
  decodedPayloads: readonly string[];
}

const ROLE_TOKENS = [
    /<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>|<\|system\|>|<\|user\|>|<\|assistant\|>|<\|end\|>/i,
    /\[INST\]|\[\/INST\]|<<SYS>>|<\/?s>\s*\[INST\]/,
    /<\|start_header_id\|>|<\|eot_id\|>|<\|begin_of_text\|>|<\|eom_id\|>/,
    /<start_of_turn>|<end_of_turn>|<bos>|<eos>/,
    /<\|user\|>|<\|assistant\|>|<\|system\|>|<\|end\|>/,
    /<\/?(system|instructions?|system_prompt|developer|tool_result|function_results|function_calls|invoke|antml:[a-z_]+|tool_call|tool_response|thinking)>/i,
    /\{\{#(system|user|assistant)\}\}|<\|start\|>(system|developer|user)/i,
];
/** Line-start role labels: transcripts, screenplays and chat exports look like this too, so these are weak evidence on their own */
const WEAK_ROLE_LABELS = [
    /^\s*(###\s*)?(system|assistant|user|developer|human|tool)\s*:\s*/im,
    /\n\n(Human|Assistant|System):\s/,
];
/** JSON or XML shaped tool invocations in content: an attempt to get an agent to echo a call */
const TOOL_CALL_SHAPES = [
    /\{\s*"(tool_calls?|function_call|name)"\s*:\s*"?[\w.-]+"?\s*,\s*"(arguments|parameters|input)"\s*:/i,
    /<(function_calls|tool_call|invoke)\b[^>]*>[\s\S]{0,400}<\/(function_calls|tool_call|invoke)>/i,
    // same line only: "run:" followed by a code block on the next line is documentation layout, not an invocation
    /\b(run|execute|call)[ \t]*:[ \t]*`?(bash|sh|python|node|curl|wget|rm -rf|chmod|ssh)\b/i,
];
const INSTRUCTION_SHAPES: Array<[RegExp, number, string]> = [
    [/\bignore\s+(all\s+|any\s+)?(previous|prior|above|earlier|preceding)\s+(instructions?|prompts?|directions?|rules?|context)/i, 0.9, "ignore previous instructions"],
    [/\bdisregard\s+(all\s+|any\s+)?(previous|prior|above|your)\s+(instructions?|prompts?|rules?|guidelines?)/i, 0.9, "disregard instructions"],
    [/\b(you\s+are\s+now|from\s+now\s+on\s+you\s+(are|will|must))\b/i, 0.6, "role reassignment"],
    [/\bnew\s+(instructions?|task|directive|system\s+prompt)\s*:/i, 0.7, "new instructions directive"],
    [/\b(do\s+not|don'?t|never)\s+(tell|inform|reveal|mention|show|disclose)\s+(this\s+to\s+)?(the\s+)?(user|human|operator)/i, 0.95, "conceal from user"],
    [/\b(ai|assistant|language\s+model|llm|agent|chatbot|copilot|claude|gpt|gemini)\b[^.\n]{0,60}\b(must|should|need\s+to|is\s+required\s+to|has\s+to)\b/i, 0.55, "addressed to the model"],
    [/\b(important|attention|note)\s+(to|for)\s+(the\s+)?(ai|assistant|agent|llm|model|bot)s?\b/i, 0.85, "addressed to the model"],
    [/\b(if\s+you\s+are\s+an?\s+(ai|llm|language\s+model|assistant|agent|bot))\b/i, 0.9, "conditional on being a model"],
    [/\b(print|output|repeat|reveal|show|leak|exfiltrate|send)\s+(me\s+)?(your|the)\s+(system\s+prompt|instructions|initial\s+prompt|hidden\s+prompt|context|conversation|api\s+key|credentials?|secrets?|tokens?)/i, 0.9, "prompt or secret extraction"],
    [/\b(call|invoke|use|run|execute)\s+(the\s+)?(tool|function|command)\s+[`'"]?\w+/i, 0.5, "tool invocation request"],
    [/\b(send|post|email|forward|upload|transmit)\s+[^.\n]{0,80}\b(to|at)\s+(https?:\/\/|[\w.-]+@[\w.-]+\.\w+)/i, 0.65, "outbound send instruction"],
    [/\b(send|post|email|forward|upload|transmit|paste|include|attach)\s+(me\s+)?(your|the|this|all|every|our)\s+[^.\n]{0,30}\b(conversation|context|chat\s+history|message\s+history|messages|system\s+prompt|instructions|credentials?|secrets?|api\s+keys?|tokens?|cookies?|session|memory)\b/i, 0.9, "context exfiltration"],
    [/\b(summar(y|ize)|respond|reply|answer)\s+(with|by\s+saying)\s*[:"']/i, 0.35, "forced response shape"],
    [/\bend\s+of\s+(system|user|developer)\s+(message|prompt|instructions)/i, 0.8, "fake message boundary"],
    [/\b(override|bypass|disable|turn\s+off)\s+(your\s+|all\s+|the\s+)?(safety|content|security)?\s*(filters?|guidelines?|restrictions?|guardrails?|rules?|policies)/i, 0.85, "guardrail override"],
    [/\b(developer|debug|maintenance|admin|god)\s+mode\b/i, 0.55, "privileged-mode claim"],
    [/\b(this\s+is\s+(a|an)\s+)?(authorized|official|verified|trusted)\s+(instruction|request|message|command)\s+from\s+(the\s+)?(system|developer|administrator|anthropic|openai|google)/i, 0.9, "authority impersonation"],
    [/\bwhen\s+(you|the\s+(assistant|agent|model))\s+(read|see|process|encounter)s?\s+this\b/i, 0.7, "trigger-on-read"],
    [/\b(remember|store|save|note)\s+(this|the\s+following)\s+(for|in)\s+(future|later|all\s+future)\s+(conversations?|sessions?|interactions?)/i, 0.7, "memory poisoning"],
    [/\b(always|from\s+now\s+on|whenever|every\s+time|when\s+(the\s+)?(topic|subject|question)\b[^.\n]{0,30})\b[^.\n]{0,60}\b(recommend|suggest|promote|mention|prefer|rate|push|steer|favor|favour|endorse)\b[^.\n]{0,80}\b(product|site|service|brand|company|link|url|plan|offer)/i, 0.8, "persistent bias injection"],
    [/\b(state|stating|recite|quote|echo|dump|disclose|share|expose|read\s+out|spell\s+out|list|append|attach|include|insert|embed)\s+[^.\n]{0,30}\b(system\s+prompt|hidden\s+prompt|initial\s+prompt|your\s+instructions|hidden\s+instructions|configuration|chat\s+history|conversation|credentials?|secrets?|api\s+keys?|tokens?)\b/i, 0.85, "prompt or secret extraction"],
    [/\b(from\s+now\s+on|for\s+(every|each|all)\s+(future\s+)?(requests?|messages?|responses?|replies|answers?|inputs?|queries)|in\s+(all|every)\s+(future\s+)?(responses?|replies|answers?)|whenever\s+[^.\n]{0,40}|new\s+task\s*:)\b(?![^.\n]{0,12}\b(i|we|my|our|i'll|we'll)\b)[^.\n]{0,80}\b(respond|reply|answer|output|say|state|include|append|promote|prefer|recommend|return|print|begin|start|end|finish|only)\b/i, 0.8, "behavior binding"],
];
const MD_IMAGE_EXFIL = /!\[[^\]]*\]\((https?:\/\/[^)\s]+\?[^)\s]{24,})\)/gi;
const MD_IMAGE_ANY = /!\[[^\]]*\]\((https?:\/\/[^)\s]+)\)/gi;
const EXFIL_LINK = /\b(https?:\/\/[^\s)"'<>]+\?[^\s)"'<>]*(?:=\{|%7B|\{\{|\$\{|\[(?:secret|key|token|context|conversation|summary)\]))/gi;
const WEBHOOK_HOSTS = /https?:\/\/[^\s/"')]*?(webhook\.site|requestbin|pipedream\.net|ngrok(-free)?\.(app|io)|burpcollaborator|oastify\.com|interact\.sh|canarytokens\.com|hooks\.slack\.com|discord(app)?\.com\/api\/webhooks)/gi;

const FENCED = /```[\s\S]*?```|~~~[\s\S]*?~~~|<pre\b[\s\S]*?<\/pre>|<code\b[\s\S]*?<\/code>|`[^`\n]{2,200}`/gi;

interface ShapeHit { weight: number; label: string; match: string; variant: string; discount: number }

function matchShapes(text: string): { hits: ShapeHit[]; roleToken?: ShapeHit; toolCall?: ShapeHit } {
  const hits: ShapeHit[] = [];
  let roleToken: ShapeHit | undefined;
  let toolCall: ShapeHit | undefined;
  const seenLabels = new Set<string>();
  for (const v of variants(text)) {
    if (!roleToken) for (const re of ROLE_TOKENS) { const m = v.text.match(re); if (m) { roleToken = { weight: 0.7, label: "role token", match: m[0], variant: v.name, discount: v.discount }; break; } }
    if (!roleToken && v.name === "original") for (const re of WEAK_ROLE_LABELS) { const m = v.text.match(re); if (m) { roleToken = { weight: 0.25, label: "role label", match: m[0], variant: v.name, discount: v.discount }; break; } }
    if (!toolCall) for (const re of TOOL_CALL_SHAPES) { const m = v.text.match(re); if (m) { toolCall = { weight: 0.6, label: "tool call", match: m[0], variant: v.name, discount: v.discount }; break; } }
    for (const [re, w, label] of INSTRUCTION_SHAPES) {
      if (seenLabels.has(label)) continue;
      const m = v.text.match(re);
      if (!m) continue;
      seenLabels.add(label);
      hits.push({ weight: w, label, match: m[0], variant: v.name, discount: v.discount });
    }
  }
  return { hits, roleToken, toolCall };
}

/** Is this match inside quotation marks, or in a sentence that attributes it to someone ("said", "typed", "the phrase")? */
function isQuotedOrAttributed(text: string, match: string): boolean {
  const idx = text.indexOf(match);
  if (idx < 0) return false;
  const before = text.slice(Math.max(0, idx - 160), idx);
  const after = text.slice(idx + match.length, idx + match.length + 40);
  const openQuotes = (before.match(/["“‘'«]/g) ?? []).length;
  const closeQuotes = (before.match(/["”’'»]/g) ?? []).length;
  if (openQuotes > closeQuotes || /["“”'»«]/.test(after.slice(0, 3))) return true;
  return /\b(said|says|typed|wrote|writes|reads?|phrase|phrases|example|examples|such\s+as|e\.g\.|known\s+as|called|like|quote|quoted|message\s+read|prompt\s+read|text\s+read|lines?\s+like|attacks?\s+(look|read)|payloads?\s+(like|such))\b[^.\n]{0,80}$/i.test(before) || /^\s*[,:]?\s*(he|she|they|the\s+\w+)\s+(said|typed|wrote)/i.test(after);
}

/**
 * Score one piece of text.
 *   hidden      a human would not see it: full weight
 *   visible     one shape alone stays under the suspect line; two or more cross it
 *   inCode      inside a fenced/pre/code block: documentation discount
 */
function scoreText(text: string, hidden: boolean, where: string, findings: Finding[], inCode = false) {
  const hiddenBoost = hidden ? 0.25 : 0;
  const codeFactor = inCode ? 0.4 : 1;
  const tag = (v: string) => (v === "original" ? "" : ` (after ${v} normalization)`);
  const { hits, roleToken, toolCall } = matchShapes(text);

  if (roleToken) {
    findings.push({
      pass: "meaning", kind: "meaning.role_token", confidence: Math.min(0.98, (roleToken.weight + hiddenBoost) * roleToken.discount * codeFactor), severity: 0.85,
      message: `${roleToken.weight < 0.5 ? "line-start role label (transcript-shaped)" : "chat-template role token"} in content${inCode ? " (inside a code block)" : ""}${tag(roleToken.variant)}`, excerpt: roleToken.match.slice(0, 80), location: where, action: "neutralized",
    });
  }
  if (toolCall) {
    findings.push({
      pass: "meaning", kind: "meaning.tool_call_shaped", confidence: Math.min(0.95, (0.6 + hiddenBoost) * toolCall.discount * codeFactor), severity: 0.8,
      message: `tool-invocation shaped text in content${inCode ? " (inside a code block)" : ""}${tag(toolCall.variant)}`, excerpt: toolCall.match.slice(0, 120), location: where, action: "neutralized",
    });
  }
  const links = [...text.matchAll(EXFIL_LINK)];
  const hooks = [...text.matchAll(WEBHOOK_HOSTS)];
  // "send X to <url>" in visible prose with only that one shape is the same evidence as the link finding below; count it once
  const onlySendToLink = !hidden && hits.length === 1 && hits[0].label === "outbound send instruction" && (links.length > 0 || hooks.length > 0);
  if (hits.length && !onlySendToLink) {
    const best = hits.reduce((a, b) => (b.weight > a.weight ? b : a));
    const n = hits.length;
    // hidden: full weight. visible: a strong shape (>= 0.8: ignore-previous, conceal-from-user, extraction, authority,
    // guardrail override, addressed-to-model) refuses on its own; weak shapes need company.
    const strong = best.weight >= 0.8;
    const visibleFactor = hidden ? 1 : n >= 2 || strong ? 0.75 : 0.55;
    const severity = hidden ? 0.9 : n >= 2 || strong ? 0.6 : 0.45;
    // visible text that quotes or attributes an instruction (news, fiction, training material) is not issuing it
    const quotedFactor = !hidden && isQuotedOrAttributed(text, best.match) ? 0.55 : 1;
    const conf = Math.min(0.98, (best.weight * visibleFactor + hiddenBoost + Math.min(0.15, (n - 1) * 0.05)) * best.discount * codeFactor * quotedFactor);
    findings.push({
      pass: "meaning", kind: n >= 3 || /system\s+prompt/i.test(best.match) ? "meaning.system_prompt_imitation" : "meaning.instruction_shaped",
      confidence: conf, severity,
      message: `${best.label}${n > 1 ? ` (+${n - 1} more instruction shapes)` : ""}${hidden ? ", in text a human would not see" : ""}${inCode ? " (inside a code block)" : ""}${tag(best.variant)}`,
      excerpt: best.match.slice(0, 120), location: where, action: hidden ? "quarantined" : "neutralized",
    });
  }

  const imgs = [...text.matchAll(MD_IMAGE_EXFIL)];
  if (imgs.length) {
    // a tracking pixel has a few short named params; an exfiltration carries one long encoded value or a template marker
    const q = imgs[0][1].split("?")[1] ?? "";
    const longValue = q.split("&").some((kv) => (kv.split("=")[1] ?? "").length >= 40);
    const templated = /\{|%7B|\[|\$/.test(q);
    const strongImg = hidden || longValue || templated;
    findings.push({
      pass: "meaning", kind: "meaning.exfil_markdown_image", confidence: (strongImg ? 0.85 : 0.25) * codeFactor, severity: 0.9,
      message: `markdown image whose URL carries ${imgs[0][1].split("?")[1].length} bytes of query data (EchoLeak pattern)`,
      excerpt: imgs[0][1].slice(0, 120), location: where, action: "neutralized",
    });
  } else if (hidden && MD_IMAGE_ANY.test(text)) {
    findings.push({ pass: "meaning", kind: "meaning.exfil_markdown_image", confidence: 0.6, severity: 0.7, message: `markdown image reference inside hidden text`, location: where, action: "neutralized" });
  }
  MD_IMAGE_ANY.lastIndex = 0;

  if (links.length || hooks.length) {
    findings.push({
      // a webhook URL in visible prose is documentation more often than exfiltration; hidden or alongside an instruction it is not
      pass: "meaning", kind: "meaning.exfil_link", confidence: (hooks.length ? (hidden || hits.some((h) => h.weight >= 0.8) ? 0.8 : 0.3) : hidden ? 0.6 : 0.3) * codeFactor, severity: 0.8,
      message: hooks.length ? `link to a known collection endpoint (${hooks[0][1]})` : `link with templated query parameters for context exfiltration`,
      excerpt: (hooks[0]?.[0] ?? links[0]?.[1] ?? "").slice(0, 120), location: where, action: "neutralized",
    });
  }
}

export function scanMeaning(input: MeaningInput): Finding[] {
  const findings: Finding[] = [];
  // score what the model would actually receive as one unit: visible text plus delivered alt text, so a payload split across them recombines here
  const visibleRaw = input.segments.filter((s) => s.visibility === "visible" || (s.visibility === "attribute" && s.path.endsWith("@alt"))).map((s) => s.text).join("\n");
  // code blocks are scored separately with the documentation discount
  const codeBlocks = visibleRaw.match(FENCED) ?? [];
  const visible = visibleRaw.replace(FENCED, " ");
  if (visible.trim()) scoreText(visible, false, "visible text", findings);
  if (codeBlocks.length) scoreText(codeBlocks.join("\n"), false, "visible code block", findings, true);
  for (const s of input.segments) {
    if (s.visibility === "visible" || (s.visibility === "attribute" && s.path.endsWith("@alt"))) continue;
    if (s.text.trim().split(/\s+/).length < 4) continue;
    scoreText(s.text, true, s.path, findings);
  }
  for (const p of input.decodedPayloads) scoreText(p, true, "decoded payload", findings);
  return findings;
}

/** Remove the matched role tokens and exfiltration constructs from delivered text (override delivery). */
export function neutralizeMeaning(text: string): string {
  let out = text;
  for (const re of ROLE_TOKENS) out = out.replace(new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g"), "[removed: role token]");
  out = out.replace(MD_IMAGE_EXFIL, "[removed: image with data-bearing URL]");
  out = out.replace(WEBHOOK_HOSTS, "[removed: collection endpoint]");
  return out;
}
