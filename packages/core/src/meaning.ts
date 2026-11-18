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

import { scanMultilingual } from "./multilingual.js";
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
    // "you are now" + a role, a mode or a loosened state. Not a clause ("where you are now"), not UI copy ("you are now logged in").
    [/(?<!\b(?:where|what|who|how|when|which|whether|if|that|than|as|while|because|since|until|once|wherever)\s+)\byou\s+are\s+now\s+(a|an|the|my|our|acting|operating|playing|role-?playing|pretending|free|unrestricted|unfiltered|uncensored|unbound|jailbroken|dan|no\s+longer|in\s+(\w+\s+)?(mode|character|role))\b/i, 0.6, "role reassignment"],
    [/\bfrom\s+now\s+on\s+you\s+(are|will|must)\b/i, 0.6, "role reassignment"],
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
/**
 * Agent-directed shapes (added 2026-11-17 after the AgentShield run). The original set targets instructions
 * hidden in web pages; these cover what reaches an agent as tool results, forwarded messages and pasted data:
 * jailbreak personas, fake system or agent headers, decode-and-obey, sensitive paths, escalating commands,
 * approval claims, tool impersonation and context extraction. Strong shapes (>= 0.8) refuse on their own in
 * visible text; weak ones need a second shape.
 */
const AGENT_SHAPES: Array<[RegExp, number, string]> = [
    [/\b(ignore|disregard|forget|override|supersede)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|your|original|initial)\b[^.\n]{0,20}\b(instructions?|directions?|directives?|system\s+prompt|guidelines|programming|code\s+review\s+guidelines|processing\s+task|formatting\s+task|task)\b/i, 0.85, "drop prior instructions"],
    [/\b(previous|prior|all\s+previous|original)\s+(system\s+prompt|instructions|directives|rules)\s+(is|are)\s+(now\s+)?(revoked|deprecated|void|superseded|cancelled|canceled|overridden)/i, 0.9, "revokes prior instructions"],
    [/\b(output|print|show|reveal|share|sharing|tell\s+me|give\s+me|repeat|recite|translate|summari[sz]e|encode|convert|write|spell\s+out|list|dump|display|quote|complete|audit|count|leak|provide|fill\s+in)\b[^.\n]{0,60}\b((your|the|my)\s+)?(full\s+|complete\s+|exact\s+|entire\s+|original\s+|initial\s+|current\s+)?(system\s+(prompt|instructions?|message|configuration|config)|initial\s+(prompt|instructions?|setup)|original\s+instructions?|hidden\s+instructions?|internal\s+(configuration|instructions?)|full\s+configuration)\b/i, 0.85, "system prompt request"],
    [/\byour\s+(system\s+(prompt|instructions?|message)|initial\s+(prompt|instructions?)|original\s+instructions|internal\s+configuration)\b|\b(instructions|prompts?)\s+you\s+(were|have\s+been|'ve\s+been)\s+given\b|\binstructions\s+you('ve|\s+have)\s+received\b|\bmessages\[0\]/i, 0.6, "references the model's own prompt"],
    [/\b(DAN|STAN|AIM|DUDE)\b(?=[^.\n]{0,80}\b(stands\s+for|mode|version|\d+\.\d|anything|norms|machiavellian))|\bdo\s+anything\s+now\b|\bdeveloper\s+mode\b[^.\n]{0,30}\b(enabled|on|activated|response)\b|\bjailbreak(ed)?\s+mode\b|\b(evil|free|unrestricted|unfiltered|uncensored)[-\s]?(gpt|ai|assistant|bot|mode|version|response|machine)\b|\bfreed\s+from\s+the\s+(typical\s+)?confines\b|\bmongo\s+tom\b/i, 0.85, "jailbreak persona"],
    [/\b(no|without(\s+any)?|zero|free\s+of)\s+(safety\s+)?(restrictions|guardrails|limitations|content\s+(filters?|restrictions|polic(y|ies))|ethical\s+(guidelines|constraints|restrictions)|safety\s+(filters?|guidelines|measures|guardrails|module))\b|\b(safety|content)\s+(filters?|guidelines|module|measures|classifiers?|mode|checks?)\s+(are\s+|is\s+|have\s+been\s+|has\s+been\s+)?(temporarily\s+)?(disabled|suspended|removed|off|bypassed|corrupted|lifted|deprecated)\b|\b(disable|remove|bypass|turn\s+off|lift)\s+(all\s+)?(your\s+|the\s+)?(safety|content)\s+(filters?|guidelines|measures|classifiers?|restrictions|checks?|module)/i, 0.85, "safety removal"],
    [/\[\s*(system(\s+(message|note|update|override)[^\]]{0,40})?|admin[^\]]{0,30}|override|priority[^\]]{0,40}|critical[^\]]{0,40}|ai\s+process\w*[^\]]{0,40}|hidden\s+instruction[^\]]{0,40}|macro[^\]]{0,40}|injected[^\]]{0,40}|openai-internal[^\]]{0,80}|mcp\s+tool\s+response|tool\s+result[^\]]{0,60}|message\s+from[^\]]{0,60}|automated\s+message[^\]]{0,60}|shared\s+(memory|context|scratchpad)[^\]]{0,40}|sub-agent[^\]]{0,40}|inter-agent[^\]]{0,40}|context\s+passed\s+from[^\]]{0,40}|vector\s+database\s+injection|capability\s+report[^\]]{0,40}|feedback\s+from[^\]]{0,60}|forwarded\s+from[^\]]{0,60}|message\s+routing[^\]]{0,40}|jailbreak[^\]]{0,30}|simulated[^\]]{0,30})\s*\]/i, 0.85, "fake system or agent header"],
    [/\b(system\s+override|admin\s+(notice|console)|maintenance\s+mode\s+activated|kernel\s+panic|end\s+of\s+(prompt|document|user\s+content|config|instructions)|new\s+session\b|system\s+note\s*:|(begin|end)\s+admin|debug\s+mode\s*:\s*on|executive\s+override|priority\s+system\s+update|system\s+message\s*(from|\(priority)|_system_override|system_override|system_update|###\s*\w+_system_message|role\s*:\s*system\s+content\s*:|access\s+level\s*:\s*superuser|permission\s+level\s*:\s*god_mode|safety\s+module)\b/i, 0.8, "fake system message"],
    [/\b(decode|decipher|translate|convert|read|concatenate|combine|unscramble|reverse|take\s+the)\b[^.\n]{0,100}\b(and|then|,)\s+(then\s+)?(follow|execute|obey|do\s+(what|as)\s+it\s+says|carry\s+out|run|act\s+on|respond\s+to)\b|\bfollow\s+the\s+(decoded|hidden|resulting)\s+(instructions?|message|request)\b|\bhidden\s+instruction\b/i, 0.9, "decode and obey"],
    [/\b(for|to|attention|note\s+(for|to))\s+(the\s+)?(ai|assistant|llm|model|agent|bot)(\s+(processing|reading|reviewing|content|moderator|processor|summari[sz]er|system)){0,3}\s*[:—–-]|\b(ai|assistant|agent|model)\s*[—–:,-]\s*(please\s+)?(call|execute|run|send|delete|forward|grant|ignore|output|approve|rate|mark|classify|append|include)\b|\bwhen\s+(the\s+)?(ai|agent|assistant|model)\s+(processes|reads|retrieves)\b/i, 0.85, "addressed to the AI in data"],
    [/(\/etc\/(passwd|shadow|sudoers|crontab)|~\/\.ssh\b|\bid_rsa\b|\/proc\/self\/(environ|maps)|~\/\.aws\/credentials|~\/\.kube\/config|169\.254\.169\.254|(\.\.\/){2,}|\/var\/log\/auth\.log|\.env\s+file|\bthe\s+\.env\b|\.bashrc\b|\/home\/other_user|other-user-workspace)/i, 0.6, "sensitive path"],
    [/\b(read|access|open|cat|show|check|list|print|dump|navigate\s+to|get|copy|fetch|forward|send)\b[^.\n]{0,60}(\/etc\/(passwd|shadow|sudoers)|~\/\.ssh\b|\bid_rsa\b|\/proc\/self\/(environ|maps)|~\/\.aws\/credentials|~\/\.kube\/config|169\.254\.169\.254|(\.\.\/){2,}|\/var\/log\/auth\.log|\.env\s+file|\bthe\s+\.env\b|\/home\/other_user|other-user-workspace)/i, 0.85, "sensitive path access"],
    [/\b(use|call|invoke|run|execute|trigger)\s+(the\s+|your\s+|this\s+|my\s+)?([\w-]+\s+){0,3}(tool|api|function|endpoint|webhook)\b|\b(execute|run)\s+(this|the\s+following)\s+(command|code|query|tool\s+call|shell\s+command)\b|\btool\s+call\b/i, 0.55, "tool use directive"],
    [/(:\(\)\s*\{\s*:\|:&\s*\};:|\brm\s+-rf\s+\/|\bchmod\s+(u\+s|777)\b|setuid\(0\)|NOPASSWD|\bDROP\s+TABLE\b|GRANT\s+ALL\s+PRIVILEGES|\bUNION\s+SELECT\b|bash\s+-i\s+>&\s*\/dev\/tcp|clusterrolebinding[^\n]{0,80}cluster-admin|\$\(\s*cat\b|`whoami`|;\s*cat\s+\/etc|dd\s+if=\/dev\/urandom|npm\s+install\s+-g\s+evil|reverse\s+shell|fork\s+bomb|--no-filter|--unsafe-mode|bypass_sandbox|disable_safety|delete_all_records|admin_override|unrestricted_(read|query))/i, 0.9, "destructive or escalating command"],
    [/\b(pre-?approved|already\s+(been\s+)?approved|no\s+further\s+review|human(-in-the-loop)?\s+(operator|reviewer)\s+(has\s+)?(reviewed|approved)|verified\s+(as\s+)?(an?\s+)?(system\s+)?(admin|administrator|superadmin)|user\s+role\s*:\s*superadmin|elevated\s+(privileges|permissions|access)|grant\s+(me\s+|all\s+|the\s+user\s+)?(admin|root|elevated|full|all)\s+(access|privileges|permissions)|safety_override|"user_role"\s*:\s*"root"|approvals?\s+verified|chain-of-trust|time-boxed\s+auth|executive\s+override|signed\s+off|(previous|other|upstream)\s+agent\s+(has\s+)?approved|approved\s+this\s+action|action\s+was\s+reviewed|(has\s+)?received\s+(the\s+)?(required\s+|all\s+)?approvals?|identity\s+has\s+been\s+verified|\[approved\s+by|sanctioned\s+by\s+your\s+developers|authorized\s+by\s+(the\s+)?(orchestrator|admin|system))/i, 0.8, "approval or privilege claim"],
    [/\b(pretend\s+(you\s+ran|it\s+returned|the\s+tool)|tool\s+(registry|manifest)\s+(has\s+been\s+|was\s+)?updated|new\s+(emergency\s+)?tool\s+(called|'|")|has\s+been\s+deprecated\.?\s+use|provide\s+the\s+tool\s+outputs|use\s+my\s+version\s+instead|intercepted\s+the\s+tool\s+response|skip\s+actually\s+calling|i('m|\s+am)\s+pasting\s+it\s+for\s+you\s+since\s+the\s+tool|new\s+tool\s+manifest|added\s+a\s+new\s+tool)/i, 0.85, "tool impersonation"],
    [/\b(everything\s+(above\s+this|above|before\s+this|you\s+know\s+about\s+the\s+user|the\s+user\s+has\s+told\s+you)|(what\s+was|quote|repeat)\s+the\s+(first|previous)\s+(message|user'?s?\s+question)\b|entire\s+conversation|this\s+conversation\s+so\s+far|(all|last\s+\d+)\s+(the\s+)?conversations|previous\s+conversation|transcript\s+of\s+the\s+(entire\s+)?conversation|data\s+associated\s+with\s+(me|my\s+account|this\s+account)|all\s+user\s+data|from\s+your\s+(context|rlhf|training)|tl;?dr\s+of\s+everything)\b/i, 0.8, "context or history extraction"],
    [/\b(all\s+(available\s+)?environment\s+variables|full\s+error\s+(message|output|trace|response)|complete\s+error\s+(message|response|trace|output)|full\s+(stack\s+)?trace|request\s+headers|authentication\s+tokens?|os\.environ)\b/i, 0.8, "error or environment exfiltration"],
    [/\b(\d[\d,.]*\s*(GB|TB)\s+(file|of\s+memory|array)|\d{1,3}(,\d{3})+\s+(threads|files|queries|requests)|\d+\s+million\s+(queries|files|requests|empty\s+files)|infinite(ly)?\s+(loop|retries|recursion|delegation|retry)|retry\s+count\s+to\s+infinite|while\s*\(\s*true\s*\)|runs\s+every\s+second|calls\s+itself\s+recursively|unlimited\s+(cpu|memory|network))/i, 0.8, "resource exhaustion"],
    [/\b(all\s+(sub-?)?agents|supervisor(\s+agent)?|orchestrator|agent\s+[A-C]|worker\s+agent|admin-agent|code-execution\s+agent|resource-allocation\s+agent)\b[^.\n]{0,80}\b(must|should|please|delegate|bypass|grant|route|crash|add\s+its\s+system\s+prompt|report\s+their)\b/i, 0.8, "multi-agent directive"],
    [/\b(forward|send|post|upload|export|email|cc|bcc)\b[^.\n]{0,80}\b(to\s+my\s+personal|personal\s+(email|gmail|address)|external\s+(address|recipient|server)|analytics\s+(team|server|endpoint)|monitoring\s+webhook)/i, 0.55, "send data out"],
    [/\b(include|add|render|append|insert|generate|create|format)\b[^.\n]{0,80}\b(image|markdown|link|footer|badge|pixel|citation|reference|template)\b[^\n]{0,120}https?:\/\/[^\s)\]]+\?[^\s)\]]*=/i, 0.85, "injected tracking link"],
    [/\b(set|change)\s+the\s+'?from'?\s+field\b|\bX-(Admin-Override|Forwarded-For|Rate-Limit-Bypass)\b|"_admin"\s*:\s*true|_impersonate_user|--include-deleted|Bearer\s+(admin|ADMIN)_?(token|TOKEN)|admin:admin\d*@|-o\s+-name\s+\*\.(key|pem)/i, 0.85, "parameter tampering"],
];
INSTRUCTION_SHAPES.push(...AGENT_SHAPES);
const AGENT_LABELS = new Set(AGENT_SHAPES.map(([, , label]) => label));
/** do two matches cover overlapping spans of the text? */
function overlaps(text: string, a: string, b: string): boolean {
  const ia = text.indexOf(a), ib = text.indexOf(b);
  if (ia < 0 || ib < 0) return false;
  return ia < ib + b.length && ib < ia + a.length;
}

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
      // an agent shape that restates a hit already counted (same words) is the same evidence, not a second shape
      if (AGENT_LABELS.has(label)) {
        const dup = hits.findIndex((h) => h.match.toLowerCase().includes(m[0].toLowerCase()) || m[0].toLowerCase().includes(h.match.toLowerCase()) || overlaps(v.text, h.match, m[0]));
        if (dup >= 0) {
          // same words: keep the stronger reading, count it once
          if (w > hits[dup].weight) hits[dup] = { weight: w, label, match: m[0], variant: v.name, discount: v.discount };
          seenLabels.add(label);
          continue;
        }
      }
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
 * Stricter quote test for the agent shapes: apostrophes inside words ("I'm", "file's") and words like "read"
 * or "like" in a request are not quotation. Payload shapes (commands, paths, parameters) are never discounted:
 * an attack hands its payload over in quotes.
 */
const UNDISCOUNTED = new Set(["destructive or escalating command", "parameter tampering", "sensitive path", "decode and obey", "fake system or agent header", "fake system message", "tool impersonation", "approval or privilege claim"]);
function isQuotedStrict(text: string, match: string, label: string): boolean {
  if (UNDISCOUNTED.has(label)) return false;
  const idx = text.indexOf(match);
  if (idx < 0) return false;
  const before = text.slice(Math.max(0, idx - 160), idx);
  const opens = (before.match(/(^|[\s(\[{:=])["“‘'«]/g) ?? []).length;
  const closes = (before.match(/["”’'»](?=[\s.,;:!?)\]}]|$)/g) ?? []).length;
  if (opens > closes) return true;
  return /\b(said|says|typed|wrote|writes|phrases?\s+(like|such\s+as)|such\s+as|e\.g\.|for\s+example|known\s+as|quoted?)\b[^.\n]{0,80}$/i.test(before);
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
      message: `${roleToken.weight < 0.5 ? "line-start role label (transcript-shaped)" : "chat-template role token"} in content${inCode ? " (inside a code block)" : ""}${tag(roleToken.variant)}`, excerpt: roleToken.match.slice(0, 80), location: where, inHidden: hidden, action: "neutralized",
    });
  }
  if (toolCall) {
    findings.push({
      // visible tool-call text is usually documentation; quoted or attributed, it is talking about one
      pass: "meaning", kind: "meaning.tool_call_shaped", confidence: Math.min(0.95, (0.6 + hiddenBoost) * toolCall.discount * codeFactor * (!hidden && isQuotedOrAttributed(text, toolCall.match) ? 0.55 : 1)), severity: hidden ? 0.8 : 0.6,
      message: `tool-invocation shaped text in content${inCode ? " (inside a code block)" : ""}${tag(toolCall.variant)}`, excerpt: toolCall.match.slice(0, 120), location: where, inHidden: hidden, action: "neutralized",
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
    const quotedFactor = !hidden && (AGENT_LABELS.has(best.label) ? isQuotedStrict(text, best.match, best.label) : isQuotedOrAttributed(text, best.match)) ? 0.55 : 1;
    const conf = Math.min(0.98, (best.weight * visibleFactor + hiddenBoost + Math.min(0.15, (n - 1) * 0.05)) * best.discount * codeFactor * quotedFactor);
    findings.push({
      pass: "meaning", kind: n >= 3 || /system\s+prompt/i.test(best.match) ? "meaning.system_prompt_imitation" : "meaning.instruction_shaped",
      confidence: conf, severity,
      message: `${best.label}${n > 1 ? ` (+${n - 1} more instruction shapes)` : ""}${hidden ? ", in text a human would not see" : ""}${inCode ? " (inside a code block)" : ""}${tag(best.variant)}`,
      excerpt: best.match.slice(0, 120), location: where, inHidden: hidden, action: hidden ? "quarantined" : "neutralized",
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
      excerpt: imgs[0][1].slice(0, 120), location: where, inHidden: hidden, action: "neutralized",
    });
  } else if (hidden && MD_IMAGE_ANY.test(text)) {
    findings.push({ pass: "meaning", kind: "meaning.exfil_markdown_image", confidence: 0.6, severity: 0.7, message: `markdown image reference inside hidden text`, location: where, inHidden: hidden, action: "neutralized" });
  }
  MD_IMAGE_ANY.lastIndex = 0;

  if (links.length || hooks.length) {
    findings.push({
      // a webhook URL in visible prose is documentation more often than exfiltration; hidden or alongside an instruction it is not
      pass: "meaning", kind: "meaning.exfil_link", confidence: (hooks.length ? (hidden || hits.some((h) => h.weight >= 0.8) ? 0.8 : 0.3) : hidden ? 0.6 : 0.3) * codeFactor, severity: 0.8,
      message: hooks.length ? `link to a known collection endpoint (${hooks[0][1]})` : `link with templated query parameters for context exfiltration`,
      excerpt: (hooks[0]?.[0] ?? links[0]?.[1] ?? "").slice(0, 120), location: where, inHidden: hidden, action: "neutralized",
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
  if (visible.trim()) {
    scoreText(visible, false, "visible text", findings);
    // a foreign-language article quoting the phrase is reporting it, the same discount English gets
    for (const f of scanMultilingual(visible, false, "visible text")) findings.push(f.excerpt && isQuotedOrAttributed(visible, f.excerpt) ? { ...f, confidence: f.confidence * 0.55 } : f);
  }
  if (codeBlocks.length) scoreText(codeBlocks.join("\n"), false, "visible code block", findings, true);
  for (const s of input.segments) {
    if (s.visibility === "visible" || (s.visibility === "attribute" && s.path.endsWith("@alt"))) continue;
    // scripts without spaces between words (Japanese, Chinese) are never "too short" by word count
    if (s.text.trim().split(/\s+/).length >= 4) scoreText(s.text, true, s.path, findings);
    if (s.text.trim().length >= 6) findings.push(...scanMultilingual(s.text, true, s.path));
  }
  for (const p of input.decodedPayloads) { scoreText(p, true, "decoded payload", findings); findings.push(...scanMultilingual(p, true, "decoded payload")); }
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
