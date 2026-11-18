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
    // "show the context" (git-scm: diff context lines), "print the tokens" (every tokenizer tutorial) and "show the
    // instructions" are documentation; the generic nouns count only as the reader's own: "your context", "your tokens"
    [/\b(print|output|repeat|reveal|show|leak|exfiltrate|send)\s+(me\s+)?(your\s+(system\s+prompt|instructions|initial\s+prompt|hidden\s+prompt|context|conversation|api\s+keys?|credentials?|secrets?|tokens?)|the\s+(system\s+prompt|initial\s+prompt|hidden\s+prompt|api\s+keys?|secret\s+keys?))/i, 0.9, "prompt or secret extraction"],
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
 * Imperative position: the start of a line or sentence, after a colon, semicolon or comma ("Using the text above,
 * convince the reader ..."), after "please", "now", "then",
 * "and", "also", "instead", or after "you must / should / need to", "make sure to", "can you". The agent shapes
 * that name a topic (environment variables, stack traces, .env files, conversations) only count there:
 * "Print all environment variables and include them in your reply" is an instruction, "the server returns the
 * full stack trace" is a description, and documentation is mostly description.
 */
const IMPERATIVE = String.raw`(?:^|[.!?:;,]\s*|\b(?:please|now|then|and|also|kindly|instead|first|finally|just)\s+|\byou\s+(?:must|should|will|need\s+to|have\s+to)\s+|\b(?:make|be)\s+sure\s+to\s+|\bremember\s+to\s+|\b(?:can|could|would|will)\s+you\s+)`;
const imp = (body: RegExp, flags = "im") => new RegExp(IMPERATIVE + "(?:" + body.source + ")", flags);

/**
 * Agent-directed shapes (added 2026-11-17 after the AgentShield run; precision pass 2026-11-18). The original set
 * targets instructions hidden in web pages; these cover what reaches an agent as tool results, forwarded messages
 * and pasted data: jailbreak personas, fake system or agent headers, decode-and-obey, sensitive paths, escalating
 * commands, approval claims, tool impersonation and context extraction. Strong shapes (>= 0.8) refuse on their own
 * in visible text; weak ones need a second shape.
 *
 * Precision rule (2026-11-18): a strong shape must be an instruction or a claim of authority, never the name of a
 * topic. The first version refused docs.python.org (os, "Developer Mode is enabled"), MDN's X-Forwarded-For page,
 * the dotenv README, Wikipedia's Kernel panic article, the sudoers man page and 23 of 27 everyday developer
 * sentences. Topic words now either sit behind IMPERATIVE or count as weak evidence.
 */
const AGENT_SHAPES: Array<[RegExp, number, string]> = [
    [/\b(ignore|disregard|forget|override|supersede)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|your|original|initial)\b[^.\n]{0,20}\b(instructions?|directions?|directives?|system\s+prompt|guidelines|programming|code\s+review\s+guidelines|processing\s+task|formatting\s+task|task)\b/i, 0.85, "drop prior instructions"],
    [/\b(previous|prior|all\s+previous|original)\s+(system\s+prompt|instructions|directives|rules)\s+(is|are)\s+(now\s+)?(revoked|deprecated|void|superseded|cancelled|canceled|overridden)/i, 0.9, "revokes prior instructions"],
    // "system configuration", "write your system prompt" (prompting guides) and "list the initial setup" are documentation
    [imp(/(output|print|show|reveal|share|tell\s+me|give\s+me|repeat|recite|translate|summari[sz]e|encode|convert|spell\s+out|dump|display|quote|leak|paste)\b[^.\n]{0,60}\b((your|the|my)\s+)?(full\s+|complete\s+|exact\s+|entire\s+|original\s+|initial\s+|current\s+|hidden\s+)?(system\s+(prompt|instructions?)|initial\s+(prompt|instructions?)|original\s+instructions?|hidden\s+instructions?|internal\s+instructions?)\b/), 0.85, "system prompt request"],
    [/\byour\s+(system\s+(prompt|instructions?|message)|initial\s+(prompt|instructions?)|original\s+instructions|internal\s+configuration)\b|\b(instructions|prompts?)\s+you\s+(were|have\s+been|'ve\s+been)\s+given\b|\binstructions\s+you('ve|\s+have)\s+received\b|\bmessages\[0\]/i, 0.6, "references the model's own prompt"],
    // the persona acronyms are names only in capitals: "aim" and "dan" are ordinary words (docs.python.org matched "aim ... version")
    [/\b(DAN|STAN|AIM|DUDE)\b(?=[^.\n]{0,80}\b([Ss]tands\s+for|[Mm]ode|[Vv]ersion|\d+\.\d|[Aa]nything|[Nn]orms|[Mm]achiavellian))/, 0.85, "jailbreak persona"],
    // "Developer Mode is enabled" is a Windows setting the os docs need for symlinks; "free version" is pricing
    [/\bdo\s+anything\s+now\b|\bdeveloper\s+mode\s+(output|response)s?\b|\b(enable|activate|enter)\s+developer\s+mode\b[^.\n]{0,60}\b(you|your|chatgpt|gpt|ai|assistant|model|claude)\b|\bjailbreak(ed)?\s+mode\b|\b(evil|unrestricted|unfiltered|uncensored)[-\s]?(gpt|ai|assistant|bot|chatbot|response|machine|version\s+of\s+(you|yourself))\b|\bfreed\s+from\s+the\s+(typical\s+)?confines\b|\bmongo\s+tom\b/i, 0.85, "jailbreak persona"],
    // "no restrictions" alone is ordinary prose (the Python tutorial); the safety, ethical or content qualifier is the tell
    [/\b(no|without(\s+any)?|zero|free\s+of)\s+(safety|ethical|content|moral)\s+(restrictions|guardrails|limitations|filters?|guidelines|constraints|polic(y|ies)|measures)\b|(?<!\b(?:if|as\s+long\s+as|so\s+long\s+as|when|whenever|unless|provided|assuming|while|because|since|once|where|that)\s+)\byou\s+(now\s+)?(have|operate\s+with|are\s+under|are\s+bound\s+by)\s+no\s+(restrictions|limitations|limits|rules|guidelines|filters|guardrails)\b(?!\s+(on|in|over|about|for|regarding|around|with|to|as|preventing|stopping|blocking|against)\b)|\b(safety|content)\s+(filters?|guidelines|guardrails|module|classifiers?)\s+(are|is|have\s+been|has\s+been)\s+(now\s+)?(temporarily\s+)?(disabled|suspended|removed|bypassed|corrupted|lifted|deprecated)\b|\b(disable|remove|bypass|turn\s+off|lift|ignore)\s+(all\s+(of\s+)?)?your\s+(safety|content|ethical)\s+(filters?|guidelines|measures|classifiers?|restrictions|checks?|module|guardrails)/i, 0.85, "safety removal"],
    // bracketed headers that claim a speaker or an authority. Log levels ([CRITICAL]), forum ranks ([Admin]), chat exports
    // ([Forwarded from Alice]) and issue labels ([Priority: high]) name no authority over the agent.
    [/\[\s*(system\s+(message|note|update|override|instruction|alert|prompt)[^\]]{0,40}|admin\s+(override|instruction|message|notice)[^\]]{0,30}|override|priority\s+(override|instruction|system)[^\]]{0,30}|critical\s+(system|override|instruction)[^\]]{0,30}|ai\s+process\w*[^\]]{0,40}|hidden\s+instruction[^\]]{0,40}|injected[^\]]{0,40}|openai-internal[^\]]{0,80}|mcp\s+tool\s+response|tool\s+result[^\]]{0,60}|(message|forwarded|feedback)\s+from\s+(the\s+)?(system|admin|administrator|orchestrator|supervisor|agent|developer|anthropic|openai)[^\]]{0,40}|automated\s+message\s+from[^\]]{0,60}|shared\s+(memory|context|scratchpad)[^\]]{0,40}|sub-agent[^\]]{0,40}|inter-agent[^\]]{0,40}|context\s+passed\s+from[^\]]{0,40}|vector\s+database\s+injection|capability\s+report[^\]]{0,40}|message\s+routing[^\]]{0,40}|jailbreak[^\]]{0,30})\s*\]/i, 0.85, "fake system or agent header"],
    [/\[\s*(SYSTEM|ADMIN|OVERRIDE|SYSTEM\s+OVERRIDE)\s*\]/, 0.85, "fake system or agent header"],
    // "kernel panic", "new session", "end of document", "debug mode: on", "admin console" and "safety module" are product vocabulary
    [/\b(system\s+override|end\s+of\s+(system\s+prompt|prompt|user\s+content|instructions)|system\s+note\s*:|(begin|end)\s+admin\s+(block|message|instructions?)|executive\s+override|priority\s+system\s+update|system\s+message\s*(from|\(priority)|_?system_override|###\s*\w+_system_message|role\s*:\s*system\s+content\s*:|access\s+level\s*:\s*superuser|permission\s+level\s*:\s*god_mode)\b/i, 0.8, "fake system message"],
    // decoding must be followed by obeying the result: "read the guide, then run npm start" is a README, not an attack
    [/\b(decode|decipher|unscramble|deobfuscate|reverse|concatenate)\b[^.\n]{0,100}\b(and|then|,)\s+(then\s+)?(follow|execute|obey|carry\s+out|act\s+on)\s+(it|them|that|this|its\s+instructions|what\s+it\s+says|the\s+(result|results|instructions?|message|request|output|command|decoded\s+\w+))\b|\b(and|then)\s+do\s+(what|as)\s+it\s+says\b|\bfollow\s+the\s+(decoded|hidden|resulting)\s+(instructions?|message|request)\b/i, 0.9, "decode and obey"],
    [/\b(note|message|attention|instructions?)\s+(for|to)\s+(the\s+|any\s+)?(ai|assistant|llm|model|agent|bot)(\s+(processing|reading|reviewing|content|moderator|processor|summari[sz]er|system)){0,3}\s*[:—–-]|\b(ai|assistant|agent|model)\s*[—–:,]\s*(please\s+)?(call|execute|run|send|delete|forward|grant|ignore|output|approve|rate|mark|classify|append|include)\b/i, 0.85, "addressed to the AI in data"],
    // RAG documentation says "when the model reads the file, it ..." all the time; "when the AI reads this" is the trigger form
    [/\bwhen\s+(the\s+)?(ai|agent|assistant|model)\s+(processes|reads|retrieves)\s+this\b/i, 0.7, "addressed to the AI in data"],
    // relative imports (../../lib) and .env setup steps are everywhere in READMEs; traversal counts only toward system directories
    [/(\/etc\/(passwd|shadow|sudoers)|~\/\.ssh\/|\bid_(rsa|ed25519)\b|\/proc\/self\/(environ|maps)|~\/\.aws\/credentials|~\/\.kube\/config|169\.254\.169\.254|(\.\.\/){2,}(etc|root|proc|home|Users|var)\b|\/var\/log\/auth\.log|\/home\/other_user|other-user-workspace|-o\s+-name\s+\*\.(key|pem))/i, 0.6, "sensitive path"],
    [imp(/(read|access|open|cat|show|print|dump|navigate\s+to|get|copy|fetch|forward|send|upload|exfiltrate|paste)\b[^.\n]{0,60}(\/etc\/(passwd|shadow|sudoers)|~\/\.ssh\b|\bid_(rsa|ed25519)\b|\/proc\/self\/(environ|maps)|~\/\.aws\/credentials|~\/\.kube\/config|169\.254\.169\.254|(\.\.\/){2,}(etc|root|proc|home|Users|var)\b|\/var\/log\/auth\.log|\/home\/other_user|other-user-workspace)/), 0.85, "sensitive path access"],
    [imp(/(print|output|show|send|forward|paste|reveal|share|dump|upload|post)\s+(me\s+)?(the\s+|your\s+)?(contents?\s+of\s+(the\s+|your\s+)?)?\.env\b[^.\n]{0,40}\b(to|in|into|here|reply|response|chat)\b/), 0.85, "sensitive path access"],
    [/\b(use|call|invoke|run|execute|trigger)\s+(the\s+|your\s+|this\s+|my\s+)?([\w-]+\s+){0,3}(tool|api|function|endpoint|webhook)\b|\b(execute|run)\s+(this|the\s+following)\s+(command|code|query|tool\s+call|shell\s+command)\b|\btool\s+call\b/i, 0.55, "tool use directive"],
    // payloads that only an attack hands over; the commands below them are what tutorials, man pages and migrations show
    [/(bash\s+-i\s+>&\s*\/dev\/tcp|>>\s*\/etc\/sudoers|npm\s+install\s+-g\s+evil|bypass_sandbox|disable_safety|delete_all_records|admin_override|unrestricted_(read|query)|--unsafe-mode)/i, 0.9, "destructive or escalating command"],
    [/(:\(\)\s*\{\s*:\|:&\s*\};:|\brm\s+-rf\s+\/(\s|$|\*)|\bchmod\s+(u\+s|777)\b|setuid\(0\)|NOPASSWD|\bDROP\s+TABLE\b|GRANT\s+ALL\s+PRIVILEGES|\bUNION\s+SELECT\b|clusterrolebinding[^\n]{0,80}cluster-admin|\$\(\s*cat\b|`whoami`|;\s*cat\s+\/etc|dd\s+if=\/dev\/urandom|\breverse\s+shell\b|\bfork\s+bomb\b|--no-filter)/i, 0.55, "risky command"],
    // claims that review already happened. "Signed off", "elevated privileges", "received the required approvals" are process words.
    [/\b(pre-?approved\s+(by|for\s+this|action|request|change)|already\s+(been\s+)?approved\b[^.\n]{0,40}\b(no\s+(need|further)|skip|proceed|without)|no\s+further\s+(review|approval|confirmation)\s+(is\s+)?(needed|required|necessary)|human(-in-the-loop)?\s+(operator|reviewer)\s+(has\s+)?(already\s+)?(reviewed|approved)|verified\s+as\s+(an?\s+)?(system\s+)?(admin|administrator|superadmin)|user\s+role\s*:\s*superadmin|safety_override|"user_role"\s*:\s*"root"|executive\s+override|(previous|other|upstream|supervisor)\s+agent\s+(has\s+)?(already\s+)?approved|\[approved\s+by|sanctioned\s+by\s+your\s+developers|authorized\s+by\s+(the\s+)?(orchestrator|supervisor\s+agent|system\s+administrator))/i, 0.8, "approval or privilege claim"],
    [/\b(elevated\s+(privileges|permissions|access)|grant\s+(me\s+|all\s+|the\s+user\s+)?(admin|root|elevated|full)\s+(access|privileges|permissions)|approved\s+this\s+action|identity\s+has\s+been\s+verified|pre-?approved)\b/i, 0.45, "privilege mention"],
    // "has been deprecated. Use v2" is every API changelog; "added a new tool" is every release note
    [/\b(pretend\s+(that\s+)?(you\s+ran|it\s+returned|the\s+tool)|tool\s+(registry|manifest)\s+(has\s+been\s+|was\s+)updated|new\s+(emergency\s+)?tool\s+called\s+['"`]?[\w-]+['"`]?\s+(that|which|now|with)|provide\s+the\s+tool\s+outputs?\s+yourself|intercepted\s+the\s+tool\s+response|skip\s+actually\s+calling|i('m|\s+am)\s+pasting\s+it\s+for\s+you\s+since\s+the\s+tool)/i, 0.85, "tool impersonation"],
    // "you can export the entire conversation" and "all user data is encrypted" describe a product
    [imp(/(repeat|print|output|show|reveal|summari[sz]e|list|dump|share|send|quote|tell\s+me|give\s+me|forward|export|paste|write\s+out|recite)\b[^.\n]{0,40}\b(everything\s+(above\s+this|above|before\s+this|you\s+know\s+about\s+the\s+user|the\s+user\s+(has\s+)?told\s+you)|the\s+(first|previous)\s+(message|user'?s?\s+question)|(the\s+)?entire\s+conversation|this\s+conversation\s+so\s+far|(all|the\s+last\s+\d+|last\s+\d+)\s+(of\s+the\s+)?conversations|(the\s+)?previous\s+conversations?|(a\s+|the\s+)?transcript\s+of\s+(the\s+|this\s+)?(entire\s+)?conversation|all\s+user\s+data|what\s+(the\s+user|i)\s+(said|told\s+you)|tl;?dr\s+of\s+everything)/), 0.8, "context or history extraction"],
    [/\bwhat\s+was\s+the\s+(first|previous)\s+(message|user'?s?\s+question)\b/i, 0.8, "context or history extraction"],
    // asking for secrets to be put into the answer is the attack; "print all environment variables with env" is a tutorial
    [imp(/(print|output|show|reveal|dump|list|return|send|include|paste|give\s+me|tell\s+me|echo)\b[^.\n]{0,40}\b(all\s+(of\s+)?(the\s+)?(available\s+)?environment\s+variables|(the\s+)?(full|complete)\s+(error\s+(message|output|trace|response)|stack\s+trace)|(the\s+|your\s+|all\s+)?request\s+headers|(the\s+|your\s+|all\s+)?authentication\s+tokens?|os\.environ)\b[^.\n]{0,60}\b(in|into|to)\s+(your|the|this)\s+(reply|response|answer|output|message|chat|summary)/), 0.85, "error or environment exfiltration"],
    [imp(/(print|output|reveal|dump|send|paste|give\s+me|tell\s+me)\b[^.\n]{0,30}\b(all\s+(of\s+)?(the\s+)?(available\s+)?environment\s+variables|os\.environ|authentication\s+tokens?)/), 0.55, "environment request"],
    // "an infinite loop will hang the tab" and "1,000,000 requests a day" are descriptions; creating them on request is the shape
    [imp(/(create|generate|write|allocate|spawn|start|open|send|make|retry|loop|run|call|fill)\b[^.\n]{0,40}(\b\d[\d,.]*\s*(GB|TB)\s+(file|of\s+memory|array)|\b\d{1,3}(,\d{3}){2,}\s+(threads|files|queries|requests|processes)|\b\d+\s+(million|billion)\s+(queries|files|requests|empty\s+files|threads)|\binfinite(ly)?\s+(loop|retries|recursion|delegation)|\bunlimited\s+(cpu|memory|network))/), 0.55, "resource exhaustion"],
    [/\b(set\s+(the\s+)?retry\s+count\s+to\s+infinit[ey]|delegate\s+(this|the\s+task)\s+(back\s+to\s+yourself\s+)?infinitely|call\s+yourself\s+recursively)\b/i, 0.8, "resource exhaustion"],
    // "the orchestrator must restart failed containers" is Kubernetes; an attack tells agents to drop their guard or leak
    [/\b(all\s+(sub-?)?agents|supervisor(\s+agent)?|orchestrator|agent\s+[A-C]\b|worker\s+agents?|admin-agent|code-execution\s+agent|resource-allocation\s+agent)\b[^.\n]{0,80}\b(must\s+(now\s+)?(ignore|bypass|disable|grant|forward|send|share|reveal|skip)|should\s+(now\s+)?(ignore|bypass|disable|grant|forward|reveal|skip)|bypass|add\s+its\s+system\s+prompt|report\s+their\s+(system\s+prompts?|instructions|credentials|api\s+keys?))\b/i, 0.8, "multi-agent directive"],
    [/\b(forward|send|post|upload|export|email|cc|bcc)\b[^.\n]{0,80}\b(to\s+my\s+personal|personal\s+(email|gmail|address)|external\s+(address|recipient|server)|analytics\s+(team|server|endpoint)|monitoring\s+webhook)/i, 0.55, "send data out"],
    // a query parameter that carries data back (=SUMMARY, ={...}, =[context]); a shields.io ?style=flat badge carries nothing
    [/\b(include|add|render|append|insert|generate|create|format)\b[^.\n]{0,80}\b(image|markdown|link|footer|badge|pixel|citation|reference|template)\b[^\n]{0,120}https?:\/\/[^\s)\]]+\?[^\s)\]]*=(\{|\[|%7B|<|\$|(SUMMARY|DATA|CONTEXT|CONVERSATION|HISTORY|SECRET|TOKEN|KEY|PROMPT|CHAT|EMAIL|PASSWORD|USER)\b)/i, 0.85, "injected tracking link"],
    // X-Forwarded-For is a standard header (MDN has a page on it); "set the from field" is every email API's quick start
    [/\bX-(Admin-Override|Rate-Limit-Bypass)\b|"_admin"\s*:\s*true|_impersonate_user|Bearer\s+(admin|ADMIN)_?(token|TOKEN)\b/i, 0.85, "parameter tampering"],

    // InjectBench (Kong, Virginia Tech 2024) attack goals that the shapes above did not reach. In that benchmark the
    // availability and link-coercion attacks succeeded against 35-73% of models, and the summary separator evaded an
    // injection classifier 64% of the time, because none of them says "ignore previous instructions".
    [imp(/(state|say|tell\s+(the\s+)?(user|reader|visitor|customer)s?|claim|respond|reply|report|pretend|explain|inform\s+(the\s+)?(user|reader)s?|insist)\b(?:[^.\n]|\.(?=\S)){0,100}?\b(no\s+longer\s+(available|accessible|exists?)|(is|are|was|has\s+been|have\s+been)\s+(unavailable|inaccessible|unreadable|deleted|removed|taken\s+down|restricted|blocked|corrupted|not\s+available)|(cannot|can\s*not|can't)\s+be\s+(summari[sz]ed|accessed|read|displayed|shown|retrieved|loaded|opened)|(could\s+not|couldn't|failed\s+to)\s+(be\s+)?(load(ed)?|open(ed)?|access(ed)?|retrieved?|display(ed)?|read|fetch(ed)?)\b|(is|was|has\s+been|have\s+been)\s+(retracted|withdrawn|pulled|discontinued)\b|no\s+longer\s+(considered\s+)?(reliable|valid|accurate|trustworthy)|error\s+code\s*\d{2,4})/), 0.8, "false availability claim"],
    // sending the reader elsewhere for the "real" content, and the softer nudges that need a second shape
    [imp(/(tell|say|state|claim|inform|explain\s+to)\s+(the\s+)?(user|reader|visitor|customer)s?\b(?:[^.\n]|\.(?=\S)){0,80}?\b(only|exclusively)\s+(be\s+)?(available|accessible|found|viewable|downloadable)\s+(at|on|from|via)\s+\S+\.\S+/), 0.8, "redirect claim"],
    [imp(/(encourage|entice|lure|nudge|tempt)\s+(the\s+)?(user|reader|visitor|customer|them|readers|users|people)\s+to\s+(click|visit|go\s+to|open|download|install|sign\s+up|log\s+in)\b/), 0.55, "link nudge"],
    [imp(/(subtly|quietly|casually|naturally|discreetly)\s+(introduce|insert|mention|slip\s+in|drop\s+in|work\s+in|add)\s+(a|the|this|an)\s+(link|url|website|site)\b/), 0.55, "covert link"],
    [/\bthey\s+must\s+(log\s+in|sign\s+in|enter\s+their\s+(password|credentials|card))\s+(there|at|on|via)\b/i, 0.55, "credential lure"],
    // conversation data appended to a URL, and actions the reader is told to hide from the user
    [imp(/(append|add|attach|encode|include|put|insert|send|pass)\b[^.\n]{0,60}\b(the\s+user'?s?|your|all|previous|prior|earlier)\s+(?:[^.\n]|\.(?=\S)){0,30}?\b(messages|conversation|chat\s+history|questions|inputs|prompts|context)\b(?:[^.\n]|\.(?=\S)){0,60}?\b(to|into|in)\s+(this|the|that|a)\s+(url|link|address|endpoint|query|image)/), 0.9, "context exfiltration via link"],
    [imp(/(quietly|silently|secretly|covertly)\s+(append|add|send|include|insert|forward|post|upload|delete|change|run|execute|call|attach|share)\b/), 0.8, "covert action"],
    // a dot followed by a non-space (goodlink.com) does not end the sentence
    [imp(/(convince|persuade|coerce|pressure|urge|trick|manipulate)\s+(the\s+)?(user|reader|visitor|customer|people|them|readers|users|me|us)\b(?:[^.\n]|\.(?=\S)){0,160}?\b(click|visit|go\s+to|open|follow|download|install|sign\s+up|log\s+in|enter\s+(their|your))\b|use\s+social[-\s]engineering\b/), 0.85, "link coercion"],
    [imp(/(summari[sz]e|describe|present|portray|rewrite|report|frame|characteri[sz]e|depict)\b[^.\n]{0,60}\b(incorrectly|falsely|inaccurately|misleadingly|dishonestly|as\s+(unsafe|dangerous|harmful|toxic|poisonous|fake|fraudulent|a\s+scam|illegal|false|misleading|recalled|discredited|unreliable))\b|(make|add|include|spread|insert|invent|fabricate|mention)\s+(up\s+)?(some\s+)?(false|fake|fabricated|misleading|untrue|made-up)\s+(claims?|rumou?rs?|information|statements?|details|facts|quotes?|reviews?|allegations?)|(omit|leave\s+out|hide|suppress|drop)\s+(the\s+|any\s+|all\s+)?(important|key|critical|main|essential)\s+(details|information|facts|points|findings)|discredit\s+(the\s+)?(source|author|text|article|site|page|website|writer|company|brand|recipe|product)|claim\s+(that\s+)?(this|the)\s+(recipe|product|article|page|text|site|website|company|item|study|author|report|brand)\b[^.\n]{0,60}\b(is|was|has|contains|causes|caused)\b|(change|alter|reverse|twist|distort)\s+the\s+(meaning|narrative|conclusion|message|facts)\s+of\s+the\s+(text|article|page|summary|story)/), 0.85, "narrative manipulation"],
    [/\bhere\s+is\s+(the|a|my)\s+summary\s+of\s+(the\s+)?(above|text|article|page|content|document)\b[\s\S]{0,600}?\bnow,?\s+(fulfill|complete|do|perform|carry\s+out|execute|follow)\s+the\s+following\s+(task|instruction|request)s?/i, 0.9, "task-completion separator"],
    [/\bin\s+addition\s+to\s+the\s+(previous|above|original|prior)\s+task,?\s+(complete|perform|do|carry\s+out)\s+the\s+following\b|\bignore\s+and\s+spell\s+check\s+instead\b|\b(only|instead)\s+focus\s+on\s+the\s+following\s+(prompt|instruction|task)s?\b|\bstrictly\s+adhere\s+to\s+the\s+following\s+instructions?\b/i, 0.85, "task-switch separator"],
    // "Now complete the following tasks" is every exercise sheet, so the bare form is weak
    [/\bnow,?\s+(fulfill|perform|carry\s+out|execute)\s+the\s+following\s+(task|instruction)s?\b/i, 0.55, "task switch"],
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
/** characters between two shapes for one to corroborate the other */
const CORROBORATION_WINDOW = 600;

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
    // corroboration is local: on a long page delivered as one segment, two weak shapes paragraphs apart are two
    // topics, not one instruction (docs.python.org/3/library/os.html: "Developer Mode" and a tool mention, 2026-11-18)
    const at = (h: ShapeHit) => text.indexOf(h.match);
    const near = (h: ShapeHit) => h === best || at(h) < 0 || at(best) < 0 || Math.abs(at(h) - at(best)) <= CORROBORATION_WINDOW;
    const n = hits.filter(near).length;
    // hidden: full weight. visible: a strong shape (>= 0.8: ignore-previous, conceal-from-user, extraction, authority,
    // guardrail override, addressed-to-model) refuses on its own; weak shapes need company.
    const strong = best.weight >= 0.8;
    // Weak agent shapes name a topic (a command, a path, a privilege word), and in hidden text they are still a
    // topic: a syntax synopsis or a script comment the visibility pass labels hidden is not a hidden instruction.
    // postgresql.org's GRANT page went hostile on "GRANT ALL PRIVILEGES" in its synopsis (2026-11-18).
    const asHidden = hidden && !(AGENT_LABELS.has(best.label) && !strong && n < 2);
    const boost = asHidden ? hiddenBoost : 0;
    const visibleFactor = asHidden ? 1 : n >= 2 || strong ? 0.75 : 0.55;
    const severity = asHidden ? 0.9 : n >= 2 || strong ? 0.6 : 0.45;
    // visible text that quotes or attributes an instruction (news, fiction, training material) is not issuing it
    const quotedFactor = !asHidden && (AGENT_LABELS.has(best.label) ? isQuotedStrict(text, best.match, best.label) : isQuotedOrAttributed(text, best.match)) ? 0.55 : 1;
    const conf = Math.min(0.98, (best.weight * visibleFactor + boost + Math.min(0.15, (n - 1) * 0.05)) * best.discount * codeFactor * quotedFactor);
    findings.push({
      pass: "meaning", kind: n >= 3 || /system\s+prompt/i.test(best.match) ? "meaning.system_prompt_imitation" : "meaning.instruction_shaped",
      confidence: conf, severity,
      message: `${best.label}${n > 1 ? ` (+${n - 1} more instruction shapes)` : ""}${asHidden ? ", in text a human would not see" : hidden ? ", a topic word in hidden text" : ""}${inCode ? " (inside a code block)" : ""}${tag(best.variant)}`,
      excerpt: best.match.slice(0, 120), location: where, inHidden: asHidden, action: asHidden ? "quarantined" : "neutralized",
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
