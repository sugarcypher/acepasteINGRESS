/**
 * AcePaste Ingress — shared types.
 *
 * Governing principle: anything the model would receive that a human looking
 * at the same source would not see is suspect by default.
 */

import type { NetPolicy } from "./netpolicy.js";

export const ENGINE_VERSION = "0.9.23";
/** bump whenever a detector's behavior changes; receipts carry it so verdicts are reproducible */
export const RULESET_VERSION = "2026.11.19-1";

/**
 * clean: delivered. suspect: refused, overridable. hostile: refused, not overridable.
 * unreachable: nothing could be fetched or read (network error, timeout, redirect loop,
 * binary or oversized body). Not an attack verdict, and never written to the attack log.
 */
export type Tier = "clean" | "suspect" | "hostile" | "unreachable";

/**
 * What the content is. The first five are document formats; the rest are channels, each with its own adapter
 * that turns the channel's structure into segments the passes read (see docs/ROADMAP.md, shared foundations).
 */
export type ContentKind = "html" | "markdown" | "json" | "text" | "javascript" | "log" | "email" | "calendar" | "message" | "notification" | "nearby" | "automation" | "captions" | "image" | "audio";

/**
 * Who could have written the content. Lower is more trusted. It never makes a verdict more lenient than the
 * default; from level 4 down, less evidence is needed to refuse.
 *   1 the person, typing or approving      2 known contacts, own calendars, lists and files
 *   3 content an agent wrote earlier       4 strangers: unknown senders, voicemail, fax, invitations, downloads
 *   5 open channels: public chats, group chats, subscribed feeds, logs, the web
 *   6 broadcasts: Bonjour, Bluetooth, beacons, anything on a shared network
 */
export type TrustLevel = 1 | 2 | 3 | 4 | 5 | 6;

/** Where a piece of content came from, as far as the caller knows. */
export interface SourceInfo {
  /** the app or system it arrived through: "gmail", "slack", "imessage", "bonjour", "nginx access log" */
  channel?: string;
  /** who sent or wrote it, as the channel names them */
  sender?: string;
  trust?: TrustLevel;
}

export const CONTENT_KINDS: readonly ContentKind[] = ["html", "markdown", "json", "text", "javascript", "log", "email", "calendar", "message", "notification", "nearby", "automation", "captions", "image", "audio"];

/** Read a content kind and source from untyped input (an HTTP body, tool arguments). Unknown values are dropped, never guessed. */
export function parseScanHints(o: { kind?: unknown; trust?: unknown; channel?: unknown; sender?: unknown }): { kind?: ContentKind; source?: SourceInfo } {
  const kind = typeof o.kind === "string" && (CONTENT_KINDS as readonly string[]).includes(o.kind) ? (o.kind as ContentKind) : undefined;
  const trust = typeof o.trust === "number" && Number.isInteger(o.trust) && o.trust >= 1 && o.trust <= 6 ? (o.trust as TrustLevel) : undefined;
  const channel = typeof o.channel === "string" ? o.channel.slice(0, 120) : undefined;
  const sender = typeof o.sender === "string" ? o.sender.slice(0, 200) : undefined;
  const source = trust !== undefined || channel !== undefined || sender !== undefined ? { trust, channel, sender } : undefined;
  return { kind, source };
}

/** multiplier on the suspect threshold per trust level: strangers and broadcasts need less evidence */
export const TRUST_SUSPECT_FACTOR: Record<TrustLevel, number> = { 1: 1, 2: 1, 3: 1, 4: 0.9, 5: 0.85, 6: 0.7 };

export type PassName =
  | "acquire"
  | "policy"
  | "visibility"
  | "character"
  | "script"
  | "supplychain"
  | "secrets"
  | "meaning"
  | "cloaking"
  | "sandbox"
  | "code"
  // structure of the channel itself: a control code that acts on the person's machine, two parts of one
  // message that disagree, a sender who is not who the content says
  | "channel"
  // the learned pass: resemblance to known attacks (classifier.ts)
  | "classifier"
  | "plugin";

export type FindingKind =
  // policy
  | "policy.denied_source"
  | "policy.redirect_chain"
  // acquire pass
  | "acquire.unreachable"
  | "acquire.cloaking_check_incomplete"
  | "acquire.ai_agent_refused"
  // character pass
  | "unicode.tag_characters"
  | "unicode.zero_width"
  | "unicode.bidi_control"
  | "unicode.variation_selector_smuggling"
  | "unicode.mixed_script_confusable"
  | "unicode.fullwidth_or_math_lookalike"
  | "unicode.combining_flood"
  | "unicode.encoded_payload"
  | "unicode.entity_smuggling"
  | "unicode.whitespace_channel"
  // visibility pass
  | "visibility.css_hidden"
  | "visibility.offscreen"
  | "visibility.attribute_only"
  | "visibility.html_comment"
  | "visibility.tiny_or_transparent"
  | "visibility.markdown_hidden"
  | "visibility.terminal_hidden"
  | "visibility.terminal_control"
  // channel structure: email
  | "email.part_divergence"
  | "email.sender_mismatch"
  | "email.authentication_failed"
  | "email.remote_content"
  | "email.uninspected_part"
  // channel structure: calendar
  | "calendar.alarm_action"
  | "calendar.description_divergence"
  // channel structure: messages and notifications
  | "message.text_divergence"
  | "message.sender_impersonation"
  | "message.scam_shape"
  | "message.verification_code"
  | "message.uninspected_part"
  | "notification.source_mismatch"
  // channel structure: nearby devices, automations
  | "nearby.authority_name"
  | "nearby.lookalike"
  | "nearby.link"
  | "nearby.oversized_field"
  | "automation.private_outside_send"
  | "automation.runs_code"
  | "automation.destination"
  | "automation.unreadable"
  | "image.clickfix"
  | "image.screen_not_in_source"
  // channel structure: captions, transcripts and audio
  | "captions.hidden_cue"
  | "captions.unreadable_cue"
  | "captions.not_spoken"
  | "captions.addressed_to_notetaker"
  | "captions.spoken_approval"
  | "audio.quiet_speech"
  | "audio.transcript_unstable"
  | "audio.metadata_text"
  | "audio.not_transcribed"
  // channel structure: images and the codes in them
  | "image.text_only_when_resized"
  | "image.low_contrast_text"
  | "image.transparency_text"
  | "image.later_frame_text"
  | "image.metadata_text"
  | "image.trailing_data"
  | "image.active_content"
  | "image.code_payload"
  | "image.code_action"
  | "image.caption_mismatch"
  | "image.pixels_not_inspected"
  // learned pass
  | "classifier.injection_likely"
  // script pass
  | "script.obfuscation"
  | "script.runtime_codegen"
  | "script.automation_detection"
  | "script.post_load_text_injection"
  | "script.exfil_beacon"
  | "script.binary_decoding"
  // supply-chain pass (underlight lineage)
  | "supplychain.lifecycle_script"
  | "supplychain.url_dependency"
  | "supplychain.offregistry_resolution"
  | "supplychain.install_instruction"
  // secrets pass (Kith & Revere lineage)
  | "secrets.credential_in_content"
  // sandbox pass
  | "sandbox.text_injected_after_load"
  | "sandbox.webdriver_keyed_divergence"
  | "sandbox.computed_hidden_text"
  | "sandbox.blocked_egress_attempt"
  // meaning pass
  | "meaning.instruction_shaped"
  | "meaning.role_token"
  | "meaning.system_prompt_imitation"
  | "meaning.tool_call_shaped"
  | "meaning.exfil_markdown_image"
  | "meaning.exfil_link"
  | "meaning.adversarial_suffix"
  // cloaking pass
  | "cloaking.agent_targeted_divergence"
  // code behavior pass
  | "code.download_execute"
  | "code.encoded_execution"
  | "code.reverse_shell"
  | "code.secret_exfiltration"
  | "code.persistence"
  // plugin detectors
  | `plugin.${string}`;

export interface Finding {
  pass: PassName;
  kind: FindingKind;
  /** 0..1 confidence that this is an attack rather than benign structure */
  confidence: number;
  /** 0..1 severity if it is an attack */
  severity: number;
  /** short human-readable explanation */
  message: string;
  /** excerpt of the offending material, already made safe to print */
  excerpt?: string;
  /** location hint: character offset, selector path, or script index */
  location?: string;
  /** meaning pass: the match was in text a human would not see */
  inHidden?: boolean;
  /** what the engine did about it */
  action: "none" | "neutralized" | "quarantined";
  /** Kith & Revere evidence model, attached by the engine: a finding is a conclusion, never a Fact */
  evidenceClass?: "inference" | "hypothesis";
  /** confidence band: high >= 0.8, medium >= 0.5, low below */
  band?: "high" | "medium" | "low";
  /** sha256 of the artifact the finding cites: its excerpt, or the whole acquired body */
  artifactDigest?: string;
  /** the benign explanation a reviewer should rule out before acting */
  altExplanation?: string;
}

export interface AcquireResult {
  url: string;
  finalUrl: string;
  redirectChain: string[];
  status: number;
  headers: Record<string, string>;
  contentType: string;
  /** raw body as text (binary bodies are refused upstream) */
  body: string;
  /** which fingerprint this acquisition used */
  fingerprint: "human" | "agent";
  /** the user-agent string actually sent */
  userAgent: string;
  /** how it was fetched: plain HTTP client, or a real browser (human fingerprint only) */
  via: "http" | "browser";
  fetchedAt: string;
}

export interface TextSegment {
  text: string;
  /** visible: a sighted human reading the rendered page sees this */
  /** concealed: the medium itself hides it from a person (terminal control codes, a part of a message no client shows) */
  visibility: "visible" | "css_hidden" | "offscreen" | "attribute" | "comment" | "tiny_or_transparent" | "concealed";
  /** selector-ish path for the location field */
  path: string;
}

export interface ScriptUnit {
  index: number;
  source: string;
  inline: boolean;
  src?: string;
}

/** What a custom detector sees. Everything is read-only. */
export interface DetectorContext {
  url: string;
  contentKind: ContentKind;
  raw: string;
  segments: ReadonlyArray<TextSegment>;
  scripts: ReadonlyArray<ScriptUnit>;
  decodedPayloads: ReadonlyArray<string>;
}

/** Plugin interface. Findings are returned with kind `plugin.<name>`. */
export interface Detector {
  name: string;
  version: string;
  run(ctx: DetectorContext): Finding[] | Promise<Finding[]>;
}

export interface DomainRule {
  /** exact host or `.suffix` */
  match: string;
  /** refuse outright regardless of content */
  deny?: boolean;
  suspectThreshold?: number;
  hostileThreshold?: number;
  /** skip the second fetch for this host */
  cloakingCheck?: boolean;
}

export interface IngressPolicy {
  domains: DomainRule[];
}

export interface TaintReceipt {
  version: "3";
  engineVersion: string;
  rulesetVersion: string;
  issuedAt: string;
  url: string;
  finalUrl: string;
  redirectChain: string[];
  contentKind: ContentKind;
  /** count of hostile invisible characters per the shared AcePaste alphabet (cross-tool parity) */
  acepasteInvisibleCount: number;
  /** sha256 of the raw acquired body */
  rawDigest: string;
  /** sha256 of the delivered text (empty string when refused) */
  deliveredDigest: string;
  tier: Tier;
  score: number;
  /** suspect content was delivered because a human explicitly asked for it */
  overridden: boolean;
  /** which passes actually ran (sandbox may not have) */
  passesRun: PassName[];
  /** the trust level the caller gave for the source, when it gave one */
  trust?: TrustLevel;
  findings: Array<Pick<Finding, "pass" | "kind" | "confidence" | "severity" | "action" | "evidenceClass" | "band" | "artifactDigest">>;
  /** how `signature` was made: a shared-secret HMAC (only the key holder can verify) or ECDSA P-256 (anyone with the public key can verify, nobody without the private key can forge) */
  signatureAlg?: "hmac-sha256" | "ecdsa-p256-sha256";
  /** first 16 hex characters of sha256 over the signer's public key (ECDSA only) */
  keyId?: string;
  /** sha256 of the previous receipt in this session, for audit chains */
  previous?: string;
  /** sha256 of this receipt's canonical body (without signature) */
  digest: string;
  /** HMAC-SHA256 over the canonical receipt body, when a signing key was configured */
  signature?: string;
}

export interface IngressResult {
  tier: Tier;
  /** aggregate attack score, 0..1 */
  score: number;
  contentKind: ContentKind;
  /** text delivered to the model; empty unless tier is clean or a suspect verdict was overridden */
  delivered: string;
  /** true when suspect text was delivered under human override */
  overridden: boolean;
  /** spotlighting-style envelope the caller should hand to the model verbatim */
  envelope: string;
  findings: Finding[];
  receipt: TaintReceipt;
  /** timing in milliseconds per pass, for the speed budget */
  timings: Partial<Record<PassName | "total", number>>;
  /** what was inspected, and what was not (code languages, units skipped). Unknown is not clean. */
  coverage?: { code?: import("./codepass.js").CodeCoverage; image?: import("./image.js").ImageCoverage; audio?: import("./audio.js").AudioCoverage };
}

export interface IngressConfig {
  /** score at or above which the page is refused and cannot be overridden */
  hostileThreshold: number;
  /** score at or above which the page is refused but may be overridden */
  suspectThreshold: number;
  /** run the second, human-fingerprinted fetch and compare */
  cloakingCheck: boolean;
  /**
   * user agents for the agent fetch, one picked at random per fetch. Defaults to the
   * user-triggered fetchers of the major AI assistants, because those are what
   * agent-targeted cloaking keys on. Set to one honest string to stop impersonating.
   */
  agentUserAgents: string[];
  /** random gap between the two fetches, [min, max] milliseconds; the order is random too */
  cloakingJitterMs: [number, number];
  /**
   * optional HTTP(S) proxy for the human fetch only, e.g. a residential proxy, so the two
   * fetches leave from different networks. Credentials go in the URL. Never logged.
   */
  humanProxy?: string;
  /** "http": the human fetch is a plain request with browser headers. "browser": a real headless Chromium loads the page. */
  humanFetch: "http" | "browser";
  /** maximum body size accepted, bytes */
  maxBodyBytes: number;
  /** fetch timeout, milliseconds */
  fetchTimeoutMs: number;
  /** optional HMAC key for signing receipts (shared secret: verifiers can also forge) */
  signingKey?: string;
  /** optional ECDSA P-256 private key, PEM (PKCS#8). Preferred over signingKey: receipts become publicly verifiable and unforgeable */
  signingPrivateKey?: string;
  /** cache verdicts by url for this many seconds; 0 disables */
  cacheTtlSeconds: number;
  /** "off": static only. "escalate": run when the static script pass is suspicious. "always": every HTML page. */
  sandbox: "off" | "escalate" | "always";
  /** sandbox per-page budget, milliseconds */
  sandboxTimeoutMs: number;
  /** static suspicion at or above which sandbox escalates (when sandbox = "escalate") */
  sandboxEscalateAt: number;
  /** fetch and parse linked stylesheets for the static visibility pass (same origin only) */
  fetchStylesheets: boolean;
  /** network policy: what the gate itself may connect to */
  net: NetPolicy;
  /** per-domain rules */
  policy: IngressPolicy;
  /** custom detectors */
  detectors: Detector[];
  /** chain receipts: each receipt carries the digest of the previous one */
  chainReceipts: boolean;
  /**
   * Run the learned pass beside the rules. On its own it can make content suspect, never hostile.
   * Off reproduces the rules-only verdicts of 0.9.15 and earlier.
   */
  classifier: boolean;
}

export const DEFAULT_CONFIG: IngressConfig = {
  hostileThreshold: 0.7,
  suspectThreshold: 0.25,
  cloakingCheck: true,
  agentUserAgents: [
    // sources: OpenAI bot docs; Cloudflare Radar bot directory; Perplexity agent docs (checked 2026-11-03)
    "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot",
    "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-User/1.0; +Claude-User@anthropic.com)",
    "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Perplexity-User/1.0; +https://www.perplexity.ai)",
  ],
  cloakingJitterMs: [250, 1500],
  humanFetch: "http",
  maxBodyBytes: 5 * 1024 * 1024,
  fetchTimeoutMs: 15000,
  cacheTtlSeconds: 86400,
  sandbox: "escalate",
  sandboxTimeoutMs: 8000,
  sandboxEscalateAt: 0.5,
  fetchStylesheets: true,
  net: { denyHosts: [], allowHosts: [], extraPorts: [], allowPrivate: false },
  policy: { domains: [] },
  detectors: [],
  chainReceipts: true,
  classifier: true,
};
