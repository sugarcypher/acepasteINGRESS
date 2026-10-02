/**
 * AcePaste Gate — shared types.
 *
 * Governing principle: anything the model would receive that a human looking
 * at the same source would not see is suspect by default.
 */

import type { NetPolicy } from "./netpolicy.js";

export const ENGINE_VERSION = "0.5.0";
/** bump whenever a detector's behavior changes; receipts carry it so verdicts are reproducible */
export const RULESET_VERSION = "2026.10.02-1";

export type Tier = "clean" | "suspect" | "hostile";

export type ContentKind = "html" | "markdown" | "json" | "text" | "javascript";

export type PassName =
  | "acquire"
  | "policy"
  | "visibility"
  | "character"
  | "script"
  | "meaning"
  | "cloaking"
  | "sandbox"
  | "plugin";

export type FindingKind =
  // policy
  | "policy.denied_source"
  | "policy.redirect_chain"
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
  // visibility pass
  | "visibility.css_hidden"
  | "visibility.offscreen"
  | "visibility.attribute_only"
  | "visibility.html_comment"
  | "visibility.tiny_or_transparent"
  | "visibility.markdown_hidden"
  // script pass
  | "script.obfuscation"
  | "script.runtime_codegen"
  | "script.automation_detection"
  | "script.post_load_text_injection"
  | "script.exfil_beacon"
  | "script.binary_decoding"
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
  // cloaking pass
  | "cloaking.agent_targeted_divergence"
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
  /** what the engine did about it */
  action: "none" | "neutralized" | "quarantined";
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
  fetchedAt: string;
}

export interface TextSegment {
  text: string;
  /** visible: a sighted human reading the rendered page sees this */
  visibility: "visible" | "css_hidden" | "offscreen" | "attribute" | "comment" | "tiny_or_transparent";
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

export interface GatePolicy {
  domains: DomainRule[];
}

export interface TaintReceipt {
  version: "2";
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
  findings: Array<Pick<Finding, "pass" | "kind" | "confidence" | "severity" | "action">>;
  /** sha256 of the previous receipt in this session, for audit chains */
  previous?: string;
  /** sha256 of this receipt's canonical body (without signature) */
  digest: string;
  /** HMAC-SHA256 over the canonical receipt body, when a signing key was configured */
  signature?: string;
}

export interface GateResult {
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
}

export interface GateConfig {
  /** score at or above which the page is refused and cannot be overridden */
  hostileThreshold: number;
  /** score at or above which the page is refused but may be overridden */
  suspectThreshold: number;
  /** run the second, human-fingerprinted fetch and compare */
  cloakingCheck: boolean;
  /** maximum body size accepted, bytes */
  maxBodyBytes: number;
  /** fetch timeout, milliseconds */
  fetchTimeoutMs: number;
  /** optional HMAC key for signing receipts */
  signingKey?: string;
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
  policy: GatePolicy;
  /** custom detectors */
  detectors: Detector[];
  /** chain receipts: each receipt carries the digest of the previous one */
  chainReceipts: boolean;
}

export const DEFAULT_CONFIG: GateConfig = {
  hostileThreshold: 0.7,
  suspectThreshold: 0.25,
  cloakingCheck: true,
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
};
