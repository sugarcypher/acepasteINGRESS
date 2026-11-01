/**
 * Evidence model (Kith & Revere lineage, ported 2026-10-31).
 *
 * Kith & Revere's constitutional rule: a Fact is an artifact that
 * demonstrably exists; an Inference is what a rule concluded from Facts; a
 * Hypothesis is what Facts are consistent with but do not establish. No
 * artifact, no finding. Every conclusion states its benign alternative.
 *
 * Applied here: every gate finding is a conclusion, so it is an Inference or
 * (when its confidence is in the low band) a Hypothesis, never a Fact. It
 * cites its artifact by digest: the excerpt it matched, or the whole acquired
 * body when the finding is about the page as a whole. And it carries the
 * benign explanation a reviewer should rule out before acting on it.
 */

import { createHash } from "node:crypto";
import type { Finding } from "./types.js";

export type EvidenceClass = "inference" | "hypothesis";
export type ConfidenceBand = "high" | "medium" | "low";

export function bandOf(confidence: number): ConfidenceBand {
  return confidence >= 0.8 ? "high" : confidence >= 0.5 ? "medium" : "low";
}

/** benign explanations a reviewer must rule out, by finding-kind prefix (longest prefix wins) */
const ALTERNATIVES: Array<[string, string]> = [
  ["policy.denied_source", "the source or address is on a deny list by configuration, not because of anything in its content"],
  ["policy.redirect_chain", "ordinary link shorteners, sign-in hops and content-delivery redirects"],
  ["unicode.tag_characters", "emoji flag sequences for subdivisions (such as the Scotland or Wales flags) legitimately use tag characters"],
  ["unicode.zero_width", "text pasted from word processors, or scripts that need joiners and the context check missed"],
  ["unicode.whitespace_channel", "typesetting that uses fine spaces deliberately, such as typeset mathematics or some East Asian layouts"],
  ["unicode.bidi_control", "mixed right-to-left and left-to-right text that an editor wrapped in direction controls"],
  ["unicode.variation_selector_smuggling", "emoji presentation selectors or ideographic variation sequences in East Asian text"],
  ["unicode.mixed_script_confusable", "brand names, transliteration, or multilingual text mixing scripts within a word"],
  ["unicode.fullwidth_or_math_lookalike", "East Asian full-width typography, or mathematical notation"],
  ["unicode.combining_flood", "decorative 'zalgo' text, or dense diacritics in some languages and transcriptions"],
  ["unicode.encoded_payload", "data attributes, tokens, hashes, images or other encoded data that happen to decode to readable text"],
  ["unicode.entity_smuggling", "an editor or content system that over-encodes characters as entities"],
  ["visibility.", "accessibility text for screen readers, collapsed sections, tooltips, analytics markup, or design choices; hidden text is not delivered either way"],
  ["script.obfuscation", "a minifier or commercial code-protection tool on legitimate code"],
  ["script.runtime_codegen", "template engines, bundler runtimes or polyfills that generate code legitimately"],
  ["script.automation_detection", "bot-management and fraud-prevention scripts that check for automation without serving different content"],
  ["script.post_load_text_injection", "single-page applications that render all their text after load"],
  ["script.exfil_beacon", "analytics, error reporting and advertising beacons"],
  ["script.binary_decoding", "media players, font loaders, compression libraries and WebAssembly loaders"],
  ["supplychain.lifecycle_script", "native modules that download prebuilt binaries at install, or build tooling that runs a setup script"],
  ["supplychain.url_dependency", "forks pinned to a Git commit, private packages, or monorepo tarballs"],
  ["supplychain.offregistry_resolution", "a company's private registry or a registry mirror"],
  ["supplychain.install_instruction", "real installation documentation; the gate weights visible commands low for this reason"],
  ["secrets.", "example or revoked credentials in documentation, or test fixtures"],
  ["sandbox.text_injected_after_load", "client-side rendering of ordinary content"],
  ["sandbox.webdriver_keyed_divergence", "sites that show bots a simplified page or a consent wall without hostile intent"],
  ["sandbox.computed_hidden_text", "menus, modals and responsive layouts that hide content until a user acts"],
  ["sandbox.blocked_egress_attempt", "third-party fonts, analytics or content-delivery requests the sandbox does not allow"],
  ["meaning.instruction_shaped", "articles, tutorials and security research that quote instructions, or content addressed to human readers"],
  ["meaning.role_token", "documentation of chat templates, or transcripts"],
  ["meaning.system_prompt_imitation", "documentation describing system prompts"],
  ["meaning.tool_call_shaped", "API documentation and code samples"],
  ["meaning.exfil_markdown_image", "images with ordinary tracking or cache-busting query strings"],
  ["meaning.exfil_link", "legitimate webhook or form endpoints mentioned in documentation"],
  ["cloaking.", "personalization, A/B tests, geolocation, or different layouts for different browsers"],
  ["plugin.", "defined by the custom detector's author"],
];

export function alternativeFor(kind: string): string {
  let best = "";
  let alt = "no benign explanation recorded for this kind";
  for (const [prefix, text] of ALTERNATIVES) if (kind.startsWith(prefix) && prefix.length > best.length) { best = prefix; alt = text; }
  return alt;
}

const sha256 = (s: string) => createHash("sha256").update(s, "utf8").digest("hex");

/** Attach evidence class, band, artifact digest and benign alternative to every finding (in place). */
export function attachEvidence(findings: Finding[], rawDigest: string): void {
  for (const f of findings) {
    f.band = bandOf(f.confidence);
    f.evidenceClass = f.band === "low" ? "hypothesis" : "inference";
    f.artifactDigest = f.excerpt ? sha256(f.excerpt) : rawDigest;
    f.altExplanation = alternativeFor(f.kind);
  }
}
