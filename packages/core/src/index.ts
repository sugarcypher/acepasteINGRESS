export { IngressEngine, aggregate, buildEnvelope, buildLogEntry } from "./engine.js";
export type { EngineDeps, IngressOptions } from "./engine.js";
export { acquire, AcquireError, MAX_REDIRECTS } from "./acquire.js";
export type { FetchLike } from "./acquire.js";
export { checkTarget, isPrivateIP, isPrivateIPv4, isPrivateIPv6, NetPolicyError, DEFAULT_NET_POLICY } from "./netpolicy.js";
export type { NetPolicy } from "./netpolicy.js";
export { analyzeHtml, findStylesheetLinks, rulesFromCss, colorRulesFromCss } from "./visibility.js";
export type { HiddenRule, ColorRule, VisibilityResult } from "./visibility.js";
export { parseColor, contrastRatio, INVISIBLE_CONTRAST } from "./color.js";
export { scanCharacters } from "./character.js";
export { analyzeScripts, analyzeScript } from "./script.js";
export { scanMeaning, neutralizeMeaning } from "./meaning.js";
export { scanSupplyChain } from "./supplychain.js";
export { scanSecrets, redactSecrets, collectSecrets, scrubExcerpt } from "./secrets.js";
export { attachEvidence, alternativeFor, bandOf } from "./evidence.js";
export type { EvidenceClass, ConfidenceBand } from "./evidence.js";
export { detectKind, decodeEntities, adaptMarkdown, adaptJson, adaptText, adaptJavascript } from "./adapters.js";
export { runSandbox, DEFAULT_SCRIPT_HOSTS } from "./sandbox.js";
export type { SandboxResult } from "./sandbox.js";
export { createTaintGuard } from "./taint.js";
export type { TaintGuard, TaintPolicy } from "./taint.js";
export { loadPolicyFile } from "./policyfile.js";
export { countHostileInvisibles, ACEPASTE_INVISIBLE_SOURCE, ACEPASTE_INVISIBLE_SUPPL_SOURCE } from "./acepaste-alphabet.js";
export * from "./types.js";

/** @deprecated renamed to IngressEngine in 0.7.0 (AcePaste Gate -> AcePaste Ingress) */
export { IngressEngine as GateEngine } from "./engine.js";
