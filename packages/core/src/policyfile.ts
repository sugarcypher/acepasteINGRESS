/**
 * Policy file loader. JSON, validated loosely; unknown keys are ignored so
 * older engines can read newer files.
 *
 * {
 *   "thresholds": { "suspect": 0.25, "hostile": 0.7 },
 *   "net": { "denyHosts": [".internal.example"], "allowHosts": [], "extraPorts": [8080] },
 *   "domains": [
 *     { "match": ".trusted-docs.example", "suspectThreshold": 0.5 },
 *     { "match": "pastebin.com", "hostileThreshold": 0.4 },
 *     { "match": ".evil.example", "deny": true }
 *   ],
 *   "sandbox": "escalate"
 * }
 */
import { readFileSync } from "node:fs";
import type { GateConfig } from "./types.js";

export function loadPolicyFile(path: string): Partial<GateConfig> {
  const raw = JSON.parse(readFileSync(path, "utf8")) as Record<string, any>;
  const out: Partial<GateConfig> = {};
  const num = (v: unknown) => (typeof v === "number" && v >= 0 && v <= 1 ? v : undefined);
  if (raw.thresholds) {
    const s = num(raw.thresholds.suspect), h = num(raw.thresholds.hostile);
    if (s !== undefined) out.suspectThreshold = s;
    if (h !== undefined) out.hostileThreshold = h;
  }
  if (raw.net && typeof raw.net === "object") {
    out.net = {
      denyHosts: Array.isArray(raw.net.denyHosts) ? raw.net.denyHosts.filter((x: unknown) => typeof x === "string") : [],
      allowHosts: Array.isArray(raw.net.allowHosts) ? raw.net.allowHosts.filter((x: unknown) => typeof x === "string") : [],
      extraPorts: Array.isArray(raw.net.extraPorts) ? raw.net.extraPorts.filter((x: unknown) => Number.isInteger(x)) : [],
      allowPrivate: raw.net.allowPrivate === true,
    };
  }
  if (Array.isArray(raw.domains)) {
    out.policy = {
      domains: raw.domains
        .filter((d: any) => d && typeof d.match === "string")
        .map((d: any) => ({ match: d.match, deny: d.deny === true, suspectThreshold: num(d.suspectThreshold), hostileThreshold: num(d.hostileThreshold), cloakingCheck: typeof d.cloakingCheck === "boolean" ? d.cloakingCheck : undefined })),
    };
  }
  if (raw.sandbox === "off" || raw.sandbox === "escalate" || raw.sandbox === "always") out.sandbox = raw.sandbox;
  if (typeof raw.cloakingCheck === "boolean") out.cloakingCheck = raw.cloakingCheck;
  if (typeof raw.fetchStylesheets === "boolean") out.fetchStylesheets = raw.fetchStylesheets;
  return out;
}
