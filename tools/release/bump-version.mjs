#!/usr/bin/env node
// Bump every package, the @acepaste/ingress pins and ENGINE_VERSION in one step.
//   node tools/release/bump-version.mjs 0.9.7
//   node tools/release/bump-version.mjs 0.9.8 --ruleset 2026.11.19-1   (when a detector's behavior changes)
// Then: npm install --package-lock-only --ignore-scripts, and add the CHANGELOG.md entry by hand.
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const [version, ...rest] = process.argv.slice(2);
if (!/^\d+\.\d+\.\d+$/.test(version ?? "")) {
  console.error("usage: bump-version.mjs <x.y.z> [--ruleset <id>]");
  process.exit(2);
}
const ruleset = rest[0] === "--ruleset" ? rest[1] : undefined;
if (rest.length && !ruleset) { console.error("--ruleset needs a value"); process.exit(2); }

const edit = (rel, fn) => {
  const p = join(root, rel);
  const before = readFileSync(p, "utf8");
  const after = fn(before);
  if (after === before) throw new Error(`${rel}: nothing changed (already at ${version}?)`);
  writeFileSync(p, after);
  console.log(`updated ${rel}`);
};

const setVersion = (s) => s.replace(/("version":\s*")\d+\.\d+\.\d+(")/, `$1${version}$2`);
const setPin = (s) => s.replace(/("@acepaste\/ingress":\s*")\d+\.\d+\.\d+(")/, `$1${version}$2`);

edit("package.json", setVersion);
edit("packages/core/package.json", setVersion);
edit("packages/mcp/package.json", (s) => setPin(setVersion(s)));
edit("packages/http/package.json", (s) => setPin(setVersion(s)));
edit("packages/core/src/types.ts", (s) => {
  let out = s.replace(/(ENGINE_VERSION = ")[^"]+(")/, `$1${version}$2`);
  if (ruleset) out = out.replace(/(RULESET_VERSION = ")[^"]+(")/, `$1${ruleset}$2`);
  return out;
});
console.log(`version ${version}${ruleset ? `, ruleset ${ruleset}` : " (ruleset unchanged)"}`);
