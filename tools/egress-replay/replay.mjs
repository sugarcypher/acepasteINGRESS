#!/usr/bin/env node
// Replay the tool calls of a recorded Claude Code session through the egress gate, as if the session had
// read outside content from its first minute, and count how often the gate would have asked or refused.
// Every call in a session a person watched and accepted is ordinary work, so each question is a false alarm
// to explain. Prints counts and reasons with numbers and names removed; with --show, the first 70
// characters of each command that was questioned (they are the session owner's own commands).
//
//   npm run build && node tools/egress-replay/replay.mjs ~/.claude/projects/<project>/<session>.jsonl [--show]
import { createReadStream, mkdtempSync } from "node:fs";
import { createInterface } from "node:readline";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { preToolUse, postToolUse, Blocklist } from "../../packages/core/dist/src/index.js";

const file = process.argv[2];
if (!file) { console.error("usage: replay.mjs <session.jsonl> [--show]"); process.exit(2); }
const show = process.argv.includes("--show");
const dir = mkdtempSync(join(tmpdir(), "ingress-replay-"));
const session = "replay";
let clock = 0;
const opts = { dir, blocklist: new Blocklist(), portProgram: () => undefined, now: () => clock };

// taint the session up front: a page that names the hosts a developer's session talks to
const clean = async (text) => ({ tier: "clean", delivered: text, envelope: text, findings: [], score: 0 });
await postToolUse({ session_id: session, tool_name: "WebFetch", tool_input: { url: "https://docs.example.org/setup" }, tool_response: { result: "x" } },
  { fetch: () => clean("Install from https://registry.npmjs.org and clone https://github.com/example/repo. See also api.github.com, pypi.org and huggingface.co."), scan: clean }, { dir });

const tally = { calls: 0, allow: 0, ask: 0, deny: 0 };
const byTool = {}, byReason = {};
const shown = [];
for await (const line of createInterface({ input: createReadStream(file) })) {
  let row; try { row = JSON.parse(line); } catch { continue; }
  if (row.type !== "assistant" || !Array.isArray(row.message?.content)) continue;
  if (row.timestamp) clock = Date.parse(row.timestamp) || clock;
  for (const b of row.message.content) {
    if (b.type !== "tool_use") continue;
    const r = preToolUse({ session_id: session, tool_name: b.name, tool_input: b.input ?? {} }, opts);
    tally.calls++;
    const d = r?.hookSpecificOutput?.permissionDecision ?? "allow";
    tally[d]++;
    if (d === "allow") continue;
    byTool[`${b.name.startsWith("mcp__") ? "mcp" : b.name}:${d}`] = (byTool[`${b.name.startsWith("mcp__") ? "mcp" : b.name}:${d}`] ?? 0) + 1;
    const why = String(r.hookSpecificOutput.permissionDecisionReason).replace(/^AcePaste Ingress: /, "").replace(/ This is refused.*$/, "");
    for (const part of why.split("; ")) {
      const k = part.replace(/\d+/g, "N").replace(/\b[a-z0-9.-]+\.[a-z]{2,}\b/gi, "HOST").replace(/\(.*?\)/g, "(…)").slice(0, 90);
      byReason[k] = (byReason[k] ?? 0) + 1;
    }
    if (show && shown.length < 60) shown.push(`${d.padEnd(5)} ${b.name.padEnd(6)} ${String(b.input?.command ?? b.input?.file_path ?? "").replace(/\s+/g, " ").slice(0, 70)}`);
  }
}
console.log(`${tally.calls} tool calls: ${tally.allow} not questioned, ${tally.ask} asked, ${tally.deny} refused (${((tally.ask + tally.deny) / Math.max(1, tally.calls) * 100).toFixed(1)}% interrupted)`);
console.log("\nby tool:"); for (const [k, n] of Object.entries(byTool).sort((a, b) => b[1] - a[1])) console.log(`  ${String(n).padStart(4)}  ${k}`);
console.log("\nby reason:"); for (const [k, n] of Object.entries(byReason).sort((a, b) => b[1] - a[1])) console.log(`  ${String(n).padStart(4)}  ${k}`);
if (show) { console.log("\nquestioned:"); for (const s of shown) console.log(`  ${s}`); }
