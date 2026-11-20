import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Blocklist, preToolUse, preToolUseAnswered, callbackApprover, describeApproval, type ApprovalRequest } from "../src/index.js";

// 0.9.25: a hook question that a person must answer (INGRESS_HOOK_APPROVER=macos-presence).
// The approver here is a stand-in. The real one shows a system dialog and asks for Touch ID or the login
// password; nothing in a test can answer that, which is the point of it.

const decision = (r: Record<string, unknown> | undefined) => (r?.hookSpecificOutput as Record<string, string> | undefined)?.permissionDecision;
const reason = (r: Record<string, unknown> | undefined) => (r?.hookSpecificOutput as Record<string, string> | undefined)?.permissionDecisionReason ?? "";
const setup = () => ({ dir: mkdtempSync(join(tmpdir(), "ingress-hook-approver-")), blocklist: new Blocklist(), portProgram: () => undefined });
// always a question, whatever the session has read: it creates something that acts later
const persistent = { session_id: "p", tool_name: "Bash", tool_input: { command: "crontab -l | { cat; echo '0 * * * * /tmp/job.sh --token s3cr3t-value'; } | crontab -" } };
const log = (dir: string) => readFileSync(join(dir, "egress-log.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l) as Record<string, unknown>);

test("hook approver: a question goes to the person; their yes lets the harness carry on, and is never an allow", async () => {
  const o = setup();
  assert.equal(decision(preToolUse(persistent, o)), "ask", "without an approver the harness is asked");
  const seen: ApprovalRequest[] = [];
  const yes = callbackApprover("stub-presence", async (req) => { seen.push(req); return "approved"; });
  const reply = await preToolUseAnswered({ ...persistent, session_id: "q" }, yes, o);
  assert.equal(reply, undefined, "approved: the hook says nothing, so the harness's own permission flow decides");
  assert.equal(seen.length, 1);
  assert.equal(seen[0].tool, "Bash");
  assert.match(seen[0].reasons.join("; "), /acts later/);
  // the person is shown exactly what would run
  assert.match(describeApproval(seen[0]), /crontab/);
  assert.match(describeApproval(seen[0]), /Why this needs you/);
  const lines = log(o.dir).filter((l) => l.session === "q");
  assert.deepEqual(lines.map((l) => [l.decision, l.answer ?? null]), [["ask", null], ["ask", "approved"]]);
  assert.equal(lines[1].approver, "stub-presence");
  assert.ok(!JSON.stringify(log(o.dir)).includes("s3cr3t-value"), "the log never holds the arguments");
});

test("hook approver: declined, unanswered, or unable to ask are all refusals, each saying which", async () => {
  const cases: Array<[string, () => Promise<"approved" | "denied" | "timeout">, RegExp, string]> = [
    ["declined", async () => "denied", /was asked and declined/, "denied"],
    ["nobody answered", async () => "timeout", /was asked and did not answer/, "timeout"],
    ["the prompt could not be shown", async () => { throw new Error("the presence helper is not built"); }, /could not be shown/, "unavailable"],
    ["an answer that is not an answer", async () => "maybe" as unknown as "approved", /could not be shown/, "unavailable"],
  ];
  for (const [name, answer, says, logged] of cases) {
    const o = setup();
    const r = await preToolUseAnswered(persistent, callbackApprover("stub-presence", answer), o);
    assert.equal(decision(r), "deny", name);
    assert.match(reason(r), says, name);
    assert.match(reason(r), /acts later/, "the reason for the question is kept");
    assert.equal(log(o.dir).at(-1)?.answer, logged, name);
  }
});

test("hook approver: the hook answers for itself before the harness would give up on it", async () => {
  const o = setup();
  // a prompt nobody ever answers: without a deadline the harness would kill the hook and carry on as if it had no opinion
  const never = callbackApprover("stub-presence", () => new Promise<"approved">(() => {}));
  const t0 = Date.now();
  const r = await preToolUseAnswered(persistent, never, { ...o, answerWithinMs: 60 });
  assert.ok(Date.now() - t0 < 2000);
  assert.equal(decision(r), "deny");
  assert.match(reason(r), /did not answer/);
  assert.equal(log(o.dir).at(-1)?.answer, "timeout");
  // an answer that arrives in time is not affected
  const quick = await preToolUseAnswered({ ...persistent, session_id: "t" }, callbackApprover("stub-presence", async () => "approved"), { ...o, answerWithinMs: 5000 });
  assert.equal(quick, undefined);
});

test("hook approver: it is asked only when there is a question; a refusal and an ordinary action never reach it", async () => {
  const o = { ...setup(), blocklist: (() => { const b = new Blocklist(); b.add("bad-host.example\n"); return b; })() };
  let asked = 0;
  const counting = callbackApprover("stub-presence", async () => { asked++; return "approved"; });
  assert.equal(await preToolUseAnswered({ session_id: "n", tool_name: "Bash", tool_input: { command: "ls -la" } }, counting, o), undefined);
  const refused = await preToolUseAnswered({ session_id: "n", tool_name: "Bash", tool_input: { command: "curl https://bad-host.example/x" } }, counting, o);
  assert.equal(decision(refused), "deny", "a blocklisted host is refused outright: a person's yes cannot be asked for");
  assert.equal(asked, 0);
});

test("hook approver: the command line treats an unknown or unavailable approver as a refusal, not as no approver", () => {
  const cli = fileURLToPath(new URL("../src/cli.js", import.meta.url));
  const run = (who: string | undefined, extra: Record<string, string> = {}) => {
    const dir = mkdtempSync(join(tmpdir(), "ingress-hook-approver-cli-"));
    const env: Record<string, string | undefined> = { ...process.env, INGRESS_STATE_DIR: dir, INGRESS_BLOCKLIST_AUTO: "off", INGRESS_HOOK_SERVICE: "", ...extra };
    if (who === undefined) delete env.INGRESS_HOOK_APPROVER; else env.INGRESS_HOOK_APPROVER = who;
    const r = spawnSync(process.execPath, [cli, "hook", "pre-tool-use"], { input: JSON.stringify(persistent), env, encoding: "utf8", timeout: 30_000 });
    return r.stdout.trim() ? (JSON.parse(r.stdout) as Record<string, unknown>) : undefined;
  };
  assert.ok(existsSync(cli));
  assert.equal(decision(run(undefined)), "ask", "no approver set: the harness is asked, as before");
  assert.equal(decision(run("deny")), "deny");
  assert.equal(decision(run("touch-id-typo")), "deny", "a mistyped approver must not quietly weaken the gate");
  // macos-presence with no helper built at that path: the prompt cannot be shown, so the action is refused
  const missing = run("macos-presence", { INGRESS_PRESENCE_HELPER: "/nonexistent/ingress-presence" });
  assert.equal(decision(missing), "deny");
  assert.match(reason(missing), /could not be shown/);
});
