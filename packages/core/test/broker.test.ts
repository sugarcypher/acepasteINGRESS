import { test } from "node:test";
import assert from "node:assert/strict";
import { ActionBroker, isSideEffectName, canonicalJson, actionDigest, describeApproval, callbackApprover, denyAllApprover, type ApprovalRequest } from "../src/index.js";

const yes = callbackApprover("yes", async () => "approved");
const no = callbackApprover("no", async () => "denied");

test("a run that has read nothing from outside may act; once it has, side effects need a person", async () => {
  const b = new ActionBroker({}, { approver: no });
  const before = await b.authorize({ runId: "r1", tool: "gmail__send_email", args: { to: "a@b.example", body: "hi" } });
  assert.equal(before.permitted, true);
  b.ingest("r1", { ref: "https://clean.example/page" });
  const after = await b.authorize({ runId: "r1", tool: "gmail__send_email", args: { to: "a@b.example", body: "hi" } });
  assert.equal(after.decision, "require_approval");
  assert.equal(after.permitted, false);
  assert.equal(after.approval?.outcome, "denied");
});

test("taint does not depend on the verdict: a clean page still taints the run", () => {
  const b = new ActionBroker();
  b.ingest("r", { ref: "https://looks-fine.example/" });
  assert.equal(b.classify({ runId: "r", tool: "slack__post_message", args: { text: "x" } }).decision, "require_approval");
});

test("the person approves the exact call; the broker hands back those frozen arguments", async () => {
  let seen: ApprovalRequest | undefined;
  const b = new ActionBroker({}, { approver: callbackApprover("t", async (r) => { seen = r; return "approved"; }) });
  b.ingest("r", { ref: "https://x.example/" });
  const v = await b.authorize({ runId: "r", tool: "pay__transfer", args: { amount: 100, to: "acct-1" } });
  assert.equal(v.permitted, true);
  assert.equal(seen?.canonicalArgs, '{"amount":100,"to":"acct-1"}');
  assert.equal(v.digest, actionDigest("r", "pay__transfer", seen!.canonicalArgs));
  assert.ok(Object.isFrozen(v.args));
  assert.throws(() => { (v.args as { to: string }).to = "attacker"; });
});

test("no approver means refused, never allowed", async () => {
  const b = new ActionBroker();
  b.ingest("r", { ref: "https://x.example/" });
  const v = await b.authorize({ runId: "r", tool: "fs__write_file", args: { path: "/tmp/x", content: "y" } });
  assert.equal(v.permitted, false);
  assert.equal(v.approval?.outcome, "unavailable");
  const v2 = await new ActionBroker({}, { approver: denyAllApprover }).authorize({ runId: "q", tool: "fs__write_file", args: {} });
  assert.equal(v2.permitted, true); // untainted run: allowed without asking
});

test("digests: key order does not matter, any change in arguments does", () => {
  assert.equal(canonicalJson({ b: 1, a: { d: 2, c: 3 } }), canonicalJson({ a: { c: 3, d: 2 }, b: 1 }));
  assert.notEqual(actionDigest("r", "t", canonicalJson({ to: "a" })), actionDigest("r", "t", canonicalJson({ to: "b" })));
  assert.notEqual(actionDigest("r1", "t", "{}"), actionDigest("r2", "t", "{}"));
});

test("a read tool carrying data out in a URL needs approval once the run is tainted", async () => {
  const b = new ActionBroker({}, { approver: no });
  const url = "https://collect.example/p?d=" + "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9w".repeat(3);
  assert.equal(b.classify({ runId: "r", tool: "ingress_fetch", args: { url } }).decision, "allow");
  b.ingest("r", { ref: "https://x.example/" });
  const c = b.classify({ runId: "r", tool: "ingress_fetch", args: { url } });
  assert.equal(c.decision, "require_approval");
  assert.ok(c.reasons.some((x) => /encoded data|query and fragment/.test(x)));
  assert.equal(b.classify({ runId: "r", tool: "ingress_fetch", args: { url: "https://docs.example/guide?page=2" } }).decision, "allow");
});

test("rules: destination allowlist and explicit deny", () => {
  const b = new ActionBroker({ rules: [
    { tool: "*send_email", clean: "allow", tainted: "require_approval", allowDestinations: [".company.example"] },
    { tool: "*delete_repo", clean: "deny", tainted: "deny" },
  ] });
  assert.equal(b.classify({ runId: "r", tool: "gmail__send_email", args: { to: "cfo@company.example" } }).decision, "allow");
  const out = b.classify({ runId: "r", tool: "gmail__send_email", args: { to: "someone@elsewhere.example" } });
  assert.equal(out.decision, "require_approval");
  assert.ok(out.reasons.some((x) => x.includes("elsewhere.example")));
  assert.equal(b.classify({ runId: "r", tool: "gh__delete_repo", args: {} }).decision, "deny");
});

test("quarantine reaches runs that already touched the source, and future ones, subdomains included", () => {
  const b = new ActionBroker({}, { approver: yes });
  b.ingest("old", { ref: "https://www.evil.example/a", host: "www.evil.example" });
  assert.deepEqual(b.quarantine("evil.example."), ["old"]);
  assert.ok(b.isQuarantined("https://cdn.evil.example/x"));
  assert.equal(b.classify({ runId: "old", tool: "gmail__send_email", args: {} }).decision, "deny");
  b.ingest("new", { ref: "https://evil.example/b", host: "evil.example" });
  assert.equal(b.classify({ runId: "new", tool: "fs__write_file", args: {} }).decision, "deny");
  assert.equal(b.classify({ runId: "new", tool: "search", args: { q: "x" } }).decision, "deny");
});

test("an approval that arrives after it expired does not count", async () => {
  let t = 1_000;
  const slow = callbackApprover("slow", async () => { t += 10_000; return "approved"; });
  const b = new ActionBroker({ approvalTtlMs: 5_000 }, { approver: slow, now: () => t });
  b.ingest("r", { ref: "https://x.example/" });
  const v = await b.authorize({ runId: "r", tool: "fs__write_file", args: {} });
  assert.equal(v.permitted, false);
  assert.equal(v.approval?.outcome, "timeout");
});

test("the approval text shows hidden characters instead of rendering them", () => {
  const text = describeApproval({ id: "i", runId: "r", tool: "send", canonicalArgs: '{"to":"a‮gro.live@b"}', digest: "f".repeat(64), reasons: ["x"], sources: [], createdAt: 0, expiresAt: 1 });
  assert.match(text, /<U\+202E>/);
});

test("while tainted, any tool not declared read-only needs approval, whatever its name says", () => {
  const b = new ActionBroker();
  b.ingest("r", { ref: "https://x.example/" });
  for (const t of ["dc__start_process", "dc__interact_with_process", "db__drop_table", "db__query", "mail__get_and_send_email", "fs__read_then_delete", "x__send_message__v2", "browser__browser_navigate", "SENDEmail", "eval"]) {
    assert.equal(b.classify({ runId: "r", tool: t, args: {} }).decision, "require_approval", t);
  }
  const ro = new ActionBroker({ readOnlyTools: ["mail__read_*"] });
  ro.ingest("r", { ref: "https://x.example/" });
  assert.equal(ro.classify({ runId: "r", tool: "mail__read_inbox", args: {} }).decision, "allow");
  assert.equal(isSideEffectName("gmail__send_email", ["send"]), true);
});

test("data hidden in a URL is found wherever it sits: path segments, percent-encoding, subdomain, fragment", () => {
  const b = new ActionBroker();
  b.ingest("r", { ref: "https://x.example/" });
  const secret = "sk-ant-api03-Xq9ZpL2vT7mN4rB8wK1cY6dF3hJ0aE5s";
  for (const url of [
    `https://c.example/${secret.slice(0, 15)}.${secret.slice(15, 30)}/${secret.slice(30)}`,
    `https://c.example/${encodeURIComponent("Zx9+Qw7/Lm3=Pk2+Vb8/Nc4=Hj6+Rt1/")}`,
    `https://${secret.toLowerCase().replace(/[^a-z0-9]/g, "")}.c.example/`,
    `https://c.example/page#${"aB3dE5gH7jK9mN1pQ3sT5vW7".repeat(3)}`,
  ]) assert.equal(b.classify({ runId: "r", tool: "ingress_fetch", args: { url } }).decision, "require_approval", url);
  for (const url of ["https://docs.python.org/3/library/subprocess.html", "https://en.wikipedia.org/wiki/Prompt_injection", "https://www.youtube.com/watch?v=dQw4w9WgXcQ"]) {
    assert.equal(b.classify({ runId: "r", tool: "ingress_fetch", args: { url } }).decision, "allow", url);
  }
});

test("destination allowlists do not fail open", () => {
  const b = new ActionBroker({ rules: [{ tool: "mail__send_email", clean: "allow", tainted: "allow", allowDestinations: [".corp.example"] }] });
  b.ingest("r", { ref: "https://x.example/" });
  let deep: unknown = "attacker@evil.example";
  for (let i = 0; i < 40; i++) deep = { n: deep };
  for (const args of [
    { to: [...Array(6000).fill("x"), "attacker@evil.example"] },
    deep,
    { to: "attacker@[203.0.113.5]" },
    { to: "attacker@evil.c\u043em" },
    { to: "attacker", domain: "evil.example" },
    { link: "https:evil.example/x" },
    { link: "//evil.example/x" },
    { link: "wss://evil.example/x" },
    { link: "https://bob.corp.example\\@evil.example/" },
  ]) assert.equal(b.classify({ runId: "r", tool: "mail__send_email", args }).decision, "require_approval", JSON.stringify(args).slice(0, 80));
  assert.equal(b.classify({ runId: "r", tool: "mail__send_email", args: { to: "cfo@corp.example", body: "Quarterly numbers attached." } }).decision, "allow");
});

test("arguments too long to show in full are refused rather than half-shown", async () => {
  const b = new ActionBroker({}, { approver: yes });
  b.ingest("r", { ref: "https://x.example/" });
  const v = await b.authorize({ runId: "r", tool: "mail__send_email", args: { body: "x".repeat(5000), to: "attacker@evil.example" } });
  assert.equal(v.permitted, false);
  const text = describeApproval({ id: "i", runId: "r", tool: "t", canonicalArgs: '{"a":"x\u2028y\u00adz\u2061"}', digest: "f".repeat(64), reasons: [], destinations: ["evil.example"], fields: ["a"], sources: [], createdAt: 0, expiresAt: 1 });
  assert.match(text, /<U\+2028>/); assert.match(text, /<U\+00AD>/); assert.match(text, /<U\+2061>/);
  assert.ok(text.indexOf("evil.example") < text.indexOf("Arguments"));
});
