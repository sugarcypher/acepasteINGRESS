import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  Blocklist, BLOCKLIST_FEEDS, updateBlocklists, blocklistsRefreshedAt, blocklistRefreshDue, claimBlocklistRefresh, startBlocklistRefresh,
  BLOCKLIST_MAX_AGE_MS, BLOCKLIST_RETRY_MS,
} from "../src/index.js";

// 0.9.25: the blocklists refresh themselves. Nothing here touches the network: the download and the process
// start are both passed in.

const fresh = () => join(mkdtempSync(join(tmpdir(), "ingress-bl-")), "blocklists");
const list = (n: number) => Array.from({ length: n }, (_, i) => `198.51.100.${i + 1}`).join("\n");
const age = (dir: string, name: string, ms: number, now: number) => { const t = new Date(now - ms); utimesSync(join(dir, `${name}.txt`), t, t); };

test("blocklist update: a download is kept only if it parses as a list, and a failed feed keeps its previous copy", async () => {
  const dir = fresh();
  const feeds = BLOCKLIST_FEEDS.slice(0, 3);
  const asked: string[] = [];
  const first = await updateBlocklists(dir, { feeds, fetchText: async (url) => { asked.push(url); return { ok: true, status: 200, text: list(8) }; } });
  assert.deepEqual(asked, feeds.map((f) => f.url), "only the listed feed addresses are contacted");
  assert.ok(first.every((f) => f.entries === 8 && !f.error));
  assert.equal(Blocklist.load(dir).match("198.51.100.3"), "198.51.100.3");
  // next time: one feed answers with a block page, one with an error, one with a real list
  const answers = [
    { ok: true, status: 200, text: "<html><body>Access denied. Too many requests.</body></html>" },
    { ok: false, status: 503, text: "" },
    { ok: true, status: 200, text: list(12) },
  ];
  let i = 0;
  const second = await updateBlocklists(dir, { feeds, fetchText: async () => answers[i++] });
  assert.match(second[0].error ?? "", /keeping the previous copy/);
  assert.match(second[1].error ?? "", /HTTP 503/);
  assert.equal(second[2].entries, 12);
  assert.match(readFileSync(join(dir, `${feeds[0].name}.txt`), "utf8"), /198\.51\.100\.8/, "the block page did not replace the list");
  assert.doesNotMatch(readFileSync(join(dir, `${feeds[0].name}.txt`), "utf8"), /Access denied/);
});

test("blocklist refresh is due when no list was downloaded or the newest is over a day old; a person's own list does not count", async () => {
  const dir = fresh();
  const now = Date.parse("2026-11-20T12:00:00Z");
  assert.equal(blocklistsRefreshedAt(dir), undefined);
  assert.equal(blocklistRefreshDue(dir, now), true, "nothing downloaded yet");
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "my-own.txt"), "bad.example\n");
  assert.equal(blocklistRefreshDue(dir, now), true, "a hand-made list is not a download");
  await updateBlocklists(dir, { fetchText: async () => ({ ok: true, status: 200, text: list(6) }) });
  for (const f of BLOCKLIST_FEEDS) age(dir, f.name, 2 * 3600 * 1000, now);
  assert.equal(blocklistRefreshDue(dir, now), false, "two hours old");
  for (const f of BLOCKLIST_FEEDS) age(dir, f.name, BLOCKLIST_MAX_AGE_MS + 60_000, now);
  assert.equal(blocklistRefreshDue(dir, now), true, "over a day old");
  // one feed that keeps failing does not hide that the others are current
  age(dir, BLOCKLIST_FEEDS[0].name, 3600 * 1000, now);
  assert.equal(blocklistRefreshDue(dir, now), false);
});

test("blocklist refresh starts one detached update, never twice at once, never when turned off, and never throws", () => {
  const dir = fresh();
  const now = Date.parse("2026-11-20T12:00:00Z");
  const started: string[][] = [];
  const spawnImpl = (_command: string, args: string[]) => { started.push(args); };
  const go = (at: number, env: Record<string, string | undefined> = { INGRESS_BLOCKLIST_AUTO: "on" }) => startBlocklistRefresh({ dir, env, now: () => at, cli: "/x/cli.js", spawnImpl });
  assert.equal(go(now, {}), "off", "unset means off");
  assert.equal(go(now, { INGRESS_BLOCKLIST_AUTO: "off" }), "off");
  assert.equal(existsSync(dir), false, "turned off, it leaves no trace");
  assert.equal(go(now), "started");
  assert.deepEqual(started, [["/x/cli.js", "blocklist", "update", "--quiet"]]);
  // a second session starting a moment later, and a third after the download failed: nothing more for an hour
  assert.equal(go(now + 1000), "recently-tried");
  assert.equal(go(now + BLOCKLIST_RETRY_MS - 1000), "recently-tried");
  assert.equal(started.length, 1);
  assert.equal(go(now + BLOCKLIST_RETRY_MS + 1000), "started", "after an hour it tries again");
  assert.equal(claimBlocklistRefresh(dir, now + BLOCKLIST_RETRY_MS + 2000), false);
  // lists that are current: nothing starts
  const dir2 = fresh();
  mkdirSync(dir2, { recursive: true });
  for (const f of BLOCKLIST_FEEDS) writeFileSync(join(dir2, `${f.name}.txt`), list(6));
  assert.equal(startBlocklistRefresh({ dir: dir2, env: { INGRESS_BLOCKLIST_AUTO: "on" }, cli: "/x/cli.js", spawnImpl }), "fresh");
  // a process that cannot be started is a refresh that did not happen, not an error for the caller
  assert.equal(startBlocklistRefresh({ dir: fresh(), env: { INGRESS_BLOCKLIST_AUTO: "on" }, now: () => now, cli: "/x/cli.js", spawnImpl: () => { throw new Error("spawn EAGAIN"); } }), "failed");
  assert.equal(startBlocklistRefresh({ dir: fresh(), env: { INGRESS_BLOCKLIST_AUTO: "on" }, now: () => now, cli: "/nonexistent/cli.js" }), "failed");
});
