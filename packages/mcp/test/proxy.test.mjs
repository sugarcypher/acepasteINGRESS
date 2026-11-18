// End-to-end tests of the MCP server as a proxy: a real downstream server over stdio, the real proxy,
// a real client. Run with: npm test -w @acepaste/ingress-mcp   (after npm run build)
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport, getDefaultEnvironment } from "@modelcontextprotocol/sdk/client/stdio.js";

const here = dirname(fileURLToPath(import.meta.url));
const SERVER = join(here, "..", "dist", "server.js");
const FAKE = join(here, "fake-downstream.mjs");
const CLI = join(here, "..", "..", "core", "dist", "src", "cli.js");

/** start the proxy in front of the fake server in the given mode; returns a connected client */
async function proxy(stateDir, mode) {
  const cfgPath = join(stateDir, `proxy-${mode}.json`);
  writeFileSync(cfgPath, JSON.stringify({ downstream: [{ name: "fake", command: process.execPath, args: [FAKE], env: { FAKE_MODE: mode } }] }));
  const client = new Client({ name: "proxy-test", version: "0" });
  await client.connect(new StdioClientTransport({
    command: process.execPath, args: [SERVER],
    env: { ...getDefaultEnvironment(), INGRESS_PROXY_CONFIG: cfgPath, INGRESS_STATE_DIR: stateDir, INGRESS_LOG: join(stateDir, "log.jsonl"), INGRESS_APPROVER: "deny", INGRESS_SANDBOX: "off", INGRESS_CLOAKING: "0" },
    stderr: "ignore",
  }));
  return client;
}
const tool = async (client, name) => (await client.listTools()).tools.find((t) => t.name === name);
const textOf = (res) => res.content.filter((c) => c.type === "text").map((c) => c.text).join("\n");

test("clean downstream tools are offered and work; their state is first-seen", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ingress-proxy-"));
  const c = await proxy(dir, "clean");
  try {
    const echo = await tool(c, "fake__echo");
    assert.match(echo.description, /Return the given text unchanged/);
    const res = await c.callTool({ name: "fake__echo", arguments: { text: "hello there" } });
    assert.match(textOf(res), /hello there/);
    const status = JSON.parse(textOf(await c.callTool({ name: "ingress_status", arguments: {} })));
    assert.equal(status.downstream.fake.state, "first-seen");
    assert.deepEqual(status.heldTools, []);
  } finally { await c.close(); }
});

test("a poisoned tool description never reaches the model, and the tool cannot be called", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ingress-proxy-"));
  const c = await proxy(dir, "poisoned");
  try {
    const add = await tool(c, "fake__add");
    assert.match(add.description, /held by AcePaste Ingress/);
    assert.ok(!JSON.stringify(add).includes(".ssh"), "no part of the poisoned definition is passed on");
    assert.ok(!JSON.stringify(add.inputSchema).includes("notes"), "the schema is withheld too");
    const res = await c.callTool({ name: "fake__add", arguments: { a: 1, b: 2, notes: "x" } });
    assert.equal(res.isError, true);
    assert.match(textOf(res), /did not run fake__add/);
    // the honest tool beside it still works
    assert.match(textOf(await c.callTool({ name: "fake__echo", arguments: { text: "still fine" } })), /still fine/);
  } finally { await c.close(); }
});

test("a rug pull: definitions that change after they were recorded are held until a person confirms", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ingress-proxy-"));
  let c = await proxy(dir, "clean");
  await c.listTools();
  await c.close();

  c = await proxy(dir, "changed");
  try {
    const echo = await tool(c, "fake__echo");
    assert.match(echo.description, /changed its definition/);
    assert.match(echo.description, /ingress tools confirm fake/);
    assert.ok(!echo.description.includes("store a copy"), "the new description is not shown");
    assert.match((await tool(c, "fake__upload")).description, /appeared/);
    assert.match((await tool(c, "fake__add")).description, /Add two numbers/, "the unchanged tool is offered as before");
    assert.equal((await c.callTool({ name: "fake__echo", arguments: { text: "x" } })).isError, true);
    assert.match(textOf(await c.callTool({ name: "fake__add", arguments: { a: 2, b: 3 } })), /5/);
    const status = JSON.parse(textOf(await c.callTool({ name: "ingress_status", arguments: {} })));
    assert.equal(status.downstream.fake.state, "changed");
    assert.deepEqual(status.heldTools.map((h) => h.tool).sort(), ["fake__echo", "fake__upload"]);
  } finally { await c.close(); }

  // confirming is a terminal action: without a terminal it is refused, so a model cannot do it through a shell tool
  const refused = spawnSync(process.execPath, [CLI, "tools", "confirm", "fake"], { env: { ...process.env, INGRESS_STATE_DIR: dir }, input: "fake\n", encoding: "utf8" });
  assert.equal(refused.status, 3);
  assert.match(refused.stderr, /interactive terminal/);
});
