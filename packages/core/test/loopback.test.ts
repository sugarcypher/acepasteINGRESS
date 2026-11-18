import { test } from "node:test";
import assert from "node:assert/strict";
import { checkTarget, isPrivateIP, NetPolicyError, DEFAULT_NET_POLICY, checkLocalRequest, isLoopbackBind } from "../src/index.js";

// Phase 11 (0.9.8): every spelling of a loopback or private address is refused, and a loopback-bound
// service refuses requests that are not addressed to it.

const publicResolver = async () => ["93.184.216.34"];
const refused = (url: string, resolver: (h: string) => Promise<string[]> = publicResolver) =>
  assert.rejects(checkTarget(new URL(url), DEFAULT_NET_POLICY, resolver), (e: NetPolicyError) => e.code === "private_address", url);

test("every way to write a loopback address is refused", async () => {
  for (const url of [
    "http://127.0.0.1/", "http://127.1/", "http://127.0.1/", "http://2130706433/", "http://0x7f000001/", "http://0x7f.0.0.1/",
    "http://0177.0.0.1/", "http://017700000001/", "http://0.0.0.0/", "http://0/",
    "http://[::1]/", "http://[::]/", "http://[0:0:0:0:0:0:0:1]/", "http://[0000:0000:0000:0000:0000:0000:0000:0001]/",
    "http://[::ffff:127.0.0.1]/", "http://[::ffff:7f00:1]/", "http://[::127.0.0.1]/",
    "http://localhost/", "http://LOCALHOST/", "http://localhost./", "http://app.localhost/", "http://printer.local/",
  ]) await refused(url);
});

test("a public name that resolves to loopback or private space is refused, whatever the spelling", async () => {
  for (const addr of ["127.0.0.1", "127.8.8.8", "::1", "0:0:0:0:0:0:0:1", "::ffff:127.0.0.1", "::ffff:7f00:1", "::ffff:a00:1", "10.0.0.5", "192.168.1.10", "169.254.169.254", "fe80::1%en0", "fd12:3456::1", "2002:7f00:1::", "2002:c0a8:101::1", "64:ff9b::7f00:1"]) {
    await refused("http://rebind.example/", async () => [addr]);
  }
  // one private answer among public ones is enough to refuse: the connection could go to any of them
  await refused("http://mixed.example/", async () => ["93.184.216.34", "127.0.0.1"]);
});

test("IPv6 spellings agree, and an unparseable address counts as blocked", () => {
  for (const ip of ["::1", "0:0:0:0:0:0:0:1", "0000:0000:0000:0000:0000:0000:0000:0001", "::ffff:127.0.0.1", "::FFFF:7F00:1", "0:0:0:0:0:ffff:7f00:1", "::", "fe80::1", "FE80::1%lo0", "febf::1", "fc00::1", "fdff::1", "ff02::1", "2001:db8::1", "2002:a00:1::", "::10.0.0.1", "fec0::1"]) assert.ok(isPrivateIP(ip), ip);
  for (const ip of ["2606:4700::1111", "2001:4860:4860::8888", "2002:808:808::1", "::ffff:8.8.8.8"]) assert.ok(!isPrivateIP(ip), ip);
  for (const ip of ["not-an-ip", "1.2.3", "12345::1", ":::1"]) assert.ok(isPrivateIP(ip), ip);
});

test("public addresses still pass", async () => {
  assert.deepEqual(await checkTarget(new URL("https://example.com/"), DEFAULT_NET_POLICY, publicResolver), ["93.184.216.34"]);
  assert.deepEqual(await checkTarget(new URL("https://[2606:4700::1111]/"), DEFAULT_NET_POLICY), ["2606:4700::1111"]);
});

test("a loopback-bound service accepts only requests addressed to itself", () => {
  const opts = { port: 8787 };
  for (const host of ["127.0.0.1:8787", "localhost:8787", "LOCALHOST:8787", "[::1]:8787", "localhost.:8787"]) assert.deepEqual(checkLocalRequest({ host }, opts), { ok: true }, host);
  // DNS rebinding: the browser sends the attacker's name, which now points at 127.0.0.1
  for (const host of ["evil.example:8787", "127.0.0.1.evil.example:8787", "localhost.evil.example:8787", "127.0.0.1:9999", "127.0.0.1", "localhost", "127.0.0.2:8787", "0.0.0.0:8787", "8787", ""]) {
    assert.equal(checkLocalRequest({ host }, opts).ok, false, host);
  }
  assert.equal(checkLocalRequest({}, opts).ok, false);
  for (const host of ["127.0.0.1:8787/path", "user@127.0.0.1:8787", "127.0.0.1:8787 evil", "127.0.0.1:8787\r\nx: y"]) assert.equal(checkLocalRequest({ host }, opts).ok, false, host);
});

test("a loopback-bound service refuses cross-site requests and accepts its own pages", () => {
  const opts = { port: 8787 };
  const host = "127.0.0.1:8787";
  for (const origin of ["http://127.0.0.1:8787", "http://localhost:8787", "http://[::1]:8787"]) assert.deepEqual(checkLocalRequest({ host, origin }, opts), { ok: true }, origin);
  for (const origin of ["https://evil.example", "http://evil.example:8787", "null", "http://127.0.0.1:3000", "http://localhost", "file://", "chrome-extension://abcdef", "http://127.0.0.1:8787.evil.example", ""]) {
    const v = checkLocalRequest({ host, origin }, opts);
    assert.equal(v.ok, false, origin);
    if (!v.ok) assert.match(v.reason, /cross-site/);
  }
});

test("extra allowed hosts: a bare name matches any port, a name with a port matches that port", () => {
  // behind a reverse proxy the public port is not this process's port
  const proxied = { port: 8787, allowedHosts: ["gate.example."] };
  assert.equal(checkLocalRequest({ host: "gate.example" }, proxied).ok, true);
  assert.equal(checkLocalRequest({ host: "gate.example:443", origin: "https://gate.example" }, proxied).ok, true);
  assert.equal(checkLocalRequest({ host: "gate.example", origin: "https://evil.example" }, proxied).ok, false);
  assert.equal(checkLocalRequest({ host: "other.example" }, proxied).ok, false);
  assert.equal(checkLocalRequest({ host: "gate.example.evil.example" }, proxied).ok, false);
  const pinned = { port: 8787, allowedHosts: ["10.0.0.5:8443"] };
  assert.equal(checkLocalRequest({ host: "10.0.0.5:8443" }, pinned).ok, true);
  assert.equal(checkLocalRequest({ host: "10.0.0.5:9000" }, pinned).ok, false);
  // loopback names always need this service's own port
  assert.equal(checkLocalRequest({ host: "127.0.0.1:8443" }, pinned).ok, false);
});

test("which listen addresses count as loopback", () => {
  for (const h of ["127.0.0.1", "127.5.6.7", "localhost", "::1", "[::1]"]) assert.ok(isLoopbackBind(h), h);
  for (const h of [undefined, "", "0.0.0.0", "::", "192.168.1.5", "example.com"]) assert.ok(!isLoopbackBind(h), String(h));
});
