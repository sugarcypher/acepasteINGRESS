import { test } from "node:test";
import assert from "node:assert/strict";
import {
  parseHidutilList, classifyInputDevices, parseLsofListen, classifyListeners, findTunnels, classifyTunnels, parseLpstatDevices, classifyPrinters,
  parseHardwarePorts, classifyHardwarePorts, auditItemKey,
} from "../src/index.js";

// 0.9.12: the audit looks at what is attached to the machine and what it exposes (Phases 7, 10b, 10d, 11).

const HID = `Services:
VendorID ProductID LocationID UsagePage Usage RegistryID  Transport Class                    Product              UserClass               Built-In
0x0      0x0       0x4950316c 65288     2     0x1000008c0 (null)    AppleSMCKeysEndpoint     PMU ildo1            (null)                  1
0x248a   0x8379    0x2110000  1         6     0x1000010d5 USB       AppleUserHIDEventService Wireless Receiver    AppleUserHIDEventDriver 0
0x248a   0x8379    0x2110000  1         2     0x1000010d6 USB       AppleUserHIDEventService Wireless Receiver    AppleUserHIDEventDriver 0
0x5ac    0x29c     0x0        1         6     0x100001111 Bluetooth AppleUserHIDEventService Magic Keyboard       AppleUserHIDEventDriver 0
0x1234   0xabcd    0x2120000  1         6     0x100001222 USB       AppleUserHIDEventService USB-C Charging Cable AppleUserHIDEventDriver 0
0x46d    0xc52b    0x2130000  1         2     0x100001333 USB       AppleUserHIDEventService USB Optical Mouse    AppleUserHIDEventDriver 0
0x5ac    0x8104    0x0        1         6     0x100000aaa SPI       AppleHIDKeyboardService  Apple Internal Keyboard (null)               1
Devices:
VendorID ProductID LocationID UsagePage Usage RegistryID  Transport Class Product Built-In
`;

test("hidutil: devices that can type are listed; a keyboard that does not look like one is flagged high", () => {
  const devices = parseHidutilList(HID);
  assert.equal(devices.length, 7);
  assert.deepEqual(devices.find((d) => d.product === "Magic Keyboard"), { vendorId: "0x5ac", productId: "0x29c", transport: "Bluetooth", product: "Magic Keyboard", usagePage: 1, usage: 6, builtIn: false });
  const f = classifyInputDevices(devices);
  assert.deepEqual(f.map((x) => [x.severity, x.title]), [
    ["review", "USB device that can type: Wireless Receiver"],
    ["review", "Bluetooth device that can type: Magic Keyboard"],
    ["high", "USB device that can type: USB-C Charging Cable"],
  ]);
  assert.match(f[2].detail, /presents itself as a keyboard/);
  // the mouse, the built-in keyboard and internal sensors are not reported
  assert.ok(!f.some((x) => /Mouse|Internal|PMU/.test(x.title)));
  // an unnamed keyboard is high too
  const unnamed = classifyInputDevices([{ vendorId: "0x1", productId: "0x2", transport: "USB", product: "", usagePage: 1, usage: 6, builtIn: false }]);
  assert.equal(unnamed[0].severity, "high");
});

const LSOF = `COMMAND    PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
rapportd  1001 avalue   11u  IPv4 0x1856305c7a631b31      0t0  TCP *:49790 (LISTEN)
rapportd  1001 avalue   12u  IPv6 0xb288fa724d8e907e      0t0  TCP *:49790 (LISTEN)
node     79147 avalue   12u  IPv4 0x6345cf3120c58221      0t0  TCP 127.0.0.1:8787 (LISTEN)
node     80001 avalue   14u  IPv6 0x6345cf3120c58222      0t0  TCP [::1]:5173 (LISTEN)
ollama   80500 avalue    3u  IPv4 0x6345cf3120c58223      0t0  TCP *:11434 (LISTEN)
Python   80600 avalue    4u  IPv4 0x6345cf3120c58224      0t0  TCP 192.168.1.20:8000 (LISTEN)
`;

test("lsof: listeners are grouped by program and exposure, not by port", () => {
  const ls = parseLsofListen(LSOF);
  assert.equal(ls.length, 6);
  assert.deepEqual(ls.map((l) => [l.command, l.port, l.exposed]), [["rapportd", 49790, true], ["rapportd", 49790, true], ["node", 8787, false], ["node", 5173, false], ["ollama", 11434, true], ["Python", 8000, true]]);
  const f = classifyListeners(ls);
  assert.deepEqual(f.map((x) => [x.severity, x.title]), [
    ["review", "rapportd accepts connections from the network"],
    ["info", "node listens on this machine only"],
    ["high", "ollama accepts connections from the network"],
    ["review", "Python accepts connections from the network"],
  ]);
  assert.match(f[2].detail, /Bind it to 127\.0\.0\.1/);
  // identity: exposed listeners are tracked without their port; local-only ones are not tracked at all
  assert.equal(auditItemKey(f[0]), "lsof | rapportd accepts connections from the network");
  assert.equal(auditItemKey(f[1]), undefined);
});

test("tunnels and reverse forwards are found among running processes; secrets in their arguments are hidden", () => {
  const ps = [
    "  501 /usr/local/bin/ngrok ngrok http 3000 --authtoken 2abcSECRETtoken",
    "  502 /opt/homebrew/bin/cloudflared cloudflared tunnel --url http://localhost:8787",
    "  503 /usr/bin/ssh ssh -N -R 80:localhost:3000 serveo.net",
    "  504 /usr/bin/ssh ssh -D 1080 user@jump.example",
    "  505 /usr/bin/ssh ssh user@server.example",
    "  506 /usr/bin/ssh ssh -L 5432:db.internal:5432 bastion.example",
    "  507 /Applications/Tailscale.app/Contents/MacOS/tailscale tailscale funnel 8080",
    "  508 /usr/local/bin/node node server.js",
    "  509 /usr/local/bin/bore bore local 8000 --to bore.pub",
  ].join("\n");
  const t = findTunnels(ps);
  assert.deepEqual(t.map((x) => x.tool), ["ngrok", "cloudflared", "ssh remote forward", "ssh dynamic forward (SOCKS proxy)", "tailscale funnel", "bore"]);
  assert.ok(!JSON.stringify(t).includes("2abcSECRETtoken"));
  const f = classifyTunnels(t);
  assert.ok(f.every((x) => x.area === "tunnels" && x.severity === "review"));
  assert.match(f[0].detail, /leaves the machine/);
  assert.deepEqual(findTunnels("  1 /usr/bin/ssh ssh host\n  2 /bin/zsh -zsh\n"), []);
});

test("printers: local ones are noted, remote ones and name twins are for review", () => {
  const lp = [
    "device for Brother_HL_L2420DW: dnssd://Brother%20HL-L2420DW._ipps._tcp.local./?uuid=e3248000-80ce-11db-8000-acf23cf7700e",
    "device for Office_Laser: ipps://192.168.1.50/ipp/print",
    "device for Office_Laser_2: ipp://203.0.113.77/ipp/print",
    "device for Label: usb://Brother/QL-800?serial=000A1B",
  ].join("\n");
  const printers = parseLpstatDevices(lp);
  assert.equal(printers.length, 4);
  const f = classifyPrinters(printers);
  const by = (t: string) => f.find((x) => x.title === t);
  assert.equal(by("printer: Brother_HL_L2420DW")?.severity, "info");
  assert.equal(by("printer: Office_Laser")?.severity, "info");
  assert.equal(by("printer: Label")?.severity, "info");
  const remote = by("printer: Office_Laser_2");
  assert.equal(remote?.severity, "review");
  assert.match(remote!.detail, /outside the local network, without encryption/);
  assert.ok(f.some((x) => /two printers share a name: Office_Laser and Office_Laser_2/.test(x.title)));
  assert.deepEqual(parseLpstatDevices("lpstat: No destinations added."), []);
});

test("network interfaces are tracked by port name, so a re-plugged adapter is the same item and a new one is not", () => {
  const hw = `
Hardware Port: Ethernet
Device: en0
Ethernet Address: 1c:f6:4c:62:8a:17

Hardware Port: USB 10/100/1000 LAN
Device: en6
Ethernet Address: d0:c0:bf:4e:46:d9

Hardware Port: Ethernet Adapter (en5)
Device: en5
Ethernet Address: c2:52:3b:54:d9:e7

Hardware Port: Wi-Fi
Device: en1
Ethernet Address: 1c:f6:4c:62:8a:18
`;
  const ports = parseHardwarePorts(hw);
  assert.deepEqual(ports.map((p) => p.port), ["Ethernet", "USB 10/100/1000 LAN", "Ethernet Adapter (en5)", "Wi-Fi"]);
  const f = classifyHardwarePorts(ports);
  assert.deepEqual(f.map((x) => x.title), ["network interface: Ethernet", "network interface: USB 10/100/1000 LAN", "network interface: Ethernet Adapter", "network interface: Wi-Fi"]);
  assert.match(f[1].detail, /plug-in network adapter/);
  assert.ok(!f.some((x) => /1c:f6|d0:c0/.test(x.title + x.detail)), "hardware addresses are not reported");
});
