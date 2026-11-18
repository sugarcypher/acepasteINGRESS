/**
 * Environment audit, local side: what is attached to this machine and what it exposes.
 * Pure parsers and classifiers (no file, process or network access here). Collectors are in audit.ts.
 *
 *   input devices   A device that presents itself as a keyboard types as the person. In an agent's terminal
 *                   keystrokes are the user, so no content check ever sees them (BadUSB, "rubber ducky"
 *                   cables, an unauthenticated Bluetooth keyboard). The audit cannot watch typing; it can say
 *                   which keyboards exist, so a new one is noticed.
 *   listening       What accepts connections, and whether from this machine only or from the network.
 *                   Identity is the program and its exposure, not the port (ports change on every restart).
 *   tunnels         A tunnel or reverse forward turns a local port into an internet address: "localhost"
 *                   stops being local.
 *   printers        A printer's name and address are set by whoever is on the network; a print job sends a
 *                   document there.
 *   interfaces      A new network adapter (a USB Ethernet dongle) can take over routing and DNS.
 */

import type { AuditFinding } from "./audit-parsers.js";

// ---------- input devices (macOS: hidutil list) ----------

export interface HidDevice {
  vendorId: string;
  productId: string;
  transport: string;
  product: string;
  usagePage: number;
  usage: number;
  builtIn: boolean;
}

/** Parse `hidutil list`. Columns are fixed-width; the header gives their positions. */
export function parseHidutilList(text: string): HidDevice[] {
  const lines = text.split(/\r?\n/);
  const out: HidDevice[] = [];
  let cols: Array<{ name: string; start: number }> | undefined;
  for (const line of lines) {
    if (/^VendorID\s+ProductID/.test(line)) {
      cols = [...line.matchAll(/\S+/g)].map((m) => ({ name: m[0], start: m.index! }));
      continue;
    }
    if (!cols || !/^0x[0-9a-f]+\s/i.test(line)) { if (/^\w+:\s*$/.test(line)) cols = undefined; continue; }
    const cell = (name: string) => {
      const i = cols!.findIndex((c) => c.name === name);
      if (i < 0) return "";
      return line.slice(cols![i].start, i + 1 < cols!.length ? cols![i + 1].start : undefined).trim();
    };
    out.push({
      vendorId: cell("VendorID").toLowerCase(), productId: cell("ProductID").toLowerCase(), transport: cell("Transport").replace(/^\(null\)$/, ""),
      product: cell("Product").replace(/^\(null\)$/, ""), usagePage: Number(cell("UsagePage")) || 0, usage: Number(cell("Usage")) || 0, builtIn: cell("Built-In") === "1",
    });
  }
  return out;
}

/** names that say the device is something other than a keyboard */
const NOT_A_KEYBOARD = /\b(cable|charger|charging|power ?bank|flash|drive|disk|storage|card ?reader|hub|adapter|dongle|camera|webcam|headset|headphone|speaker|audio|microphone|lan|ethernet|display|monitor|light|fan|usb ?c)\b/i;
const KEYBOARD_NAME = /\b(keyboard|keypad|kbd|receiver|magic|mx ?keys|k\d{2,3}|keychron|hhkb|planck|ergodox|corne|moonlander|numpad|macropad|stream ?deck|yubikey|security key|titan|scanner|barcode)\b/i;

export function classifyInputDevices(devices: readonly HidDevice[]): AuditFinding[] {
  // one physical device has several HID interfaces; it is a keyboard if any of them is (generic desktop page 1, usage 6 or 7)
  const byDevice = new Map<string, { d: HidDevice; keyboard: boolean }>();
  for (const d of devices) {
    if (d.builtIn || !d.transport) continue;
    const id = `${d.vendorId}:${d.productId}:${d.product}`;
    const e = byDevice.get(id) ?? { d, keyboard: false };
    if (d.usagePage === 1 && (d.usage === 6 || d.usage === 7)) e.keyboard = true;
    byDevice.set(id, e);
  }
  const out: AuditFinding[] = [];
  for (const { d, keyboard } of byDevice.values()) {
    if (!keyboard) continue;
    const name = d.product || "(unnamed device)";
    const odd = NOT_A_KEYBOARD.test(name) && !KEYBOARD_NAME.test(name);
    const unnamed = !d.product;
    out.push({
      area: "input-devices", severity: odd || unnamed ? "high" : "review",
      title: `${d.transport} device that can type: ${name}`,
      detail: odd
        ? `"${name}" (${d.vendorId}:${d.productId}) presents itself as a keyboard, which its name does not suggest. A device that types acts as you: in an agent's terminal its keystrokes are your prompts. Unplug it unless you know why it needs to type.`
        : unnamed
          ? `An unnamed ${d.transport} device (${d.vendorId}:${d.productId}) presents itself as a keyboard. A device that types acts as you.`
          : `"${name}" (${d.vendorId}:${d.productId}) can type. Yours if you recognise it; a keyboard you did not attach acts as you.`,
      where: `${d.transport} ${d.vendorId}:${d.productId}`,
    });
  }
  return out;
}

// ---------- listening services (lsof -nP -iTCP -sTCP:LISTEN) ----------

export interface Listener { command: string; pid: number; user: string; address: string; port: number; exposed: boolean }

export function parseLsofListen(text: string): Listener[] {
  const out: Listener[] = [];
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^(\S+)\s+(\d+)\s+(\S+)\s+.*\sTCP\s+(\S+):(\d+)\s+\(LISTEN\)\s*$/);
    if (!m) continue;
    const address = m[4].replace(/^\[|\]$/g, "");
    const loopback = address === "localhost" || address === "::1" || /^127\./.test(address);
    out.push({ command: m[1].replace(/\\x20/g, " "), pid: Number(m[2]), user: m[3], address, port: Number(m[5]), exposed: !loopback });
  }
  return out;
}

/** programs that serve a model or agent tools; exposed to the network without a login they hand both to anyone nearby */
const AI_SERVERS = /^(ollama|lm ?studio|lms|llama-server|llama\.cpp|koboldcpp|text-generation|oobabooga|vllm|localai|jan|open-webui|comfyui|invokeai|mcp[-\w]*|claude)$/i;

export function classifyListeners(listeners: readonly Listener[]): AuditFinding[] {
  const by = new Map<string, { command: string; exposed: boolean; ports: Set<number>; users: Set<string> }>();
  for (const l of listeners) {
    const key = `${l.command}|${l.exposed}`;
    const e = by.get(key) ?? { command: l.command, exposed: l.exposed, ports: new Set<number>(), users: new Set<string>() };
    e.ports.add(l.port); e.users.add(l.user);
    by.set(key, e);
  }
  const out: AuditFinding[] = [];
  for (const e of by.values()) {
    const ports = [...e.ports].sort((a, b) => a - b).slice(0, 8).join(", ");
    const ai = AI_SERVERS.test(e.command);
    if (e.exposed) {
      out.push({
        area: "listening", severity: ai ? "high" : "review",
        title: `${e.command} accepts connections from the network`,
        detail: ai
          ? `${e.command} looks like a model or tool server and listens on every interface (port ${ports}). Anyone on the same network can use it, and what it returns reaches your agents as if it were local. Bind it to 127.0.0.1 unless you mean to share it.`
          : `Port ${ports}. Reachable from other machines on the network. Yours if you turned on a sharing feature or run a server on purpose.`,
        where: "lsof",
      });
    } else {
      out.push({
        area: "listening", severity: "info",
        title: `${e.command} listens on this machine only`,
        detail: `Port ${ports}. Reachable only from this machine. Programs here, including web pages in a browser, can still talk to it; content it serves is not trusted because it is local.`,
        where: "lsof",
      });
    }
  }
  return out;
}

// ---------- tunnels (ps -axo pid=,comm=,args=) ----------

export interface Tunnel { tool: string; detail: string }

export function findTunnels(psOutput: string): Tunnel[] {
  const out: Tunnel[] = [];
  for (const raw of psOutput.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    const args = line.replace(/^\d+\s+\S+\s+/, "");
    const prog = (args.split(/\s+/)[0] ?? "").split("/").pop() ?? "";
    const short = args.replace(/(--?(?:authtoken|token|password|key|secret)[=\s]+)\S+/gi, "$1[hidden]").slice(0, 160);
    if (/^ngrok$/i.test(prog) && /\b(http|tcp|tls|start|tunnel)\b/.test(args)) out.push({ tool: "ngrok", detail: short });
    else if (/^cloudflared$/i.test(prog) && /\btunnel\b/.test(args)) out.push({ tool: "cloudflared", detail: short });
    else if (/^ssh$/.test(prog) && /\s-[A-Za-z]*[RD]\b|\s-[A-Za-z]*R\s*\d|RemoteForward|DynamicForward/.test(args)) out.push({ tool: /\s-[A-Za-z]*D\b|DynamicForward/.test(args) ? "ssh dynamic forward (SOCKS proxy)" : "ssh remote forward", detail: short });
    else if (/^tailscale$/i.test(prog) && /\b(funnel|serve)\b/.test(args)) out.push({ tool: `tailscale ${/funnel/.test(args) ? "funnel" : "serve"}`, detail: short });
    else if (/^(frpc|bore|lt|localtunnel|devtunnel|zrok|pinggy|localhost\.run|serveo|pagekite(\.py)?|chisel|inlets)$/i.test(prog)) out.push({ tool: prog, detail: short });
    else if (/^ssh$/.test(prog) && /(serveo\.net|localhost\.run|pinggy\.io|tunnelto|tmate\.io)/.test(args)) out.push({ tool: "ssh tunnel service", detail: short });
  }
  return out;
}

export function classifyTunnels(tunnels: readonly Tunnel[]): AuditFinding[] {
  return tunnels.map((t) => ({
    area: "tunnels" as const, severity: "review" as const,
    title: `tunnel open: ${t.tool}`,
    detail: `${t.detail}. A tunnel gives a port on this machine an address on the internet (or carries this machine's traffic elsewhere). Data an agent sends to that local port leaves the machine. Yours if you started it.`,
    where: "running processes",
  }));
}

// ---------- printers (lpstat -v) ----------

export interface Printer { name: string; uri: string }

export function parseLpstatDevices(text: string): Printer[] {
  const out: Printer[] = [];
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^device for (.+?):\s+(\S.*)$/);
    if (m) out.push({ name: m[1], uri: m[2].trim() });
  }
  return out;
}

const normName = (n: string) => n.toLowerCase().replace(/[^a-z0-9]+/g, "");

export function classifyPrinters(printers: readonly Printer[]): AuditFinding[] {
  const out: AuditFinding[] = [];
  const seen = new Map<string, Printer>();
  for (const p of printers) {
    let host = "", scheme = "";
    try { const u = new URL(p.uri); host = decodeURIComponent(u.hostname); scheme = u.protocol.replace(":", ""); } catch { scheme = p.uri.split(":")[0]; }
    const local = scheme === "usb" || scheme === "dnssd" || /\.local\.?$/i.test(host) || /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|f[cd]|fe80)/i.test(host);
    const twin = seen.get(normName(p.name).replace(/\d+$/, ""));
    if (twin && twin.uri !== p.uri) {
      out.push({ area: "printers", severity: "review", title: `two printers share a name: ${twin.name} and ${p.name}`, detail: `They point to different addresses (${twin.uri.slice(0, 80)} and ${p.uri.slice(0, 80)}). A printer that copies the name of one you use receives the documents meant for it.`, where: "lpstat -v" });
    } else seen.set(normName(p.name).replace(/\d+$/, ""), p);
    out.push({
      area: "printers", severity: local ? "info" : "review",
      title: `printer: ${p.name}`,
      detail: local
        ? `${p.uri.slice(0, 120)}. On this machine or the local network. A print job sends the document there.`
        : `${p.uri.slice(0, 120)}. This printer is reached at an address outside the local network${scheme === "ipp" || scheme === "http" || scheme === "lpd" || scheme === "socket" ? ", without encryption" : ""}: every document printed to it leaves the building.`,
      where: p.uri.slice(0, 120),
    });
  }
  return out;
}

// ---------- network interfaces (macOS: networksetup -listallhardwareports) ----------

export interface HardwarePort { port: string; device: string }

export function parseHardwarePorts(text: string): HardwarePort[] {
  const out: HardwarePort[] = [];
  let port: string | undefined;
  for (const line of text.split(/\r?\n/)) {
    const p = line.match(/^Hardware Port:\s*(.+)$/);
    if (p) { port = p[1].trim(); continue; }
    const d = line.match(/^Device:\s*(\S+)/);
    if (d && port) { out.push({ port, device: d[1] }); port = undefined; }
  }
  return out;
}

export function classifyHardwarePorts(ports: readonly HardwarePort[]): AuditFinding[] {
  return ports.map((p) => {
    const usb = /usb|lan adapter|dongle|rndis|tether|iphone|android/i.test(p.port);
    return {
      area: "network-interfaces" as const, severity: "info" as const,
      // the device name (en6) changes when adapters are re-plugged; the port's name is the identity
      title: `network interface: ${p.port.replace(/\s*\(en\d+\)$/, "")}`,
      detail: usb
        ? `${p.device}. A plug-in network adapter. One you did not attach can take over routing and name resolution for the whole machine.`
        : `${p.device}.`,
      where: "networksetup",
    };
  });
}
