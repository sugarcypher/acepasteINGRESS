/**
 * Environment audit (collectors). Read-only: it reads settings files and runs a few
 * read-only system commands; it changes nothing. Secrets are never printed (MCP env
 * values, proxy credentials). macOS is covered most fully; Linux partly; what was not
 * checked is listed in `checked`, so a short report is never mistaken for a clean one.
 */

import { execFile } from "node:child_process";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { homedir, platform, networkInterfaces } from "node:os";
import { join } from "node:path";
import { lookup } from "node:dns/promises";
import { connect } from "node:tls";
import { createHash } from "node:crypto";
import { compareServed } from "./engine.js";
import {
  classifyHosts, classifyDnsmasq, classifyDnscryptRules, classifyResolvConf, classifyScutilDns, classifyScutilProxy, classifyProxyEnv,
  classifyChromiumSearch, classifyExtension, classifyChromiumPolicy, classifyTrustSettings, classifySystemExtensions, classifyMcpServers,
  classifyHooks, classifyResolution, summarizeAudit, ipv6Prefix64, WATCHED_DOMAINS, type AuditFinding, type AuditArea, type ExtensionInfo,
} from "./audit-parsers.js";

export interface AuditCheck { area: AuditArea; what: string; status: "checked" | "not present" | "skipped" | "error"; note?: string }
export interface AuditReport { at: string; platform: string; summary: { high: number; review: number; info: number }; findings: AuditFinding[]; checked: AuditCheck[] }
export interface AuditOptions {
  /** also compare name resolution with DNS-over-HTTPS and test TLS to sites agents rely on */
  network?: boolean;
  /** gate for global agent instruction files (the engine's scan); verdicts are added to the report */
  gate?: (text: string, source: string) => Promise<{ tier: string; findings: { kind: string; message: string }[] }>;
  /**
   * compare stable pages fetched from this machine with the same pages fetched by a gate
   * on another network (the hosted service): tampering on this machine's path shows as a
   * difference. Needs that service's API key.
   */
  remote?: { base: string; key: string; urls?: string[]; localFetch: (url: string) => Promise<{ tier: string; delivered: string }> };
  home?: string;
  /** override for tests */
  run?: (cmd: string, args: string[]) => Promise<string | undefined>;
}

const read = (p: string) => { try { return readFileSync(p, "utf8"); } catch { return undefined; } };
const json = (p: string) => { const t = read(p); if (t === undefined) return undefined; try { return JSON.parse(t); } catch { return undefined; } };
const isDir = (p: string) => { try { return statSync(p).isDirectory(); } catch { return false; } };
const ls = (p: string) => { try { return readdirSync(p); } catch { return []; } };

function defaultRun(cmd: string, args: string[]): Promise<string | undefined> {
  return new Promise((res) => execFile(cmd, args, { timeout: 15_000, maxBuffer: 8 * 1024 * 1024 }, (err, out, errOut) => res(err && !out ? (String(errOut || "") || undefined) : String(out))));
}

export async function auditEnvironment(o: AuditOptions = {}): Promise<AuditReport> {
  const home = o.home ?? homedir();
  const run = o.run ?? defaultRun;
  const os = platform();
  const findings: AuditFinding[] = [];
  const checked: AuditCheck[] = [];
  const note = (area: AuditArea, what: string, status: AuditCheck["status"], n?: string) => checked.push({ area, what, status, note: n });

  // ---------- hosts and local DNS ----------
  const hostsPath = os === "win32" ? "C:\\Windows\\System32\\drivers\\etc\\hosts" : "/etc/hosts";
  const hosts = read(hostsPath);
  if (hosts !== undefined) { findings.push(...classifyHosts(hosts, hostsPath)); note("hosts", hostsPath, "checked"); } else note("hosts", hostsPath, "error", "could not read");

  const resolv = read("/etc/resolv.conf");
  if (resolv !== undefined) {
    const prefixes = Object.values(networkInterfaces()).flat().filter((a): a is NonNullable<typeof a> => !!a && a.family === "IPv6" && !a.internal && !/^fe80:/i.test(a.address)).map((a) => ipv6Prefix64(a.address));
    findings.push(...classifyResolvConf(resolv, "/etc/resolv.conf", prefixes)); note("dns", "/etc/resolv.conf", "checked");
  }
  if (os === "darwin") {
    const dns = await run("/usr/sbin/scutil", ["--dns"]);
    if (dns) { findings.push(...classifyScutilDns(dns)); note("dns", "scutil --dns", "checked"); } else note("dns", "scutil --dns", "error");
    for (const f of ls("/etc/resolver")) { const t = read(join("/etc/resolver", f)); if (t) findings.push({ area: "dns", severity: "review", title: `per-domain resolver for ${f}`, detail: `/etc/resolver/${f} sends lookups for ${f} to: ${[...t.matchAll(/nameserver\s+(\S+)/g)].map((m) => m[1]).join(", ") || "(see file)"}.`, where: `/etc/resolver/${f}` }); }
    note("dns", "/etc/resolver", isDir("/etc/resolver") ? "checked" : "not present");
  }
  const dnsmasqFiles = ["/opt/homebrew/etc/dnsmasq.conf", "/usr/local/etc/dnsmasq.conf", "/etc/dnsmasq.conf", ...ls("/opt/homebrew/etc/dnsmasq.d").map((f) => `/opt/homebrew/etc/dnsmasq.d/${f}`), ...ls("/etc/dnsmasq.d").map((f) => `/etc/dnsmasq.d/${f}`)];
  let sawDnsmasq = false;
  for (const p of dnsmasqFiles) {
    const t = read(p);
    if (t === undefined) continue;
    sawDnsmasq = true;
    const r = classifyDnsmasq(t, p);
    findings.push(...r.findings);
    for (const h of r.addnHosts) { const ht = read(h); if (ht) findings.push(...classifyHosts(ht, h)); }
    for (const d of r.confDirs) for (const f of ls(d)) { const ft = read(join(d, f)); if (ft) findings.push(...classifyDnsmasq(ft, join(d, f)).findings); }
  }
  note("dns", "dnsmasq configuration", sawDnsmasq ? "checked" : "not present");
  let sawDnscrypt = false;
  for (const dir of ["/opt/homebrew/etc", "/usr/local/etc", "/etc/dnscrypt-proxy", "/opt/homebrew/etc/dnscrypt-proxy"]) {
    for (const [f, kind] of [["cloaking-rules.txt", "cloaking"], ["forwarding-rules.txt", "forwarding"]] as const) {
      const t = read(join(dir, f));
      if (t !== undefined) { sawDnscrypt = true; findings.push(...classifyDnscryptRules(t, join(dir, f), kind)); }
    }
    if (existsSync(join(dir, "dnscrypt-proxy.toml"))) sawDnscrypt = true;
  }
  note("dns", "dnscrypt-proxy rules", sawDnscrypt ? "checked" : "not present");

  // ---------- proxies ----------
  findings.push(...classifyProxyEnv(process.env));
  note("proxy", "proxy environment variables", "checked");
  if (os === "darwin") {
    const p = await run("/usr/sbin/scutil", ["--proxy"]);
    if (p) { findings.push(...classifyScutilProxy(p)); note("proxy", "scutil --proxy", "checked"); } else note("proxy", "scutil --proxy", "error");
  }

  // ---------- browsers ----------
  const chromiumRoots: Array<[string, string, string[]]> = os === "darwin" ? [
    ["Chrome", join(home, "Library/Application Support/Google/Chrome"), ["com.google.Chrome"]],
    ["Brave", join(home, "Library/Application Support/BraveSoftware/Brave-Browser"), ["com.brave.Browser"]],
    ["Edge", join(home, "Library/Application Support/Microsoft Edge"), ["com.microsoft.Edge"]],
    ["Arc", join(home, "Library/Application Support/Arc/User Data"), ["company.thebrowser.Browser"]],
    ["Vivaldi", join(home, "Library/Application Support/Vivaldi"), ["com.vivaldi.Vivaldi"]],
    ["Chromium", join(home, "Library/Application Support/Chromium"), ["org.chromium.Chromium"]],
  ] : [
    ["Chrome", join(home, ".config/google-chrome"), []], ["Brave", join(home, ".config/BraveSoftware/Brave-Browser"), []],
    ["Edge", join(home, ".config/microsoft-edge"), []], ["Chromium", join(home, ".config/chromium"), []], ["Vivaldi", join(home, ".config/vivaldi"), []],
  ];
  for (const [browser, root, bundles] of chromiumRoots) {
    if (!isDir(root)) { note("browser-search", `${browser}`, "not present"); continue; }
    const profiles = ls(root).filter((d) => d === "Default" || /^Profile \d+$/.test(d));
    for (const prof of profiles) {
      const pdir = join(root, prof);
      const prefs = json(join(pdir, "Preferences")) ?? {};
      const secure = json(join(pdir, "Secure Preferences")) ?? {};
      findings.push(...classifyChromiumSearch(prefs, `${browser} ${prof}`));
      const settings = { ...(prefs.extensions?.settings ?? {}), ...(secure.extensions?.settings ?? {}) };
      for (const x of readChromiumExtensions(join(pdir, "Extensions"), settings)) findings.push(...classifyExtension(x, `${browser} ${prof}`));
    }
    note("browser-search", `${browser} (${profiles.length} profile${profiles.length === 1 ? "" : "s"})`, "checked");
    note("browser-extension", `${browser} extensions`, "checked");
    // policies
    if (os === "darwin") {
      for (const b of bundles) {
        for (const p of [`/Library/Managed Preferences/${b}.plist`, `/Library/Managed Preferences/${process.env.USER ?? ""}/${b}.plist`]) {
          if (!existsSync(p)) continue;
          const j = await run("/usr/bin/plutil", ["-convert", "json", "-o", "-", p]);
          try { if (j) findings.push(...classifyChromiumPolicy(JSON.parse(j), p)); } catch { note("browser-policy", p, "error", "unreadable"); }
        }
      }
      note("browser-policy", `${browser} managed policies`, "checked");
    }
  }
  if (os === "linux") for (const d of ["/etc/opt/chrome/policies/managed", "/etc/chromium/policies/managed", "/etc/brave/policies/managed", "/etc/opt/edge/policies/managed"]) {
    for (const f of ls(d)) { const j = json(join(d, f)); if (j) findings.push(...classifyChromiumPolicy(j, join(d, f))); }
    note("browser-policy", d, isDir(d) ? "checked" : "not present");
  }
  // Firefox: policies, proxy prefs, extensions
  const ffPolicies = os === "darwin" ? "/Applications/Firefox.app/Contents/Resources/distribution/policies.json" : "/etc/firefox/policies/policies.json";
  const ffp = json(ffPolicies);
  if (ffp?.policies) {
    const p = ffp.policies;
    if (p.SearchEngines?.Default || p.SearchEngines?.Add) findings.push({ area: "browser-policy", severity: "high", title: "Firefox policy sets search engines", detail: `Default: ${p.SearchEngines.Default ?? "(unchanged)"}; added: ${(p.SearchEngines.Add ?? []).map((e: any) => e.Name).join(", ")}.`, where: ffPolicies });
    if (p.Proxy) findings.push({ area: "browser-policy", severity: "high", title: "Firefox policy sets a proxy", detail: JSON.stringify(p.Proxy).slice(0, 200), where: ffPolicies });
    if (p.ExtensionSettings || p.Extensions) findings.push({ area: "browser-policy", severity: "review", title: "Firefox policy manages extensions", detail: JSON.stringify(p.ExtensionSettings ?? p.Extensions).slice(0, 200), where: ffPolicies });
    if (p.WebsiteFilter) findings.push({ area: "browser-policy", severity: "review", title: "Firefox policy filters websites", detail: JSON.stringify(p.WebsiteFilter).slice(0, 200), where: ffPolicies });
  }
  const ffRoot = os === "darwin" ? join(home, "Library/Application Support/Firefox/Profiles") : join(home, ".mozilla/firefox");
  if (isDir(ffRoot)) {
    for (const prof of ls(ffRoot).filter((d) => isDir(join(ffRoot, d)))) {
      const prefs = read(join(ffRoot, prof, "prefs.js")) ?? "";
      const ptype = prefs.match(/user_pref\("network\.proxy\.type",\s*(\d)\)/)?.[1];
      if (ptype === "1" || ptype === "2") findings.push({ area: "proxy", severity: "review", title: `Firefox profile ${prof} uses a ${ptype === "2" ? "PAC" : "manual"} proxy`, detail: (prefs.match(/user_pref\("network\.proxy\.(?:autoconfig_url|http)",\s*"([^"]+)"\)/)?.[1]) ?? "", where: join(ffRoot, prof, "prefs.js") });
      const ext = json(join(ffRoot, prof, "extensions.json"));
      for (const a of ext?.addons ?? []) {
        if (a.location === "app-builtin" || a.location === "app-system-defaults" || a.isSystem) continue;
        const perms = [...(a.userPermissions?.permissions ?? []), ...(a.optionalPermissions?.permissions ?? [])];
        const origins = a.userPermissions?.origins ?? [];
        findings.push(...classifyExtension({ id: a.id, name: a.defaultLocale?.name ?? a.id, version: a.version, permissions: perms, hostPermissions: origins, contentMatches: [], searchOverride: undefined, fromStore: a.signedState >= 2 || a.sourceURI?.startsWith?.("https://addons.mozilla.org"), enabled: a.active !== false }, `Firefox ${prof}`));
      }
    }
    note("browser-extension", "Firefox profiles", "checked", "search engine settings are stored compressed and not read");
  } else note("browser-extension", "Firefox", "not present");
  if (os === "darwin") note("browser-search", "Safari", "skipped", "Safari's settings are sandboxed from other programs");

  // ---------- certificates and network extensions ----------
  if (os === "darwin") {
    const admin = await run("/usr/bin/security", ["dump-trust-settings", "-d"]);
    const user = await run("/usr/bin/security", ["dump-trust-settings"]);
    if (admin !== undefined) findings.push(...classifyTrustSettings(admin, "admin"));
    if (user !== undefined) findings.push(...classifyTrustSettings(user, "user"));
    note("certificates", "custom certificate trust (admin and user)", admin !== undefined || user !== undefined ? "checked" : "error");
    const sx = await run("/usr/bin/systemextensionsctl", ["list"]);
    if (sx) { findings.push(...classifySystemExtensions(sx)); note("network-extension", "system extensions", "checked"); } else note("network-extension", "system extensions", "error");
  } else if (os === "linux") {
    const extra = ls("/usr/local/share/ca-certificates");
    for (const c of extra) findings.push({ area: "certificates", severity: "review", title: `locally added CA certificate: ${c}`, detail: "A certificate added to the system trust store. It can be used to read and change encrypted traffic.", where: "/usr/local/share/ca-certificates" });
    note("certificates", "/usr/local/share/ca-certificates", isDir("/usr/local/share/ca-certificates") ? "checked" : "not present");
  }

  // ---------- agent configuration ----------
  const mcpConfigs: Array<[string, string]> = [
    ["Claude Desktop", os === "darwin" ? join(home, "Library/Application Support/Claude/claude_desktop_config.json") : join(home, ".config/Claude/claude_desktop_config.json")],
    ["Claude Code", join(home, ".claude.json")], ["Claude Code settings", join(home, ".claude/settings.json")],
    ["Cursor", join(home, ".cursor/mcp.json")], ["Windsurf", join(home, ".codeium/windsurf/mcp_config.json")],
    ["VS Code", os === "darwin" ? join(home, "Library/Application Support/Code/User/mcp.json") : join(home, ".config/Code/User/mcp.json")],
    ["Gemini CLI", join(home, ".gemini/settings.json")],
  ];
  for (const [label, p] of mcpConfigs) {
    const j = json(p);
    if (!j) { note("agent-config", label, "not present"); continue; }
    findings.push(...classifyMcpServers(j, `${label} (${p})`), ...classifyHooks(j, `${label} (${p})`));
    note("agent-config", label, "checked");
  }
  const globalInstr = [join(home, ".claude/CLAUDE.md"), join(home, ".codex/AGENTS.md"), join(home, ".gemini/GEMINI.md"), join(home, ".codeium/windsurf/memories/global_rules.md"), join(home, ".config/opencode/AGENTS.md"), ...ls(join(home, ".cursor/rules")).map((f) => join(home, ".cursor/rules", f)), ...ls(join(home, ".claude/commands")).map((f) => join(home, ".claude/commands", f)), ...ls(join(home, ".claude/agents")).map((f) => join(home, ".claude/agents", f))];
  for (const p of globalInstr) {
    const t = read(p);
    if (t === undefined) continue;
    const sha = createHash("sha256").update(t).digest("hex").slice(0, 12);
    let verdict = "";
    if (o.gate) {
      const v = await o.gate(t, `file:${p}`);
      if (v.tier !== "clean") {
        findings.push({ area: "agent-instructions", severity: "high", title: `global agent instructions flagged: ${p}`, detail: `Loaded into every session of that agent, and the gate rates it ${v.tier}: ${[...new Set(v.findings.map((f) => f.message))].slice(0, 3).join("; ")}.`, where: p });
        continue;
      }
      verdict = ", gate: clean";
    }
    findings.push({ area: "agent-instructions", severity: "info", title: `global agent instructions: ${p}`, detail: `${t.length} characters, fingerprint ${sha}${verdict}. Loaded into every session of that agent; check it says only what you wrote.`, where: p });
  }
  note("agent-instructions", "global instruction files (Claude, Codex, Gemini, Windsurf, Cursor)", "checked");

  // ---------- live resolution and TLS ----------
  if (o.network) {
    const names = WATCHED_DOMAINS.filter((d) => !d.startsWith("www.") && d !== "en.wikipedia.org");
    await Promise.all(names.map(async (n) => {
      let local: string[] = [];
      try { local = (await lookup(n, { all: true })).map((a) => a.address); } catch { /* unresolvable here */ }
      let doh: string[] | undefined;
      try {
        const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(n)}&type=A`, { headers: { accept: "application/dns-json" }, signal: AbortSignal.timeout(8000) });
        const j = await r.json() as { Answer?: Array<{ type: number; data: string }> };
        doh = (j.Answer ?? []).filter((a) => a.type === 1).map((a) => a.data);
      } catch { doh = undefined; }
      const tlsError = local.length && !local.every((a) => a === "0.0.0.0" || a.startsWith("127.")) ? await tlsCheck(n) : undefined;
      findings.push(...classifyResolution(n, local, doh, tlsError));
    }));
    note("resolution", `name resolution and TLS for ${names.length} sites agents rely on, compared with DNS-over-HTTPS`, "checked");
  } else note("resolution", "live resolution and TLS checks", "skipped", "run with --network");

  // ---------- the same pages from another network ----------
  if (o.remote) {
    const urls = o.remote.urls ?? ["https://example.com/", "https://www.iana.org/help/example-domains", "https://en.wikipedia.org/wiki/Domain_Name_System"];
    for (const u of urls) {
      try {
        const [here, there] = await Promise.all([
          o.remote.localFetch(u),
          fetch(new URL("/v1/fetch", o.remote.base), { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${o.remote.key}` }, body: JSON.stringify({ url: u }), signal: AbortSignal.timeout(30_000) }).then(async (r) => { const j = await r.json() as { tier?: string; delivered?: string; error?: string }; return { tier: j.tier ?? `error ${r.status}${j.error ? ": " + j.error : ""}`, delivered: j.delivered ?? "" }; }),
        ]);
        if (!here.delivered || !there.delivered) { findings.push({ area: "resolution", severity: "info", title: `could not compare ${u}`, detail: `here: ${here.tier}, from the remote gate: ${there.tier}.`, where: u }); continue; }
        const c = compareServed(here.delivered, there.delivered);
        if (c.agentOnlyWords >= 15 && c.agentOnlyShare >= 0.1) findings.push({ area: "resolution", severity: "high", title: `${u} reads differently from this machine`, detail: `${(c.agentOnlyShare * 100).toFixed(0)}% of the words this machine received never appear in the copy fetched from another network. Something on this machine's path is changing pages. Words seen only here: ${c.sample}`, where: u });
        else findings.push({ area: "resolution", severity: "info", title: `${u} matches the copy from another network`, detail: `${c.agentWords} words compared.`, where: u });
      } catch (e) { findings.push({ area: "resolution", severity: "info", title: `could not compare ${u}`, detail: (e as Error).message, where: u }); }
    }
    note("resolution", `${urls.length} stable pages compared with copies fetched by ${new URL(o.remote.base).host}`, "checked");
  } else note("resolution", "comparison with another network", "skipped", "run with --remote=<gate URL> and INGRESS_API_KEY");

  const order = { high: 0, review: 1, info: 2 } as const;
  findings.sort((a, b) => order[a.severity] - order[b.severity]);
  return { at: new Date().toISOString(), platform: os, summary: summarizeAudit(findings), findings, checked };
}

function tlsCheck(host: string): Promise<string | undefined> {
  return new Promise((res) => {
    const s = connect({ host, port: 443, servername: host, timeout: 8000 }, () => { s.end(); res(undefined); });
    s.on("error", (e: NodeJS.ErrnoException) => res(/ECONNREFUSED|ENOTFOUND|EHOSTUNREACH|ENETUNREACH|ETIMEDOUT|ECONNRESET/.test(e.code ?? "") ? undefined : `${e.code ?? "error"}: ${e.message}`));
    s.on("timeout", () => { s.destroy(); res(undefined); });
  });
}

/** installed Chromium extensions from the profile's Extensions folder, joined with their settings (store or not, enabled or not) */
export function readChromiumExtensions(dir: string, settings: Record<string, any>): ExtensionInfo[] {
  const out: ExtensionInfo[] = [];
  for (const id of ls(dir)) {
    if (!/^[a-p]{32}$/.test(id)) continue;
    const vers = ls(join(dir, id)).filter((v) => isDir(join(dir, id, v))).sort();
    const v = vers[vers.length - 1];
    if (!v) continue;
    const base = join(dir, id, v);
    const m = json(join(base, "manifest.json"));
    if (!m) continue;
    const st = settings[id] ?? {};
    if (st.location === 5 || st.location === 10) continue; // the browser's own components
    let name: string = m.name ?? id;
    const msg = name.match(/^__MSG_(\w+)__$/);
    if (msg) {
      const loc = json(join(base, "_locales", "en", "messages.json")) ?? json(join(base, "_locales", m.default_locale ?? "en", "messages.json")) ?? {};
      const key = Object.keys(loc).find((k) => k.toLowerCase() === msg[1].toLowerCase());
      name = key ? loc[key].message : id;
    }
    const cso = m.chrome_settings_overrides ?? {};
    out.push({
      id, name, version: m.version,
      permissions: (m.permissions ?? []).filter((p: unknown) => typeof p === "string"),
      hostPermissions: [...(m.host_permissions ?? []), ...(m.permissions ?? []).filter((p: string) => typeof p === "string" && /[:/*]/.test(p))],
      contentMatches: (m.content_scripts ?? []).flatMap((c: any) => c.matches ?? []),
      searchOverride: cso.search_provider?.search_url, homepageOverride: cso.homepage, startupOverride: !!cso.startup_pages,
      fromStore: st.from_webstore === true || st.location === 1 || (st.location === undefined && !!m.update_url && /clients2\.google\.com|edge\.microsoft\.com/.test(m.update_url)),
      enabled: st.state === undefined ? !st.disable_reasons : st.state === 1,
    });
  }
  return out;
}

export function formatAudit(r: AuditReport): string {
  const lines = [`AcePaste Ingress environment audit, ${r.at} (${r.platform})`, `${r.summary.high} high, ${r.summary.review} to review, ${r.summary.info} noted`, ""];
  for (const sev of ["high", "review", "info"] as const) {
    const fs = r.findings.filter((f) => f.severity === sev);
    if (!fs.length) continue;
    lines.push(sev === "high" ? "HIGH: can steer what agents receive and looks out of place" : sev === "review" ? "REVIEW: changes what agents receive; may well be yours" : "NOTED", "");
    for (const f of fs) lines.push(`  [${f.area}] ${f.title}`, `      ${f.detail}`, ...(f.where ? [`      where: ${f.where}`] : []), "");
  }
  lines.push("What was checked:");
  for (const c of r.checked) lines.push(`  ${c.status.padEnd(11)} ${c.what}${c.note ? ` (${c.note})` : ""}`);
  return lines.join("\n");
}
