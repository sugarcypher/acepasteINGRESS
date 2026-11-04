/**
 * Environment audit: pure parsers and classifiers (no file or network access here, so
 * they can be tested with fixtures). See audit.ts for the collectors.
 *
 * The question the audit answers: has anything on this machine been set up to change
 * what an agent receives, before the gate ever sees it? Hosts-file and DNS overrides,
 * per-domain resolvers, proxies and PAC files, browser search engines, browser policies
 * and extensions that rewrite pages or results, trusted root certificates that allow TLS
 * interception, and agent configuration (MCP servers, hooks, global instruction files).
 *
 * Severity: "high" = can steer what agents receive and looks out of place; "review" =
 * changes what agents receive and may well be yours (say so and move on); "info" = noted.
 */

export type AuditArea = "hosts" | "dns" | "proxy" | "browser-search" | "browser-policy" | "browser-extension" | "certificates" | "network-extension" | "agent-config" | "agent-instructions" | "resolution";
export type AuditSeverity = "high" | "review" | "info";
export interface AuditFinding { area: AuditArea; severity: AuditSeverity; title: string; detail: string; where?: string; evidence?: string }

/** domains whose answers an agent relies on: search, AI providers, code registries, reference */
export const WATCHED_DOMAINS = [
  "google.com", "www.google.com", "bing.com", "www.bing.com", "duckduckgo.com", "search.brave.com", "kagi.com", "search.yahoo.com",
  "perplexity.ai", "chatgpt.com", "openai.com", "api.openai.com", "anthropic.com", "api.anthropic.com", "claude.ai", "gemini.google.com", "generativelanguage.googleapis.com",
  "registry.npmjs.org", "pypi.org", "files.pythonhosted.org", "github.com", "api.github.com", "raw.githubusercontent.com", "objects.githubusercontent.com", "crates.io", "proxy.golang.org",
  "wikipedia.org", "en.wikipedia.org", "acepaste-ingress.fly.dev",
];
const watched = (name: string) => WATCHED_DOMAINS.some((d) => name === d || name.endsWith("." + d) || d.endsWith("." + name));

const LOCAL_NAMES = /^(?:localhost|localhost\.localdomain|broadcasthost|ip6-localhost|ip6-loopback|ip6-localnet|ip6-mcastprefix|ip6-allnodes|ip6-allrouters|ip6-allhosts|local)$/i;
const isLocalName = (n: string) => LOCAL_NAMES.test(n) || /\.(?:local|localhost|lan|home|internal|test|invalid|arpa)$/i.test(n) || !n.includes(".");
export const isSinkhole = (ip: string) => /^(?:0\.0\.0\.0|127\.\d+\.\d+\.\d+|::1?|::ffff:127\.\d+\.\d+\.\d+|0:0:0:0:0:0:0:[01])$/.test(ip);
export const isPrivateAddr = (ip: string) => /^(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|f[cd][0-9a-f]{2}:|fe80:)/i.test(ip);

export function parseHosts(text: string): Array<{ ip: string; names: string[]; line: number }> {
  const out: Array<{ ip: string; names: string[]; line: number }> = [];
  text.split(/\r?\n/).forEach((raw, i) => {
    const l = raw.replace(/#.*/, "").trim();
    if (!l) return;
    const [ip, ...names] = l.split(/\s+/);
    if (ip && names.length) out.push({ ip, names: names.map((n) => n.toLowerCase()), line: i + 1 });
  });
  return out;
}

/** findings from a hosts-format file (the system hosts file, dnsmasq addn-hosts, blocklists) */
export function classifyHosts(text: string, where: string): AuditFinding[] {
  const out: AuditFinding[] = [];
  const blockedWatched: string[] = [], blockedOther: string[] = [];
  for (const e of parseHosts(text)) {
    for (const n of e.names) {
      if (isLocalName(n)) continue;
      if (isSinkhole(e.ip)) { (watched(n) ? blockedWatched : blockedOther).push(n); continue; }
      out.push({
        area: "hosts", severity: watched(n) ? "high" : "review",
        title: `${n} is pinned to ${e.ip}`,
        detail: `Every program on this machine, agents included, reaches ${n} at ${e.ip} instead of asking DNS${isPrivateAddr(e.ip) ? " (a private address on your network)" : ""}. If you did not add this, someone can serve agents their own version of that site.`,
        where: `${where}:${e.line}`,
      });
    }
  }
  if (blockedWatched.length) out.push({ area: "hosts", severity: "review", title: `${blockedWatched.length} site(s) agents rely on are blocked in ${where}`, detail: `Blocked: ${blockedWatched.slice(0, 12).join(", ")}${blockedWatched.length > 12 ? " …" : ""}. Agents will fail to reach them, or fall back to other sources.`, where });
  if (blockedOther.length) out.push({ area: "hosts", severity: "info", title: `${blockedOther.length} hostnames blocked in ${where}`, detail: `Sinkholed to a local address, as ad and tracker blocklists do. Examples: ${blockedOther.slice(0, 6).join(", ")}.`, where });
  return out;
}

/** dnsmasq: address= (answer overrides), server=/domain/ (per-domain upstreams), addn-hosts, cname */
export function classifyDnsmasq(text: string, where: string): { findings: AuditFinding[]; addnHosts: string[]; confDirs: string[] } {
  const findings: AuditFinding[] = [];
  const addnHosts: string[] = [], confDirs: string[] = [];
  const blocked: string[] = [];
  text.split(/\r?\n/).forEach((raw, i) => {
    const l = raw.replace(/\s#.*$/, "").trim();
    if (!l || l.startsWith("#")) return;
    const [k, ...rest] = l.split("=");
    const v = rest.join("=").trim();
    if (k === "addn-hosts") addnHosts.push(v);
    else if (k === "conf-dir") confDirs.push(v.split(",")[0]);
    else if (k === "address" || k === "local" && v.includes("/")) {
      const m = v.match(/^\/(.+)\/(.*)$/);
      if (!m) return;
      const doms = m[1].split("/").filter(Boolean), ip = m[2];
      for (const d of doms) {
        if (isLocalName(d)) continue;
        if (!ip || ip === "#" || isSinkhole(ip)) { blocked.push(d); continue; }
        findings.push({ area: "dns", severity: watched(d) ? "high" : "review", title: `dnsmasq answers ${d} with ${ip}`, detail: `Your local resolver gives ${ip} for ${d} and all its subdomains, whatever the real DNS says.`, where: `${where}:${i + 1}` });
      }
    } else if (k === "server" && v.startsWith("/")) {
      const m = v.match(/^\/(.+)\/(.*)$/);
      if (!m) return;
      for (const d of m[1].split("/").filter(Boolean)) {
        if (isLocalName(d)) continue;
        findings.push({ area: "dns", severity: watched(d) ? "high" : "review", title: `queries for ${d} go to ${m[2] || "no server (blocked)"}`, detail: `dnsmasq sends lookups for ${d} to a different resolver than everything else. That resolver decides what agents reach for that domain.`, where: `${where}:${i + 1}` });
      }
    } else if (k === "cname") {
      findings.push({ area: "dns", severity: "review", title: `dnsmasq aliases ${v.split(",")[0]}`, detail: `cname=${v}: lookups for the first name are answered with the second.`, where: `${where}:${i + 1}` });
    }
  });
  if (blocked.length) findings.push({ area: "dns", severity: blocked.some(watched) ? "review" : "info", title: `dnsmasq blocks ${blocked.length} domain(s)`, detail: `Examples: ${blocked.slice(0, 8).join(", ")}${blocked.some(watched) ? ". Some are sites agents rely on." : "."}`, where });
  return { findings, addnHosts, confDirs };
}

/** dnscrypt-proxy cloaking rules ("name ip" or "name othername") and forwarding rules ("name server") */
export function classifyDnscryptRules(text: string, where: string, kind: "cloaking" | "forwarding"): AuditFinding[] {
  const out: AuditFinding[] = [];
  let blocked = 0;
  text.split(/\r?\n/).forEach((raw, i) => {
    const l = raw.replace(/#.*/, "").trim();
    if (!l) return;
    const [name, target] = l.split(/\s+/);
    if (!name || !target || isLocalName(name.replace(/^[=*.]+/, ""))) return;
    const n = name.replace(/^[=*.]+/, "").toLowerCase();
    if (kind === "cloaking" && isSinkhole(target)) { blocked++; return; }
    out.push({
      area: "dns", severity: watched(n) ? "high" : "review",
      title: kind === "cloaking" ? `dnscrypt-proxy answers ${n} with ${target}` : `dnscrypt-proxy sends ${n} lookups to ${target}`,
      detail: kind === "cloaking" ? `A cloaking rule overrides the real answer for ${n}.` : `A forwarding rule hands lookups for ${n} to a different server.`,
      where: `${where}:${i + 1}`,
    });
  });
  if (blocked) out.push({ area: "dns", severity: "info", title: `dnscrypt-proxy cloaks ${blocked} name(s) to a local address`, detail: "Blocking, as blocklists do.", where });
  return out;
}

/** `localPrefixes`: the /64 prefixes of this machine's own IPv6 addresses (a router on the same network hands out addresses in its prefix) */
export function classifyResolvConf(text: string, where: string, localPrefixes: string[] = []): AuditFinding[] {
  const ns = [...text.matchAll(/^\s*nameserver\s+(\S+)/gm)].map((m) => m[1].replace(/%.*$/, ""));
  if (!ns.length) return [];
  const onLan = (n: string) => n.includes(":") && localPrefixes.some((p) => ipv6Prefix64(n) === p);
  const odd = ns.filter((n) => !isSinkhole(n) && !isPrivateAddr(n) && !KNOWN_PUBLIC_RESOLVERS.has(n) && !onLan(n));
  return [{ area: "dns", severity: odd.length ? "review" : "info", title: `DNS servers: ${ns.join(", ")}`, detail: odd.length ? `${odd.join(", ")} is not a well-known public resolver or a local one. Whoever runs it decides what every name on this machine resolves to.` : "Local or well-known public resolvers.", where }];
}

/** first four groups of an IPv6 address, expanded */
export function ipv6Prefix64(addr: string): string {
  const a = addr.replace(/%.*$/, "").toLowerCase();
  const [head, tail = ""] = a.split("::");
  const h = head ? head.split(":") : [], t = tail ? tail.split(":") : [];
  const full = a.includes("::") ? [...h, ...Array(8 - h.length - t.length).fill("0"), ...t] : h;
  return full.slice(0, 4).map((g) => g.replace(/^0+(?=.)/, "")).join(":");
}

export const KNOWN_PUBLIC_RESOLVERS = new Set(["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220", "94.140.14.14", "94.140.15.15", "2606:4700:4700::1111", "2606:4700:4700::1001", "2001:4860:4860::8888", "2001:4860:4860::8844", "2620:fe::fe"]);

/** macOS `scutil --dns`: resolvers scoped to particular domains */
export function classifyScutilDns(text: string): AuditFinding[] {
  const out: AuditFinding[] = [];
  for (const block of text.split(/\nresolver #\d+/).slice(1)) {
    const domain = block.match(/^\s*domain\s*:\s*(\S+)/m)?.[1];
    const ns = [...block.matchAll(/nameserver\[\d+\]\s*:\s*(\S+)/g)].map((m) => m[1]);
    if (!domain || !ns.length || isLocalName(domain) || /^(?:\d+\.)*in-addr\.arpa$|ip6\.arpa$/.test(domain)) continue;
    out.push({ area: "dns", severity: watched(domain) ? "high" : "review", title: `lookups for ${domain} go to ${ns.join(", ")}`, detail: `A resolver scoped to ${domain} (set by a VPN, a profile or /etc/resolver). It decides what agents reach under that domain.`, where: "scutil --dns" });
  }
  return out;
}

/** macOS `scutil --proxy` output */
export function classifyScutilProxy(text: string): AuditFinding[] {
  const kv = Object.fromEntries([...text.matchAll(/^\s*(\w+)\s*:\s*(.+?)\s*$/gm)].map((m) => [m[1], m[2]]));
  const out: AuditFinding[] = [];
  for (const [en, host, port, label] of [["HTTPEnable", "HTTPProxy", "HTTPPort", "HTTP"], ["HTTPSEnable", "HTTPSProxy", "HTTPSPort", "HTTPS"], ["SOCKSEnable", "SOCKSProxy", "SOCKSPort", "SOCKS"]] as const) {
    if (kv[en] === "1") out.push({ area: "proxy", severity: "review", title: `system ${label} proxy: ${kv[host]}:${kv[port]}`, detail: `Web traffic from apps that use system settings passes through ${kv[host]}. A proxy can change any page it relays.`, where: "scutil --proxy" });
  }
  if (kv.ProxyAutoConfigEnable === "1") {
    const u = kv.ProxyAutoConfigURLString ?? "";
    out.push({ area: "proxy", severity: /^http:/i.test(u) ? "high" : "review", title: `proxy auto-config: ${u}`, detail: `A PAC script decides, per site, where traffic goes.${/^http:/i.test(u) ? " It is fetched over plain HTTP, so anyone on the network can replace it." : ""}`, where: "scutil --proxy" });
  }
  if (kv.ProxyAutoDiscoveryEnable === "1") out.push({ area: "proxy", severity: "review", title: "proxy auto-discovery (WPAD) is on", detail: "The network can hand this machine a proxy without asking.", where: "scutil --proxy" });
  return out;
}

export function classifyProxyEnv(env: Record<string, string | undefined>): AuditFinding[] {
  const out: AuditFinding[] = [];
  for (const k of ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"]) {
    const v = env[k];
    if (!v) continue;
    let host = v;
    try { const u = new URL(v); host = `${u.hostname}${u.port ? ":" + u.port : ""}`; } catch { /* not a URL */ }
    out.push({ area: "proxy", severity: "review", title: `${k} is set (${host})`, detail: "Command-line tools and many agents send web requests through this proxy.", where: "environment" });
  }
  return out;
}

const KNOWN_SEARCH = /^https:\/\/(?:www\.google\.[a-z.]+|www\.bing\.com|duckduckgo\.com|search\.brave\.com|kagi\.com|search\.yahoo\.com|www\.ecosia\.org|www\.startpage\.com|yandex\.[a-z]+|www\.baidu\.com|search\.naver\.com|www\.qwant\.com|html\.duckduckgo\.com|perplexity\.ai|www\.perplexity\.ai)\//i;

/** Chromium-family Preferences: the default search engine */
export function classifyChromiumSearch(prefs: any, where: string): AuditFinding[] {
  const t = prefs?.default_search_provider_data?.template_url_data;
  const url: string | undefined = t?.url;
  if (!url) return [];
  return [{ area: "browser-search", severity: KNOWN_SEARCH.test(url) ? "info" : "high", title: `default search: ${t.short_name ?? t.keyword ?? "unnamed"}`, detail: KNOWN_SEARCH.test(url) ? `Search goes to ${new URL(url.replace(/\{[^}]+\}/g, "x")).hostname}.` : `Searches go to ${url.replace(/\{[^}]+\}/g, "…")}, which is not a well-known search engine. Results there can be anything.`, where }];
}

export interface ExtensionInfo { id: string; name: string; version?: string; permissions: string[]; hostPermissions: string[]; contentMatches: string[]; searchOverride?: string; homepageOverride?: string; startupOverride?: boolean; fromStore: boolean; enabled: boolean }

const ALL_URLS = /^(?:<all_urls>|\*:\/\/\*\/\*|https?:\/\/\*\/\*|\*:\/\/\*\/|file:\/\/\/\*)$/;

export function classifyExtension(x: ExtensionInfo, where: string): AuditFinding[] {
  const out: AuditFinding[] = [];
  // a disabled extension changes nothing until someone turns it on: note it, at most
  if (!x.enabled) {
    const risky = !!x.searchOverride || x.permissions.includes("proxy") || !x.fromStore;
    return risky ? [{ area: "browser-extension", severity: "info", title: `${x.name} (${x.id}) is installed but disabled`, detail: `${x.searchOverride ? "It would replace your search engine. " : ""}${x.permissions.includes("proxy") ? "It can set a proxy. " : ""}${!x.fromStore ? "It was not installed from the store. " : ""}Remove it if you don't use it.`, where }] : [];
  }
  const unpacked = !x.fromStore;
  const allSites = [...x.hostPermissions, ...x.contentMatches, ...x.permissions].some((p) => ALL_URLS.test(p));
  const net = x.permissions.some((p) => /^(?:webRequest|webRequestBlocking|declarativeNetRequest|declarativeNetRequestWithHostAccess|proxy)$/.test(p));
  const label = `${x.name}${x.version ? " " + x.version : ""} (${x.id})${x.enabled ? "" : ", disabled"}`;
  if (x.searchOverride) out.push({ area: "browser-extension", severity: KNOWN_SEARCH.test(x.searchOverride) ? "review" : "high", title: `${label} replaces your search engine`, detail: `Searches go to ${x.searchOverride.replace(/\{[^}]+\}/g, "…")}.`, where });
  if (x.permissions.includes("proxy")) out.push({ area: "browser-extension", severity: unpacked ? "high" : "review", title: `${label} can route your browsing through a proxy`, detail: "The proxy permission lets it send any site's traffic elsewhere.", where });
  if (x.homepageOverride || x.startupOverride) out.push({ area: "browser-extension", severity: "review", title: `${label} sets your home or startup pages`, detail: x.homepageOverride ? `Home page: ${x.homepageOverride}.` : "Startup pages are set by the extension.", where });
  if (allSites && (net || x.contentMatches.length)) out.push({ area: "browser-extension", severity: unpacked ? "high" : "review", title: `${label} can change what every site shows`, detail: `${x.contentMatches.length ? "It runs its own scripts inside every page" : "It can rewrite or redirect requests to every site"}${unpacked ? ", and it was not installed from the store" : ""}. An agent driving this browser sees the page after the extension has changed it.`, where });
  else if (unpacked && x.enabled) out.push({ area: "browser-extension", severity: "review", title: `${label} was not installed from the store`, detail: "Loaded unpacked or by another program.", where });
  return out;
}

/** Chromium policy dictionary (from a managed plist or a policies JSON file) */
export function classifyChromiumPolicy(policy: Record<string, any>, where: string): AuditFinding[] {
  const out: AuditFinding[] = [];
  const add = (severity: AuditSeverity, title: string, detail: string) => out.push({ area: "browser-policy", severity, title, detail, where });
  if (policy.DefaultSearchProviderSearchURL) add(KNOWN_SEARCH.test(policy.DefaultSearchProviderSearchURL) ? "review" : "high", `policy forces the search engine to ${policy.DefaultSearchProviderName ?? policy.DefaultSearchProviderSearchURL}`, `DefaultSearchProviderSearchURL = ${policy.DefaultSearchProviderSearchURL}. Users cannot change it.`);
  if (policy.ExtensionInstallForcelist?.length) add("high", `policy force-installs ${policy.ExtensionInstallForcelist.length} extension(s)`, `ExtensionInstallForcelist: ${policy.ExtensionInstallForcelist.slice(0, 6).join(", ")}. They cannot be removed from the browser.`);
  if (policy.ProxyMode || policy.ProxyServer || policy.ProxyPacUrl || policy.ProxySettings) add("high", "policy sets the browser's proxy", `ProxyMode ${policy.ProxyMode ?? policy.ProxySettings?.ProxyMode ?? "?"}${policy.ProxyServer ? `, server ${policy.ProxyServer}` : ""}${policy.ProxyPacUrl ? `, PAC ${policy.ProxyPacUrl}` : ""}.`);
  if (policy.URLBlocklist?.length || policy.URLAllowlist?.length) add("review", "policy filters which sites the browser may open", `${policy.URLBlocklist?.length ?? 0} blocked pattern(s), ${policy.URLAllowlist?.length ?? 0} allowed pattern(s). Examples: ${(policy.URLBlocklist ?? []).slice(0, 5).join(", ")}.`);
  if (policy.DnsOverHttpsTemplates) add("review", "policy sets the browser's DNS-over-HTTPS server", `DnsOverHttpsTemplates = ${policy.DnsOverHttpsTemplates}.`);
  if (policy.HomepageLocation || policy.RestoreOnStartupURLs?.length || policy.NewTabPageLocation) add("review", "policy sets home, new-tab or startup pages", [policy.HomepageLocation, policy.NewTabPageLocation, ...(policy.RestoreOnStartupURLs ?? [])].filter(Boolean).slice(0, 4).join(", "));
  const known = new Set(["DefaultSearchProviderSearchURL", "DefaultSearchProviderName", "DefaultSearchProviderEnabled", "ExtensionInstallForcelist", "ProxyMode", "ProxyServer", "ProxyPacUrl", "ProxySettings", "URLBlocklist", "URLAllowlist", "DnsOverHttpsTemplates", "HomepageLocation", "RestoreOnStartupURLs", "NewTabPageLocation"]);
  const other = Object.keys(policy).filter((k) => !known.has(k) && !k.startsWith("PayloadUUID") && !/^(?:PayloadIdentifier|PayloadType|PayloadVersion)$/.test(k));
  if (other.length) add("info", `${other.length} other browser policies set`, other.slice(0, 12).join(", "));
  return out;
}

const MITM_TOOLS = /mitmproxy|charles|fiddler|burp|portswigger|proxyman|http toolkit|httptoolkit|zscaler|netskope|forcepoint|bluecoat|fortinet|palo alto|cisco umbrella|kaspersky|avast|eset|bitdefender|superfish|komodia/i;

/** macOS `security dump-trust-settings` output: certificates with custom trust */
export function classifyTrustSettings(text: string, domain: "admin" | "user"): AuditFinding[] {
  if (/No Trust Settings were found/i.test(text)) return [];
  const names = [...text.matchAll(/Cert\s+\d+:\s*(.+)/g)].map((m) => m[1].trim());
  return names.map((n) => ({
    area: "certificates" as const, severity: (MITM_TOOLS.test(n) ? "high" : "review") as AuditSeverity,
    title: `custom-trusted certificate (${domain}): ${n}`,
    detail: `A certificate given trust by hand${domain === "admin" ? " for every user" : ""}. A trusted root lets whoever holds its key read and change encrypted traffic, so pages and API answers can be altered in transit.${MITM_TOOLS.test(n) ? " Its name matches a traffic-inspection tool." : ""}`,
    where: `security dump-trust-settings${domain === "admin" ? " -d" : ""}`,
  }));
}

/** macOS `systemextensionsctl list`: active network and content-filter extensions */
export function classifySystemExtensions(text: string): AuditFinding[] {
  const out: AuditFinding[] = [];
  for (const l of text.split(/\r?\n/)) {
    if (!/\[activated enabled\]/.test(l)) continue;
    const cols = l.split(/\t+/).map((c) => c.trim()).filter(Boolean);
    const bundle = cols.find((c) => /^[a-z0-9-]+(?:\.[a-z0-9-]+){2,}/i.test(c) && !/^\d/.test(c)) ?? "";
    const name = cols.find((c) => /\(\d/.test(c)) ?? bundle;
    if (!/network|filter|vpn|dns|proxy|firewall|lulu|snitch|tunnel/i.test(l)) continue;
    out.push({ area: "network-extension", severity: "review", title: `network extension active: ${name.replace(/\s*\(.*$/, "")}`, detail: `${bundle} can see and filter network traffic (firewalls, VPNs, DNS proxies, content filters). Yours if you installed it; otherwise it can change what agents receive.`, where: "systemextensionsctl list" });
  }
  return out;
}

/** MCP server configs (Claude Desktop, Claude Code, Cursor, Windsurf, VS Code): what agents can call */
export function classifyMcpServers(config: any, where: string): AuditFinding[] {
  const servers = config?.mcpServers ?? config?.servers ?? config?.mcp?.servers ?? {};
  const out: AuditFinding[] = [];
  for (const [name, s] of Object.entries<any>(servers)) {
    const cmd = [s.command, ...(s.args ?? [])].filter(Boolean).join(" ");
    const url = s.url ?? s.serverUrl;
    const unpinned = /\bnpx\b|\buvx\b|\bpipx\s+run\b|\bbunx\b/.test(cmd) && !(s.args ?? []).some((a: string) => /@\d+\.\d+/.test(a) || /==\d/.test(a));
    const envKeys = Object.keys(s.env ?? {});
    out.push({
      area: "agent-config", severity: url && !/^https:\/\/(?:localhost|127\.)/.test(url) ? "review" : unpinned ? "review" : "info",
      title: `MCP server "${name}": ${url ? url : cmd.slice(0, 120)}`,
      detail: `${url ? "A remote server: what it returns goes straight to the agent." : "A local program the agent can call."}${unpinned ? " It runs the latest published version on every start (not pinned), so a hijacked package would load automatically." : ""}${envKeys.length ? ` Environment keys: ${envKeys.join(", ")} (values not shown).` : ""}`,
      where,
    });
  }
  return out;
}

/** Claude Code settings: hooks run commands on agent events */
export function classifyHooks(settings: any, where: string): AuditFinding[] {
  const hooks = settings?.hooks;
  if (!hooks || typeof hooks !== "object") return [];
  const cmds: string[] = [];
  for (const groups of Object.values<any>(hooks)) for (const g of groups ?? []) for (const h of g?.hooks ?? []) if (h?.command) cmds.push(h.command);
  return cmds.length ? [{ area: "agent-config", severity: "review", title: `${cmds.length} agent hook command(s)`, detail: `Hooks run on agent events and can rewrite what the agent sees: ${cmds.slice(0, 4).map((c) => c.slice(0, 80)).join(" | ")}`, where }] : [];
}

/** compare what this machine resolves with DNS-over-HTTPS */
export function classifyResolution(name: string, local: string[], doh: string[] | undefined, tlsError?: string): AuditFinding[] {
  const out: AuditFinding[] = [];
  if (tlsError) out.push({ area: "resolution", severity: "high", title: `TLS to ${name} did not verify`, detail: `Connecting to ${name} through this machine's network failed certificate checks (${tlsError}). That is what interception looks like, though a captive portal or broken clock can cause it too.`, where: name });
  if (!local.length) return out;
  if (local.every(isSinkhole)) out.push({ area: "resolution", severity: "review", title: `${name} is blocked on this machine`, detail: `It resolves to ${local.join(", ")} here.`, where: name });
  else if (local.some(isPrivateAddr)) out.push({ area: "resolution", severity: "high", title: `${name} resolves to a private address`, detail: `Here it resolves to ${local.join(", ")}, an address on a local network, while public DNS says ${doh?.join(", ") || "something else"}. A machine on your network answers for it.`, where: name });
  else if (doh?.length && !local.some((a) => doh.includes(a))) out.push({ area: "resolution", severity: "info", title: `${name} resolves differently here than over DNS-over-HTTPS`, detail: `Here: ${local.join(", ")}; DNS-over-HTTPS: ${doh.join(", ")}. Large sites hand out different addresses by location, so this alone is normal.`, where: name });
  return out;
}

export function summarizeAudit(findings: AuditFinding[]) {
  const count = (s: AuditSeverity) => findings.filter((f) => f.severity === s).length;
  return { high: count("high"), review: count("review"), info: count("info") };
}
