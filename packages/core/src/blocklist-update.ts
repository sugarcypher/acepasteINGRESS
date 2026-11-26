/**
 * Keeping the blocklists current.
 *
 * `ingress blocklist update` downloads the free lists. Until 0.9.25 a person had to run it, so an installed
 * gate had an empty list on its first day and a stale one a month later. With INGRESS_BLOCKLIST_AUTO=on the lists
 * refresh themselves: when the newest downloaded list is more than a day old (or there is none), the session-start
 * hook, the HTTP service and the MCP proxy start the same command as a separate, detached process and carry on.
 * Nothing waits for it and nothing fails because of it.
 *
 * Since 0.9.31 this is off unless you turn it on. Each download tells abuse.ch, Spamhaus and Emerging Threats
 * your IP address, and the gate makes no outside contact a person did not ask for.
 *
 * Only the addresses in BLOCKLIST_FEEDS are contacted. A download is kept only if it parses as a list: a block
 * page or an error page saved as a list would silently protect nothing.
 */

import { spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, renameSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { HONEST_USER_AGENT } from "./acquire.js";
import { stateDir } from "./changes.js";
import { Blocklist, BLOCKLIST_FEEDS } from "./egress.js";

/** lists older than this are refreshed */
export const BLOCKLIST_MAX_AGE_MS = 24 * 3600 * 1000;
/** after an attempt, nothing tries again for this long: several sessions starting together refresh once, and a machine without a network does not retry at every session */
export const BLOCKLIST_RETRY_MS = 3600 * 1000;

type Feed = (typeof BLOCKLIST_FEEDS)[number];
type FetchText = (url: string) => Promise<{ ok: boolean; status: number; text: string }>;

const defaultFetch: FetchText = async (url) => {
  const res = await fetch(url, { signal: AbortSignal.timeout(30_000), redirect: "follow", headers: { "user-agent": HONEST_USER_AGENT } });
  return { ok: res.ok, status: res.status, text: res.ok ? await res.text() : "" };
};

export interface FeedOutcome { name: string; what: string; entries?: number; error?: string }

/** Download each feed into `dir`. A feed that fails, or does not parse as a list, leaves the previous copy in place. */
export async function updateBlocklists(dir: string = join(stateDir(), "blocklists"), o: { feeds?: readonly Feed[]; fetchText?: FetchText; now?: () => number } = {}): Promise<FeedOutcome[]> {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const out: FeedOutcome[] = [];
  for (const f of o.feeds ?? BLOCKLIST_FEEDS) {
    try {
      const res = await (o.fetchText ?? defaultFetch)(f.url);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      if (res.text.length > 50_000_000) throw new Error("larger than 50 MB");
      const n = new Blocklist().add(res.text, f.name);
      if (n < 5) throw new Error(`only ${n} entries parsed; keeping the previous copy`);
      const p = join(dir, `${f.name}.txt`);
      writeFileSync(`${p}.tmp`, `# ${f.what}\n# from ${f.url} on ${new Date(o.now?.() ?? Date.now()).toISOString()} (${f.terms})\n${res.text}`, { mode: 0o600 });
      renameSync(`${p}.tmp`, p);
      out.push({ name: f.name, what: f.what, entries: n });
    } catch (e) { out.push({ name: f.name, what: f.what, error: (e as Error).message ?? String(e) }); }
  }
  return out;
}

/** When the newest downloaded list was written, or undefined when none has been. Lists a person added do not count. */
export function blocklistsRefreshedAt(dir: string = join(stateDir(), "blocklists"), feeds: readonly Feed[] = BLOCKLIST_FEEDS): number | undefined {
  let newest: number | undefined;
  for (const f of feeds) {
    try { const t = statSync(join(dir, `${f.name}.txt`)).mtimeMs; if (newest === undefined || t > newest) newest = t; } catch { /* not downloaded yet */ }
  }
  return newest;
}

export function blocklistRefreshDue(dir: string, now: number, feeds: readonly Feed[] = BLOCKLIST_FEEDS): boolean {
  const at = blocklistsRefreshedAt(dir, feeds);
  return at === undefined || now - at > BLOCKLIST_MAX_AGE_MS;
}

/**
 * One refresh at a time, and not more often than BLOCKLIST_RETRY_MS: the file is created exclusively, so of
 * several processes that find the lists stale at the same moment exactly one gets it. It is never removed; its
 * age is the time since the last attempt.
 */
export function claimBlocklistRefresh(dir: string, now: number): boolean {
  const lock = join(dir, ".refresh-attempt");
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  for (let i = 0; i < 2; i++) {
    try { writeFileSync(lock, `${new Date(now).toISOString()} pid ${process.pid}\n`, { flag: "wx", mode: 0o600 }); return true; }
    catch {
      let at: number;
      try { at = Date.parse(readFileSync(lock, "utf8").split(" ")[0]); } catch { return false; }
      // an unreadable stamp is treated as old: better one extra download than never refreshing again
      if (Number.isFinite(at) && now - at < BLOCKLIST_RETRY_MS) return false;
      try { unlinkSync(lock); } catch { return false; }
    }
  }
  return false;
}

/** Automatic refresh runs only when INGRESS_BLOCKLIST_AUTO is on, 1, true or yes. Unset means off. */
export function blocklistAutoOn(env: Record<string, string | undefined> = process.env): boolean {
  return /^(on|1|true|yes)$/i.test((env.INGRESS_BLOCKLIST_AUTO ?? "").trim());
}

export type RefreshStart = "started" | "off" | "fresh" | "recently-tried" | "failed";

/**
 * Start `ingress blocklist update --quiet` as a detached process if the lists are due. Returns at once, and
 * never throws: a refresh that cannot start leaves the lists as they were.
 */
export function startBlocklistRefresh(o: { dir?: string; env?: Record<string, string | undefined>; now?: () => number; cli?: string; spawnImpl?: (command: string, args: string[]) => void } = {}): RefreshStart {
  try {
    const env = o.env ?? process.env;
    if (!blocklistAutoOn(env)) return "off";
    const dir = o.dir ?? join(stateDir(), "blocklists");
    const now = o.now?.() ?? Date.now();
    if (!blocklistRefreshDue(dir, now)) return "fresh";
    if (!claimBlocklistRefresh(dir, now)) return "recently-tried";
    const cli = o.cli ?? fileURLToPath(new URL("./cli.js", import.meta.url));
    if (!o.spawnImpl && !existsSync(cli)) return "failed";
    const run = o.spawnImpl ?? ((command: string, args: string[]) => {
      const child = spawn(command, args, { detached: true, stdio: "ignore", env: { ...process.env, INGRESS_BLOCKLIST_AUTO: "off" } });
      child.on("error", () => { /* the lists stay as they were */ });
      child.unref();
    });
    run(process.execPath, [cli, "blocklist", "update", "--quiet"]);
    return "started";
  } catch { return "failed"; }
}
