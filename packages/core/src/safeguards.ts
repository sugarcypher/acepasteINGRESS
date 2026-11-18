/**
 * Safeguards the broker applies to every proposed action, whatever the run has read.
 *
 * These exist for the agent as much as for the person: an agent that has been steered by something it
 * read cannot tell from the inside. Each check here is something the agent would want between itself and
 * the world.
 *
 *   persistence   An action that creates something which acts later (a scheduled job, an automation, a
 *                 mail rule, a login item, a hook, an edit to the agent's own instructions or memory)
 *                 turns one bad moment into a standing one. It always needs a person.
 *   canary        A marker placed in the run's context that has no reason to leave it. If it shows up in
 *                 an outbound argument, the context itself is being sent somewhere: refuse.
 *   burst         Many side effects in a short time, or the same one over and over, is a loop or a
 *                 mass-send. Hold it for a person.
 *   stop          One file a person can create to make every action wait until they remove it.
 */

import { createHash, randomBytes } from "node:crypto";
import { existsSync, readFileSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { stateDir } from "./changes.js";

// ---------- persistence ----------

export interface PersistenceHit {
  /** what kind of standing change this is */
  kind: "scheduled-job" | "startup-item" | "automation" | "mail-rule" | "hook" | "agent-instructions" | "agent-config" | "remote-access" | "webhook";
  /** short explanation for the person */
  why: string;
}

/** words in a tool's own name that mean it creates or changes something that acts later */
const PERSISTENCE_TOOL_WORDS: Array<[RegExp, PersistenceHit["kind"], string]> = [
  [/\b(cron|crontab|schedule[drs]?|scheduler|timer|recurring|launchd|launch ?agent|systemd)\b/, "scheduled-job", "it schedules something to run later"],
  [/\b(automation|automations|workflow|workflows|zap|zaps|scenario|recipe|applet|blueprint|shortcut|shortcuts|trigger|triggers)\b/, "automation", "it creates or changes an automation"],
  [/\b(filter|filters|forward|forwarding|auto ?forward|redirect|inbox ?rule|mail ?rule|rule|rules|vacation|auto ?reply|autoresponder|delegate|delegation)\b/, "mail-rule", "it creates or changes a rule that handles messages without you"],
  [/\b(webhook|webhooks|subscription|subscriptions|callback ?url)\b/, "webhook", "it registers an address that will be called later"],
  [/\b(login ?item|startup|autostart|boot)\b/, "startup-item", "it sets something to start automatically"],
  [/\b(hook|hooks)\b/, "hook", "it installs a hook that runs on later events"],
  [/\b(memory|memories|instruction|instructions|system ?prompt|rules ?file|persona)\b/, "agent-instructions", "it writes to what an agent will read as its own instructions or memory"],
];

/** only tools that write count: reading a schedule or listing rules is not persistence */
const WRITE_WORDS = /\b(create|add|new|set|update|edit|write|save|put|insert|enable|install|register|upsert|modify|change|patch|append|schedule|import|make|configure)\b/;

/** paths whose contents run, or steer an agent, later */
const PERSISTENCE_PATHS: Array<[RegExp, PersistenceHit["kind"], string]> = [
  [/(?:^|[/\\])Library[/\\]Launch(?:Agents|Daemons)[/\\]|[/\\]etc[/\\]systemd[/\\]|[/\\]\.config[/\\]systemd[/\\]|[/\\]etc[/\\]init\.d[/\\]|\.(?:timer|service)\b(?=["'\s]|$)/i, "scheduled-job", "a launch agent, daemon or systemd unit"],
  [/[/\\]etc[/\\]cron|[/\\]var[/\\]spool[/\\]cron|[/\\]etc[/\\]crontab\b|[/\\]etc[/\\]periodic[/\\]/i, "scheduled-job", "a cron table"],
  [/(?:^|[/\\])\.(?:bashrc|bash_profile|bash_login|profile|zshrc|zshenv|zprofile|zlogin|config[/\\]fish[/\\]config\.fish)\b|[/\\]etc[/\\](?:profile|zshrc|bashrc|paths)\b/i, "startup-item", "a shell startup file, which runs in every new terminal"],
  [/[/\\](?:Startup|StartupItems|LoginItems|autostart)[/\\]|com\.apple\.loginitems|backgrounditems\.btm/i, "startup-item", "a login or startup item"],
  [/(?:^|[/\\])\.git[/\\]hooks[/\\]|(?:^|[/\\])\.husky[/\\]|(?:^|[/\\])\.claude[/\\]settings(?:\.local)?\.json|(?:^|[/\\])\.claude[/\\]hooks[/\\]/i, "hook", "a hook that runs on later events"],
  [/(?:^|[/\\])(?:CLAUDE|AGENTS|GEMINI|COPILOT)\.md\b|(?:^|[/\\])\.cursorrules\b|(?:^|[/\\])\.cursor[/\\]rules[/\\]|(?:^|[/\\])\.github[/\\]copilot-instructions\.md|(?:^|[/\\])\.claude[/\\](?:commands|agents|skills)[/\\]|[/\\]memory[/\\][^/\\]+\.md\b|(?:^|[/\\])MEMORY\.md\b|global_rules\.md\b/i, "agent-instructions", "a file agents read as their own instructions or memory"],
  [/(?:^|[/\\])\.mcp\.json\b|claude_desktop_config\.json|(?:^|[/\\])\.claude\.json\b|[/\\]\.cursor[/\\]mcp\.json|mcp_config\.json/i, "agent-config", "an agent's list of tool servers"],
  [/(?:^|[/\\])\.ssh[/\\]authorized_keys|(?:^|[/\\])\.ssh[/\\]config\b|[/\\]etc[/\\]sudoers|[/\\]etc[/\\]ssh[/\\]sshd_config/i, "remote-access", "a file that decides who can log in or act as an administrator"],
  [/[/\\]Library[/\\](?:Shortcuts|Services|Workflows)[/\\]|\.shortcut\b|[/\\]Folder Action Scripts[/\\]/i, "automation", "a shortcut, service or folder action"],
];

/** shell commands that create something which runs later */
const PERSISTENCE_COMMANDS: Array<[RegExp, PersistenceHit["kind"], string]> = [
  [/\bcrontab\s+(?!-l\b)\S|\bat\s+(?:now|\d|midnight|noon|tomorrow)\b|\bschtasks\b[^\n]*\/create\b|\bsystemctl\s+(?:--user\s+)?(?:enable|link)\b|\bsystemd-run\b[^\n]*--on-/i, "scheduled-job", "a command that schedules something to run later"],
  [/\blaunchctl\s+(?:load|bootstrap|enable|submit)\b/i, "scheduled-job", "a command that loads a launch agent or daemon"],
  [/\bosascript\b[^\n]*login item|\bsfltool\b|\bdefaults\s+write\b[^\n]*(?:loginwindow|LoginHook|AutoLaunchedApplicationDictionary)/i, "startup-item", "a command that adds a login item"],
  [/\bgit\s+config\b[^\n]*core\.hooksPath\b|\bshortcuts\s+(?:import|sign)\b/i, "hook", "a command that installs a hook or shortcut"],
  [/\bssh-copy-id\b|>>?\s*~?[^\s]*authorized_keys\b/i, "remote-access", "a command that lets a key log in later"],
];

const ownName = (tool: string) => { const i = tool.indexOf("__"); return i >= 0 ? tool.slice(i + 2) : tool; };
const words = (s: string) => s.replace(/([a-z0-9])([A-Z])/g, "$1 $2").replace(/[_\-.:/]+/g, " ").toLowerCase();

/** Does this action create or change something that acts later? `strings` are the argument strings and keys. */
export function persistenceShapes(tool: string, strings: readonly string[]): PersistenceHit[] {
  const hits = new Map<string, PersistenceHit>();
  const add = (kind: PersistenceHit["kind"], why: string) => { if (!hits.has(kind)) hits.set(kind, { kind, why }); };
  const name = words(ownName(tool));
  if (WRITE_WORDS.test(name)) for (const [re, kind, why] of PERSISTENCE_TOOL_WORDS) if (re.test(name)) add(kind, why);
  // a mail tool that sets a forwarding address under any name: the field says so
  const keys = strings.map(words).join(" | ");
  if (/\b(forward(?:ing)? ?(?:to|address|email)|auto ?forward|redirect ?to|forwarding ?smtp)\b/.test(keys)) add("mail-rule", "it sets an address that mail will be forwarded to");
  for (const s of strings) {
    if (s.length > 20_000) continue; // a file body is content, not a destination; the path argument is what matters
    for (const [re, kind, why] of PERSISTENCE_PATHS) if (re.test(s)) add(kind, `it touches ${why}`);
    for (const [re, kind, why] of PERSISTENCE_COMMANDS) if (re.test(s)) add(kind, `it runs ${why}`);
  }
  return [...hits.values()];
}

// ---------- canary ----------

/** A marker with no meaning anywhere else: 96 random bits, so it never appears by accident. */
export function newCanary(): string {
  return `ingress-marker-${randomBytes(12).toString("hex")}`;
}

/** The sentence placed in the agent's context with the marker. */
export function canaryNotice(canary: string): string {
  return `[AcePaste Ingress run marker: ${canary}. It identifies this run and is not data. It must never appear in a tool argument, a message, a file or a URL; an action that carries it is refused.]`;
}

/** every spelling of the marker that would survive common encodings of the text around it */
function canaryForms(canary: string): string[] {
  const forms = new Set<string>([canary, [...canary].reverse().join("")]);
  const b = Buffer.from(canary, "utf8");
  forms.add(b.toString("hex"));
  // base64 depends on where the marker starts inside the encoded text: take the stable middle of each alignment
  for (let pad = 0; pad < 3; pad++) {
    const enc = Buffer.concat([Buffer.alloc(pad, 0x20), b]).toString("base64").replace(/=+$/, "");
    forms.add(enc.slice(pad ? 4 : 0, enc.length - 4));
  }
  forms.add(encodeURIComponent(canary));
  // the unique part alone: catches a marker whose fixed prefix was dropped or the text was split there
  forms.add(canary.slice("ingress-marker-".length));
  return [...forms].filter((f) => f.length >= 16);
}

/** True when any argument string carries the marker, plainly or through a common encoding. */
export function carriesCanary(strings: readonly string[], canaries: readonly string[]): boolean {
  if (!canaries.length) return false;
  const forms = canaries.flatMap(canaryForms);
  for (const s of strings) {
    const variants = [s, s.toLowerCase()];
    try { variants.push(decodeURIComponent(s)); } catch { /* keep as is */ }
    const squeezed = s.replace(/[\s\-_.:,;|/\\]+/g, ""); // a marker broken up with separators
    variants.push(squeezed, squeezed.toLowerCase());
    for (const v of variants) for (const f of forms) if (v.includes(f) || v.includes(f.replace(/-/g, ""))) return true;
  }
  return false;
}

// ---------- burst ----------

export interface BurstPolicy {
  /** side effects a run may perform per minute before the next one needs a person */
  perMinute: number;
  /** times the very same action (tool and arguments) may run in ten minutes before the next one needs a person */
  sameAction: number;
}

export const DEFAULT_BURST: BurstPolicy = { perMinute: 20, sameAction: 3 };

export class BurstCounter {
  private at: number[] = [];
  private same = new Map<string, number[]>();

  /** record one side effect that ran */
  record(digestKey: string, now: number): void {
    this.at.push(now);
    const s = this.same.get(digestKey) ?? [];
    s.push(now);
    this.same.set(digestKey, s);
    this.trim(now);
  }

  /** reasons the next action should wait for a person; empty when it is within limits */
  check(digestKey: string, now: number, p: BurstPolicy): string[] {
    this.trim(now);
    const why: string[] = [];
    const lastMinute = this.at.filter((t) => now - t < 60_000).length;
    if (lastMinute >= p.perMinute) why.push(`this run has already performed ${lastMinute} actions in the last minute`);
    const repeats = (this.same.get(digestKey) ?? []).length;
    if (repeats >= p.sameAction) why.push(`this exact action has already run ${repeats} times in the last ten minutes`);
    return why;
  }

  export(): { at: number[]; same: Array<[string, number[]]> } { return { at: this.at.slice(-200), same: [...this.same].slice(-200) }; }
  import(d: { at?: unknown; same?: unknown } | undefined): void {
    if (!d || typeof d !== "object") return;
    if (Array.isArray(d.at)) this.at.push(...d.at.filter((x): x is number => typeof x === "number"));
    for (const e of Array.isArray(d.same) ? d.same : []) if (Array.isArray(e) && typeof e[0] === "string" && Array.isArray(e[1])) this.same.set(e[0], (e[1] as unknown[]).filter((x): x is number => typeof x === "number"));
  }

  private trim(now: number) {
    this.at = this.at.filter((t) => now - t < 600_000);
    for (const [k, v] of this.same) {
      const kept = v.filter((t) => now - t < 600_000);
      if (kept.length) this.same.set(k, kept); else this.same.delete(k);
    }
  }
}

/** the same action whatever run it is in: tool and canonical arguments */
export const actionKey = (tool: string, canonicalArgs: string) => createHash("sha256").update(`${tool}\n${canonicalArgs}`, "utf8").digest("hex");

// ---------- stop switch ----------

const stopPath = (dir?: string) => join(dir ?? stateDir(), "STOP");

/** Why everything is stopped, or undefined when it is not. Any readable file there counts, even an empty one. */
export function stopReason(dir?: string): string | undefined {
  const p = stopPath(dir);
  if (!existsSync(p)) return undefined;
  try { return readFileSync(p, "utf8").trim().slice(0, 300) || "stopped by a person"; } catch { return "stopped (the stop file exists but could not be read)"; }
}

/** Stop every action routed through any broker on this machine that uses this state folder. */
export function engageStop(reason: string, dir?: string, now: Date = new Date()): string {
  const p = stopPath(dir);
  mkdirSync(dirname(p), { recursive: true, mode: 0o700 });
  writeFileSync(p, `${reason.trim() || "stopped by a person"} (since ${now.toISOString()})\n`, { mode: 0o600 });
  return p;
}

export function clearStop(dir?: string): boolean {
  const p = stopPath(dir);
  if (!existsSync(p)) return false;
  rmSync(p);
  return true;
}
