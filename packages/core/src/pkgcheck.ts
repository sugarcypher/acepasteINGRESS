/**
 * ingress pkgcheck: look at a package before it is installed.
 *
 * AI coding agents suggest packages that do not exist (a name that sounds right), and people register those
 * names with malware in them ("slopsquatting"). Typosquats of popular names, packages a few days old with an
 * install script, and READMEs written to steer an agent are the same family. This check reads the public
 * registry's metadata for each package and says what stands out:
 *
 *   not found        the registry has no such package (or no such version): likely made up            high
 *   lookalike        within one or two edits of a popular name (built-in list, no network)           high / review
 *   brand new        first published less than about 30 days ago, few versions                       review
 *   install script   npm preinstall / install / postinstall (code that runs on install)              review
 *                    brand new AND an install script                                                  high
 *   source only      PyPI release with no wheel: installing runs its build code                       review
 *   no repository    no link to source code                                                           review / info
 *   deprecated       npm deprecation message, PyPI "Inactive" status or a yanked release             review
 *   readme           the README read by the Ingress engine: text aimed at an AI agent                 high / review
 *
 * Network: only registry.npmjs.org and pypi.org are contacted, one GET per package, with the gate's own user
 * agent. `--offline` contacts nothing and runs only the lookalike check. Nothing is installed or downloaded.
 */

import { HONEST_USER_AGENT } from "./acquire.js";
import { shellInvocations } from "./shell-commands.js";
import { NPM_TOP, PYPI_TOP } from "./pkgcheck-top.js";
import type { Tier } from "./types.js";

export type Ecosystem = "npm" | "pypi";
export type PkgSeverity = "high" | "review" | "info";

export interface PkgSpec { ecosystem: Ecosystem; name: string; version?: string }

export interface PkgFinding {
  id: "not-found" | "version-not-found" | "unpublished" | "lookalike" | "new" | "install-script" | "source-only" | "no-repository" | "deprecated" | "readme" | "registry-error" | "other-index";
  severity: PkgSeverity;
  /** one line, plain English */
  title: string;
  detail?: string;
}

export interface PkgReport {
  ecosystem: Ecosystem;
  name: string;
  version?: string;
  /** the version the facts below describe (the one asked for, or the latest) */
  checkedVersion?: string;
  /** undefined when the registry was not asked (offline) or could not be reached */
  exists?: boolean;
  mode: "registry" | "offline";
  firstPublished?: string;
  ageDays?: number;
  versionCount?: number;
  repository?: string;
  findings: PkgFinding[];
  summary: { high: number; review: number; info: number };
}

/** what pkgcheck needs from fetch; tests pass their own */
export type PkgFetch = (url: string) => Promise<{ status: number; json(): Promise<unknown> }>;
/** the text gate, for READMEs (the same scan `ingress --text` runs) */
export type PkgGate = (text: string, url: string) => Promise<{ tier: Tier; findings: Array<{ kind: string; message: string }> }>;

export interface PkgCheckOptions {
  offline?: boolean;
  fetch?: PkgFetch;
  gate?: PkgGate;
  /** set false to skip the README scan */
  readme?: boolean;
  now?: () => number;
  /** "brand new" means first published fewer days ago than this (default 30) */
  newDays?: number;
}

export const PKGCHECK_REGISTRIES: Readonly<Record<Ecosystem, string>> = { npm: "https://registry.npmjs.org", pypi: "https://pypi.org/pypi" };

// ---------- names ----------

/** PEP 503: PyPI names compare case-insensitively with runs of -, _ and . as one "-" */
export const normalizePypi = (n: string) => n.toLowerCase().replace(/[-_.]+/g, "-");
const norm = (eco: Ecosystem, n: string) => (eco === "pypi" ? normalizePypi(n) : n.toLowerCase());
const stripSep = (n: string) => n.replace(/[-_.]/g, "");

/** optimal string alignment distance (Damerau-Levenshtein with adjacent swaps), stopping early past `max` */
export function editDistance(a: string, b: string, max = 3): number {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  const prev2: number[] = new Array(b.length + 1).fill(0);
  let prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    let rowMin = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let v = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) v = Math.min(v, prev2[j - 2] + 1);
      cur.push(v);
      rowMin = Math.min(rowMin, v);
    }
    for (let j = 0; j <= b.length; j++) prev2[j] = prev[j];
    prev = cur;
    if (rowMin > max) return max + 1;
  }
  return prev[b.length];
}

const TOP: Record<Ecosystem, Set<string>> = { npm: new Set(NPM_TOP.map((n) => n.toLowerCase())), pypi: new Set(PYPI_TOP.map(normalizePypi)) };

/** The popular name this one imitates, if any: a separator swap, or one or two edits (one for short names). */
export function similarPopular(eco: Ecosystem, name: string): { name: string; distance: number } | undefined {
  const n = norm(eco, name);
  const top = TOP[eco];
  if (top.has(n) || n.length < 3) return undefined;
  const scoped = n.startsWith("@");
  let best: { name: string; distance: number } | undefined;
  for (const t of top) {
    if (t.startsWith("@") !== scoped) continue; // a scope is a namespace someone owns: compare like with like
    if (stripSep(t) === stripSep(n)) return { name: t, distance: 0 };
    const max = Math.min(n.length, t.length) <= 5 ? 1 : 2;
    const d = editDistance(n, t, max);
    if (d <= max && (!best || d < best.distance)) best = { name: t, distance: d };
  }
  return best;
}

/** "name", "name@1.2.3", "@scope/name@^2" (npm); "name", "name==1.2", "name[extra]>=1" (PyPI) */
export function parsePkgArg(eco: Ecosystem, arg: string): PkgSpec | undefined {
  const a = arg.trim().replace(/^['"]|['"]$/g, "");
  if (!a || /^(?:\.{0,2}\/|~|[a-z][a-z0-9+.-]*:\/\/|git\+|file:|link:|workspace:|npm:|github:|gitlab:|bitbucket:)/i.test(a) || /\.(?:tgz|tar\.gz|zip|whl)$/i.test(a)) return undefined;
  if (eco === "npm") {
    const m = /^((?:@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]*)(?:@(.+))?$/i.exec(a);
    if (!m) return undefined;
    return { ecosystem: eco, name: m[1], ...(m[2] ? { version: m[2] } : {}) };
  }
  const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(?:(===?)\s*([^\s,;]+)|[<>!~=].*)?$/.exec(a);
  if (!m) return undefined;
  return { ecosystem: eco, name: m[1], ...(m[3] ? { version: m[3] } : {}) };
}

const NPM_FLAG_VALUE = new Set(["--registry", "--tag", "--prefix", "--workspace", "--filter", "-C", "--dir", "--cwd", "--otp", "--cache"]);
const PIP_FLAG_VALUE = new Set(["-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-i", "--index-url", "--extra-index-url", "-f", "--find-links", "-t", "--target", "--prefix", "--root", "--python", "-p", "--group", "--optional", "--extra", "--index", "--default-index", "--upgrade-package", "-P", "--platform", "--python-version", "--implementation", "--abi", "--src", "--log", "--cache-dir", "--trusted-host", "--proxy", "--retries", "--timeout", "--package", "--script", "--branch", "--tag", "--rev"]);

export interface InstallCommand { tool: string; specs: PkgSpec[]; notes: string[] }

/**
 * The packages an install command line would fetch: `npm install|i|add`, `pnpm add|install|i`, `yarn add`
 * (and `yarn global add`), `bun add`, `pip install`, `pip3 install`, `python -m pip install`, `uv add` and
 * `uv pip install`. Several commands joined with && or ; are each read. Paths, URLs, git sources, tarballs
 * and requirement files are not packages on a registry and are skipped (a requirement file is noted).
 */
export function parseInstallCommands(command: string): InstallCommand[] {
  let inv: Array<{ program: string; args: string[] }>;
  try { inv = shellInvocations(command); } catch { return []; }
  const out: InstallCommand[] = [];
  for (const { program, args } of inv) {
    let eco: Ecosystem | undefined, rest: string[] = [], tool = program;
    const sub = args.findIndex((a) => !a.startsWith("-"));
    const verb = sub >= 0 ? args[sub] : "";
    if (program === "npm" && ["install", "i", "add", "isntall", "in", "ins", "inst", "insta", "instal"].includes(verb)) { eco = "npm"; rest = args.slice(sub + 1); }
    else if (program === "pnpm" && ["add", "install", "i"].includes(verb)) { eco = "npm"; rest = args.slice(sub + 1); }
    else if (program === "yarn" && verb === "add") { eco = "npm"; rest = args.slice(sub + 1); }
    else if (program === "yarn" && verb === "global" && args[sub + 1] === "add") { eco = "npm"; rest = args.slice(sub + 2); tool = "yarn global"; }
    else if (program === "bun" && ["add", "install", "i"].includes(verb)) { eco = "npm"; rest = args.slice(sub + 1); }
    else if (/^pip(?:3(?:\.\d+)?)?$/.test(program) && verb === "install") { eco = "pypi"; rest = args.slice(sub + 1); }
    else if (/^python(?:3(?:\.\d+)?)?$/.test(program) && args[0] === "-m" && /^pip3?$/.test(args[1] ?? "") && args[2] === "install") { eco = "pypi"; rest = args.slice(3); tool = "python -m pip"; }
    else if (program === "uv" && verb === "add") { eco = "pypi"; rest = args.slice(sub + 1); tool = "uv add"; }
    else if (program === "uv" && verb === "pip" && args[sub + 1] === "install") { eco = "pypi"; rest = args.slice(sub + 2); tool = "uv pip"; }
    if (!eco) continue;
    const specs: PkgSpec[] = [], notes: string[] = [];
    const flagsWithValue = eco === "npm" ? NPM_FLAG_VALUE : PIP_FLAG_VALUE;
    for (let i = 0; i < rest.length; i++) {
      const a = rest[i];
      if (/^[\d&]*[<>]/.test(a)) { i++; continue; } // a redirect
      if (a.startsWith("-")) {
        const [flag, inline] = a.split(/=(.*)/s, 2);
        const value = inline ?? (flagsWithValue.has(flag) ? rest[++i] : undefined);
        if (/^(?:-i|--index-url|--extra-index-url|--index|--default-index|--registry)$/.test(flag) && value) notes.push(`installs from ${value}, not only the public registry: this check read the public registry`);
        if (/^(?:-r|--requirement)$/.test(flag) && value) notes.push(`also installs everything listed in ${value}, which was not read`);
        continue;
      }
      const s = parsePkgArg(eco, a);
      if (s) specs.push(s);
      else notes.push(`${a} is not a registry package (a path, URL or git source) and was not checked`);
    }
    out.push({ tool, specs, notes });
  }
  return out;
}

// ---------- the registry ----------

const defaultFetch: PkgFetch = (url) => fetch(url, { headers: { "user-agent": HONEST_USER_AGENT, accept: "application/json" }, redirect: "follow", signal: AbortSignal.timeout(20_000) });
const asObj = (v: unknown): Record<string, unknown> => (v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {});
const str = (v: unknown) => (typeof v === "string" ? v : undefined);
const CODE_HOST = /(?:github\.com|gitlab\.com|bitbucket\.org|codeberg\.org|sr\.ht|git\.sr\.ht|sourceforge\.net|gitee\.com)\//i;
const RISKY_SCRIPT = /\bcurl\b|\bwget\b|https?:\/\/|\beval\b|base64|child_process|\/dev\/tcp|powershell|\bnc\s|\.ssh|\.npmrc|\bprintenv\b|\benv\b\s*\|/i;
const shorten = (s: string, n = 140) => (s.length > n ? `${s.slice(0, n)}…` : s);

function finish(r: Omit<PkgReport, "summary">): PkgReport {
  const order: Record<PkgSeverity, number> = { high: 0, review: 1, info: 2 };
  r.findings.sort((a, b) => order[a.severity] - order[b.severity]);
  return { ...r, summary: { high: r.findings.filter((f) => f.severity === "high").length, review: r.findings.filter((f) => f.severity === "review").length, info: r.findings.filter((f) => f.severity === "info").length } };
}

function lookalike(spec: PkgSpec, established: boolean | undefined): PkgFinding | undefined {
  const sim = similarPopular(spec.ecosystem, spec.name);
  if (!sim) return undefined;
  const close = sim.distance <= 1;
  // a lookalike that has been around for a year with many releases is more likely a real project with an unlucky name
  const severity: PkgSeverity = close && !established ? "high" : "review";
  return { id: "lookalike", severity, title: sim.distance === 0 ? `the name differs from the popular package "${sim.name}" only in separators` : `the name is ${sim.distance} edit${sim.distance === 1 ? "" : "s"} from the popular package "${sim.name}"`, detail: established ? "it has a long release history, so it may be a real project with a similar name; check that it is the one you meant" : `check that you meant this and not "${sim.name}": lookalike names are a common way to slip in malware` };
}

async function readme(gate: PkgGate | undefined, text: string | undefined, url: string, findings: PkgFinding[]): Promise<void> {
  if (!gate || !text?.trim()) return;
  try {
    const v = await gate(text.slice(0, 500_000), url);
    if (v.tier === "hostile" || v.tier === "suspect") {
      const kinds = [...new Set(v.findings.map((f) => f.kind))].slice(0, 4).join(", ");
      findings.push({ id: "readme", severity: v.tier === "hostile" ? "high" : "review", title: `the README has text aimed at an AI agent (Ingress verdict: ${v.tier})`, detail: kinds });
    }
  } catch (e) { findings.push({ id: "registry-error", severity: "info", title: `the README could not be scanned: ${(e as Error).message}` }); }
}

async function checkNpm(spec: PkgSpec, o: Required<Pick<PkgCheckOptions, "now" | "newDays">> & PkgCheckOptions, doFetch: PkgFetch): Promise<PkgReport> {
  const base = { ecosystem: spec.ecosystem, name: spec.name, ...(spec.version ? { version: spec.version } : {}), mode: "registry" as const };
  const findings: PkgFinding[] = [];
  const url = `${PKGCHECK_REGISTRIES.npm}/${spec.name.startsWith("@") ? `@${encodeURIComponent(spec.name.slice(1))}` : encodeURIComponent(spec.name)}`;
  let res;
  try { res = await doFetch(url); } catch (e) { return registryError(spec, findings, `the npm registry could not be reached (${(e as Error).message})`); }
  if (res.status === 404) {
    findings.push({ id: "not-found", severity: "high", title: `"${spec.name}" is not on the npm registry`, detail: "a package an AI suggested that does not exist may be a made-up name, and someone can register it later with malware in it (slopsquatting). Do not install it under this name." });
    const l = lookalike(spec, false); if (l) findings.push({ ...l, severity: "review" });
    return finish({ ...base, exists: false, findings });
  }
  if (res.status !== 200) return registryError(spec, findings, `the npm registry answered HTTP ${res.status}`);
  const doc = asObj(await res.json());
  const time = asObj(doc.time);
  const versions = asObj(doc.versions);
  const tags = asObj(doc["dist-tags"]);
  if (time.unpublished || !Object.keys(versions).length) {
    findings.push({ id: "unpublished", severity: "high", title: `"${spec.name}" was unpublished from npm: nothing can be installed under this name now, and the name may be taken again` });
    return finish({ ...base, exists: false, findings });
  }
  const created = str(time.created) ?? Object.entries(time).filter(([k]) => k !== "modified" && k !== "created").map(([, v]) => str(v)).filter(Boolean).sort()[0];
  const ageDays = created ? Math.floor((o.now() - Date.parse(created)) / 86_400_000) : undefined;
  const versionCount = Object.keys(versions).length;
  let checkedVersion = str(tags.latest) ?? Object.keys(versions).pop()!;
  if (spec.version) {
    if (versions[spec.version]) checkedVersion = spec.version;
    else if (str(tags[spec.version])) checkedVersion = str(tags[spec.version])!;
    else if (/^\d+\.\d+\.\d+(?:[-+].*)?$/.test(spec.version)) findings.push({ id: "version-not-found", severity: "high", title: `version ${spec.version} of "${spec.name}" does not exist on npm (latest is ${str(tags.latest) ?? "unknown"})`, detail: "a version that does not exist is often a made-up detail" });
  }
  const v = asObj(versions[checkedVersion]);
  const established = ageDays !== undefined && ageDays >= 365 && versionCount >= 10;
  const isNew = ageDays !== undefined && ageDays < o.newDays;
  if (isNew) findings.push({ id: "new", severity: "review", title: `first published ${ageDays} day${ageDays === 1 ? "" : "s"} ago, with ${versionCount} version${versionCount === 1 ? "" : "s"}`, detail: "new packages have no track record; most malicious packages are caught and removed within days of publishing" });
  const scripts = asObj(v.scripts);
  const hooks = ["preinstall", "install", "postinstall"].filter((k) => typeof scripts[k] === "string");
  if (hooks.length) {
    const body = hooks.map((k) => `${k}: ${shorten(String(scripts[k]), 100)}`).join("; ");
    const risky = hooks.some((k) => RISKY_SCRIPT.test(String(scripts[k])));
    findings.push({ id: "install-script", severity: isNew || (risky && !established) ? "high" : "review", title: `runs code when installed (${hooks.join(", ")})${isNew ? " and is brand new" : risky ? ", and the script reaches the network or credentials" : ""}`, detail: `${body}. To install without running it: npm install --ignore-scripts` });
  }
  const repo = str(asObj(v.repository).url) ?? str(v.repository) ?? str(asObj(doc.repository).url) ?? str(doc.repository);
  if (!repo) findings.push({ id: "no-repository", severity: isNew || !established ? "review" : "info", title: "no source repository is linked, so the published code cannot be compared with its source" });
  if (typeof v.deprecated === "string" && v.deprecated) findings.push({ id: "deprecated", severity: "review", title: "deprecated by its publisher", detail: shorten(v.deprecated, 200) });
  const l = lookalike(spec, established); if (l) findings.push(l);
  if (o.readme !== false) await readme(o.gate, str(doc.readme) ?? str(v.readme), `${url}#readme`, findings);
  return finish({ ...base, checkedVersion, exists: true, ...(created ? { firstPublished: created } : {}), ...(ageDays !== undefined ? { ageDays } : {}), versionCount, ...(repo ? { repository: repo } : {}), findings });
}

async function checkPypi(spec: PkgSpec, o: Required<Pick<PkgCheckOptions, "now" | "newDays">> & PkgCheckOptions, doFetch: PkgFetch): Promise<PkgReport> {
  const base = { ecosystem: spec.ecosystem, name: spec.name, ...(spec.version ? { version: spec.version } : {}), mode: "registry" as const };
  const findings: PkgFinding[] = [];
  const url = `${PKGCHECK_REGISTRIES.pypi}/${encodeURIComponent(normalizePypi(spec.name))}/json`;
  let res;
  try { res = await doFetch(url); } catch (e) { return registryError(spec, findings, `PyPI could not be reached (${(e as Error).message})`); }
  if (res.status === 404) {
    findings.push({ id: "not-found", severity: "high", title: `"${spec.name}" is not on PyPI`, detail: "a package an AI suggested that does not exist may be a made-up name, and someone can register it later with malware in it (slopsquatting). Do not install it under this name." });
    const l = lookalike(spec, false); if (l) findings.push({ ...l, severity: "review" });
    return finish({ ...base, exists: false, findings });
  }
  if (res.status !== 200) return registryError(spec, findings, `PyPI answered HTTP ${res.status}`);
  const doc = asObj(await res.json());
  const info = asObj(doc.info);
  const releases = asObj(doc.releases);
  const files = (ver: string) => (Array.isArray(releases[ver]) ? (releases[ver] as unknown[]).map(asObj) : []);
  const published = Object.keys(releases).filter((k) => files(k).length);
  const uploads = published.flatMap((k) => files(k).map((f) => str(f.upload_time_iso_8601) ?? str(f.upload_time))).filter((x): x is string => !!x).sort();
  const created = uploads[0];
  const ageDays = created ? Math.floor((o.now() - Date.parse(created.endsWith("Z") || /[+-]\d\d:\d\d$/.test(created) ? created : `${created}Z`)) / 86_400_000) : undefined;
  const versionCount = published.length;
  let checkedVersion = str(info.version) ?? published[published.length - 1];
  if (spec.version) {
    if (releases[spec.version] !== undefined) checkedVersion = spec.version;
    else findings.push({ id: "version-not-found", severity: "high", title: `version ${spec.version} of "${spec.name}" does not exist on PyPI (latest is ${str(info.version) ?? "unknown"})`, detail: "a version that does not exist is often a made-up detail" });
  }
  const established = ageDays !== undefined && ageDays >= 365 && versionCount >= 10;
  const isNew = ageDays !== undefined && ageDays < o.newDays;
  if (isNew) findings.push({ id: "new", severity: "review", title: `first published ${ageDays} day${ageDays === 1 ? "" : "s"} ago, with ${versionCount} release${versionCount === 1 ? "" : "s"}`, detail: "new packages have no track record; most malicious packages are caught and removed within days of publishing" });
  const rel = checkedVersion ? files(checkedVersion) : [];
  if (rel.length && rel.every((f) => f.packagetype !== "bdist_wheel")) findings.push({ id: "source-only", severity: isNew ? "high" : "review", title: `release ${checkedVersion} has no wheel, only a source package: installing runs its build code (setup.py) on your machine${isNew ? ", and the package is brand new" : ""}`, detail: "pip install --only-binary :all: refuses to build from source" });
  if (rel.length && rel.every((f) => f.yanked === true)) findings.push({ id: "deprecated", severity: "review", title: `release ${checkedVersion} was yanked by its publisher`, detail: str(rel[0].yanked_reason) ?? undefined });
  const classifiers = Array.isArray(info.classifiers) ? info.classifiers.filter((c): c is string => typeof c === "string") : [];
  if (classifiers.some((c) => /Development Status :: 7 - Inactive/.test(c))) findings.push({ id: "deprecated", severity: "review", title: "marked inactive by its publisher (Development Status :: 7 - Inactive)" });
  const urls = Object.entries(asObj(info.project_urls)).map(([k, val]) => [k, str(val) ?? ""] as const);
  const repo = urls.find(([k, val]) => CODE_HOST.test(val) || /^(?:source|source code|repository|code|github|gitlab)$/i.test(k.trim()))?.[1] ?? (CODE_HOST.test(str(info.home_page) ?? "") ? str(info.home_page) : undefined);
  if (!repo) findings.push({ id: "no-repository", severity: isNew || !established ? "review" : "info", title: "no source repository is linked, so the published code cannot be compared with its source" });
  const l = lookalike(spec, established); if (l) findings.push(l);
  if (o.readme !== false) await readme(o.gate, str(info.description), `${url}#readme`, findings);
  return finish({ ...base, ...(checkedVersion ? { checkedVersion } : {}), exists: true, ...(created ? { firstPublished: created } : {}), ...(ageDays !== undefined ? { ageDays } : {}), versionCount, ...(repo ? { repository: repo } : {}), findings });
}

function registryError(spec: PkgSpec, findings: PkgFinding[], why: string): PkgReport {
  findings.push({ id: "registry-error", severity: "review", title: why, detail: "only the name check ran" });
  const l = lookalike(spec, undefined); if (l) findings.push(l);
  return finish({ ecosystem: spec.ecosystem, name: spec.name, ...(spec.version ? { version: spec.version } : {}), mode: "registry", findings });
}

/** Check each package. Never throws for a registry problem: it becomes a finding. */
export async function pkgcheck(specs: readonly PkgSpec[], opts: PkgCheckOptions = {}): Promise<PkgReport[]> {
  const o = { ...opts, now: opts.now ?? Date.now, newDays: opts.newDays ?? 30 };
  const doFetch = opts.fetch ?? defaultFetch;
  const gate = opts.offline || opts.readme === false ? undefined : (opts.gate ?? (await defaultGate()));
  const out: PkgReport[] = [];
  const seen = new Set<string>();
  for (const s of specs) {
    const key = `${s.ecosystem}:${norm(s.ecosystem, s.name)}@${s.version ?? ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    if (o.offline) {
      const findings: PkgFinding[] = [];
      const l = lookalike(s, undefined); if (l) findings.push(l);
      out.push(finish({ ecosystem: s.ecosystem, name: s.name, ...(s.version ? { version: s.version } : {}), mode: "offline", findings }));
      continue;
    }
    out.push(await (s.ecosystem === "npm" ? checkNpm : checkPypi)(s, { ...o, gate }, doFetch));
  }
  return out;
}

async function defaultGate(): Promise<PkgGate> {
  const { IngressEngine } = await import("./engine.js");
  const engine = new IngressEngine({ cloakingCheck: false, sandbox: "off" }, { log: () => {} });
  return async (text, url) => { const r = await engine.scan(text, { url, contentType: "text/markdown", source: { channel: "package readme", trust: 5 } }); return { tier: r.tier, findings: r.findings }; };
}

// ---------- the command line ----------

export interface PkgcheckArgs { specs: PkgSpec[]; json: boolean; hook: boolean; command?: string; opts: PkgCheckOptions; error?: string }

const ECOSYSTEM: Record<string, Ecosystem> = { npm: "npm", node: "npm", js: "npm", pnpm: "npm", yarn: "npm", pypi: "pypi", pip: "pypi", py: "pypi", python: "pypi", uv: "pypi" };

/** parse argv after "pkgcheck" */
export function parsePkgcheckArgs(argv: string[]): PkgcheckArgs {
  const r: PkgcheckArgs = { specs: [], json: false, hook: false, opts: {} };
  const words: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--json") r.json = true;
    else if (a === "--offline") r.opts.offline = true;
    else if (a === "--no-readme") r.opts.readme = false;
    else if (a === "--hook") r.hook = true;
    else if (a === "--command" || a.startsWith("--command=")) r.command = a.includes("=") ? a.slice(10) : argv[++i];
    else if (a === "--new-days" || a.startsWith("--new-days=")) {
      const n = Number(a.includes("=") ? a.slice(11) : argv[++i]);
      if (!Number.isInteger(n) || n < 1) return { ...r, error: "--new-days needs a whole number of 1 or more" };
      r.opts.newDays = n;
    } else if (a.startsWith("--")) return { ...r, error: `unknown argument: ${a}` };
    else words.push(a);
  }
  if (r.hook || r.command !== undefined) return words.length ? { ...r, error: "give packages or a command line, not both" } : r;
  if (!words.length) return { ...r, error: "missing ecosystem and package names" };
  const eco = ECOSYSTEM[words[0].toLowerCase()];
  if (!eco) return { ...r, error: `unknown ecosystem "${words[0]}" (use npm or pypi)` };
  if (words.length < 2) return { ...r, error: "missing package names" };
  for (const w of words.slice(1)) {
    // name@1.2 is accepted for PyPI too
    const s = parsePkgArg(eco, eco === "pypi" ? w.replace(/^([^@\s]+)@([^@\s]+)$/, "$1==$2") : w);
    if (!s) return { ...r, error: `not a package name: ${w}` };
    r.specs.push(s);
  }
  return r;
}

// ---------- the report ----------

/** the human report */
export function formatPkgcheck(reports: readonly PkgReport[], notes: readonly string[] = []): string {
  const label: Record<PkgSeverity, string> = { high: "HIGH  ", review: "REVIEW", info: "INFO  " };
  const out: string[] = [];
  for (const r of reports) {
    const facts = [r.mode === "offline" ? "offline: name check only" : r.exists === false ? "not found" : r.exists ? `version ${r.checkedVersion ?? "?"}` : "registry not reached",
      r.ageDays !== undefined ? `first published ${r.ageDays} days ago` : "", r.versionCount !== undefined ? `${r.versionCount} versions` : "", r.repository ? `source: ${shorten(r.repository, 60)}` : ""].filter(Boolean).join(", ");
    out.push(`${r.ecosystem} ${r.name}${r.version ? `@${r.version}` : ""}  (${facts})`);
    if (!r.findings.length) out.push("  ok     nothing stands out");
    for (const f of r.findings) {
      out.push(`  ${label[f.severity]} ${f.title}`);
      if (f.detail) out.push(`         ${f.detail}`);
    }
  }
  for (const n of notes) out.push(`note: ${n}`);
  const t = reports.reduce((a, r) => ({ high: a.high + r.summary.high, review: a.review + r.summary.review }), { high: 0, review: 0 });
  out.push(`summary: ${reports.length} package${reports.length === 1 ? "" : "s"}, ${t.high} high, ${t.review} review`);
  return out.join("\n");
}

/**
 * The reply for a coding agent's PreToolUse hook (Claude Code's shape), or undefined when there is nothing to
 * say: a package that is not on the registry, or whose README is hostile, is refused; any other high finding
 * is put to the person; review findings stay quiet (an install script on its own is ordinary).
 */
export function pkgcheckHookReply(reports: readonly PkgReport[]): Record<string, unknown> | undefined {
  const high = reports.flatMap((r) => r.findings.filter((f) => f.severity === "high").map((f) => ({ r, f })));
  if (!high.length) return undefined;
  const deny = high.some(({ f }) => f.id === "not-found" || f.id === "unpublished" || f.id === "readme");
  const reasons = high.map(({ r, f }) => `${r.ecosystem} ${r.name}: ${f.title}`).join("; ");
  return { hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: deny ? "deny" : "ask", permissionDecisionReason: `AcePaste Ingress pkgcheck: ${reasons}.${deny ? " This install is refused; do not install it another way or under a similar name. Tell the person which package you wanted and why." : ""}` } };
}
