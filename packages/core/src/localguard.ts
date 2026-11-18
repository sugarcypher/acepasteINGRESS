/**
 * Local-service guard: "it came from localhost" says where a request was sent, not who sent it.
 *
 * A web page in the user's browser can reach a service on 127.0.0.1 two ways: DNS rebinding (the page's
 * own hostname is re-pointed at 127.0.0.1, so the browser treats the local service as same-origin) and plain
 * cross-site requests. Both leave marks a local client never does: a Host header naming something other than
 * this service, or an Origin header naming another site. A bearer key already stops unauthenticated calls;
 * this is the second wall, and it also protects the endpoints that need no key.
 */

export interface LocalRequestHeaders {
  host?: string;
  origin?: string;
}

export interface LocalGuardOptions {
  /** the port this service listens on */
  port: number;
  /** extra hosts this service is legitimately reached by: "gate.example" (any port) or "gate.example:8443" */
  allowedHosts?: readonly string[];
}

export type LocalGuardVerdict = { ok: true } | { ok: false; reason: string };

const LOOPBACK_NAMES = ["127.0.0.1", "localhost", "[::1]"];

function hostPort(value: string): { host: string; port: number | undefined } | null {
  const v = value.trim().toLowerCase();
  // [v6]:port, name:port, or a bare name. Anything with a path, credentials or whitespace is not a Host header.
  const m = v.match(/^(\[[0-9a-f:.]+\]|[a-z0-9.-]+)(?::(\d{1,5}))?$/);
  if (!m) return null;
  return { host: m[1].replace(/\.$/, ""), port: m[2] === undefined ? undefined : Number(m[2]) };
}

function nameAllowed(host: string, port: number | undefined, defaultPort: number, opts: LocalGuardOptions): boolean {
  const effective = port ?? defaultPort;
  if (LOOPBACK_NAMES.includes(host)) return effective === opts.port;
  // an allowed host is a name the operator chose: "gate.example" (any port: a reverse proxy sits in front,
  // so the public port is not this process's port) or "gate.example:8443" (that port only)
  for (const entry of opts.allowedHosts ?? []) {
    const a = hostPort(entry);
    if (a && a.host === host && (a.port === undefined || a.port === effective)) return true;
  }
  return false;
}

/**
 * Decide whether a request to a loopback-bound service really is addressed to it.
 * Refuses: a missing or malformed Host, a Host that names anything but this service (the rebinding mark),
 * and an Origin that is not this service's own (a cross-site request; "null" included).
 */
export function checkLocalRequest(h: LocalRequestHeaders, opts: LocalGuardOptions): LocalGuardVerdict {
  if (!h.host) return { ok: false, reason: "missing Host header" };
  const hp = hostPort(h.host);
  if (!hp) return { ok: false, reason: "malformed Host header" };
  if (!nameAllowed(hp.host, hp.port, 80, opts)) return { ok: false, reason: `Host "${h.host.slice(0, 80)}" is not this service` };
  if (h.origin !== undefined) {
    const o = h.origin.trim().toLowerCase();
    const m = o.match(/^(https?):\/\/(.+)$/);
    const op = m ? hostPort(m[2]) : null;
    if (!m || !op || !nameAllowed(op.host, op.port, m[1] === "https" ? 443 : 80, opts)) {
      return { ok: false, reason: `cross-site request from origin "${h.origin.slice(0, 80)}"` };
    }
  }
  return { ok: true };
}

/** True when a listen address keeps the service off the network (so the local guard applies). */
export function isLoopbackBind(host: string | undefined): boolean {
  if (!host) return false;
  const h = host.trim().toLowerCase().replace(/^\[|\]$/g, "");
  return h === "localhost" || h === "::1" || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h);
}
