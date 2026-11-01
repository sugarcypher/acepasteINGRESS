/**
 * Acquire pass.
 *
 * Fetches a URL under one of two fingerprints. The "agent" fingerprint looks
 * like what an automated fetch tool sends; the "human" fingerprint looks like
 * a desktop browser. The cloaking pass compares the two.
 *
 * Every hop is checked against the network policy before connecting, and
 * the connection is pinned to the addresses that were checked (DNS rebinding
 * defense). Redirects are followed manually so each hop is checked.
 */

import { Agent, fetch as undiciFetch, type Dispatcher } from "undici";
import { checkTarget, NetPolicyError, type NetPolicy } from "./netpolicy.js";
import type { AcquireResult, IngressConfig } from "./types.js";

const HUMAN_HEADERS: Record<string, string> = {
  "user-agent":
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
  accept:
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
  "accept-language": "en-US,en;q=0.9",
  "sec-fetch-dest": "document",
  "sec-fetch-mode": "navigate",
  "sec-fetch-site": "none",
  "sec-fetch-user": "?1",
  "upgrade-insecure-requests": "1",
};

const AGENT_HEADERS: Record<string, string> = {
  "user-agent": "AcePasteIngress/0.7 (+https://acepaste.xyz/ingress)",
  accept: "text/html,application/xhtml+xml,text/markdown,text/plain;q=0.9,application/json;q=0.8,*/*;q=0.5",
};

export const MAX_REDIRECTS = 5;

export class AcquireError extends Error {
  constructor(
    message: string,
    public readonly code: "unsupported_scheme" | "too_large" | "timeout" | "network" | "binary" | "too_many_redirects" | "policy",
    public readonly policyCode?: NetPolicyError["code"],
  ) {
    super(message);
  }
}

export type FetchLike = (url: string, init: RequestInit & { dispatcher?: Dispatcher }) => Promise<Response>;

/** undici fetch pinned to pre-checked addresses */
function pinnedFetch(addrs: string[]): FetchLike {
  const agent = new Agent({
    connect: {
      lookup: (_host, _opts, cb) => cb(null, addrs.map((address) => ({ address, family: address.includes(":") ? 6 : 4 }))),
    },
  });
  return (url, init) => undiciFetch(url, { ...(init as any), dispatcher: agent }) as unknown as Promise<Response>;
}

export async function acquire(
  url: string,
  fingerprint: "human" | "agent",
  config: IngressConfig,
  policy: NetPolicy,
  fetchImpl?: FetchLike,
  resolver?: (host: string) => Promise<string[]>,
): Promise<AcquireResult> {
  let current = new URL(url);
  if (current.protocol !== "http:" && current.protocol !== "https:") {
    throw new AcquireError(`unsupported scheme ${current.protocol}`, "unsupported_scheme");
  }
  const chain: string[] = [];
  const headersIn = fingerprint === "human" ? HUMAN_HEADERS : AGENT_HEADERS;

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    let addrs: string[];
    try {
      addrs = await checkTarget(current, policy, resolver);
    } catch (e) {
      if (e instanceof NetPolicyError) throw new AcquireError(e.message, "policy", e.code);
      throw e;
    }
    const doFetch = fetchImpl ?? pinnedFetch(addrs);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), config.fetchTimeoutMs);
    let res: Response;
    try {
      res = await doFetch(current.toString(), { headers: headersIn, redirect: "manual", signal: controller.signal });
    } catch (e) {
      clearTimeout(timer);
      const aborted = (e as Error).name === "AbortError";
      throw new AcquireError(aborted ? "fetch timed out" : `network error: ${(e as Error).message}`, aborted ? "timeout" : "network");
    }
    clearTimeout(timer);

    if (res.status >= 300 && res.status < 400 && res.headers.get("location")) {
      chain.push(current.toString());
      let next: URL;
      try { next = new URL(res.headers.get("location")!, current); } catch { throw new AcquireError("bad redirect location", "network"); }
      if (next.protocol !== "http:" && next.protocol !== "https:") throw new AcquireError(`redirect to unsupported scheme ${next.protocol}`, "unsupported_scheme");
      try { await res.body?.cancel(); } catch { /* ignore */ }
      current = next;
      if (hop === MAX_REDIRECTS) throw new AcquireError(`more than ${MAX_REDIRECTS} redirects`, "too_many_redirects");
      continue;
    }

    const contentType = res.headers.get("content-type") ?? "";
    const lengthHeader = Number(res.headers.get("content-length") ?? "0");
    if (lengthHeader > config.maxBodyBytes) throw new AcquireError(`body ${lengthHeader} bytes exceeds limit`, "too_large");
    if (contentType && !/^(text\/|application\/(xhtml\+xml|xml|json|ld\+json|javascript|x-javascript|markdown))/i.test(contentType)) {
      throw new AcquireError(`binary or unsupported content-type ${contentType}`, "binary");
    }

    // stream with a hard cap so a lying content-length cannot exhaust memory
    const reader = res.body?.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    if (reader) {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > config.maxBodyBytes) { try { await reader.cancel(); } catch { /* ignore */ } throw new AcquireError(`body exceeds ${config.maxBodyBytes} bytes`, "too_large"); }
        chunks.push(value);
      }
    }
    const buf = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) { buf.set(c, off); off += c.byteLength; }
    const body = new TextDecoder("utf-8", { fatal: false }).decode(buf);

    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => (headers[k] = v));

    return {
      url,
      finalUrl: current.toString(),
      redirectChain: chain,
      status: res.status,
      headers,
      contentType,
      body,
      fingerprint,
      fetchedAt: new Date().toISOString(),
    };
  }
  throw new AcquireError("unreachable", "network");
}
