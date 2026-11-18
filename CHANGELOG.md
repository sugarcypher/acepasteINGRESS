# Changelog

Every change bumps the patch version of all three packages. The ruleset id changes only when a detector's
behavior changes; receipts carry it so verdicts are reproducible. Releases up to 0.9.6 are in the
[README](README.md#changes-in-096-2026-11-18-ruleset-20261118-3-unchanged).

## 0.9.10 (2026-11-18, ruleset unchanged)

Broker safeguards that apply whatever the run has read (`safeguards.ts`; Phases 9d and 12).

- **Persistence guard.** An action that creates something which acts later always needs a person, even in a
  run that has read nothing from outside: scheduled jobs (cron, launchd, systemd), startup items and shell
  startup files, automations and shortcuts, mail rules and forwarding addresses, webhooks, hooks (git,
  agent settings), edits to an agent's own instruction or memory files and its list of tool servers, and
  login access (`authorized_keys`, sudoers). Recognised by tool name (writes only), field names, paths and
  shell commands. Policy: `persistenceGuard: "always" | "tainted" | "off"` (default `always`).
- **Canary tripwire.** `broker.plantCanary(runId)` returns a marker for the run's context; the MCP server
  hands it over with every delivered envelope. An action whose arguments carry it (plain, base64 at any
  alignment, hex, URL-encoded, reversed, or without its fixed prefix) is denied, not sent for approval:
  nothing a person asked for needs the marker to leave, so the conversation itself is being sent out.
- **Burst guard.** More than 20 actions a minute, or the same action more than 3 times in ten minutes, waits
  for a person (`burst` in the policy). Read-only tools never count.
- **Stop switch.** `ingress stop [reason]` makes every broker on the machine refuse every action, read-only
  tools included, until `ingress resume`. Anyone may stop, an agent included; resuming needs an interactive
  terminal. `ingress_status` reports it.
- Proxy end-to-end tests for the marker and the stop switch.

## 0.9.9 (2026-11-18, ruleset unchanged)

Change tracking, from Kith & Revere (`Baselines.swift`, `Changes.swift`), and tool definitions as outside content.

- **`changes.ts`:** snapshots compared run to run, and "confirm these are correct" baselines. Items are
  identified by what they are, never by notes, sizes or dates; a group new in this version is not a change on
  the machine; a confirmed set stays confirmed only while it is exactly that set. State lives in
  `INGRESS_STATE_DIR` (default `~/.acepaste-ingress/state`), owner-readable only, identities only.
- **Environment audit:** `ingress audit` now starts with what changed since the last audit and which areas a
  person has not confirmed. `ingress audit confirm <area>` confirms an area, from an interactive terminal only.
  An edited instruction file or hook counts as a change; blocklist sizes and the network's DNS servers do not.
- **MCP proxy, tool definitions:** a downstream server's tool names, descriptions and parameter schemas
  reached the model unchecked. Each definition is now gated (everything in it a model would read, including
  parameter descriptions and default values), and its fingerprint is recorded. A definition that is not
  clean is withheld. A definition that changes, or a tool that appears, after the set was recorded is held
  (a "rug pull"): the model sees a notice in its place and calls are refused until a person runs
  `ingress tools confirm <server>`. `ingress_status` lists held tools.
- First end-to-end tests of the proxy (`npm test -w @acepaste/ingress-mcp`): a real downstream server, the
  real proxy and a real client over stdio.

## 0.9.8 (2026-11-18, ruleset unchanged)

Phase 11, loopback: "it came from localhost" is not a trust boundary.

- **HTTP service local guard.** When `INGRESS_HOST` is a loopback address (or `INGRESS_ALLOWED_HOSTS` is set),
  every request must name this service in its `Host` header and may not carry another site's `Origin`. A web
  page in the user's browser can otherwise reach a local gate by DNS rebinding or a cross-site request; both
  are now refused with 403, on the endpoints that need no key too. `checkLocalRequest` and `isLoopbackBind`
  are exported for other local services.
- **Every spelling of a private address.** IPv6 addresses are expanded before they are judged, so
  `0:0:0:0:0:0:0:1`, `::ffff:127.0.0.1`, `::ffff:7f00:1`, zone ids (`fe80::1%en0`), IPv4-compatible `::127.0.0.1`,
  6to4 (`2002:7f00:1::`), NAT64 and deprecated site-local all give the same answer; an address that cannot be
  parsed is blocked. Hosts are compared without a trailing dot (`localhost.`).
- Tests for decimal, hex, octal and short IPv4 forms, and for public names that resolve to private space.

## 0.9.7 (2026-11-18, ruleset unchanged)

- `docs/ROADMAP.md`: the plan to extend Ingress to every channel an agent reads from or acts through, and to
  what agents send out. `docs/ROADMAP-LOG.md` tracks each change against it.
- This changelog. `tools/release/bump-version.mjs` bumps every package, the pins and `ENGINE_VERSION` in one step.
