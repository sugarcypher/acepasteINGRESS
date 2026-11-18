# Changelog

Every change bumps the patch version of all three packages. The ruleset id changes only when a detector's
behavior changes; receipts carry it so verdicts are reproducible. Releases up to 0.9.6 are in the
[README](README.md#changes-in-096-2026-11-18-ruleset-20261118-3-unchanged).

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
