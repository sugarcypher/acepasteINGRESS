# @acepaste/ingress-mcp

**Stops your AI agent from obeying instructions that web pages hide from you.**

![Ingress refusing a page with white-on-white instructions, then passing a clean page](https://raw.githubusercontent.com/sugarcypher/acepasteINGRESS/main/docs/demo/ingress-demo.gif)

**The problem:** a web page can hide text that a person never sees, and an AI agent reads all of it: white-on-white text, invisible Unicode, off-screen notes, or a different page served only to bots. The agent can follow those instructions, and afterward nobody can show what it read. Ingress sits in front of your agent's web fetch and refuses anything the model would receive that you would not see.

- **Refuses hidden instructions:** invisible Unicode, CSS-hidden or background-coloured text, and payloads in attributes, comments, SVG or `srcdoc`.
- **Catches cloaking:** fetches twice, and can render in a throwaway browser, to catch pages that show bots something different.
- **Signs a receipt for every verdict:** hash-chained and signed with ECDSA P-256, so you can prove later what your agent read.
- **Quarantines sources:** block a host and see everything it already delivered.
- **Asks a person before risky actions:** once outside content is read, side-effecting tool calls need human approval.
- **Runs on your machine:** MCP server, CLI and library, or HTTP service. No telemetry ([PRIVACY.md](https://github.com/sugarcypher/acepasteINGRESS/blob/main/PRIVACY.md)).

Full documentation: https://github.com/sugarcypher/acepasteINGRESS

---

AcePaste Ingress as a Model Context Protocol server. Put it in front of an agent's web access: hostile pages are refused and never reach the model; every verdict leaves a signed receipt.

```json
{
  "mcpServers": {
    "acepaste-ingress": {
      "command": "npx",
      "args": ["-y", "@acepaste/ingress-mcp"],
      "env": { "INGRESS_SANDBOX": "off" }
    }
  }
}
```

Tools: `ingress_fetch(url, override?)`, `ingress_scan(content, source?, contentType?, override?)`, `ingress_status()`, `ingress_confirm()`, `ingress_verify_receipt(receipt)`.

Environment: `INGRESS_SIGNING_KEY`, `INGRESS_HOSTILE`, `INGRESS_SUSPECT`, `INGRESS_CLOAKING=0`, `INGRESS_SANDBOX=off|escalate|always`, `INGRESS_POLICY=path`, `INGRESS_LOG=path`.

Full documentation: https://github.com/sugarcypher/acepasteINGRESS
