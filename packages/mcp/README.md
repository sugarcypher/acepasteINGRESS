# @acepaste/ingress-mcp

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
