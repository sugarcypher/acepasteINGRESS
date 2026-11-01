# @acepaste/gate-mcp

AcePaste Gate as a Model Context Protocol server. Put it in front of an agent's web access: hostile pages are refused and never reach the model; every verdict leaves a signed receipt.

```json
{
  "mcpServers": {
    "acepaste-gate": {
      "command": "npx",
      "args": ["-y", "@acepaste/gate-mcp"],
      "env": { "GATE_SANDBOX": "off" }
    }
  }
}
```

Tools: `gate_fetch(url, override?)`, `gate_scan(content, source?, contentType?, override?)`, `gate_status()`, `gate_confirm()`, `gate_verify_receipt(receipt)`.

Environment: `GATE_SIGNING_KEY`, `GATE_HOSTILE`, `GATE_SUSPECT`, `GATE_CLOAKING=0`, `GATE_SANDBOX=off|escalate|always`, `GATE_POLICY=path`, `GATE_LOG=path`.

Full documentation: https://github.com/sugarcypher/acepasteGATE
