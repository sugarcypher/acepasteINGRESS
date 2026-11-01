# @acepaste/gate-core

The AcePaste Gate engine: a security gate between internet content and AI ingestion. Anything a model would receive that a human looking at the same source would not see is suspect by default.

```ts
import { GateEngine } from "@acepaste/gate-core";
const gate = new GateEngine({ signingKey: process.env.GATE_SIGNING_KEY });
const r = await gate.fetch("https://example.com/doc");   // or gate.scan(text)
model.push(r.envelope);   // clean text in a provenance envelope, or a refusal with the reason
```

Verdicts: `clean` (delivered with a signed receipt), `suspect` (refused, human-overridable), `hostile` (refused, not overridable). Passes: acquire, policy, visibility, character (the production AcePaste invisible alphabet), script and supply-chain (underlight lineage), sandbox (optional headless Chromium), meaning, plugins.

CLI: `npx @acepaste/gate-core https://example.com` or `gate --text < page.html`.

Full documentation: https://github.com/sugarcypher/acepasteGATE
