# @acepaste/ingress

The AcePaste Ingress engine: a security gate between internet content and AI ingestion. Anything a model would receive that a human looking at the same source would not see is suspect by default.

```ts
import { IngressEngine } from "@acepaste/ingress";
const ingress = new IngressEngine({ signingKey: process.env.INGRESS_SIGNING_KEY });
const r = await ingress.fetch("https://example.com/doc");   // or ingress.scan(text)
model.push(r.envelope);   // clean text in a provenance envelope, or a refusal with the reason
```

Verdicts: `clean` (delivered with a signed receipt), `suspect` (refused, human-overridable), `hostile` (refused, not overridable). Passes: acquire, policy, visibility, character (the production AcePaste invisible alphabet), script and supply-chain (underlight lineage), sandbox (optional headless Chromium), meaning, plugins.

CLI: `npx @acepaste/ingress https://example.com` or `ingress --text < page.html`.

Full documentation: https://github.com/sugarcypher/acepasteGATE
