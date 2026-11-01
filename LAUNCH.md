# Launch copy

Drafts to send as yourself. Edit freely; these are built from your stated register, not a saved style profile. Claude-generated drafts, 2026-10-01 — the claims are scoped to be defensible (corpus numbers are labeled as a self-written floor, not a field result). Verify the live URL and the install line before posting.

---

## Show HN

**Title** (80 char limit; pick one):

- `Show HN: AcePaste Gate – a security gate between web content and AI ingestion`
- `Show HN: Catch prompt injection in the gap between what a page shows and what an AI reads`

**Body:**

I spent five years as the target of an intrusion and taught myself forensics to understand it; one of the things that stuck with me is that the dangerous payload is almost never the part you can see. It's in the gap between what something displays and what a machine actually ingests.

Prompt injection lives in exactly that gap. Most defenses classify the prompt after extraction, at the model boundary. AcePaste Gate works one step earlier, on the page itself, and its whole design follows a single rule: anything a model would receive that a human looking at the same source would not see is suspect by default.

So it checks the places the model is blind to. Invisible and smuggled Unicode (tag characters, zero-width channels, bidi overrides, variation-selector encoding, homoglyphs). Text hidden by CSS, off-screen, in attributes, comments, SVG, srcdoc. Scripts that detect automation and serve agents a different page than humans (it fetches twice and diffs; optionally renders in a disposable headless browser and diffs again). Then it hands the model the clean text inside a provenance envelope and a signed, tamper-evident receipt of what it stripped and why.

What it deliberately does not do: re-judge plain visible prose. A modern model already resists "ignore previous instructions" in the body text, in any language; a second classifier there mostly generates false positives. The gate covers what the model can't see and delegates what it can.

It runs three ways from one engine: a Model Context Protocol proxy you drop in front of an agent's fetch tool, a library, and a hosted HTTP service. Open core, Apache-2.0.

Honest about the numbers: against my own corpus (78 attack cases, 41 benign, hardened over three adversarial review passes) it refuses every attack with zero false positives — but that's a regression floor on fixtures I wrote, not a claim about the open web. The live feed below shows what it actually catches in the wild; that's the real test, and I'd rather you watch that than trust my corpus.

Live feed: <https://YOUR-APP.fly.dev/>
Repo: <https://github.com/sugarcypher/acepasteGATE>

I built this because I've been on the receiving end of the invisible kind of attack. Feedback welcome, especially bypasses — there's a taint/capability layer and a sandbox I'd like to stress against real traffic.

---

## LinkedIn / X thread

**1/**
Prompt injection isn't usually in the text you can see. It's in the gap between what a page displays and what the AI actually reads. I built a gate that lives in that gap. Open source. 🧵

**2/**
Everyone's classifier sits at the prompt boundary — it reads the text after it's already extracted. By then the invisible part is gone: the zero-width characters, the off-screen div, the script that served your agent a different page than it served you.

**3/**
AcePaste Gate works one step earlier, on the page itself. One rule generates the whole thing: anything the model would receive that a human looking at the same source would not see is suspect by default.

**4/**
Invisible Unicode. CSS-hidden and off-screen text. Attribute, comment, SVG and srcdoc carriers. Agent-targeted cloaking (it fetches twice and compares; renders in a throwaway browser and compares again). Then it wraps the clean text in a provenance envelope and a signed receipt of what it stripped.

**5/**
What it doesn't do, on purpose: argue with plain visible text. Your model already handles "ignore previous instructions" in the body, in any language. The gate covers the blind spots and hands the model a clean, labeled input instead of competing with it.

**6/**
One engine, three shapes: a Model Context Protocol proxy in front of an agent's fetch tool, a library, a hosted service. The receipts are the part that matters for anyone who has to prove to a security review what their agents ingested.

**7/**
I built this because I spent years as the target of the invisible kind of attack and learned forensics the hard way. Watch it work on live traffic: <https://YOUR-APP.fly.dev/> · Code: <https://github.com/sugarcypher/acepasteGATE>

---

## For the acepaste.xyz "For developers" link

> **AcePaste Gate** — the same invisible-text defense that powers the cleaner, as a security gate in front of your AI. Drop it between the web and your agent: it strips the hidden channels a model can't see and hands back clean text with a signed receipt. Open source. [See what it catches, live →](https://YOUR-APP.fly.dev/)

---

## MCP proxy install snippet

For an agent builder to paste. Replace the path once published to npm.

```json
{
  "mcpServers": {
    "acepaste-gate": {
      "command": "npx",
      "args": ["-y", "@acepaste/gate-mcp"],
      "env": { "GATE_SANDBOX": "escalate" }
    }
  }
}
```

Then the agent fetches the web through `gate_fetch` / `gate_scan` instead of a raw fetch tool; hostile pages are refused and never reach the model, and every verdict leaves a receipt.

---

## Sequencing when you post

1. Deploy first (DEPLOY.md), confirm the feed page loads and `/v1/scan` works, and let a little real traffic through so the feed isn't empty on launch day.
2. Fill the two `YOUR-APP.fly.dev` placeholders and the npm name.
3. Post the Show HN in the morning US time; put the thread up the same hour and link the HN post from it.
4. The ask in every one is the same: send bypasses. Every bypass that comes in is a corpus case and a reason for the next person to trust the feed.
