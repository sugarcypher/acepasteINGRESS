# Launch copy

Drafts to send as yourself. Revised 2026-11-01 to remove first-and-only claims after a competitor check (see README, Related work). Edit freely; these are built from your stated register, not a saved style profile. Claude-generated drafts, 2026-10-01 — the claims are scoped to be defensible (corpus numbers are labeled as a self-written floor, not a field result). Verify the live URL and the install line before posting.

---

## Show HN

**Title** (80 char limit; pick one):

- `Show HN: AcePaste Ingress – a security gate between web content and AI ingestion`
- `Show HN: Catch prompt injection in the gap between what a page shows and what an AI reads`

**Body:**

I spent five years as the target of an intrusion and taught myself forensics to understand it; one of the things that stuck with me is that the dangerous payload is almost never the part you can see. It's in the gap between what something displays and what a machine actually ingests.

Prompt injection lives in exactly that gap. Plenty of good tools now look for it (I list the ones I know in the README, and one of them, wysiwyg, starts from the same rule I do). What I wanted was something that sits in front of an agent's fetch and refuses by default, rather than reporting: anything a model would receive that a human looking at the same source would not see is suspect, and suspect content doesn't reach the model unless a person says so.

So it checks the places the model is blind to. Invisible and smuggled Unicode (tag characters, zero-width channels, look-alike spaces, bidi overrides, variation-selector encoding, homoglyphs). Text hidden by CSS, or coloured to match its background, off-screen, in attributes, comments, SVG, srcdoc. Scripts that detect automation and serve agents a different page than humans (it fetches twice and diffs; optionally renders in a disposable headless browser and diffs again). Then it hands the model the clean text inside a provenance envelope and a signed, tamper-evident receipt of what it stripped and why.

What it deliberately keeps narrow: judging plain visible prose. A modern model already resists most "ignore previous instructions" text in the body, so visible text only gets a check for the strongest instruction shapes (and those are refused as overridable, not hostile). The weight of the gate is on what the model can't see.

It runs three ways from one engine: a Model Context Protocol proxy you drop in front of an agent's fetch tool, a library, and a hosted HTTP service. Every verdict comes with a receipt signed with a public key, so a security reviewer can check what an agent took in without trusting me. Source-available and free to use (FSL: anything except a competing product; each version turns Apache 2.0 after two years).

Honest about the numbers: against my own corpus (85 attack cases, 45 benign, hardened over three adversarial review passes) it refuses every attack with zero false positives — but that's a regression floor on fixtures I wrote, not a claim about the open web. The live feed below shows what it actually catches in the wild; that's the real test, and I'd rather you watch that than trust my corpus.

Live feed: <https://acepaste-ingress.fly.dev/>
Repo: <https://github.com/sugarcypher/acepasteINGRESS>

I built this because I've been on the receiving end of the invisible kind of attack. Feedback welcome, especially bypasses — there's a taint/capability layer and a sandbox I'd like to stress against real traffic.

---

## LinkedIn / X thread

**1/**
Prompt injection isn't usually in the text you can see. It's in the gap between what a page displays and what the AI actually reads. I built a gate that lives in that gap. Free to use, source on GitHub. 🧵

**2/**
A classifier that only reads extracted text has already lost part of the evidence: the off-screen div, the white-on-white line, the script that served your agent a different page than it served you. Some newer tools look at the page itself; this one does that and refuses by default.

**3/**
AcePaste Ingress works on the page itself, in front of the agent's fetch. One rule generates the whole thing: anything the model would receive that a human looking at the same source would not see is suspect by default, and suspect content waits for a human.

**4/**
Invisible Unicode. CSS-hidden and off-screen text. Attribute, comment, SVG and srcdoc carriers. Agent-targeted cloaking (it fetches twice and compares; renders in a throwaway browser and compares again). Then it wraps the clean text in a provenance envelope and a signed receipt of what it stripped.

**5/**
What it keeps narrow, on purpose: judging plain visible text. Your model already handles most "ignore previous instructions" in the body. The gate concentrates on the blind spots and hands the model a clean, labeled input instead of competing with it.

**6/**
One engine, three shapes: a Model Context Protocol proxy in front of an agent's fetch tool, a library, a hosted service. Every verdict gets a receipt anyone can verify with a public key: the part that matters if you have to prove to a security review what your agents ingested. Prior art and neighbours are credited in the README.

**7/**
I built this because I spent years as the target of the invisible kind of attack and learned forensics the hard way. Watch it work on live traffic: <https://acepaste-ingress.fly.dev/> · Code: <https://github.com/sugarcypher/acepasteINGRESS>

---

## For the acepaste.xyz "For developers" link

> **AcePaste Ingress** — the same invisible-text defense that powers the cleaner, as a security gate in front of your AI. Drop it between the web and your agent: it strips the hidden channels a model can't see and hands back clean text with a signed receipt. Free to use. [See what it catches, live →](https://acepaste-ingress.fly.dev/)

---

## MCP proxy install snippet

For an agent builder to paste. Replace the path once published to npm.

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

Then the agent fetches the web through `ingress_fetch` / `ingress_scan` instead of a raw fetch tool; hostile pages are refused and never reach the model, and every verdict leaves a receipt.

---

## Sequencing when you post

1. Deploy first (DEPLOY.md), confirm the feed page loads and `/v1/scan` works, and let a little real traffic through so the feed isn't empty on launch day.
2. Live service: https://acepaste-ingress.fly.dev/ (deployed 2026-11-01). Publish the npm packages before posting so the install snippet works.
3. Post the Show HN in the morning US time; put the thread up the same hour and link the HN post from it.
4. The ask in every one is the same: send bypasses. Every bypass that comes in is a corpus case and a reason for the next person to trust the feed.
