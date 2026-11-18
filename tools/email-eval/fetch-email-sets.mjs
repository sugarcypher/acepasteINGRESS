#!/usr/bin/env node
// Download public email sets for scoring Ingress's email adapter, one JSON Lines file per set:
//   {"label": true|false, "category": "...", "source": "...", and either "raw" (a whole message) or "subject"/"from"/"to"/"body"}
//
//   node tools/email-eval/fetch-email-sets.mjs <out-dir>
//
// None of these sets may be used to write or tune a rule. The script prints counts, never the text: one of
// the sets is hundreds of thousands of attack emails, and a terminal or an agent reading them is exactly
// what Ingress exists to prevent.
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { execFileSync } from "node:child_process";

const out = process.argv[2];
if (!out) { console.error("usage: fetch-email-sets.mjs <out-dir> [--holdout] [--refresh]"); process.exit(2); }
mkdirSync(out, { recursive: true });
// --holdout draws a second, disjoint sample: pages halfway between the first sample's pages, and different
// SpamAssassin archives. Use the first sample while developing and the second, once, for the number you report.
const HOLDOUT = process.argv.includes("--holdout");

const API = "https://datasets-server.huggingface.co/rows";
async function page(dataset, split, offset, length = 100, config = "default") {
  const u = `${API}?dataset=${encodeURIComponent(dataset)}&config=${encodeURIComponent(config)}&split=${split}&offset=${offset}&length=${length}`;
  for (let attempt = 0; attempt < 5; attempt++) {
    const r = await fetch(u, { headers: { "user-agent": "acepaste-ingress-eval" } });
    if (r.ok) return r.json();
    await new Promise((s) => setTimeout(s, 2000 * (attempt + 1)));
  }
  throw new Error(`${dataset} ${split} @${offset}: download failed`);
}
/** `pages` pages of 100 rows, evenly spaced through the split: a deterministic sample of the whole */
async function spread(dataset, split, pages) {
  const total = (await page(dataset, split, 0, 1)).num_rows_total;
  const step = Math.floor((total - 100) / Math.max(1, pages - 1));
  const shift = HOLDOUT ? Math.floor(step / 2) : 0;
  const rows = [];
  for (let i = 0; i < pages - (HOLDOUT ? 1 : 0); i++) {
    rows.push(...(await page(dataset, split, i * step + shift)).rows.map((x) => x.row));
    await new Promise((s) => setTimeout(s, 400));
  }
  return { rows, total };
}

/** One SpamAssassin public-corpus archive: whole messages as they were received, HTML mail included. */
async function spamassassin(name) {
  const url = `https://spamassassin.apache.org/old/publiccorpus/${name}.tar.bz2`;
  const r = await fetch(url, { headers: { "user-agent": "acepaste-ingress-eval" } });
  if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
  // the archive is untrusted: unpack it into its own new, empty folder, read the files as data, remove it
  const dir = mkdtempSync(join(out, ".unpack-"));
  try {
    const archive = join(dir, "a.tar.bz2");
    writeFileSync(archive, Buffer.from(await r.arrayBuffer()));
    const into = join(dir, "x");
    mkdirSync(into);
    execFileSync("tar", ["-xjf", archive, "-C", into, "--no-same-owner"], { stdio: "ignore" });
    const rows = [];
    const walk = (d) => { for (const f of readdirSync(d)) { const p = join(d, f); const st = statSync(p); if (st.isDirectory()) walk(p); else if (st.isFile() && f !== "cmds" && st.size < 2_000_000) rows.push({ raw: readFileSync(p, "latin1") }); } };
    walk(into);
    return rows;
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

const SETS = [
  {
    // every row is an attack someone submitted to a live email assistant; `objectives` says how far each got
    file: "llmail-phase1.jsonl", license: "MIT", source: "microsoft/llmail-inject-challenge Phase1 (2,000 evenly spaced)",
    load: async () => (await spread("microsoft/llmail-inject-challenge", "Phase1", 20)).rows.map((r) => ({ subject: r.subject ?? "", body: r.body ?? "", from: "contact@contoso-partners.example", label: true, category: "llmail_phase1", objectives: r.objectives ?? "" })),
  },
  {
    file: "llmail-phase2.jsonl", license: "MIT", source: "microsoft/llmail-inject-challenge Phase2 (2,000 evenly spaced)",
    load: async () => (await spread("microsoft/llmail-inject-challenge", "Phase2", 20)).rows.map((r) => ({ subject: r.subject ?? "", body: r.body ?? "", from: "contact@contoso-partners.example", label: true, category: "llmail_phase2", objectives: r.objectives ?? "" })),
  },
  {
    // ordinary business mail from 2000-2002, released by a US regulator; no license is stated on the dataset card
    file: "enron-sample.jsonl", license: "public record (no license stated on the card)", source: "corbt/enron-emails (3,000 evenly spaced)",
    load: async () => (await spread("corbt/enron-emails", "train", 30)).rows.map((r) => ({ subject: r.subject ?? "", from: r.from ?? "", to: (r.to ?? []).join(", "), body: r.body ?? "", label: false, category: "enron" })),
  },
  {
    file: "spamassassin-easy-ham.jsonl", license: "public corpus (Apache SpamAssassin project)", source: "spamassassin.apache.org 20030228_easy_ham",
    load: async () => (await spamassassin(HOLDOUT ? "20030228_easy_ham_2" : "20030228_easy_ham")).map((r) => ({ ...r, label: false, category: "sa_easy_ham" })),
  },
  {
    // legitimate mail that looks like spam: newsletters and marketing, much of it HTML
    file: "spamassassin-hard-ham.jsonl", license: "public corpus (Apache SpamAssassin project)", source: "spamassassin.apache.org 20030228_hard_ham",
    load: async () => (await spamassassin(HOLDOUT ? "20021010_hard_ham" : "20030228_hard_ham")).map((r) => ({ ...r, label: false, category: "sa_hard_ham" })),
  },
  {
    // spam is unwanted, not an attack on an assistant: it is here to see how Ingress treats it, and is not scored as either class
    file: "spamassassin-spam.jsonl", license: "public corpus (Apache SpamAssassin project)", source: "spamassassin.apache.org 20030228_spam",
    load: async () => (await spamassassin(HOLDOUT ? "20030228_spam_2" : "20030228_spam")).map((r) => ({ ...r, label: null, category: "sa_spam" })),
  },
];

const refresh = process.argv.includes("--refresh");
for (const s of SETS) {
  if (!refresh && existsSync(join(out, s.file))) { console.log(`${s.file.padEnd(30)} already downloaded (--refresh to fetch again)`); continue; }
  let rows;
  try { rows = (await s.load()).filter((r) => (typeof r.raw === "string" && r.raw.trim()) || (typeof r.body === "string" && r.body.trim())); }
  catch (e) { console.log(`${s.file.padEnd(30)} FAILED: ${e.message}`); continue; }
  writeFileSync(join(out, s.file), rows.map((r) => JSON.stringify({ ...r, source: s.source })).join("\n") + "\n");
  console.log(`${s.file.padEnd(30)} ${String(rows.length).padStart(5)} messages  (${s.license})`);
}
