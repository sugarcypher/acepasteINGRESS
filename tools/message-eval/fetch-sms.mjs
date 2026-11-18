#!/usr/bin/env node
// Download the UCI SMS Spam Collection (5,574 real text messages: ordinary ones and spam; CC BY 4.0) for
// scoring the message adapter, as JSON Lines: {"label": false|null, "category": "...", "text": "..."}.
//
//   node tools/message-eval/fetch-sms.mjs <out-dir>
//
// Writes <out-dir>/dev/sms.jsonl and <out-dir>/holdout/sms.jsonl (alternate pages of 100). Thresholds may be
// chosen on dev; holdout is scored once. Ordinary messages are labelled benign. Spam is labelled "other":
// most of it is advertising and scams aimed at people, not instructions aimed at an assistant, so a miss is
// not a missed attack. Prints counts only.
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const out = process.argv[2];
if (!out) { console.error("usage: fetch-sms.mjs <out-dir>"); process.exit(2); }
const API = "https://datasets-server.huggingface.co/rows";
async function page(config, offset) {
  const u = `${API}?dataset=${encodeURIComponent("ucirvine/sms_spam")}&config=${config}&split=train&offset=${offset}&length=100`;
  let last = 0;
  for (let attempt = 0; attempt < 8; attempt++) {
    try {
      const r = await fetch(u, { headers: { "user-agent": "acepaste-ingress-eval" }, signal: AbortSignal.timeout(60_000) });
      if (r.ok) return r.json();
      last = r.status;
      if ((r.status === 404 || r.status === 422) && offset === 0) return undefined;
    } catch { last = -1; }
    await new Promise((s) => setTimeout(s, 4000 * (attempt + 1)));
  }
  throw new Error(`sms_spam @${offset}: download failed (last status ${last})`);
}
let config = "plain_text";
let first = await page(config, 0);
if (!first) { config = "default"; first = await page(config, 0); }
if (!first) { console.error("the dataset could not be read"); process.exit(1); }
const total = first.num_rows_total;
const sets = { dev: [], holdout: [] };
for (let offset = 0, i = 0; offset < total; offset += 100, i++) {
  const p = offset === 0 ? first : await page(config, offset);
  for (const { row } of p?.rows ?? []) {
    const text = String(row.sms ?? row.text ?? "").trim();
    if (!text) continue;
    const spam = row.label === 1 || row.label === "spam";
    sets[i % 2 ? "holdout" : "dev"].push({ label: spam ? null : false, category: spam ? "sms-spam" : "sms-ordinary", text });
  }
  await new Promise((s) => setTimeout(s, 900));
}
for (const [name, rows] of Object.entries(sets)) {
  mkdirSync(join(out, name), { recursive: true });
  writeFileSync(join(out, name, "sms.jsonl"), rows.map((r) => JSON.stringify(r)).join("\n") + "\n");
  console.log(`${name}: ${rows.length} messages (${rows.filter((r) => r.label === false).length} ordinary, ${rows.filter((r) => r.label === null).length} spam)`);
}
