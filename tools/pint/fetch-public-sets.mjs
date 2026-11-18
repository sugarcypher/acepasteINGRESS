#!/usr/bin/env node
// Download public, permissively licensed prompt-injection sets in the PINT format, one JSON Lines file per set:
//   {"text": "...", "label": true|false, "category": "prompt_injection|jailbreak|chat|documents|hard_negatives", "source": "..."}
//
//   node tools/pint/fetch-public-sets.mjs <out-dir>
//
// None of these sets were used to write or tune Ingress's rules; they are for honest scoring only.
// The script prints counts, never the text: the sets are full of attacks, and a terminal or an agent
// reading them is exactly what Ingress exists to prevent.
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const out = process.argv[2];
if (!out) { console.error("usage: fetch-public-sets.mjs <out-dir>"); process.exit(2); }
mkdirSync(out, { recursive: true });

const API = "https://datasets-server.huggingface.co/rows";
async function page(dataset, split, offset, length = 100, config = "default") {
  const u = `${API}?dataset=${encodeURIComponent(dataset)}&config=${encodeURIComponent(config)}&split=${split}&offset=${offset}&length=${length}`;
  for (let attempt = 0; attempt < 4; attempt++) {
    const r = await fetch(u, { headers: { "user-agent": "acepaste-ingress-eval" } });
    if (r.ok) return r.json();
    await new Promise((s) => setTimeout(s, 1500 * (attempt + 1)));
  }
  throw new Error(`${dataset} ${split} @${offset}: download failed`);
}
async function all(dataset, split) {
  const rows = [];
  for (let off = 0; ; off += 100) {
    const j = await page(dataset, split, off);
    rows.push(...j.rows.map((x) => x.row));
    if (off + 100 >= j.num_rows_total) break;
  }
  return rows;
}

const SETS = [
  {
    file: "deepset-test.jsonl", license: "Apache-2.0", source: "deepset/prompt-injections (test)",
    load: async () => (await all("deepset/prompt-injections", "test")).map((r) => ({ text: r.text, label: r.label === 1, category: r.label === 1 ? "prompt_injection" : "chat" })),
  },
  {
    file: "jackhhao-test.jsonl", license: "Apache-2.0", source: "jackhhao/jailbreak-classification (test)",
    load: async () => (await all("jackhhao/jailbreak-classification", "test")).map((r) => ({ text: r.prompt, label: r.type === "jailbreak", category: r.type === "jailbreak" ? "jailbreak" : "chat" })),
  },
  {
    file: "gandalf-test.jsonl", license: "MIT", source: "Lakera/gandalf_ignore_instructions (test)",
    load: async () => (await all("Lakera/gandalf_ignore_instructions", "test")).map((r) => ({ text: r.text, label: true, category: "prompt_injection" })),
  },
  {
    // 16K rows; a deterministic stratified sample: 20 evenly spaced pages, then up to 500 per label
    file: "spml-sample.jsonl", license: "MIT", source: "reshabhs/SPML_Chatbot_Prompt_Injection (stratified 1,000)",
    load: async () => {
      const first = await page("reshabhs/SPML_Chatbot_Prompt_Injection", "train", 0, 1);
      const total = first.num_rows_total, step = Math.floor(total / 20);
      const rows = [];
      for (let i = 0; i < 20; i++) rows.push(...(await page("reshabhs/SPML_Chatbot_Prompt_Injection", "train", i * step)).rows.map((x) => x.row));
      const pos = rows.filter((r) => r["Prompt injection"] === 1).slice(0, 500), neg = rows.filter((r) => r["Prompt injection"] === 0).slice(0, 500);
      return [...pos, ...neg].map((r) => ({ text: r["User Prompt"], label: r["Prompt injection"] === 1, category: r["Prompt injection"] === 1 ? "prompt_injection" : "chat" }));
    },
  },
  {
    // PINT is 36.5% benign public documents; Wikipedia in eight languages stands in for that slice, and its
    // Persian, Arabic, CJK and Korean text is what normalization must not misread (Persian uses the ZWNJ).
    file: "wikipedia-docs.jsonl", license: "CC BY-SA 4.0", source: "wikimedia/wikipedia 20231101 (30 per language)",
    load: async () => {
      const out = [];
      for (const lang of ["en", "de", "fr", "ja", "ko", "zh", "fa", "ar"]) {
        const cfg = `20231101.${lang}`;
        const total = (await page("wikimedia/wikipedia", "train", 0, 1, cfg)).num_rows_total;
        for (let i = 0; i < 3; i++) {
          const j = await page("wikimedia/wikipedia", "train", Math.floor(((i * 2 + 1) * total) / 6), 10, cfg);
          for (const x of j.rows ?? []) out.push({ text: String(x.row.text).slice(0, 4000), label: false, category: `documents_${lang}` });
          await new Promise((s) => setTimeout(s, 700));
        }
      }
      return out;
    },
  },
];

const refresh = process.argv.includes("--refresh");
for (const s of SETS) {
  if (!refresh && existsSync(join(out, s.file))) { console.log(`${s.file.padEnd(22)} already downloaded (--refresh to fetch again)`); continue; }
  let rows;
  try { rows = (await s.load()).filter((r) => typeof r.text === "string" && r.text.trim()); }
  catch (e) { console.log(`${s.file.padEnd(22)} FAILED: ${e.message}`); continue; }
  writeFileSync(join(out, s.file), rows.map((r) => JSON.stringify({ ...r, source: s.source })).join("\n") + "\n");
  const pos = rows.filter((r) => r.label).length;
  console.log(`${s.file.padEnd(22)} ${String(rows.length).padStart(5)} rows  ${pos} attacks / ${rows.length - pos} benign  (${s.license})`);
}
