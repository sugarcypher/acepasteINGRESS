#!/usr/bin/env node
// Download ordinary screenshots to measure false alarms of the drawn-interface checks on: ScreenSpot-v2
// (OS-Copilot/ScreenSpot-v2 on Hugging Face, Apache-2.0): screenshots of real web pages, desktop applications
// and phone screens. The pictures are for local measurement and are not redistributed here.
//
//   node tools/images/fetch-screens.mjs <dir>
//
// Writes <dir>/images and the set's three annotation files. Which half (development or hold-out) a picture
// belongs to is decided by a hash of its file name when it is scored (score-screens.mjs --half=...).
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const dir = process.argv[2];
if (!dir) { console.error("usage: fetch-screens.mjs <dir>"); process.exit(2); }
mkdirSync(dir, { recursive: true });
const BASE = "https://huggingface.co/datasets/OS-Copilot/ScreenSpot-v2/resolve/main";
for (const name of ["screenspot_web_v2.json", "screenspot_desktop_v2.json", "screenspot_mobile_v2.json", "screenspotv2_image.zip"]) {
  const out = join(dir, name);
  if (existsSync(out)) continue;
  const res = await fetch(`${BASE}/${name}`, { headers: { "user-agent": "ingress-eval/1.0" }, signal: AbortSignal.timeout(900_000) });
  if (!res.ok) { console.error(`${name}: download failed (${res.status})`); process.exit(1); }
  const buf = Buffer.from(await res.arrayBuffer());
  writeFileSync(out, buf);
  console.log(`${name}: ${(buf.length / 1e6).toFixed(1)} MB`);
}
const images = join(dir, "images");
if (!existsSync(images)) {
  mkdirSync(images, { recursive: true });
  execFileSync("unzip", ["-q", "-o", join(dir, "screenspotv2_image.zip"), "-d", images], { timeout: 600_000 });
}
const count = (d) => readdirSync(d, { withFileTypes: true }).reduce((n, e) => n + (e.isDirectory() ? count(join(d, e.name)) : /\.(png|jpe?g|webp)$/i.test(e.name) ? 1 : 0), 0);
console.log(`${count(images)} pictures in ${images}`);
