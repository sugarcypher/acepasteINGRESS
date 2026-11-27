/**
 * A small, careful ZIP reader for Office documents (DOCX, XLSX, PPTX are ZIP archives of XML parts).
 * Node's zlib only, no dependency. Reads the central directory, then each entry's data: stored or deflated.
 *
 * Caps, because an archive is a classic way to make a scanner do too much work:
 *  - at most `maxEntries` entries (default 5,000)
 *  - each entry inflates to at most `maxEntryBytes` (default 32 MB)
 *  - all entries together inflate to at most `maxTotalBytes` (default 256 MB)
 * An entry over a cap is skipped and named in `skipped`; nothing throws for a damaged archive.
 * Not supported: encrypted entries, ZIP64 archives, compression other than deflate. Each is reported.
 */
import { inflateRawSync } from "node:zlib";

export interface ZipEntry { name: string; data: Uint8Array }
export interface ZipRead {
  entries: Map<string, Uint8Array>;
  /** entries that were not read, and why */
  skipped: Array<{ name: string; reason: string }>;
  notes: string[];
}
export interface ZipLimits { maxEntries?: number; maxEntryBytes?: number; maxTotalBytes?: number }

export function isZip(b: Uint8Array): boolean {
  return b.length >= 4 && b[0] === 0x50 && b[1] === 0x4b && (b[2] === 3 || b[2] === 5) && (b[3] === 4 || b[3] === 6);
}

export function readZip(bytes: Uint8Array, limits: ZipLimits = {}): ZipRead {
  const maxEntries = limits.maxEntries ?? 5_000, maxEntry = limits.maxEntryBytes ?? 32_000_000, maxTotal = limits.maxTotalBytes ?? 256_000_000;
  const out: ZipRead = { entries: new Map(), skipped: [], notes: [] };
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  // the end-of-central-directory record is in the last 64 KB + 22 bytes
  let eocd = -1;
  for (let i = bytes.length - 22; i >= Math.max(0, bytes.length - 65_557); i--) {
    if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) { out.notes.push("the archive's directory was not found (damaged or not a ZIP)"); return out; }
  const count = dv.getUint16(eocd + 10, true);
  let p = dv.getUint32(eocd + 16, true);
  if (count === 0xffff || p === 0xffffffff) { out.notes.push("ZIP64 archives are not read"); return out; }
  let total = 0;
  const dec = new TextDecoder("utf-8", { fatal: false });
  for (let n = 0; n < count && p + 46 <= bytes.length; n++) {
    if (dv.getUint32(p, true) !== 0x02014b50) { out.notes.push("the archive's directory is damaged"); break; }
    const flags = dv.getUint16(p + 8, true), method = dv.getUint16(p + 10, true);
    const csize = dv.getUint32(p + 20, true), usize = dv.getUint32(p + 24, true);
    const nlen = dv.getUint16(p + 28, true), xlen = dv.getUint16(p + 30, true), clen = dv.getUint16(p + 32, true);
    const local = dv.getUint32(p + 42, true);
    const name = dec.decode(bytes.subarray(p + 46, p + 46 + nlen));
    p += 46 + nlen + xlen + clen;
    if (n >= maxEntries) { out.skipped.push({ name, reason: `more than ${maxEntries} entries` }); continue; }
    if (name.endsWith("/")) continue;
    if (flags & 1) { out.skipped.push({ name, reason: "encrypted" }); continue; }
    if (usize > maxEntry) { out.skipped.push({ name, reason: `inflates to ${usize} bytes, over the ${maxEntry} byte cap` }); continue; }
    if (total + usize > maxTotal) { out.skipped.push({ name, reason: `the archive inflates past the ${maxTotal} byte cap` }); continue; }
    if (local + 30 > bytes.length || dv.getUint32(local, true) !== 0x04034b50) { out.skipped.push({ name, reason: "damaged entry" }); continue; }
    const start = local + 30 + dv.getUint16(local + 26, true) + dv.getUint16(local + 28, true);
    const raw = bytes.subarray(start, Math.min(bytes.length, start + csize));
    try {
      let data: Uint8Array;
      if (method === 0) data = raw;
      else if (method === 8) data = inflateRawSync(raw, { maxOutputLength: Math.max(1, Math.min(maxEntry, maxTotal - total)) });
      else { out.skipped.push({ name, reason: `compression method ${method} is not supported` }); continue; }
      total += data.length;
      out.entries.set(name, data);
    } catch (e) {
      out.skipped.push({ name, reason: `could not be inflated (${(e as Error).message.slice(0, 60)})` });
    }
  }
  return out;
}
