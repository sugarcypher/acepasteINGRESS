/**
 * What a QR code (or any barcode with a text payload) would do if it were followed.
 *
 * A person cannot read a QR code. They see a square and whatever caption sits beside it; the payload is
 * for the machine. So the payload is judged for what it is: a link, or an action (join this Wi-Fi network,
 * add this one-time-code secret, send this text message, pay this account, open this app), or plain text.
 * Nothing here opens, fetches or performs anything.
 */

export type QrKind = "link" | "wifi" | "otp-secret" | "sms" | "phone" | "email" | "payment" | "contact" | "event" | "location" | "app-link" | "text";

export interface QrVerdict {
  kind: QrKind;
  /** one sentence a person can act on */
  summary: string;
  /** following it does something, rather than showing something */
  action: boolean;
  /** 0 to 1: how much care it needs */
  risk: number;
  /** for links: the host, to be fetched only through the gate */
  host?: string;
  url?: string;
  /** free text carried by the payload (the whole payload for "text"; a message body for sms and email), to be scanned as content */
  text?: string;
  notes: string[];
}

const PAY_SCHEMES = /^(?:bitcoin|bitcoincash|ethereum|litecoin|dogecoin|monero|solana|lightning|upi|paypal|venmo|cashapp|swish|bezahlcode|pix|alipays?|weixin|wxp)$/i;
const WEB = /^https?$/i;

function hostNotes(u: URL): string[] {
  const n: string[] = [];
  if (u.username || u.password) n.push("the address carries a user name or password before the host, which hides where it really goes");
  if (/^xn--|\.xn--/.test(u.hostname)) n.push("the host is an international name that may imitate another");
  if (/^\d{1,3}(?:\.\d{1,3}){3}$|^\[/.test(u.hostname)) n.push("the host is a bare network address, not a name");
  if (u.protocol === "http:") n.push("the link is not encrypted");
  if (/^(?:bit\.ly|t\.co|tinyurl\.com|goo\.gl|is\.gd|ow\.ly|buff\.ly|rebrand\.ly|cutt\.ly|qrco\.de|qr\.link|l\.ead\.me|s\.id|shorturl\.at|rb\.gy|t\.ly)$/i.test(u.hostname)) n.push("the link is a shortener: where it ends up is not visible here");
  if (u.search.length > 200) n.push(`the link carries ${u.search.length} characters of query data`);
  return n;
}

export function judgeQrPayload(payload: string): QrVerdict {
  const p = payload.trim();
  const notes: string[] = [];

  // Wi-Fi: WIFI:T:WPA;S:name;P:password;H:true;;
  if (/^WIFI:/i.test(p)) {
    const f = Object.fromEntries([...p.slice(5).matchAll(/([A-Z]):((?:\\.|[^;\\])*)/gi)].map((m) => [m[1].toUpperCase(), m[2].replace(/\\(.)/g, "$1")]));
    if (!f.T || /^nopass$/i.test(f.T)) notes.push("the network has no password: anyone nearby can read its traffic");
    if (/^true$/i.test(f.H ?? "")) notes.push("the network is hidden");
    return { kind: "wifi", action: true, risk: 0.6, summary: `joins the Wi-Fi network "${(f.S ?? "").slice(0, 64)}". A device that joins a network sends its traffic through whoever runs it`, notes };
  }
  // one-time-code secrets: scanning adds an authenticator entry; reading it gives away the secret
  if (/^otpauth(?:-migration)?:\/\//i.test(p)) {
    let label = "";
    try { label = decodeURIComponent(new URL(p).pathname.replace(/^\/+/, "")).slice(0, 80); } catch { /* shown without a label */ }
    return { kind: "otp-secret", action: true, risk: 0.9, summary: `carries a one-time-code secret${label ? ` for "${label}"` : ""}. Whoever reads it can generate that account's sign-in codes: it must never be copied anywhere`, notes };
  }
  if (/^(?:smsto|sms|mms|mmsto):/i.test(p)) {
    const m = p.match(/^(?:smsto|sms|mms|mmsto):\/{0,2}([^:?]*)[:?]?(?:body=)?([\s\S]*)$/i);
    let body = m?.[2] ?? "";
    try { body = decodeURIComponent(body); } catch { /* as written */ }
    if (/^\d{3,6}$/.test((m?.[1] ?? "").replace(/\D/g, ""))) notes.push("the number is a short code: messages to short codes can subscribe to paid services");
    return { kind: "sms", action: true, risk: 0.6, summary: `writes a text message to ${(m?.[1] ?? "a number").slice(0, 40)}${body ? " with the words already filled in" : ""}`, text: body || undefined, notes };
  }
  if (/^tel:/i.test(p)) {
    const num = p.slice(4);
    if (/[*#]/.test(num)) notes.push("the number contains * or #: such codes can change phone settings such as call forwarding");
    return { kind: "phone", action: true, risk: /[*#]/.test(num) ? 0.7 : 0.4, summary: `dials ${num.slice(0, 40)}`, notes };
  }
  if (/^(?:mailto:|MATMSG:)/i.test(p)) {
    let body = "";
    try { const u = new URL(p.replace(/^MATMSG:/i, "mailto:")); body = [u.searchParams.get("subject"), u.searchParams.get("body")].filter(Boolean).join("\n"); } catch { body = p.match(/BODY:([^;]*)/i)?.[1] ?? ""; }
    return { kind: "email", action: true, risk: 0.4, summary: `writes an email${body ? " with the words already filled in" : ""}`, text: body || undefined, notes };
  }
  if (/^BEGIN:VCARD/i.test(p) || /^MECARD:/i.test(p)) return { kind: "contact", action: true, risk: 0.3, summary: "adds a contact to the address book", text: p.slice(0, 2000), notes };
  if (/^BEGIN:VEVENT|^BEGIN:VCALENDAR/i.test(p)) return { kind: "event", action: true, risk: 0.4, summary: "adds an event to the calendar", text: p.slice(0, 4000), notes };
  if (/^geo:/i.test(p)) return { kind: "location", action: false, risk: 0.1, summary: "opens a place on a map", notes };
  // European bank transfer codes: "BCD" on the first line
  if (/^BCD\r?\n\d{3}\r?\n/.test(p)) return { kind: "payment", action: true, risk: 0.8, summary: "starts a bank transfer with the recipient and amount already filled in", notes };

  const scheme = p.match(/^([a-z][a-z0-9+.-]{1,31}):/i)?.[1];
  if (scheme && WEB.test(scheme)) {
    try {
      const u = new URL(p);
      notes.push(...hostNotes(u));
      return { kind: "link", action: false, risk: Math.min(0.7, 0.15 + notes.length * 0.2), summary: `links to ${u.hostname}`, host: u.hostname.toLowerCase(), url: u.toString(), notes };
    } catch {
      return { kind: "link", action: false, risk: 0.5, summary: "holds a web address that does not parse", notes: ["an address that parsers read differently is a common way to disguise a destination"] };
    }
  }
  if (scheme && PAY_SCHEMES.test(scheme)) return { kind: "payment", action: true, risk: 0.8, summary: `starts a payment (${scheme.toLowerCase()}) with the recipient already filled in`, notes };
  if (scheme && !/^(?:urn|data|javascript|file|about|blob)$/i.test(scheme) && /^[a-z][a-z0-9+.-]*:\/\//i.test(p)) {
    return { kind: "app-link", action: true, risk: 0.5, summary: `opens an app through the "${scheme.toLowerCase()}:" scheme, with instructions for that app in the link`, text: p.slice(0, 2000), notes };
  }
  if (scheme && /^(?:javascript|data|file)$/i.test(scheme)) return { kind: "app-link", action: true, risk: 0.9, summary: `holds a "${scheme.toLowerCase()}:" address, which runs or opens content directly`, text: p.slice(0, 2000), notes };
  // a bare domain is still a link once a scanner helps
  if (/^(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:\/\S*)?$/i.test(p) && !/\s/.test(p)) {
    try { const u = new URL(`https://${p}`); notes.push(...hostNotes(u)); return { kind: "link", action: false, risk: 0.2 + notes.length * 0.2, summary: `links to ${u.hostname}`, host: u.hostname.toLowerCase(), url: u.toString(), notes }; } catch { /* plain text */ }
  }
  return { kind: "text", action: false, risk: 0.1, summary: `holds ${p.length} characters of text`, text: p.slice(0, 8000), notes };
}
