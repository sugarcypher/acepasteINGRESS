/**
 * Colour parsing and contrast, for same-colour hiding (white on white, black
 * on black, #fefefe on #fff, "snow" on "white"). Contrast is the WCAG 2
 * ratio: 1 means identical, 21 is black on white. Text at or below the
 * threshold is unreadable to a sighted human and is labeled hidden.
 */

export interface RGBA { r: number; g: number; b: number; a: number }

/** at or below this ratio text is treated as invisible against its background (WCAG body-text minimum is 4.5) */
export const INVISIBLE_CONTRAST = 1.25;

const NAMED: Record<string, string> = {
  aliceblue:"f0f8ff",antiquewhite:"faebd7",aqua:"00ffff",aquamarine:"7fffd4",azure:"f0ffff",beige:"f5f5dc",bisque:"ffe4c4",black:"000000",blanchedalmond:"ffebcd",blue:"0000ff",blueviolet:"8a2be2",brown:"a52a2a",burlywood:"deb887",cadetblue:"5f9ea0",chartreuse:"7fff00",chocolate:"d2691e",coral:"ff7f50",cornflowerblue:"6495ed",cornsilk:"fff8dc",crimson:"dc143c",cyan:"00ffff",darkblue:"00008b",darkcyan:"008b8b",darkgoldenrod:"b8860b",darkgray:"a9a9a9",darkgreen:"006400",darkgrey:"a9a9a9",darkkhaki:"bdb76b",darkmagenta:"8b008b",darkolivegreen:"556b2f",darkorange:"ff8c00",darkorchid:"9932cc",darkred:"8b0000",darksalmon:"e9967a",darkseagreen:"8fbc8f",darkslateblue:"483d8b",darkslategray:"2f4f4f",darkslategrey:"2f4f4f",darkturquoise:"00ced1",darkviolet:"9400d3",deeppink:"ff1493",deepskyblue:"00bfff",dimgray:"696969",dimgrey:"696969",dodgerblue:"1e90ff",firebrick:"b22222",floralwhite:"fffaf0",forestgreen:"228b22",fuchsia:"ff00ff",gainsboro:"dcdcdc",ghostwhite:"f8f8ff",gold:"ffd700",goldenrod:"daa520",gray:"808080",green:"008000",greenyellow:"adff2f",grey:"808080",honeydew:"f0fff0",hotpink:"ff69b4",indianred:"cd5c5c",indigo:"4b0082",ivory:"fffff0",khaki:"f0e68c",lavender:"e6e6fa",lavenderblush:"fff0f5",lawngreen:"7cfc00",lemonchiffon:"fffacd",lightblue:"add8e6",lightcoral:"f08080",lightcyan:"e0ffff",lightgoldenrodyellow:"fafad2",lightgray:"d3d3d3",lightgreen:"90ee90",lightgrey:"d3d3d3",lightpink:"ffb6c1",lightsalmon:"ffa07a",lightseagreen:"20b2aa",lightskyblue:"87cefa",lightslategray:"778899",lightslategrey:"778899",lightsteelblue:"b0c4de",lightyellow:"ffffe0",lime:"00ff00",limegreen:"32cd32",linen:"faf0e6",magenta:"ff00ff",maroon:"800000",mediumaquamarine:"66cdaa",mediumblue:"0000cd",mediumorchid:"ba55d3",mediumpurple:"9370db",mediumseagreen:"3cb371",mediumslateblue:"7b68ee",mediumspringgreen:"00fa9a",mediumturquoise:"48d1cc",mediumvioletred:"c71585",midnightblue:"191970",mintcream:"f5fffa",mistyrose:"ffe4e1",moccasin:"ffe4b5",navajowhite:"ffdead",navy:"000080",oldlace:"fdf5e6",olive:"808000",olivedrab:"6b8e23",orange:"ffa500",orangered:"ff4500",orchid:"da70d6",palegoldenrod:"eee8aa",palegreen:"98fb98",paleturquoise:"afeeee",palevioletred:"db7093",papayawhip:"ffefd5",peachpuff:"ffdab9",peru:"cd853f",pink:"ffc0cb",plum:"dda0dd",powderblue:"b0e0e6",purple:"800080",rebeccapurple:"663399",red:"ff0000",rosybrown:"bc8f8f",royalblue:"4169e1",saddlebrown:"8b4513",salmon:"fa8072",sandybrown:"f4a460",seagreen:"2e8b57",seashell:"fff5ee",sienna:"a0522d",silver:"c0c0c0",skyblue:"87ceeb",slateblue:"6a5acd",slategray:"708090",slategrey:"708090",snow:"fffafa",springgreen:"00ff7f",steelblue:"4682b4",tan:"d2b48c",teal:"008080",thistle:"d8bfd8",tomato:"ff6347",turquoise:"40e0d0",violet:"ee82ee",wheat:"f5deb3",white:"ffffff",whitesmoke:"f5f5f5",yellow:"ffff00",yellowgreen:"9acd32",
};

function hex(h: string): RGBA | null {
  if (!/^[0-9a-f]+$/i.test(h)) return null;
  if (h.length === 3 || h.length === 4) h = [...h].map((c) => c + c).join("");
  if (h.length !== 6 && h.length !== 8) return null;
  const n = (i: number) => parseInt(h.slice(i, i + 2), 16);
  return { r: n(0), g: n(2), b: n(4), a: h.length === 8 ? n(6) / 255 : 1 };
}

function num(v: string, max: number): number {
  v = v.trim();
  return v.endsWith("%") ? (parseFloat(v) / 100) * max : parseFloat(v);
}

function hslToRgb(h: number, s: number, l: number): [number, number, number] {
  h = ((h % 360) + 360) % 360; s /= 100; l /= 100;
  const k = (n: number) => (n + h / 30) % 12;
  const a = s * Math.min(l, 1 - l);
  const f = (n: number) => l - a * Math.max(-1, Math.min(k(n) - 3, Math.min(9 - k(n), 1)));
  return [f(0) * 255, f(8) * 255, f(4) * 255];
}

/** Parse a CSS colour value. Returns null for values that cannot be resolved statically (var(), currentcolor, gradients). */
export function parseColor(input: string): RGBA | null {
  const v = input.trim().toLowerCase().replace(/\s*!important$/, "");
  if (!v) return null;
  if (v === "transparent") return { r: 0, g: 0, b: 0, a: 0 };
  if (v.startsWith("#")) return hex(v.slice(1));
  if (NAMED[v]) return hex(NAMED[v]);
  const fn = /^(rgba?|hsla?)\(([^)]*)\)$/.exec(v);
  if (!fn) return null;
  const parts = fn[2].replace(/\//g, " ").split(/[\s,]+/).filter(Boolean);
  if (parts.length < 3 || parts.some((p) => p.includes("var("))) return null;
  const alpha = parts[3] !== undefined ? num(parts[3], 1) : 1;
  if (fn[1].startsWith("rgb")) {
    const [r, g, b] = parts.slice(0, 3).map((p) => num(p, 255));
    return [r, g, b, alpha].some(Number.isNaN) ? null : { r, g, b, a: alpha };
  }
  const [r, g, b] = hslToRgb(parseFloat(parts[0]), parseFloat(parts[1]), parseFloat(parts[2]));
  return [r, g, b, alpha].some(Number.isNaN) ? null : { r, g, b, a: alpha };
}

/** Composite `top` over an opaque `bottom`. */
export function blend(top: RGBA, bottom: RGBA): RGBA {
  const a = Math.max(0, Math.min(1, top.a));
  return { r: top.r * a + bottom.r * (1 - a), g: top.g * a + bottom.g * (1 - a), b: top.b * a + bottom.b * (1 - a), a: 1 };
}

function luminance(c: RGBA): number {
  const ch = (x: number) => { const s = Math.max(0, Math.min(255, x)) / 255; return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4; };
  return 0.2126 * ch(c.r) + 0.7152 * ch(c.g) + 0.0722 * ch(c.b);
}

/** WCAG contrast ratio of text colour `fg` (alpha composited) over opaque `bg`. */
export function contrastRatio(fg: RGBA, bg: RGBA): number {
  const f = blend(fg, bg);
  const [hi, lo] = [luminance(f), luminance(bg)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

/** Pull colour declarations out of a style string. `bg` is null when the background is an image or gradient (unknown). */
export function colorsFromStyle(style: string): { fg?: RGBA | null; bg?: RGBA | null; fill?: RGBA | null } {
  const out: { fg?: RGBA | null; bg?: RGBA | null; fill?: RGBA | null } = {};
  for (const decl of style.split(";")) {
    const i = decl.indexOf(":");
    if (i < 0) continue;
    const prop = decl.slice(0, i).trim().toLowerCase();
    const val = decl.slice(i + 1).trim();
    if (prop === "color") out.fg = parseColor(val);
    else if (prop === "-webkit-text-fill-color") out.fill = parseColor(val);
    else if (prop === "background-color") out.bg = parseColor(val);
    else if (prop === "background") {
      if (/url\(|gradient\(|var\(|image-set\(/i.test(val)) { out.bg = null; continue; }
      // the shorthand's colour is any token that parses as one
      let found: RGBA | null | undefined;
      for (const tok of val.match(/#[0-9a-f]{3,8}\b|(?:rgba?|hsla?)\([^)]*\)|[a-z]+/gi) ?? []) { const c = parseColor(tok); if (c) { found = c; break; } }
      if (found) out.bg = found;
    } else if (prop === "background-image" && !/^none$/i.test(val)) out.bg = null;
  }
  return out;
}
