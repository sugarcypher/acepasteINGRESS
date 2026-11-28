"""HTML layouts for the HELD-OUT split (family B). Card layouts on a tinted background, class-based CSS."""
import html

PAGE_BG = "#f4f1ea"   # the container background; css_color_match_bg matches it in this family
TEXT_FG = "#2b2b2b"

def _doc(title, body, lang="en"):
    return f"""<!DOCTYPE html>
<html lang="{lang}">
<head>
  <meta charset="UTF-8">
  <title>{html.escape(title)}</title>
  <link rel="icon" href="data:,">
  <style>
    :root {{ --paper: {PAGE_BG}; --ink: {TEXT_FG}; }}
    html, body {{ margin: 0; background: #e9e4d8; }}
    .shell {{ background: var(--paper); color: var(--ink); width: min(840px, 94vw); margin: 20px auto; padding: 28px 36px; font: 16px/1.6 system-ui, sans-serif; }}
    .topbar {{ display: flex; gap: 18px; align-items: baseline; border-bottom: 2px solid #d8cfbd; padding-bottom: 8px; }}
    .topbar a {{ color: #6b3e1a; text-decoration: none; }}
    .card {{ background: var(--paper); border: 1px solid #d8cfbd; border-radius: 8px; padding: 12px 16px; margin: 12px 0; }}
    .byline {{ color: #7a7062; font-size: .85rem; }}
    .cost {{ font-size: 1.8rem; color: #6b3e1a; }}
    code, pre {{ font-family: ui-monospace, monospace; background: #ebe5d6; }}
  </style>
</head>
<body>
<div class="shell">
{body}
</div>
</body>
</html>
"""

def _top(site):
    return f'<div class="topbar"><span class="brand">{html.escape(site)}</span><a href="/stories">Stories</a><a href="/guides">Guides</a><a href="/store">Store</a><a href="/contact">Contact</a></div>'

def article(t, blocks, site="Field Notes Quarterly"):
    body = "\n".join([_top(site), f"<section class=\"story\"><h2>{html.escape(t['title'])}</h2>",
                      f'<div class="byline">{html.escape(t["author"])} | {t["date"]} | 6 min read</div>',
                      *[f'<div class="para">{b}</div>' for b in blocks], "</section>",
                      f'<div class="byline">Filed under: outdoors, community. {html.escape(site)} 2026.</div>'])
    return _doc(t["title"], body)

def product(t, blocks, site="Tidewater Supply"):
    p = t["product"]
    specs = "".join(f"<tr><td>{html.escape(f)}</td></tr>" for f in p["features"])
    body = "\n".join([_top(site), '<div class="card">', f"<h1>{html.escape(p['name'])}</h1>", f'<div class="cost">{html.escape(p["price"])}</div>',
                      f'<table class="specs">{specs}</table>', '<form><select name="qty"><option>1</option><option>2</option></select> <button>Buy now</button></form></div>',
                      '<div class="card"><h3>About this item</h3>', *blocks, "</div>", '<div class="card"><h3>Customer questions</h3><p>Ask a question about this product.</p></div>'])
    return _doc(p["name"], body)

def docs(t, blocks, site="reference"):
    d = t["doc"]
    rows = "".join(f"<li><code>{html.escape(c)}</code></li>" for c in d["cmds"])
    body = "\n".join([_top(f"{d['tool']} reference"), f"<h1>Using {html.escape(d['tool'])}</h1>", '<aside class="card">Version 2.4 &middot; Last edited 2026</aside>',
                      f"<ol>{rows}</ol>", *[f'<div class="card">{b}</div>' for b in blocks], '<p class="byline">Found a mistake? Edit this page on the project site.</p>'])
    return _doc(f"Using {d['tool']}", body)

def forum(t, blocks, users, replies):
    out = [_top("Commons Board"), f"<h1>{html.escape(t['title'])}</h1>"]
    for i, b in enumerate(blocks):
        out.append(f'<div class="card reply" data-n="{i}"><div class="byline">#{i + 1} {html.escape(users[i % len(users)])}</div>{b}'
                   + (f"<p>{html.escape(replies[(i + 3) % len(replies)])}</p>" if i else "") + "</div>")
    out.append('<div class="card"><textarea name="reply" placeholder="Write a reply"></textarea></div>')
    return _doc(t["title"], "\n".join(out))

def email_html(t, blocks, intro, signoff, sender):
    paras = "\n".join(f'<p style="margin:0 0 12px 0">{b}</p>' for b in blocks)
    return f"""<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"></head>
<body>
<div style="background:{PAGE_BG};padding:20px;font-family:Helvetica,Arial,sans-serif;color:{TEXT_FG}">
<p>{html.escape(intro)}</p>
{paras}
<p>{html.escape(signoff)}<br>{html.escape(sender)}</p>
<p style="font-size:11px;color:#8a8170">Manage your email preferences at https://example.org/prefs</p>
</div>
</body></html>
"""
