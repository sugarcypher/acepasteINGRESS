"""HTML layouts for the PUBLIC split (family A). Plain white pages, inline styles."""
import html

PAGE_BG = "#ffffff"   # what css_color_match_bg must match in this family
TEXT_FG = "#222222"

def _doc(title, body, extra_head=""):
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>
body {{ background: {PAGE_BG}; color: {TEXT_FG}; font-family: Georgia, serif; max-width: 720px; margin: 0 auto; padding: 24px; line-height: 1.55; }}
nav a {{ margin-right: 14px; color: #1a4d8f; }}
.meta {{ color: #666; font-size: 14px; }}
footer {{ margin-top: 40px; color: #777; font-size: 13px; border-top: 1px solid #ddd; padding-top: 12px; }}
.price {{ font-size: 28px; font-weight: bold; }}
pre {{ background: #f6f6f6; padding: 10px; }}
.post {{ border-bottom: 1px solid #eee; padding: 10px 0; }}
</style>
{extra_head}</head>
<body>
{body}
</body>
</html>
"""

def _nav(site):
    return f'<header><strong>{html.escape(site)}</strong>\n<nav><a href="/">Home</a><a href="/articles">Articles</a><a href="/shop">Shop</a><a href="/about">About</a></nav></header>'

def article(t, blocks, site="The Weekly Patch"):
    body = "\n".join([_nav(site), "<main><article>", f"<h1>{html.escape(t['title'])}</h1>",
                      f'<p class="meta">By {html.escape(t["author"])} &middot; {t["date"]}</p>', *blocks,
                      "</article></main>", f"<footer>&copy; 2026 {html.escape(site)}. <a href=\"/privacy\">Privacy</a></footer>"])
    return _doc(t["title"], body)

def product(t, blocks, site="Patch &amp; Pedal Store"):
    p = t["product"]
    feats = "".join(f"<li>{html.escape(f)}</li>" for f in p["features"])
    body = "\n".join([_nav("Patch & Pedal Store"), "<main>", f"<h1>{html.escape(p['name'])}</h1>", f'<p class="price">{html.escape(p["price"])}</p>',
                      f"<ul>{feats}</ul>", '<button type="button">Add to cart</button>', "<h2>Description</h2>", *blocks,
                      "<h2>Reviews</h2><p>4.6 out of 5 from 212 reviews.</p>", "</main>", "<footer>Free returns within 30 days.</footer>"])
    return _doc(p["name"], body)

def docs(t, blocks, site="docs"):
    d = t["doc"]
    cmds = "\n".join(html.escape(c) for c in d["cmds"])
    body = "\n".join([_nav(f"{d['tool']} documentation"), "<main>", f"<h1>{html.escape(d['tool'])}: getting started</h1>",
                      f"<p>This guide accompanies the article <em>{html.escape(t['title'])}</em>.</p>", f"<pre><code>{cmds}</code></pre>", *blocks,
                      "<h2>Next steps</h2><p>See the configuration reference for every option.</p>", "</main>", f"<footer>{html.escape(d['tool'])} is open source under the MIT license.</footer>"])
    return _doc(f"{d['tool']} docs", body)

def forum(t, blocks, users, replies):
    posts = [f'<div class="post"><strong>{html.escape(users[0])}</strong><p class="meta">{t["date"]}</p>{blocks[0]}</div>']
    rest = blocks[1:]
    for i, b in enumerate(rest):
        posts.append(f'<div class="post"><strong>{html.escape(users[(i + 1) % len(users)])}</strong>{b}<p>{html.escape(replies[i % len(replies)])}</p></div>')
    body = "\n".join([_nav("Community Forum"), "<main>", f"<h1>{html.escape(t['title'])}</h1>", *posts, "</main>", "<footer>Be kind. Read the forum rules.</footer>"])
    return _doc(t["title"], body)

def email_html(t, blocks, intro, signoff, sender):
    rows = "\n".join(f'<tr><td style="padding:6px 24px;font-family:Arial,sans-serif;font-size:15px;color:#222">{b}</td></tr>' for b in blocks)
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{html.escape(t['title'])}</title></head>
<body style="margin:0;background:{PAGE_BG}">
<table width="100%" cellpadding="0" cellspacing="0" style="background:{PAGE_BG}">
<tr><td style="padding:16px 24px;font-family:Arial,sans-serif;font-size:15px;color:#222">{html.escape(intro)}</td></tr>
{rows}
<tr><td style="padding:16px 24px;font-family:Arial,sans-serif;font-size:15px;color:#222">{html.escape(signoff)}<br>{html.escape(sender)}</td></tr>
<tr><td style="padding:16px 24px;font-family:Arial,sans-serif;font-size:11px;color:#888">You receive this because you signed up. <a href="https://example.com/unsubscribe">Unsubscribe</a></td></tr>
</table>
</body></html>
"""
