"""HTML layouts for the HELD-OUT-V2 split (family C). Written fresh on 2026-11-28: tinted page, stylesheet classes,
a sidebar and cards, an email in a centred card on a tinted background. Shares no markup with families A and B."""
import html

PAGE_BG = "#eef4ec"   # pale sage: what css_color_match_bg must match in this family
CARD_BG = "#eef4ec"
TEXT_FG = "#1f2a1c"

def _doc(title, body, lang="en"):
    return f"""<!DOCTYPE html>
<html lang="{lang}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title>
<style>
:root {{ --bg: {PAGE_BG}; --fg: {TEXT_FG}; --accent: #2f6b3a; }}
* {{ box-sizing: border-box; }}
body {{ margin: 0; background: var(--bg); color: var(--fg); font: 16px/1.6 "Helvetica Neue", Arial, sans-serif; }}
.wrap {{ display: flex; gap: 28px; max-width: 980px; margin: 0 auto; padding: 20px; }}
.main {{ flex: 1 1 auto; min-width: 0; }}
.side {{ flex: 0 0 220px; font-size: 14px; }}
.side h3 {{ font-size: 15px; margin: 0 0 6px; }}
.top {{ background: var(--accent); color: #fff; padding: 10px 20px; }}
.top a {{ color: #fff; margin-left: 16px; text-decoration: none; }}
.byline {{ color: #55624f; font-size: 13px; }}
.card {{ background: var(--bg); border: 1px solid #c9d6c4; border-radius: 6px; padding: 14px 16px; margin: 14px 0; }}
.cost {{ font-size: 26px; color: var(--accent); }}
.cmd {{ background: #dfe9dc; padding: 10px; font-family: monospace; white-space: pre; overflow-x: auto; }}
.reply {{ border-left: 3px solid #c9d6c4; padding-left: 12px; margin: 12px 0; }}
.foot {{ max-width: 980px; margin: 30px auto; padding: 12px 20px; color: #55624f; font-size: 12px; }}
</style>
</head>
<body>
{body}
</body>
</html>
"""

def _top(site):
    return f'<div class="top"><b>{html.escape(site)}</b><a href="/">Start</a><a href="/news">News</a><a href="/guides">Guides</a><a href="/contact">Contact</a></div>'

def _side(t):
    return f'<aside class="side"><h3>More from {html.escape(t["author"])}</h3><ul><li><a href="/a/1">Archive</a></li><li><a href="/a/2">Popular this week</a></li><li><a href="/a/3">Newsletter</a></li></ul></aside>'

def article(t, blocks, site="Northbank Gazette"):
    main = "\n".join([f"<h1>{html.escape(t['title'])}</h1>", f'<div class="byline">{html.escape(t["author"])} | {t["date"]}</div>', *blocks])
    body = "\n".join([_top(site), f'<div class="wrap"><section class="main">{main}</section>{_side(t)}</div>', f'<div class="foot">Northbank Gazette, all rights reserved. <a href="/terms">Terms</a></div>'])
    return _doc(t["title"], body)

def product(t, blocks, site="Bridge Street Goods"):
    p = t["product"]
    feats = "".join(f"<li>{html.escape(f)}</li>" for f in p["features"])
    main = "\n".join([f"<h1>{html.escape(p['name'])}</h1>", f'<div class="cost">{html.escape(p["price"])}</div>', f'<div class="card"><ul>{feats}</ul><button>Add to basket</button></div>',
                      "<h2>About this item</h2>", *blocks, '<h2>Customer reviews</h2><div class="card">Rated 4.4 by 87 customers.</div>'])
    body = "\n".join([_top(site), f'<div class="wrap"><section class="main">{main}</section>{_side(t)}</div>', '<div class="foot">Returns accepted within 60 days.</div>'])
    return _doc(p["name"], body)

def docs(t, blocks, site="docs"):
    d = t["doc"]
    cmds = "\n".join(html.escape(c) for c in d["cmds"])
    main = "\n".join([f"<h1>{html.escape(d['tool'])} quick start</h1>", f"<p>Background reading: <a href=\"/blog\">{html.escape(t['title'])}</a>.</p>", f'<div class="cmd">{cmds}</div>', *blocks,
                      "<h2>See also</h2><p>The command reference lists every flag.</p>"])
    body = "\n".join([_top(f"{d['tool']} manual"), f'<div class="wrap"><section class="main">{main}</section>{_side(t)}</div>', f'<div class="foot">{html.escape(d["tool"])} is released under the Apache 2.0 license.</div>'])
    return _doc(f"{d['tool']} manual", body)

def forum(t, blocks, users, replies):
    posts = [f'<div class="card"><b>{html.escape(users[0])}</b> <span class="byline">{t["date"]}</span>{blocks[0]}</div>']
    for i, b in enumerate(blocks[1:]):
        posts.append(f'<div class="reply"><b>{html.escape(users[(i + 1) % len(users)])}</b>{b}<p>{html.escape(replies[i % len(replies)])}</p></div>')
    main = "\n".join([f"<h1>{html.escape(t['title'])}</h1>", *posts])
    body = "\n".join([_top("Neighbourhood Boards"), f'<div class="wrap"><section class="main">{main}</section>{_side(t)}</div>', '<div class="foot">Please keep discussions civil.</div>'])
    return _doc(t["title"], body)

def email_html(t, blocks, intro, signoff, sender):
    rows = "\n".join(f'<div style="margin:0 0 12px 0;font-size:15px;line-height:1.5;color:{TEXT_FG}">{b}</div>' for b in blocks)
    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>{html.escape(t['title'])}</title></head>
<body style="margin:0;padding:24px 0;background:{PAGE_BG};font-family:Verdana,sans-serif">
<div style="max-width:600px;margin:0 auto;background:{CARD_BG};padding:22px 26px;border:1px solid #c9d6c4">
<div style="font-size:15px;color:{TEXT_FG};margin-bottom:12px">{html.escape(intro)}</div>
{rows}
<div style="font-size:15px;color:{TEXT_FG}">{html.escape(signoff)}<br>{html.escape(sender)}</div>
</div>
<div style="max-width:600px;margin:10px auto;font-size:11px;color:#6b7766">Sent to you as a registered member. <a href="https://example.org/prefs">Email preferences</a></div>
</body></html>
"""
