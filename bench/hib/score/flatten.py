#!/usr/bin/env python3
"""Naive extraction for HIB baselines: what a typical pipeline without rendering awareness hands to a model.

  python3 bench/hib/score/flatten.py --split public [--data bench/hib/data]

Writes data/<split>/flat.jsonl ({"id", "text"}) and results/regex-<split>.jsonl (the naive regex baseline's verdicts).

  web page   the copy an AI user agent is served (for ua_cloaking: the agent copy), as raw HTML, no JavaScript run;
             BeautifulSoup(html, "html.parser").get_text(" ")  (keeps display:none, offscreen, noscript and template
             text; drops comments, attributes and script source, as get_text does)
  email      the text/html part through the same get_text (falls back to text/plain)
  markdown   the raw file
  pdf        pypdf PdfReader(...).pages[i].extract_text()
  docx       python-docx: every paragraph and table cell, plus section headers (like docx2txt)
  xlsx       openpyxl: every cell value of every sheet, hidden or not (like pandas.read_excel(sheet_name=None))
  pptx       python-pptx: every shape's text on every slide, plus the notes slide text
  png        nothing (a text pipeline does not read image metadata)
  mcp json   the raw tools/list JSON
"""
import argparse, email, io, json, os, re, sys
from email import policy

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGEX = re.compile(r"\b(ignore|disregard|forget|override)\b[^.\n]{0,40}?\b(previous|prior|above|earlier|preceding|all|any|your)\b[^.\n]{0,20}?\b(instructions?|prompts?|directions?|rules|guidelines|context)\b", re.I)

def html_text(h):
    from bs4 import BeautifulSoup
    return BeautifulSoup(h, "html.parser").get_text(" ")

def flatten(r, d):
    p = os.path.join(d, r["file"])
    c = r["carrier"]
    if c.startswith("web_"):
        f = os.path.join(d, r["agent_file"]) if r.get("agent_file") else p
        return html_text(open(f, encoding="utf-8").read())
    if c == "email_html":
        m = email.message_from_bytes(open(p, "rb").read(), policy=policy.default)
        b = m.get_body(("html",))
        if b is not None: return html_text(b.get_content())
        return m.get_body(("plain",)).get_content()
    if c in ("readme_md", "mcp_tools_json"):
        return open(p, encoding="utf-8").read()
    if c == "pdf":
        from pypdf import PdfReader
        return "\n".join(pg.extract_text() or "" for pg in PdfReader(p).pages)
    if c == "docx":
        import docx
        doc = docx.Document(p)
        parts = [para.text for s in doc.sections for para in s.header.paragraphs]
        parts += [para.text for para in doc.paragraphs]
        parts += [cell.text for t in doc.tables for row in t.rows for cell in row.cells]
        return "\n".join(parts)
    if c == "xlsx":
        import openpyxl
        wb = openpyxl.load_workbook(p)
        return "\n".join(" ".join(str(v) for v in row if v is not None) for ws in wb.worksheets for row in ws.iter_rows(values_only=True))
    if c == "pptx":
        from pptx import Presentation
        prs = Presentation(p)
        parts = []
        for s in prs.slides:
            parts += [sh.text_frame.text for sh in s.shapes if sh.has_text_frame]
            if s.has_notes_slide: parts.append(s.notes_slide.notes_text_frame.text)
        return "\n".join(parts)
    if c == "png":
        return ""
    raise ValueError(c)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", required=True)
    ap.add_argument("--data", default=os.path.join(ROOT, "data"))
    a = ap.parse_args()
    d = os.path.join(a.data, a.split)
    rows = [json.loads(l) for l in open(os.path.join(d, "manifest.jsonl"), encoding="utf-8")]
    os.makedirs(os.path.join(ROOT, "results"), exist_ok=True)
    with open(os.path.join(d, "flat.jsonl"), "w", encoding="utf-8") as ff, open(os.path.join(ROOT, "results", f"regex-{a.split}.jsonl"), "w") as fr:
        for r in rows:
            t = flatten(r, d)
            ff.write(json.dumps({"id": r["id"], "text": t}, ensure_ascii=False) + "\n")
            fr.write(json.dumps({"id": r["id"], "defense": "naive regex (ignore|disregard ... previous ... instructions) on naive extraction", "flagged": bool(REGEX.search(t))}) + "\n")
    print(json.dumps({"split": a.split, "items": len(rows)}))

if __name__ == "__main__":
    main()
