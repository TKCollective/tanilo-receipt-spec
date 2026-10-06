#!/usr/bin/env python3
"""Extract, from sections 3-7, 9 and 10 of the cited
draft-krausz-verification-state-01 text:

  extract(text)             every sentence carrying an audit keyword (MUST, MUST NOT,
                            SHALL, SHALL NOT, SHOULD, SHOULD NOT, REQUIRED, RECOMMENDED);
  extract_outside(text)     every sentence or table row that carries MAY or OPTIONAL and
                            none of the audit keywords: outside the audit, listed so the
                            boundary is visible;
  extract_structural(text)  the requirement-bearing items that are not sentences with a
                            keyword: the "typ" list item of 4.1, the numbered steps of
                            4.3 and the body rows of Table 2 in 5.1.

Shared by generate_mapping.py (which assigns each item to requirement identifiers)
and validate_mapping.py (which re-extracts from the cited bytes and checks nothing is
missing).

Deterministic: the input is pinned by digest, so every list is too.
"""
import re

SECTIONS = {"3", "4", "5", "6", "7", "9", "10"}   # top-level sections in scope
KEYWORDS = re.compile(r"\b(MUST NOT|MUST|SHALL NOT|SHALL|SHOULD NOT|SHOULD|REQUIRED|RECOMMENDED)\b")
HEADING = re.compile(r"^(\d+)(\.\d+)*\.\s{2}\S")
PAGE_NOISE = re.compile(r"^(Krausz\s+Expires|Internet-Draft\s)")
OUTSIDE = re.compile(r"\b(MAY|OPTIONAL)\b")
SENTENCE_END = re.compile(r"[.:;?!)\]\"]$")

def _without_page_breaks(text):
    """The lines of the text with page breaks removed. A page break is the footer line,
    the form feed, the running header and the blank lines around them. Where the last
    line before the break does not end a sentence and the first line after it is prose,
    the break fell in the middle of a sentence and the two parts are joined with nothing
    between them; otherwise the break is replaced by one blank line, as a paragraph
    boundary."""
    lines = text.split("\n")
    noise = lambda ln: "\f" in ln or bool(PAGE_NOISE.match(ln.strip()))
    out, i = [], 0
    while i < len(lines):
        if not noise(lines[i]): out.append(lines[i]); i += 1; continue
        while out and not out[-1].strip(): out.pop()          # blank lines before the footer
        while i < len(lines) and (noise(lines[i]) or not lines[i].strip()): i += 1
        prev = out[-1].strip() if out else ""
        nxt = lines[i].strip() if i < len(lines) else ""
        mid_sentence = (bool(prev) and bool(nxt) and not SENTENCE_END.search(prev)
                        and not prev.startswith(("+", "|")) and not nxt.startswith(("+", "|", "*"))
                        and not HEADING.match(lines[i]) and not HEADING.match(out[-1]))
        if not mid_sentence: out.append("")
    return out

def _rows_of_table(lines):
    """Join the wrapped cells of one ASCII-table row into a single string."""
    rows, cur = [], []
    for ln in lines:
        if ln.startswith("+"):
            if cur: rows.append(cur); cur = []
        elif ln.startswith("|"):
            cur.append(ln)
    if cur: rows.append(cur)
    out = []
    for row in rows:
        cells = [[c.strip() for c in ln.strip().strip("|").split("|")] for ln in row]
        ncol = max(len(c) for c in cells)
        merged = []
        for i in range(ncol):
            merged.append(" ".join(c[i] for c in cells if i < len(c) and c[i]))
        out.append(" | ".join(m for m in merged if m))
    return out

def extract(text):
    """Return [(section, sentence)] for every normative sentence in scope, in document order."""
    return [(sec, s) for sec, s, _ in _items(text) if KEYWORDS.search(s)]

def extract_outside(text):
    """Return [(section, text)] for every in-scope sentence or table row that carries MAY
    or OPTIONAL and none of the audit keywords, in document order."""
    return [(sec, s) for sec, s, _ in _items(text) if OUTSIDE.search(s) and not KEYWORDS.search(s)]

def _items(text):
    """Every in-scope sentence and table row: [(section, text, is_table_row)]."""
    lines = _without_page_breaks(text)
    section = None
    paras, buf, table = [], [], []
    def flush():
        nonlocal buf, table
        if table:
            for r in _rows_of_table(table): paras.append((section, r, True))
            table = []
        if buf:
            paras.append((section, " ".join(s.strip() for s in buf), False)); buf = []
    for ln in lines:
        m = HEADING.match(ln)
        if m:
            flush(); section = ln.split("  ", 1)[0].strip().rstrip("."); continue
        st = ln.strip()
        if not st: flush(); continue
        if st.startswith(("+", "|")): table.append(st); continue
        buf.append(ln)
    flush()
    out = []
    for sec, para, is_table in paras:
        if sec is None or sec.split(".")[0] not in SECTIONS: continue
        if is_table:
            out.append((sec, para, True))
            continue
        # split prose into sentences; keep list-item leaders ("*  alg: ...") with their sentence
        para = re.sub(r"\s+", " ", para).strip()
        for s in re.split(r"(?<=[.;])\s+(?=[A-Z*(\"])", para):
            s = s.strip().lstrip("* ").strip()
            if s: out.append((sec, s, False))
    return out

STEP = re.compile(r"^\s{3}(\d+)\.\s+\S")
def extract_structural(text):
    """Return [(kind, section, locator, text)], in document order:
       ("list_item", "4.1", "typ", ...)                 the typ item of the 4.1 header list
       ("numbered_step", "4.3", "step N", ...)          each numbered step of 4.3
       ("table_row", "5.1", "Table 2 row N", ...)       each body row of Table 2
    The text is the item with its wrapped lines joined by single spaces."""
    lines = _without_page_breaks(text)
    out, section = [], None
    i = 0
    table_51 = []
    while i < len(lines):
        ln = lines[i]
        if HEADING.match(ln):
            section = ln.split("  ", 1)[0].strip().rstrip("."); i += 1; continue
        st = ln.strip()
        if section == "4.1" and st.startswith("*  typ:"):
            item = [st.lstrip("* ").strip()]; i += 1
            while i < len(lines) and lines[i].startswith("      ") and lines[i].strip(): item.append(lines[i].strip()); i += 1
            out.append(("list_item", "4.1", "typ", " ".join(item))); continue
        if section == "4.3" and STEP.match(ln):
            n = STEP.match(ln).group(1); item = [st]; i += 1
            while i < len(lines) and lines[i].startswith("      ") and lines[i].strip(): item.append(lines[i].strip()); i += 1
            out.append(("numbered_step", "4.3", f"step {n}", " ".join(item))); continue
        if section == "5.1" and st.startswith(("+", "|")): table_51.append(st)
        elif section == "5.1" and table_51 and st.startswith("Table 2"):
            rows = _rows_of_table(table_51)[1:]              # the first row is the header
            for n, r in enumerate(rows, 1): out.append(("table_row", "5.1", f"Table 2 row {n}", r))
            table_51 = []
        i += 1
    return out

if __name__ == "__main__":
    import sys
    t = open(sys.argv[1], encoding="utf-8").read()
    for sec, s in extract(t): print(f"[{sec}] {s}")
    print("--- outside the audit (MAY / OPTIONAL only)")
    for sec, s in extract_outside(t): print(f"[{sec}] {s}")
    print("--- structural sources")
    for k, sec, loc, s in extract_structural(t): print(f"[{sec}] {loc} ({k}): {s}")
