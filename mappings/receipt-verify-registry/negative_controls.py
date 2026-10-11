#!/usr/bin/env python3
"""Negative controls for validate_mapping.py: deliberately broken copies of
mapping.json that the validator MUST reject (an unlinked vector; zeroed -01 and
mapping digests; a wrong snapshot commit; a missing audit source, alone and
combined with an unassigned sentence or a deleted audit row; an audit source
whose bytes do not match the recorded digest), plus the real file, which it
must accept.

Revision 3 adds Michael Msebenzi's three mutations from his re-check of 91e66a7,
each made self-consistent (the reverse view and its summaries are recomputed after
the change, so nothing but the rule under test can catch it), and controls for the
other revision-3 rules:
  - comp-001 relinked only to EP-4.1.2-canonical-order (a document its corpus does
    not name);
  - the excluding-NOT-NORMATIVE summary and per-row coverage removed from a view
    whose scope includes a NOT NORMATIVE corpus (whole view; one row; the MAP view);
  - registry row D01-4.1-typ deleted (alone, and together with its structural source);
  - the audit's second count altered; sentence 27 cut at the page break again; an
    outside-audit item removed; a structural source's text altered.
Revision 4 adds Michael Msebenzi's later-revision findings: a D01 or MAP row with a
value outside the enum or a missing member (the per-view schema had been bypassed for
those two views, and the validator answered with a traceback); a corpus naming a
document whose view does not include it, and the converse; a row id whose section or
slug does not match its source (sentence section, structural locator, or the cited
mapping's rule numbers). A validator crash (a Traceback) never counts as a pass.

For each case the expected rule must appear in the validator's output, not merely a
non-zero exit. Exit 0 only when every case behaves as expected.

    python3 mappings/receipt-verify-registry/negative_controls.py
"""
import copy, json, os, subprocess, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
real = json.load(open(os.path.join(HERE, "mapping.json")))

def unlinked(d):
    v = d["corpora"]["v0.3-composed"]["vectors"][0]
    v["requirements"] = []; v.pop("status", None); v.pop("reason", None)   # a vector with no link and no deferral
    return d
def zeroed_digests(d):
    z = "0" * 64
    d["requirement_documents"]["D01"]["sha256"] = z
    d["requirement_documents"]["MAP"]["sha256"] = z
    for t in d["cited_texts"].values(): t["sha256"] = z
    return d
def wrong_commit(d):
    d["corpus_snapshot"]["commit"] = "0" * 40
    return d

def missing_audit_source(d):
    d["normative_audit"]["source"] = "mappings/receipt-verify-registry/cited/does-not-exist.txt"
    return d
def missing_source_unassigned(d):
    d = missing_audit_source(d)
    d["normative_audit"]["sentences"][5]["requirements"] = []      # the §4.1 IANA SHOULD row, unassigned
    return d
def missing_source_deleted_row(d):
    d = missing_audit_source(d)
    del d["normative_audit"]["sentences"][5]                       # the §4.1 IANA SHOULD row, deleted
    return d
def mismatched_audit_source(d):
    d["cited_texts"]["D01"]["sha256"] = "1" * 64                   # recorded digest no longer matches the bytes
    d["requirement_documents"]["D01"]["sha256"] = "1" * 64
    return d

# ── revision 3 ──────────────────────────────────────────────────────
RANK = {"not covered": 0, "partial": 1, "covered": 2}
NAME = {v: k for k, v in RANK.items()}
def resync_reverse(d):
    """Recompute every reverse view from the forward view, the way the generator does,
    so a mutation of the forward view or the registry leaves no stale reverse data."""
    for doc_id, view in d["reverse_view"].items():
        scope = view["corpora"]
        sub = view.get("summary_excluding_not_normative")
        normative = [c for c in scope if d["corpora"][c].get("normative") is True]
        reqs = d["requirement_documents"][doc_id]["requirements"]
        rows = {}
        for rid, text in reqs.items():
            old = view["requirements"].get(rid, {})
            hits = [{"corpus": c, "vector": v["id"], "coverage": r["coverage"]} for c in scope for v in d["corpora"][c]["vectors"] for r in v.get("requirements", []) if r["requirement"] == rid]
            row = {"text": text, "coverage": NAME[max((RANK[h["coverage"]] for h in hits), default=0)]}
            if sub is not None: row["coverage_excluding_not_normative"] = NAME[max((RANK[h["coverage"]] for h in hits if h["corpus"] in normative), default=0)]
            if "note" in old: row["note"] = old["note"]
            row["vectors"] = hits; rows[rid] = row
        def summ(key): return {"requirements": len(rows), "covered": sum(r[key] == "covered" for r in rows.values()), "partial": sum(r[key] == "partial" for r in rows.values()),
                               "not_covered": sum(r[key] == "not covered" for r in rows.values()), "not_covered_list": [k for k, r in rows.items() if r[key] == "not covered"]}
        view["requirements"] = rows; view["summary"] = summ("coverage")
        if sub is not None: view["summary_excluding_not_normative"] = {"corpora": normative, **summ("coverage_excluding_not_normative")}
    d01 = d["reverse_view"]["D01"]["requirements"]; aud = d["normative_audit"]
    for r in aud["sentences"]:
        r["exercised"] = any(d01.get(i, {}).get("coverage", "not covered") != "not covered" for i in r["requirements"])
        r["exercised_excluding_not_normative"] = any(d01.get(i, {}).get("coverage_excluding_not_normative", "not covered") != "not covered" for i in r["requirements"])
    n = len(aud["sentences"]); a = sum(r["exercised"] for r in aud["sentences"]); b = sum(r["exercised_excluding_not_normative"] for r in aud["sentences"])
    aud["summary"] = {"sentences": n, "exercised": a, "unexercised": n - a}
    aud["summary_excluding_not_normative"].update({"sentences": n, "exercised": b, "unexercised": n - b, "exercised_only_through_not_normative": [r["n"] for r in aud["sentences"] if r["exercised"] and not r["exercised_excluding_not_normative"]]})
    return d

def relink_to_unnamed_document(d):          # Michael's mutation (a)
    v = next(v for v in d["corpora"]["v0.3-composed"]["vectors"] if v["id"] == "comp-001")
    v["requirements"] = [{"requirement": "EP-4.1.2-canonical-order", "coverage": "covered", "checker": "examples/v0.3-composed/verify.mjs", "assertion": "relinked by the negative control"}]
    return resync_reverse(d)
def drop_excluding_from_d01(d):             # Michael's mutation (b): the whole second count removed from the D01 view
    view = d["reverse_view"]["D01"]; view.pop("summary_excluding_not_normative")
    for row in view["requirements"].values(): row.pop("coverage_excluding_not_normative")
    return d
def drop_excluding_from_one_row(d):
    d["reverse_view"]["D01"]["requirements"]["D01-5.1-row-2"].pop("coverage_excluding_not_normative"); return d
def drop_excluding_from_map(d):
    view = d["reverse_view"]["MAP"]; view.pop("summary_excluding_not_normative")
    for row in view["requirements"].values(): row.pop("coverage_excluding_not_normative")
    return d
def delete_typ_row(d):                      # Michael's mutation (c)
    d["requirement_documents"]["D01"]["requirements"].pop("D01-4.1-typ")
    d["requirement_documents"]["D01"].get("requirement_notes", {}).pop("D01-4.1-typ", None)
    d = resync_reverse(d)
    d["normative_audit"]["rows_without_audit_sentence"].remove("D01-4.1-typ")
    return d
def delete_typ_row_and_its_source(d):
    d = delete_typ_row(d)
    d["normative_audit"]["structural_sources"] = [x for x in d["normative_audit"]["structural_sources"] if x["requirement"] != "D01-4.1-typ"]
    return d
def audit_second_count_altered(d):
    s2 = d["normative_audit"]["summary_excluding_not_normative"]; s2["exercised"], s2["unexercised"] = 10, 45; return d
def sentence_27_cut_at_page_break(d):
    r = d["normative_audit"]["sentences"][26]; assert r["n"] == 27 and r["text"].endswith("a new mapping version with a new ID.")
    r["text"] = r["text"][: -len(" mapping version with a new ID.")]; return d
def outside_item_removed(d):
    d["normative_audit"]["outside_audit"].pop(); return d
def structural_text_altered(d):
    d["normative_audit"]["structural_sources"][0]["text"] = "typ: application/vnd.something-else"; return d

# ── revision 4: Michael Msebenzi's later-revision findings ───────────
def rename_requirement(d, old, new):
    """Rename a registry row everywhere it is referenced, then resync: only an
    id-to-source rule can tell the renamed file from the real one."""
    for doc in d["requirement_documents"].values():
        if old in doc["requirements"]:
            doc["requirements"] = {(new if k == old else k): v for k, v in doc["requirements"].items()}
            if old in doc.get("requirement_notes", {}): doc["requirement_notes"][new] = doc["requirement_notes"].pop(old)
    for c in d["corpora"].values():
        for v in c["vectors"]:
            for r in v.get("requirements", []):
                if r["requirement"] == old: r["requirement"] = new
    for view in d["reverse_view"].values():
        if old in view["requirements"]: view["requirements"] = {(new if k == old else k): v for k, v in view["requirements"].items()}
    aud = d["normative_audit"]
    for r in aud["sentences"]: r["requirements"] = [new if i == old else i for i in r["requirements"]]
    for x in aud["structural_sources"]:
        if x["requirement"] == old: x["requirement"] = new
    aud["rows_without_audit_sentence"] = [new if i == old else i for i in aud["rows_without_audit_sentence"]]
    return resync_reverse(d)
def d01_row_bad_coverage(d):                # (1) a value outside the enum in a D01 row
    d["reverse_view"]["D01"]["requirements"]["D01-3.2-conjunction"]["coverage"] = "bogus"; return d
def map_row_without_vectors(d):             # (1) a MAP row missing a required member
    d["reverse_view"]["MAP"]["requirements"]["MAP-rule-1"].pop("vectors"); return d
def corpus_names_unscoped_document(d):      # (2) v0.3-composed names EP, but the EP view does not include it
    d["corpora"]["v0.3-composed"]["requirement_documents"].append("EP"); return resync_reverse(d)
def view_scopes_unnaming_corpus(d):         # (2) the EP view includes leaf-screen-halt, which names no document
    d["reverse_view"]["EP"]["corpora"].append("leaf-screen-halt"); return resync_reverse(d)
def typ_row_wrong_section(d):               # (3) id section 4.2, source section 4.1
    return rename_requirement(d, "D01-4.1-typ", "D01-4.2-typ")
def typ_row_wrong_locator(d):               # (3) id slug "type", locator "typ"
    return rename_requirement(d, "D01-4.1-typ", "D01-4.1-type")
def map_rule_renumbered(d):                 # (3) MAP-rule-8: the cited mapping has rules 1 to 7
    return rename_requirement(d, "MAP-rule-7", "MAP-rule-8")

V4_CASES = [
    ("(1) D01 row coverage 'bogus'", d01_row_bad_coverage, "coverage 'bogus'"),
    ("(1) MAP row without vectors", map_row_without_vectors, "vectors is missing"),
    ("(2) v0.3-composed names EP but the EP view does not include it", corpus_names_unscoped_document, "names EP but the EP view does not include"),
    ("(2) the EP view includes leaf-screen-halt, which does not name EP", view_scopes_unnaming_corpus, "includes leaf-screen-halt but leaf-screen-halt does not name EP"),
    ("(3) D01-4.1-typ renamed D01-4.2-typ (section differs from its source)", typ_row_wrong_section, "id section 4.2"),
    ("(3) D01-4.1-typ renamed D01-4.1-type (slug differs from its locator)", typ_row_wrong_locator, "does not match its structural source"),
    ("(3) MAP-rule-7 renamed MAP-rule-8 (no such rule in the cited mapping)", map_rule_renumbered, "MAP-rule-8"),
]

V3_CASES = [
    ("(a) comp-001 relinked only to EP-4.1.2-canonical-order", relink_to_unnamed_document, "the corpus names only"),
    ("(b) D01 view: excluding-NOT-NORMATIVE summary and row fields removed", drop_excluding_from_d01, "summary_excluding_not_normative is missing"),
    ("(b) D01 view: one row's coverage_excluding_not_normative removed", drop_excluding_from_one_row, "coverage_excluding_not_normative is missing"),
    ("(b) MAP view: excluding-NOT-NORMATIVE summary and row fields removed", drop_excluding_from_map, "summary_excluding_not_normative is missing"),
    ("(c) registry row D01-4.1-typ deleted", delete_typ_row, "is not a D01 registry row"),
    ("(c) registry row D01-4.1-typ deleted together with its structural source", delete_typ_row_and_its_source, "structural_sources differ from the extraction"),
    ("(d) audit second count altered to 10 / 45", audit_second_count_altered, "summary_excluding_not_normative disagrees with rows"),
    ("(e) sentence 27 cut at the page break", sentence_27_cut_at_page_break, "listed sentences differ from the extraction"),
    ("(f) an outside-audit item removed", outside_item_removed, "outside_audit differs from the extraction"),
    ("(c) a structural source's text altered", structural_text_altered, "structural_sources differ from the extraction"),
]

CASES = [("real mapping.json (control)", lambda d: d, 0),
         ("missing audit source", missing_audit_source, 1),
         ("missing audit source + an unassigned sentence", missing_source_unassigned, 1),
         ("missing audit source + a deleted audit row", missing_source_deleted_row, 1),
         ("audit source present but its bytes do not match the recorded digest", mismatched_audit_source, 1),
         ("unlinked vector (no requirement link, not deferred)", unlinked, 1),
         ("zeroed -01 and mapping-document digests", zeroed_digests, 1),
         ("wrong corpus_snapshot.commit", wrong_commit, 1)]
bad = 0
with tempfile.TemporaryDirectory() as tmp:
    # the resync helper must reproduce the real file exactly, or the consistent mutations prove nothing
    same = json.dumps(resync_reverse(copy.deepcopy(real)), sort_keys=True) == json.dumps(real, sort_keys=True)
    bad += 0 if same else 1
    print(("PASS" if same else "FAIL") + ": resync_reverse() on the unmodified mapping reproduces it exactly")
    for label, mutate, needle in V3_CASES + V4_CASES:
        path = os.path.join(tmp, "mapping.json")
        json.dump(mutate(copy.deepcopy(real)), open(path, "w"))
        r = subprocess.run([sys.executable, os.path.join(HERE, "validate_mapping.py"), "--mapping", path], capture_output=True, text=True)
        probs = [ln for ln in r.stdout.splitlines() if ln.startswith("PROBLEM")]
        hit = next((ln for ln in probs if needle in ln), None)
        crashed = "Traceback" in r.stderr
        ok = r.returncode != 0 and hit is not None and not crashed
        bad += 0 if ok else 1
        print(("PASS" if ok else "FAIL") + f": {label} -> validator exit {r.returncode}, {len(probs)} problem(s); " + ("TRACEBACK instead of a PROBLEM line; " if crashed else "") + (hit[:150] if hit else f"expected rule not reported: {needle!r}; first: {(probs or ['(none)'])[0][:120]}"))
    for label, mutate, want in CASES:
        path = os.path.join(tmp, "mapping.json")
        json.dump(mutate(copy.deepcopy(real)), open(path, "w"))
        r = subprocess.run([sys.executable, os.path.join(HERE, "validate_mapping.py"), "--mapping", path], capture_output=True, text=True)
        got = 0 if r.returncode == 0 else 1
        first = next((ln for ln in r.stdout.splitlines() if ln.startswith("PROBLEM")), "(no problem line)")
        ok = got == want
        bad += 0 if ok else 1
        print(("PASS" if ok else "FAIL") + f": {label} -> validator exit {r.returncode} (expected {'0' if want == 0 else 'non-zero'}); {first[:140]}")
print("RESULT:", "OK" if not bad else f"{bad} control(s) misbehaved")
sys.exit(0 if not bad else 1)
