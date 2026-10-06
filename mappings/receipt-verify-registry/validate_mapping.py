#!/usr/bin/env python3
"""Validate mapping.json against the corpus at its snapshot commit, the cited
texts and the schema. Independent of the generator. It checks that
  1. every corpus's manifest, read with `git show <corpus_snapshot.commit>:<path>`
     (never the working tree), has the recorded sha256 and the recorded count,
     and every mapped vector id exists in it (and vice versa);
  2. every requirement identifier referenced exists in the registry, every
     registry identifier appears in the reverse view, and every requirement link
     points into a document that the linking vector's own corpus names in its
     requirement_documents (a link to a document the corpus does not name fails);
  3. every vector carries at least one in-scope requirement link, or an explicit
     status "deferred" with a reason (and a deferred vector carries no coverage);
  4. the reverse view EQUALS the forward view scoped to the corpora each view names
     (every hit and the best coverage), recomputed here; a view whose scope
     includes a NOT NORMATIVE corpus MUST publish summary_excluding_not_normative
     (naming exactly the normative corpora of its scope) and
     coverage_excluding_not_normative on every row, and both are recomputed; a
     view with no such corpus must not carry them;
  5. the digests recorded for the cited -01 text and the mapping document are
     recomputed from the cited bytes (cited_texts[].path), and the evidence-pinning
     drafts' digests from their bytes at the snapshot commit;
  6. the normative audit's source is the digest-checked D01 cited text (same path
     as cited_texts.D01, bytes hashing to the recorded digest; a missing or
     mismatched source is a hard failure, never a skip), and the audit lists
     exactly the sentences normative_audit.py extracts from those bytes, each
     mapped to at least one registry identifier, with exercised and
     exercised_excluding_not_normative recomputed from the reverse view and both
     summaries recomputed from the rows; the structural sources (the typ item of
     4.1, the numbered steps of 4.3, the rows of Table 2) are re-extracted from
     the same bytes and must match; every D01 registry row must be named by an
     audit sentence or a structural source, and every row so named must exist
     (so deleting a row fails); the outside-audit list (MAY / OPTIONAL only) is
     re-extracted and must match;
  7. mapping.json conforms to mapping.schema.json (jsonschema package; this script
     says so when it is not installed and the structural checks stand alone).
Exit code 0 only when every check holds.

    python3 mappings/receipt-verify-registry/validate_mapping.py [--mapping PATH]
"""
import hashlib, json, os, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from normative_audit import extract as extract_normative, extract_outside, extract_structural

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
problems = []
mapping_path = os.path.join(HERE, "mapping.json")
if "--mapping" in sys.argv: mapping_path = sys.argv[sys.argv.index("--mapping") + 1]
doc = json.load(open(mapping_path))
COMMIT = doc["corpus_snapshot"]["commit"]

def snapshot_bytes(rel):
    r = subprocess.run(["git", "show", f"{COMMIT}:{rel}"], cwd=ROOT, capture_output=True)
    if r.returncode != 0:
        problems.append(f"git show {COMMIT[:12]}:{rel} failed: {r.stderr.decode().strip()}")
        return None
    return r.stdout

# 1. manifests at the snapshot commit
def manifest_ids(rel):
    data = snapshot_bytes(rel)
    if data is None: return None, None, None
    m = json.loads(data)
    if "accept_vectors" in m: ids = [v["id"] for v in m["accept_vectors"] + m["reject_vectors"]]
    else: ids = [v["id"] for v in m["vectors"]]
    return ids, hashlib.sha256(data).hexdigest(), m
for name, c in doc["corpora"].items():
    ids, digest, m = manifest_ids(c["manifest"])
    if ids is None: continue
    if c["manifest_sha256"] != digest: problems.append(f"{name}: manifest sha256 at snapshot {digest} != recorded {c['manifest_sha256']}")
    mapped = [v["id"] for v in c["vectors"]]
    if c["vector_count"] != len(ids): problems.append(f"{name}: vector_count {c['vector_count']} != manifest {len(ids)}")
    if len(mapped) != c["vector_count"]: problems.append(f"{name}: {len(mapped)} mapped vectors != vector_count")
    if sorted(mapped) != sorted(ids): problems.append(f"{name}: mapped ids differ from manifest ids: {sorted(set(mapped) ^ set(ids))}")
    if name == "evidence-pinning-rev8" and m["header"]["vector_count"] != len(ids): problems.append("rev8 header.vector_count disagrees with its vectors")

# 2. requirement identifiers; 3. every vector linked or deferred
registry = {rid for d in doc["requirement_documents"].values() for rid in d["requirements"]}
doc_of = {rid: doc_id for doc_id, d in doc["requirement_documents"].items() for rid in d["requirements"]}
for name, c in doc["corpora"].items():
    for d_id in c.get("requirement_documents", []):
        if d_id not in doc["requirement_documents"]: problems.append(f"{name}: requirement_documents names unknown document {d_id}")
external = set(doc["external_documents"])
deferred_count = 0
for name, c in doc["corpora"].items():
    for v in c["vectors"]:
        for r in v.get("requirements", []):
            if r["requirement"] not in registry: problems.append(f"{name}/{v['id']}: unknown requirement {r['requirement']}")
            elif doc_of[r["requirement"]] not in c.get("requirement_documents", []):
                problems.append(f"{name}/{v['id']}: links {r['requirement']}, which is in document {doc_of[r['requirement']]}; the corpus names only {c.get('requirement_documents', [])}")
        for e in v.get("external_requirements", []):
            if e["requirement"] not in external: problems.append(f"{name}/{v['id']}: unknown external {e['requirement']}")
        if v.get("status") == "deferred":
            deferred_count += 1
            if v.get("requirements"): problems.append(f"{name}/{v['id']}: deferred vector carries requirement coverage")
            if not isinstance(v.get("reason"), str) or not v["reason"].strip(): problems.append(f"{name}/{v['id']}: deferred without a reason")
        elif not v.get("requirements"):
            problems.append(f"{name}/{v['id']}: no requirement link and not deferred")
in_reverse = {rid for view in doc["reverse_view"].values() for rid in view["requirements"]}
for rid in registry - in_reverse: problems.append(f"registry requirement missing from the reverse view: {rid}")
if doc["totals"].get("deferred") != deferred_count: problems.append(f"totals.deferred {doc['totals'].get('deferred')} != {deferred_count}")

# 4. reverse view MUST EQUAL the forward view scoped to the corpora it names
rank = {"not covered": 0, "partial": 1, "covered": 2}
def check_summary(label, s, rows, key):
    counts = {"covered": 0, "partial": 0, "not covered": 0}
    for row in rows.values(): counts[row[key]] += 1
    if (s["requirements"], s["covered"], s["partial"], s["not_covered"]) != (len(rows), counts["covered"], counts["partial"], counts["not covered"]):
        problems.append(f"{label}: summary counts disagree with rows")
    if sorted(s["not_covered_list"]) != sorted(rid for rid, row in rows.items() if row[key] == "not covered"):
        problems.append(f"{label}: not_covered_list disagrees with rows")
for doc_id, view in doc["reverse_view"].items():
    scope = view["corpora"]
    for name in scope:
        if name not in doc["corpora"]: problems.append(f"reverse {doc_id}: names unknown corpus {name}")
    doc_reqs = set(doc["requirement_documents"][doc_id]["requirements"])
    if set(view["requirements"]) != doc_reqs: problems.append(f"reverse {doc_id}: requirement set differs from the registry")
    sub = view.get("summary_excluding_not_normative")
    normative_in_scope = [n for n in scope if doc["corpora"].get(n, {}).get("normative") is True]
    needs_sub = any(n in doc["corpora"] and doc["corpora"][n].get("normative") is not True for n in scope)
    if needs_sub and not isinstance(sub, dict):
        problems.append(f"reverse {doc_id}: scope includes a NOT NORMATIVE corpus but summary_excluding_not_normative is missing")
        sub = None
    if not needs_sub and sub is not None:
        problems.append(f"reverse {doc_id}: summary_excluding_not_normative present although no corpus in scope is NOT NORMATIVE")
    subscope = sub.get("corpora") if sub else None
    if sub and subscope != normative_in_scope:
        problems.append(f"reverse {doc_id}: summary_excluding_not_normative.corpora {subscope} != the normative corpora of the scope {normative_in_scope}")
        subscope = normative_in_scope
    for rid, row in view["requirements"].items():
        hits = []
        for name in scope:
            for v in doc["corpora"][name]["vectors"]:
                for r in v.get("requirements", []):
                    if r["requirement"] == rid: hits.append((name, v["id"], r["coverage"]))
        listed = [(h["corpus"], h["vector"], h["coverage"]) for h in row["vectors"]]
        if sorted(listed) != sorted(hits): problems.append(f"reverse {rid}: listed hits {sorted(listed)} != scoped forward hits {sorted(hits)}")
        best = max((rank[h[2]] for h in hits), default=0)
        if rank[row["coverage"]] != best: problems.append(f"reverse {rid}: coverage {row['coverage']} != best of the scoped forward hits")
        if needs_sub:
            best2 = max((rank[h[2]] for h in hits if h[0] in normative_in_scope), default=0)
            got = row.get("coverage_excluding_not_normative")
            if got not in rank: problems.append(f"reverse {rid}: coverage_excluding_not_normative is missing (the view's scope includes a NOT NORMATIVE corpus)")
            elif rank[got] != best2: problems.append(f"reverse {rid}: coverage_excluding_not_normative {got} != best of the normative-only hits")
        elif "coverage_excluding_not_normative" in row:
            problems.append(f"reverse {rid}: coverage_excluding_not_normative present although no corpus in scope is NOT NORMATIVE")
        if row["text"] != doc["requirement_documents"][doc_id]["requirements"][rid]: problems.append(f"reverse {rid}: text differs from the registry")
    check_summary(f"reverse {doc_id}", view["summary"], view["requirements"], "coverage")
    if sub and all(row.get("coverage_excluding_not_normative") in rank for row in view["requirements"].values()):
        check_summary(f"reverse {doc_id} (excluding not normative)", sub, view["requirements"], "coverage_excluding_not_normative")

# 5. digests recomputed from the cited bytes and from the snapshot
for key, t in doc["cited_texts"].items():
    p = os.path.join(ROOT, t["path"])
    if not os.path.exists(p): problems.append(f"cited text {key}: {t['path']} missing"); continue
    with open(p, "rb") as f: actual = hashlib.sha256(f.read()).hexdigest()
    if actual != t["sha256"]: problems.append(f"cited text {key}: sha256 of the cited bytes {actual} != cited_texts.sha256 {t['sha256']}")
    recorded = doc["requirement_documents"][key].get("sha256")
    if actual != recorded: problems.append(f"cited text {key}: sha256 of the cited bytes {actual} != requirement_documents.{key}.sha256 {recorded}")
for key, t in doc["requirement_documents"]["EP"]["texts"].items():
    data = snapshot_bytes(t["path"])
    if data is None: continue
    actual = hashlib.sha256(data).hexdigest()
    if actual != t["sha256"]: problems.append(f"EP text {key}: sha256 at snapshot {actual} != recorded")
tot = doc["totals"]
if tot["mapped_or_deferred"] != sum(c["vector_count"] for c in doc["corpora"].values()): problems.append("totals.mapped_or_deferred disagrees")
if len(COMMIT) != 40 or any(ch not in "0123456789abcdef" for ch in COMMIT): problems.append("corpus_snapshot.commit is not a 40-hex commit id")

# 6. normative audit re-extracted from the cited bytes
aud = doc.get("normative_audit")
if not aud: problems.append("normative_audit missing")
else:
    # Fail closed: the audit source MUST be the digest-checked D01 cited text. A
    # source that is not that path, is missing, or whose bytes do not hash to the
    # recorded digest is a hard failure; the audit is never silently skipped.
    d01_cited = doc["cited_texts"].get("D01", {})
    p = os.path.join(ROOT, aud["source"])
    audit_bytes = None
    if aud["source"] != d01_cited.get("path"):
        problems.append(f"normative_audit.source {aud['source']!r} is not cited_texts.D01.path {d01_cited.get('path')!r}")
    elif not os.path.exists(p):
        problems.append(f"normative_audit.source {aud['source']} is missing: the audit cannot be checked (hard failure)")
    else:
        with open(p, "rb") as f: audit_bytes = f.read()
        h = hashlib.sha256(audit_bytes).hexdigest()
        if h != d01_cited.get("sha256") or h != doc["requirement_documents"]["D01"].get("sha256"):
            problems.append(f"normative_audit.source bytes hash to {h}, not the recorded D01 digest; audit not trusted (hard failure)")
            audit_bytes = None
    if audit_bytes is not None:
        expected = extract_normative(audit_bytes.decode("utf-8"))
        listed = [(r["section"], r["text"]) for r in aud["sentences"]]
        if listed != expected: problems.append(f"normative_audit: listed sentences differ from the extraction ({len(listed)} listed, {len(expected)} extracted)")
        d01 = doc["reverse_view"]["D01"]["requirements"]
        d01_registry = set(doc["requirement_documents"]["D01"]["requirements"])
        for r in aud["sentences"]:
            if not r["requirements"]: problems.append(f"normative_audit sentence {r['n']}: no requirement assigned")
            for i in r["requirements"]:
                if i not in d01: problems.append(f"normative_audit sentence {r['n']}: unknown requirement {i}")
            ex = any(d01.get(i, {}).get("coverage") != "not covered" for i in r["requirements"] if i in d01)
            if r["exercised"] != ex: problems.append(f"normative_audit sentence {r['n']}: exercised {r['exercised']} != recomputed {ex}")
            ex2 = any(d01.get(i, {}).get("coverage_excluding_not_normative", "not covered") != "not covered" for i in r["requirements"] if i in d01)
            if r.get("exercised_excluding_not_normative") is not ex2: problems.append(f"normative_audit sentence {r['n']}: exercised_excluding_not_normative {r.get('exercised_excluding_not_normative')} != recomputed {ex2}")
        s = aud["summary"]
        if (s["sentences"], s["exercised"], s["unexercised"]) != (len(aud["sentences"]), sum(1 for r in aud["sentences"] if r["exercised"]), sum(1 for r in aud["sentences"] if not r["exercised"])):
            problems.append("normative_audit: summary disagrees with rows")
        s2 = aud.get("summary_excluding_not_normative")
        if not isinstance(s2, dict): problems.append("normative_audit: summary_excluding_not_normative is missing")
        else:
            want_scope = doc["reverse_view"]["D01"].get("summary_excluding_not_normative", {}).get("corpora")
            if s2.get("corpora") != want_scope: problems.append(f"normative_audit: summary_excluding_not_normative.corpora {s2.get('corpora')} != the D01 view's {want_scope}")
            yes = [r["n"] for r in aud["sentences"] if r.get("exercised_excluding_not_normative") is True]
            if (s2.get("sentences"), s2.get("exercised"), s2.get("unexercised")) != (len(aud["sentences"]), len(yes), len(aud["sentences"]) - len(yes)):
                problems.append("normative_audit: summary_excluding_not_normative disagrees with rows")
            only = [r["n"] for r in aud["sentences"] if r["exercised"] and r.get("exercised_excluding_not_normative") is not True]
            if s2.get("exercised_only_through_not_normative") != only: problems.append(f"normative_audit: exercised_only_through_not_normative {s2.get('exercised_only_through_not_normative')} != recomputed {only}")
        # structural sources: re-extracted from the cited bytes
        text = audit_bytes.decode("utf-8")
        want_struct = [(k, sec, loc, t) for k, sec, loc, t in extract_structural(text)]
        got_struct = [(x.get("kind"), x.get("section"), x.get("locator"), x.get("text")) for x in aud.get("structural_sources", [])]
        if got_struct != want_struct: problems.append(f"normative_audit: structural_sources differ from the extraction ({len(got_struct)} listed, {len(want_struct)} extracted)")
        for x in aud.get("structural_sources", []):
            if x.get("requirement") not in d01_registry: problems.append(f"normative_audit structural source {x.get('section')} {x.get('locator')}: requirement {x.get('requirement')} is not a D01 registry row")
        by_sentence = {i for r in aud["sentences"] for i in r["requirements"]}
        by_structure = {x.get("requirement") for x in aud.get("structural_sources", [])}
        for rid in sorted(d01_registry - by_sentence - by_structure): problems.append(f"D01 registry row {rid} is named by no audit sentence and no structural source")
        for rid in sorted((by_sentence | by_structure) - d01_registry): problems.append(f"a source names {rid}, which is not a D01 registry row (was a row deleted?)")
        want_without = [rid for rid in doc["requirement_documents"]["D01"]["requirements"] if rid not in by_sentence]
        if aud.get("rows_without_audit_sentence") != want_without: problems.append(f"normative_audit: rows_without_audit_sentence disagrees with the rows ({len(aud.get('rows_without_audit_sentence') or [])} listed, {len(want_without)} recomputed)")
        # outside the audit: MAY / OPTIONAL only, re-extracted
        want_out = extract_outside(text)
        got_out = [(x.get("section"), x.get("text")) for x in aud.get("outside_audit", [])]
        if got_out != want_out: problems.append(f"normative_audit: outside_audit differs from the extraction ({len(got_out)} listed, {len(want_out)} extracted)")
        if aud.get("keywords") != ["MUST", "MUST NOT", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "REQUIRED", "RECOMMENDED"]: problems.append("normative_audit: keywords differ from the extractor's")

# 7. schema
try:
    import jsonschema
    jsonschema.validate(doc, json.load(open(os.path.join(HERE, "mapping.schema.json"))))
    schema_note = "schema: valid (jsonschema)"
except ImportError:
    schema_note = "schema: jsonschema package not installed; structural checks only"
except Exception as e:
    problems.append(f"schema: {str(e).splitlines()[0]}")
    schema_note = "schema: INVALID"

for p in problems: print("PROBLEM:", p)
print(schema_note)
print("snapshot:", COMMIT[:12], "| counts:", {k: c["vector_count"] for k, c in doc["corpora"].items()}, "| total", tot["mapped_or_deferred"], "| deferred", tot.get("deferred"))
print("RESULT:", "OK" if not problems else f"{len(problems)} problem(s)")
sys.exit(0 if not problems else 1)
