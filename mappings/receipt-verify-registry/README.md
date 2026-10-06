# Vector → requirement mapping (receipt-verify registry, methodology §2.7)

`mapping.json` states, for each published conformance vector in this repository
at commit `cbba94b7576cf2aec08c70aeb2899fdfa4d35c66`, which normative
requirement it exercises and whether the corresponding assertion is actually
executed by a published checker (**forward view**), and, for each in-scope
requirement, which vectors exercise it or that none does (**reverse view**).
It is written for the receipt-verify registry's axis §2.7 (*Vector requirement
mapping*, methodology v0.4.5 draft, unchanged from v0.4.1) and follows its
procedure: mapped vectors exist in the corpus, and requirements no vector
exercises are listed. The requirement identifiers are this mapping's own labels
for sentences in the cited texts at the recorded revision (none of the
specifications numbers its requirements); each label carries the sentence it
stands for, so a reader can check it against the text. Where a rule was amended
after the review draft, the identifier names the amending finding.

Revision 3 (2026-10-06) applies Michael Msebenzi's re-check of `91e66a7`;
revision 2 (2026-10-01) applied his review of `b1da800`. The changes are listed
under *What changed in revision 3* and *What changed in revision 2* below.

## Corpora

| Corpus | Manifest | Vectors | Normative | Requirement texts |
|---|---|---|---|---|
| `v0.3-composed` | `examples/v0.3-composed/vectors.json` | 11 | yes | `draft-krausz-verification-state-01`; README "Mycelium Trails" at `196df22b` |
| `v0.4-composed` | `examples/v0.4-composed/vectors.json` | 3 | yes | same |
| `evidence-pinning-rev8` | `fixtures/evidence-pinning-fixtures-v2-rev8.json` | 44 (FINAL) | yes | the evidence-pinning section: review draft + amendments rev5–rev8 at the digests the fixture header pins; rev2 and rev4 at this commit (digests recorded) |
| `rule2` | `conformance/vectors-rule2.json` | 9 | **NOT NORMATIVE** (the manifest's own label) | mapping `agentoracle-v0.3-2026-05-30`; `-01` §5 |
| `leaf-screen-halt` | `examples/conformance/delegation-chain-ref/leaf-screen-halt/vectors.json` | 1 | yes | deferred: its requirement text is third-party (`delegation-chain-ref-v1`) |

Every manifest and every evidence-pinning draft is read at the snapshot commit
with `git show`, never from the working tree. Not counted: the 7 vectors on the
unmerged v0.4 branch; the rev5–rev7 fixture files (superseded by rev8).

## Coverage vocabulary

Coverage is recorded only where an assertion is actually executed:

- **covered** — executed by a checker published with the corpus against the shipped file;
- **partial** — declared in the manifest and executed only by the emitter that produced it or by an external run, or the checker exercises part of the requirement;
- **not covered** — no executed assertion.

The reverse view takes the best coverage any vector gives a requirement within
the corpora it names. The rev8 cross-check
(`fixtures/evidence-pinning-fixture-crosscheck-rev8.mjs`) is, in its own
README's words, *not a conformance verifier*: it checks roots, census and
condition identifiers, so it can give *covered* only to root-construction rules
and to the four rev8 discriminating vectors; every halt or `unknown` expectation
is *partial* (executed by the emitter and by an external run) or *not covered*.
Requirements that live only in third-party texts (`action-ref-v1`,
`delegation-chain-ref-v1`, the Mycelium Provider protocol) are listed under
`external_documents` and never counted as coverage of the in-scope texts.

## Every vector is linked or deferred

Every vector carries at least one in-scope requirement link, or an explicit
`status: "deferred"` with a `reason`. Four vectors are deferred: `comp-r05` and
`comp-r06` (the decisive rule is third-party, `delegation-chain-ref-v1`),
`d1-no-receipt` (a service-level rule, not a format requirement; its runner
skips it) and `leaf-screen-halt` (third-party text). The schema and the
validator both enforce the rule.

A link must also point into a document the vector's own corpus names in its
`requirement_documents`. A `v0.3-composed` vector may link to `-01` and to the
README section, and not to the evidence-pinning text; the validator rejects a
link to a document the corpus does not name.

## Two counts for `-01`

The `rule2` set keeps its manifest's NOT NORMATIVE label, so the reverse view
for `-01` reports two counts over its 58 requirements:

| Count | Corpora | covered | partial | not covered |
|---|---|---|---|---|
| all corpora (`summary`) | v0.3-composed, v0.4-composed, rule2 | 10 | 6 | 42 |
| excluding NOT NORMATIVE (`summary_excluding_not_normative`) | v0.3-composed, v0.4-composed | 3 | 5 | 50 |

Each row also carries `coverage_excluding_not_normative`. The rows that differ
between the two counts are the §5.1 table rows 1–6 and the two §5.2 rules that
only `rule2` exercises.

The second count is required, not optional: a view whose scope includes a NOT
NORMATIVE corpus must publish `summary_excluding_not_normative` (naming exactly
the normative corpora of its scope) and `coverage_excluding_not_normative` on
every row, and the validator and the schema reject a view that lacks them. The
view for the mapping document (`MAP`) is exercised only by `rule2`, so its
second count names no corpus and reads 0 covered, 0 partial, 9 not covered.

## Finding 1: `typ`

`-01` §4.1 names `typ: verification-receipt+jws`. The v0.3 fixtures use
`application/vnd.verification.v0.3+composed+jws` and the v0.4 fixtures (all 12
protected headers) use `application/vnd.verification.v0.4+composed+jws`;
neither matches `-01` §4.1, and no published checker asserts `typ`. The
requirement `D01-4.1-typ` is *not covered* and carries this note.

## Normative audit of `-01` §§3–7, 9, 10

**Scope.** The audit covers the sentences of the cited `-01` text in sections
3–7, 9 and 10 that carry one of these keywords: MUST, MUST NOT, SHALL, SHALL
NOT, SHOULD, SHOULD NOT, REQUIRED, RECOMMENDED. It does not claim to cover
every normative statement. Statements that carry only MAY or OPTIONAL are
outside it. There are six in these sections, listed in `mapping.json` under
`normative_audit.outside_audit`: the §5.2 sentence that relying parties MAY
require a higher threshold mapping; the four OPTIONAL provenance claims of §4.2
(`v_method`, `v_calibration`, `v_sources_used`, `v_evidence`); and the
`v_evidence.valid_until (OPTIONAL)` row of Table 3 in §6.1.

**Sentences.** `normative_audit.py` extracts the keyword sentences;
`mapping.json` lists all 55 under `normative_audit.sentences`, each mapped to
one or more requirement identifiers. A sentence the text breaks across a page
is listed whole (sentence 27 runs across the page 10 break and ends "a new
mapping version with a new ID."). Like the reverse view, the audit reports two
counts:

| Count | Corpora | exercised | unexercised |
|---|---|---|---|
| all corpora (`summary`) | v0.3-composed, v0.4-composed, rule2 | 10 | 45 |
| excluding NOT NORMATIVE (`summary_excluding_not_normative`) | v0.3-composed, v0.4-composed | 8 | 47 |

Sentences 27 and 28 (both §5.2) are exercised only through `rule2`. A sentence
is exercised when at least one of its requirements has coverage covered or
partial in the corresponding count.

**Rows no sentence names.** Fourteen of the 58 `-01` rows are not named by any
keyword sentence, because the text states them as a list item, a numbered step
or a table row: `typ` in §4.1; steps 1 and 3–7 of §4.3; and the seven rows of
Table 2 in §5.1. `normative_audit.structural_sources` records the source of
each: the extractor reads the `typ` item, all eight §4.3 steps and all seven
Table 2 rows from the cited bytes (16 items; steps 2 and 8 are also named by
sentences), each with the one registry row that stands for it.
`rows_without_audit_sentence` lists the fourteen. Every `-01` row must be named
by at least one sentence or one structural source, and every row a source names
must exist, so deleting a row fails validation.

The generator refuses to run if a sentence or a structural item is unassigned.
The validator requires the audit source to be the digest-checked `-01` cited
text (same path as `cited_texts.D01`, bytes hashing to the recorded digest; a
missing or mismatched source is a hard failure, never a skip), re-extracts the
sentences, the structural sources and the outside-audit list from those bytes,
and fails if any list differs.

Obligations added in revision 2 from this audit:
`D01-4.1-iana-alg` (§4.1 SHOULD follow the IANA JOSE Algorithms registry),
`D01-6.1-reject-expired` (§6.1 table: MUST reject expired signatures),
`D01-9.1-no-mask-env-halt` (§9.1 MUST NOT mask an environment.* HALT),
`D01-9.1-env-terminal-first` (§9.1 MUST evaluate environment.* to its
terminal state first; SHALL NOT reach a verification.* state otherwise) and
`D01-9.2-unverifiable-mapping-hash-malformed` (§9.2 a relying party that
cannot verify the mapping hash MUST treat the receipt as malformed), each with
cross-references to the rows it overlaps; `D01-4.6-mapping-immutable` and
`D01-9.2-mapping-tampering` now carry the full sentence text.

## Cited bytes

`cited/` holds the bytes the `-01` and mapping-document digests are computed
over: `draft-krausz-verification-state-01.txt` (fetched 2026-10-01 from
`https://www.ietf.org/archive/id/draft-krausz-verification-state-01.txt`) and
`agentoracle-v0.3-2026-05-30.json` (fetched 2026-10-01 from
`https://agentoracle.co/mappings/agentoracle-v0.3-2026-05-30.json`). The
generator and the validator both recompute the recorded digests from these
files; the recorded values are not copied from anywhere else.

## Files

- `mapping.json` — the mapping.
- `mapping.schema.json` — JSON Schema (2020-12) for it; requires every vector to carry a requirement link or a deferral with a reason, the second count on the views that include `rule2`, and the audit's second count, structural sources and outside-audit list.
- `generate_mapping.py` — builds `mapping.json` from the manifests at the snapshot commit (`git show`); every count comes from the files, and the mapping judgments and the audit assignments are the tables in this script.
- `validate_mapping.py` — independent checks: manifests read at `corpus_snapshot.commit`, counts and ids, identifiers against the registry, link-or-defer per vector, every link checked against the linking corpus's own `requirement_documents`, the reverse view required to EQUAL the forward view scoped to the corpora each view names, the second count required wherever a view's scope includes a NOT NORMATIVE corpus, digests recomputed from the cited bytes and from the snapshot, the normative audit, its structural sources and its outside-audit list re-extracted, both audit counts recomputed, and the schema (when `jsonschema` is installed). Takes `--mapping PATH`.
- `normative_audit.py` — the extractor shared by the two scripts: keyword sentences, structural sources, and the MAY/OPTIONAL-only items.
- `negative_controls.py` — seventeen broken copies the validator must reject, plus the real file it must accept. Seven from revision 2 (an unlinked vector; zeroed `-01` and mapping digests; a wrong snapshot commit; a missing audit source, alone, with an unassigned sentence and with a deleted audit row; an audit source whose bytes do not match the recorded digest). Ten from revision 3, each required to fail on the named rule and not merely to exit non-zero: `comp-001` relinked only to `EP-4.1.2-canonical-order`; the second count removed from the `-01` view, from one row, and from the `MAP` view; row `D01-4.1-typ` deleted, alone and with its structural source; the audit's second count altered; sentence 27 cut at the page break; an outside-audit item removed; a structural source's text altered. The first three kinds are Michael Msebenzi's mutations from his re-check; each is made self-consistent (the reverse view is recomputed after the change) so that only the rule under test can catch it.
- `cited/` — the cited bytes (above).

```
python3 mappings/receipt-verify-registry/generate_mapping.py
python3 mappings/receipt-verify-registry/validate_mapping.py
python3 mappings/receipt-verify-registry/negative_controls.py
```

## What changed in revision 3

After Michael Msebenzi's re-check of `91e66a7`. No count published at `91e66a7` changes: the vector counts, the totals, all four reverse views (summaries, per-row coverage, hits), the `-01` second count (3 / 5 / 50), the registry, the forward view and the audit's all-corpora count (10 / 45) are identical. What is new is listed here.

1. Validator: every requirement link is checked against the linking corpus's own `requirement_documents`; a link to a document the corpus does not name fails.
2. The second count is required wherever a view's scope includes a NOT NORMATIVE corpus (validator and schema). The `MAP` view therefore gains one: no normative corpus, 0 / 0 / 9.
3. The fourteen `-01` rows no audit sentence names carry a recorded source (list item, numbered step or table row), extracted from the cited bytes; rows are validated against sentences plus sources, so deleting a row fails.
4. The audit summary reports two counts: all corpora 10 exercised / 45 not; excluding `rule2` 8 / 47 (sentences 27 and 28 are exercised only through `rule2`).
5. Audit sentence 27 is completed across the page break ("...a new mapping version with a new ID."). No other sentence text changes.
6. The scope line is narrowed from "every normative statement" to the eight keywords the audit uses, and the six MAY/OPTIONAL-only items of §§3–7, 9, 10 are listed as outside the audit.

Negative controls added for each of his three mutations and for items 4 to 6.

## What changed in revision 2

1. Reverse view for `-01` reports two counts: all corpora, and excluding `rule2` (NOT NORMATIVE).
2. Finding 1 recorded on `D01-4.1-typ` with the fixtures' actual `typ` values.
3. Omitted `-01` obligations added (§4.1 IANA registry, §9.1 no-mask and terminal-first, §6.1 reject expired, §9.2 unverifiable hash → malformed), cross-referenced; full re-audit of §§3–7, 9, 10 published as `normative_audit`.
4. Every vector linked or explicitly deferred with a reason (schema + validator); `comp-r05`, `comp-r06`, `d1-no-receipt` made explicit deferrals.
5. Validator recomputes the `-01` and mapping-document digests from the cited bytes and reads the corpus at `corpus_snapshot.commit` via `git show`, not the working tree; negative controls added.
