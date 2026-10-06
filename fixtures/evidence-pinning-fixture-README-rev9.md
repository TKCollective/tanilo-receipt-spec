# evidence-pinning fixtures — v2 preimage, rev 9

**Status: cut 2026-10-02. One implementer has reported a run: babyblueviper1, 47/47 with his unchanged
checker (reported 2026-10-03). Tetsurohhori reran that same checker on three platforms (reported
2026-10-04): reruns, not a second implementation. See "Reported runs".**

Updated 2026-10-06. Changed: the status above, the new sections "Reported runs" and "Runner notes
(non-normative)", and the opening of "What is verified and what is not". Until this update the
status said that no implementer had run rev 9. The corpus, its generator, its cross-check, the
contributed file and the amendments document are byte-unchanged. Commit `0dffb77` of this
repository, which both reports pin, remains in its history, and the corpus file at the current head
is byte-identical to the one at that commit.

Forty-seven conformance vectors for the evidence-set step of
`draft-krausz-verification-state-03` (Sections 5.3 and 5.4.1; filed text sha256
`1d142b3effbfc612dca388567902f63823b45dcf69eece423e6b2b9a28dcbed9`). Rev 9 repairs the rev 8 corpus
where it conflicted with the filed text; it does not change the specification. The changes are
recorded as Findings 47–51 in `drafts/evidence-pinning-02-amendments-rev9-2026-10-02.md`.

Rev 8 stays as published: its generator, cross-check, corpus and README are byte-unchanged.

## Why rev 9 exists

babyblueviper1 ran his cold-built checker against the rev 8 corpus and reported 40 of 44 vectors
agreeing under five stated harness adaptations (H1 to H5), with all four disagreements coming from
one conflict: four positive fixtures omitted `snippet_sha256` on an unpinned entry, and the text
requires the member on every entry
(x402-foundation/tsc issue #4, 2026-09-29,
https://github.com/x402-foundation/tsc/issues/4#issuecomment-5881946061; run at
preaction-governance-conformance `8e98c0e`, `examples/evidence-set-cold/run_companion_corpus.py`).
The text stands; the corpus follows it.

## What changed against rev 8

Derived by diffing the two emitted files, not by reading the patch:

| | count | vectors |
|---|---|---|
| Byte-identical to rev 8 | 31 | — |
| `condition` identifier renamed, nothing else | 8 | see Finding 49 below |
| Input regenerated with an explicit `"snippet_sha256": null` | 5 | four under Finding 47, one under Finding 51 (that one is also renamed under Finding 49) |
| Added | 3 | see Findings 48 and 50 below |
| Removed | 0 | — |

The first 44 vectors keep their rev 8 order. Every `computed` value in rev 8 (all 26 roots and the
9 booleans) is unchanged in rev 9.

**Finding 47 — explicit null on four positive fixtures.** `snippet_sha256` is now present and null
on the unpinned entry of `evi-fully-pinned-fallback-derives-from-sources-accepted`,
`evi-root-present-pinned-count-absent-accepted`, `evi-unpinned-item-reason-content-not-held` and
`evi-unpinned-members-absent-accepted`. Two `expect` strings changed with it:
`evi-root-present-pinned-count-absent-accepted` now names the renamed condition, and
`evi-unpinned-members-absent-accepted` now says what it still tests — the omission of
`content_kind` on an unpinned entry, which remains equivalent to null. For `snippet_sha256`,
omission is no longer equivalent to null (this supersedes rev 6 Finding 30 for that member only).

**Finding 48 — one new negative vector.** `evi-snippet-sha256-member-absent-on-unpinned-rejects`
(MALFORMED, `snippet_sha256_member_absent`): an unpinned entry with a valid `unpinned_reason` and no
`snippet_sha256` member.

**Finding 49 — eight condition identifiers renamed to the -03 registry**, on nine vectors:

| rev 8 identifier | rev 9 identifier | vector(s) |
|---|---|---|
| `content_kind_absent_when_pinned` | `content_kind_absent_or_invalid_when_pinned` | `evi-content-kind-absent-when-pinned-rejects` |
| `snippet_digest_present_for_full_resource` | `resource_sha256_present_for_full_resource` | `evi-resource-sha256-with-full-resource-rejects`, `evi-full-resource-digest-on-unpinned-rejects` |
| `unpinned_reason_outside_domain` | `unpinned_reason_absent_or_invalid` | `evi-unpinned-reason-outside-domain-rejects` |
| `unpinned_without_reason` | `unpinned_reason_absent_or_invalid` | `evi-unpinned-without-reason-rejects` |
| `source_count_disagrees_with_sources` | `source_count_mismatch` | `evi-source-count-mismatch-rejects` |
| `pinned_count_disagrees_with_pinned_entries` | `pinned_count_mismatch` | `evi-count-inconsistency-rejects` |
| `root_present_with_zero_pinned` | `evidence_root_present_with_no_pinned_items` | `evi-root-with-zero-pinned-rejects` |
| `root_null_with_pinned_entries` | `evidence_root_absent_with_pinned_items` | `evi-nonzero-pinned-null-root-rejects` |

The old identifiers are published in `header.superseded_conditions` (ten entries: two from rev 8,
eight from rev 9), and both the generator and the cross-check fail the build if a vector names one.
The corpus still names fifteen distinct conditions: `unpinned_reason_outside_domain` and
`unpinned_without_reason` are now the single `unpinned_reason_absent_or_invalid` (minus one), and
`snippet_sha256_member_absent` is new (plus one).

**Finding 50 — two contributed vectors for the mixed pinned/unpinned pair**, written by
**babyblueviper1** and included under **CC0 1.0** with his stated expected outcomes:
`evi-duplicate-pinned-unpinned-pair-rejects` (halt, `duplicate_bound_tuple`) and
`evi-pinned-unpinned-same-url-distinct-time-accepted` (accepted; the step resolves `unknown`). His
file is vendored unmodified at `fixtures/contrib/babyblueviper1-open-issue-3/` with the notice and
the link to his CC0 statement; the generator reads the inputs, designations and `expect` strings
from it and pins its digest. The corpus adds only the `condition` member rev 7 Finding 33 requires
on a MALFORMED vector (the value his own `expect` string names) and the attribution members
(`contributed_by`, `license`, `source`); his checker's reported output is carried as
`contributed_checker_result`. This closes the gap the rev 8 README recorded ("no vector covers it").

**Finding 51 — explicit null on one MALFORMED vector.**
`evi-full-resource-digest-on-unpinned-rejects` omitted `snippet_sha256` on its unpinned entry, as in
rev 8, so a checker that reports every condition listed `snippet_sha256_member_absent` beside the
vector's named condition. Its entry now carries `"snippet_sha256": null`. After this the only vector
that omits the member on an unpinned entry is the one that exists to omit it (Finding 48), and the
generator and the cross-check both fail the build otherwise. The vector still breaks two rules under
-03, not one: testing the full-resource rule on an unpinned entry needs `content_kind:
full_resource` on that entry, which -03 Section 5.3.2 names `content_kind_present_when_unpinned`. A
report-all checker lists that beside `resource_sha256_present_for_full_resource`. The named
condition and the expected outcome (halt) are unchanged.

## H1–H5 comparability

The rev 8 run used five harness adaptations, stated in the header of `run_companion_corpus.py`.
Rev 9 is built so that the same five apply without edits:

- H1 (add `evidence_set_version` where absent), H2 (wrap a bare `entry` / `sources` fragment),
  H3 (inject the root where a vector omits it and is not about the root), H4 (`set_retrieved_at` →
  the set-level member): the 44 carried vectors keep their rev 8 fragment shapes, so these apply as
  before. The new negative vector is a bare `entry` fragment like its neighbours. The two
  contributed vectors are complete `evidence_set` objects and need none of the four.
- H5 (map rev 8 condition names to the -03 registry): the eight names it mapped are the eight
  Finding 49 renames, so under rev 9 the map has nothing left to rename and passes names through.

## Files

- `evidence-pinning-fixture-generator-rev9.py` — reference generator, the sole emitter of
  `evidence-pinning-fixtures-v2-rev9.json`. Needs
  `contrib/babyblueviper1-open-issue-3/proposed_vectors_open_issue_3.json` beside it.
- `evidence-pinning-fixture-crosscheck-rev9.mjs` — Node cross-check, same author. Recomputes every
  root and the census, re-derives the Finding 35–37 scope discrimination, rejects superseded
  identifiers, and checks Findings 47, 48, 50 and 51 on the shipped file. As in rev 8 it is **not a
  conformance verifier**: it does not evaluate whether a vector's input triggers its named condition
  in a real verifier, except where stated (the identity rule on the mixed pair; the member-absent
  entry really omitting the member).
- `evidence-pinning-fixtures-v2-rev9.json` — the emitted set.
- `contrib/babyblueviper1-open-issue-3/` — the two CC0 vectors as their author wrote them, and the notice.

## Counts (all derived from the emitted set; `header.census`)

| | rev 8 | rev 9 |
|---|---|---|
| Total vectors | 44 | **47** |
| Root-bearing vectors | 16 | **16** |
| Root values carried | 26 | **26** |
| `MALFORMED` | 20 | **22** |
| Remaining (all other designations) | 9 | **10** |
| Overlap (`MALFORMED` and root-bearing) | 1 | **1** |
| Distinct conditions named | 15 | **15** |
| Entry objects | 79 | **84** |
| Pinned entries | 62 | **64** |
| Unpinned entries | 17 | **20** |
| Vectors carrying ≥1 unpinned entry | 16 | **19** |

> **16 + 22 + 10 − 1 = 47.**

## Reproduce

Executed in a clean directory holding only the generator, the cross-check, the contributed file in
`contrib/babyblueviper1-open-issue-3/` and the rev 9 amendments document:

```
grep -o 'rev9_sha256="[a-f0-9]*"' evidence-pinning-fixture-generator-rev9.py
shasum -a 256 evidence-pinning-02-amendments-rev9-2026-10-02.md
python3 evidence-pinning-fixture-generator-rev9.py > evidence-pinning-fixtures-v2-rev9.json
node evidence-pinning-fixture-crosscheck-rev9.mjs --check evidence-pinning-fixtures-v2-rev9.json
```

The first two lines print the same value, `1b4be7f91cd76262e653e86d33828c796b21849474f6b66d7f14c8d6bf9d831c`.
Emission is deterministic across runs and byte-identical to the shipped file (`cmp`). The cross-check
exits 0 and reports:

```
"total_roots_checked": 26,
"roots_checked_raw_children": 24,
"roots_checked_hex_children": 1,
"roots_checked_leaf_raw_digest": 1,
"vectors_in_file": 47,
"mismatches": 0,
"all_agree": true
```

| Artifact | sha256 |
|---|---|
| `evidence-pinning-fixtures-v2-rev9.json` (50,336 bytes, 1,296 lines) | `3c5f4bf42d5e60c4e424d9a301f1efbfdffba642f2f7b80b2cec1727e0873724` |
| `evidence-pinning-fixture-generator-rev9.py` | `158d42204c37059868e9d22390a7412a805f3ea6d94b6651e25b27aea1be0608` |
| `evidence-pinning-fixture-crosscheck-rev9.mjs` | `f76ab869279247475fa9a9586159322a085790f7ce6925c781e58f02bf67c254` |
| `contrib/babyblueviper1-open-issue-3/proposed_vectors_open_issue_3.json` | `cc41da97113cab3e65d0aff0ef492d7e2799d7e43a335b5099a911364a3b792c` |
| `drafts/evidence-pinning-02-amendments-rev9-2026-10-02.md` | `1b4be7f91cd76262e653e86d33828c796b21849474f6b66d7f14c8d6bf9d831c` |

## The fail paths were exercised

Each mutation was applied to a copy of the shipped file and run through the cross-check:

| Mutation | Result |
|---|---|
| Restore the rev 7 name `pinned_set_empty` | exit 1 — names superseded condition |
| Restore the rev 8 name `root_present_with_zero_pinned` | exit 1 — names superseded condition |
| Drop the explicit null from a regenerated fixture | exit 1 — unpinned entry without an explicit null `snippet_sha256` (Finding 47) |
| Give the member-absent vector the member | exit 1 — its entry carries the member it exists to omit |
| Corrupt the contributed pair's `evidence_root` | exit 1 — not the root of its pinned entries |
| Give the mixed pair distinct `retrieved_at` | exit 1 — identity rule does not halt |
| Strip the attribution from a contributed vector | exit 1 — attribution members missing or changed |
| Set `header.census.malformed` to 21 by hand | exit 1 — file says 21, recomputed 22 |
| Drop the explicit null from `evi-full-resource-digest-on-unpinned-rejects` | exit 1 — MALFORMED vector other than the member-absent one omits `snippet_sha256` (Finding 51) |
| **None (shipped file)** | **exit 0, `all_agree: true`** |

## Reported runs

Added 2026-10-06. Both reports were posted on x402-foundation/tsc issue #4. They are recorded here
as their authors reported them. This repository did not produce them and has not re-executed them.

**babyblueviper1's run (reported 2026-10-03).**
https://github.com/x402-foundation/tsc/issues/4#issuecomment-5969811279

- Checker: preaction-governance-conformance at `8a7599f`, unchanged. This is the commit the local
  run described under "What is verified and what is not" used on 2026-10-02. He ran from fresh
  clones with nothing modified on either side, on Python 3.12.3, and posted the two file digests in
  abbreviated form: `run_companion_corpus.py` `23f1fec6…2c27c`, `tools/evidence_set_check.py`
  `d6a7c3a5…0bd6`.
- Corpus: this repository at `0dffb77` (`0dffb77fa117099438d5ec15fbb48b2311792d26`),
  `fixtures/evidence-pinning-fixtures-v2-rev9.json`. The sha256 he computed, `3c5f4bf4…73724`, is
  the value in the table under "Reproduce".
- Result: **rev 9, 47/47 agree.** Control: rev 8 from the same checkout, **40/44 agree**, with the
  same four vectors disagreeing as in his 2026-09-29 run.
- Transcript: the vector-by-vector output is committed in his repository at `be2a291`,
  https://github.com/babyblueviper1/preaction-governance-conformance/blob/be2a291/examples/evidence-set-cold/companion_corpus_rev9_run.txt
- Harness use on rev 9, as he reported it: H1 on 45 vectors, H2 on 27, H3 applied as stated in the
  script's header, H4 on 1, H5 on none.

This is a run of his cold-built checker by its author, against a corpus generated in this
repository. Two of the 47 vectors are his own contribution (Finding 50).

**Tetsurohhori's reruns (reported 2026-10-04).**
https://github.com/x402-foundation/tsc/issues/4#issuecomment-5985409120

These are reruns of the same checker, not a second implementation. By his account he wrote neither
the checker nor the corpus. He ran the unmodified code at the same two commits (checker `8a7599f`,
corpus `0dffb77`) with the network disabled and the repositories mounted read-only, on Python
3.12.15, and reported that the three digests matched the ones posted.

| Platform | rev 9 | rev 8 (control) |
|---|---|---|
| x86_64 glibc | 47/47 agree | 40/44 agree |
| x86_64 musl | 47/47 agree | 40/44 agree |
| s390x big-endian (qemu) | 47/47 agree | 40/44 agree |

He reported that the four rev 8 disagreements are the same four fixtures, and that the three
vectors which report a second condition do so as babyblueviper1 listed (see the runner notes
below). The limits he stated: he ran the harness and its readings as written and takes no position
on H1–H5, on the readings or on the open questions; he did not compare his output with the
committed transcript byte for byte; s390x ran under qemu, not on hardware.

**What the two reports amount to.** One checker, written by someone other than the corpus's author,
agrees with all 47 vectors under its stated harness (H1–H5), and that result was reproduced by a
second person on three platforms. They are not a second implementation, and they say nothing about
this corpus's own tooling, whose generator and cross-check still share an author.

**Two documents that say otherwise, and why they are not edited.**

- `drafts/evidence-pinning-02-amendments-rev9-2026-10-02.md` says that no implementer has run
  rev 9. That was true when it was written. The corpus pins that file's digest, so it stays as it
  is; this section is the correction.
- The corpus cross-check item in -03 Section 10 was filed before either report. -03 is filed text
  and is not changed. The result is planned to be recorded in -04's Section 10.

## Runner notes (non-normative)

Added 2026-10-06. These notes describe how one harness, babyblueviper1's `run_companion_corpus.py`
at `8a7599f`, gets from this corpus's vectors to the result reported above, so that another runner
does not have to reconstruct it from the issue thread. They are **not part of the corpus and not
normative**. They add no expectation and change none: a vector's expectation is what its
`designation`, `condition` and `expect` members say in `evidence-pinning-fixtures-v2-rev9.json`,
and that file is byte-unchanged. Nothing in this section is required of a verifier.

**H3: root injection.** A bare `entry` or `sources` fragment carries no `evidence_root`, and some
complete `evidence_set` vectors omit the member. As the script's header and code state, the harness
does this before it calls the checker:

- where a vector omits `evidence_root` and is not about the root, it computes the root over the
  vector's `sources` and adds the member;
- where a vector carries the member, as a value or as an explicit null, it keeps it as given;
- where the root cannot be computed from the fragment, it leaves the member absent.

A runner using this harness supplies nothing for H3; the harness applies it. Tetsurohhori reported
that his reruns needed only the two commit ids. A runner using a different harness has to do the
equivalent, or give its verifier complete `evidence_set` objects.

**A second condition on three vectors.** The checker reports every condition it finds. The harness
counts a MALFORMED vector as agreeing when the checker halts and the vector's named condition is
among those reported (H5 in the script's header, lines 15–16, and the code at line 86:
https://github.com/babyblueviper1/preaction-governance-conformance/blob/8a7599f/examples/evidence-set-cold/run_companion_corpus.py#L86).
In the reported run, three agreeing vectors reported a second condition beside the named one:

| Vector | Named condition (from the corpus) | Also reported in this run | Where the second one comes from |
|---|---|---|---|
| `evi-full-resource-digest-on-unpinned-rejects` | `resource_sha256_present_for_full_resource` | `content_kind_present_when_unpinned` | The vector's own input: its unpinned entry carries `content_kind` (Finding 51). Not a harness effect. |
| `evi-content-kind-absent-when-pinned-rejects` | `content_kind_absent_or_invalid_when_pinned` | `evidence_root_absent_with_pinned_items` | H3, as babyblueviper1 explains it (below). |
| `evi-snippet-sha256-absent-when-pinned-rejects` | `snippet_sha256_absent_when_pinned` | `evidence_root_absent_with_pinned_items` | H3, as babyblueviper1 explains it (below). |

For the last two, babyblueviper1's explanation is that H3 cannot compute a root over a pinned entry
that lacks a member the root commits to, so the root stays absent and the checker reports that as
well. He calls this a harness artifact, not a corpus defect, and states that a verifier given a
complete -03 object would report only the named condition. That last statement is his reading: no
run with complete objects has been reported, and none was made here. In his transcript neither
vector reports `root_not_recomputable_from_sources` (lines 16 and 21:
https://github.com/babyblueviper1/preaction-governance-conformance/blob/be2a291/examples/evidence-set-cold/companion_corpus_rev9_run.txt#L16-L21).

A runner comparing output with the transcript should expect two conditions on these three lines.
The second conditions are observations from one harness and one checker. They are not expected
outcomes, and this note does not decide whether a verifier may or must report them: the
expectation for each vector is the one the corpus file carries.

## What is verified and what is not

**Verified here (same-author tooling):** every root value and the census, recomputed by the Node
cross-check; the four regenerated fixtures and every other non-MALFORMED vector carry an explicit
null on unpinned entries; among MALFORMED vectors only the member-absent vector omits the member
on an unpinned entry (Finding 51); the member-absent vector omits the member and breaks no second rule; the
mixed pair halts under the whole-of-`sources` identity rule and not under a pinned-only reading; the
roots the two contributed vectors carry recompute; rev 8's files are byte-unchanged.

**A local run of someone else's checker, reported as that and nothing more.** On 2026-10-02 this
repository's maintainer ran babyblueviper1's unmodified `run_companion_corpus.py` and
`tools/evidence_set_check.py` (preaction-governance-conformance at `8a7599f`) locally: against the
rev 8 file it printed `40/44 agree`, the same four vectors he reported; against this rev 9 file it
printed `47/47 agree`. That is a local execution of his code by a party who wrote the corpus. It is
**not** his run and **not** an independent result.

**Reported by others, not verified here (added 2026-10-06).** babyblueviper1's run and
Tetsurohhori's reruns, as set out under "Reported runs". Until this update the list below opened by
saying that no implementer had run rev 9. That stopped being true on 2026-10-03, when
babyblueviper1 reported his run.

**Not verified:**

- **No second implementation has been run against rev 9.** One checker has been run against it: by
  its author, as reruns by one other person, and locally by this repository's maintainer (above). A
  rerun of the same checker is not another implementation.
- No independent from-text build of any revision of this corpus's tooling exists; the generator and
  the cross-check share an author (see the rev 8 README's independence disclosure, which still applies).
- These -03 registry conditions are not named as a vector's condition in this corpus:
  `evidence_set_not_object`, `evidence_set_version_absent_or_not_string`,
  `evidence_set_version_unsupported`, `fully_pinned_mismatch`, `sources_not_array`,
  `source_entry_not_object`, `url_absent_or_not_string`, `snippet_sha256_present_when_unpinned`,
  `snippet_sha256_not_lowercase_hex64`, `content_kind_present_when_unpinned`,
  `resource_sha256_not_lowercase_hex64`, `member_contains_nul`.
- That each MALFORMED vector triggers only its named condition. The cross-check does not evaluate
  this. In the local run described above, two fragment vectors also reported
  `evidence_root_absent_with_pinned_items`, and `evi-full-resource-digest-on-unpinned-rejects` also
  reported `content_kind_present_when_unpinned` (Finding 51). `content_kind_present_when_unpinned` is
  therefore triggered by one vector but named by none. babyblueviper1's reported run shows the same
  three vectors; they are named in the runner notes.
- Verifier-side resolution logic for the `UNKNOWN`, `ADDITIVE`, `COMPLETENESS` and `RESOLUTION`
  vectors, and the separate signature-key resolution step of -03 Section 5.4.2, which this corpus
  does not cover.
