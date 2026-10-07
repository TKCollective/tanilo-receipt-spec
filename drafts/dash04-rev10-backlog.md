# -04 / rev 10 backlog: items noted, not applied

Opened 2026-10-06. Items for the next revision of the draft (-04) and of the evidence-pinning
corpus (rev 10). Nothing here changes the filed -03 text or the rev 9 corpus; rev 9's bytes and its
`0dffb77` pin stay as they are. Format follows `agentoracle-ietf-id/drafts/DASH03-QUEUE.md`.

## For -04 (spec text) and rev 10 (corpus)

1. **Presence rule for `resource_sha256_present_for_full_resource` (raised by robertolocatelli81-dev,
   tsc#4, 2026-10-06).**
   - The question: an entry has `content_kind: full_resource` and a non-null `resource_sha256` that
     is not 64 lowercase hex characters. Read literally, the general rule in -03 §5.4.1(a) would
     suppress `resource_sha256_present_for_full_resource`, because an input member failed its form
     check; the presence exemption names only `*_present_when_*` and `*_absent_when_*`. The
     account's implementation reports both conditions. No rev 9 vector covers the case.
   - The registry name for the form violation, quoted from -03 Section 5.3.2 and its registry table
     (`draft-krausz-verification-state-03.txt`, lines 922–924 and 1437): "A non-null value MUST be
     exactly 64 lowercase hexadecimal characters; reported condition on violation:
     resource_sha256_not_lowercase_hex64." and
     `| resource_sha256_not_lowercase_hex64        | 5.3.2   | malformed |`.
   - Proposed clarification (Joe Krausz, tsc#4, 2026-10-06, for review): the condition tests
     non-null presence, independently of the digest's form. With a valid `content_kind:
     full_resource` and a malformed non-null `resource_sha256`, both conditions are reported
     (`resource_sha256_present_for_full_resource` and `resource_sha256_not_lowercase_hex64`). A
     malformed `content_kind` still suppresses the dependent check.
   - Status on the thread, as reported (neither result has been independently rerun here):
     - babyblueviper1 changed his checker at `c64b41d` (2026-10-06) to report both conditions
       for a malformed non-null `resource_sha256` on a `full_resource` entry; reported 35/35
       passing with the new test (https://github.com/x402-foundation/tsc/issues/4#issuecomment-6025142483).
     - The robertolocatelli81-dev account confirmed that the proposed clarification matches its
       reading and that its implementation already behaves that way
       (https://github.com/x402-foundation/tsc/issues/4#issuecomment-6027722937, 2026-10-06). It
       reported four condition sets, measured with the code at
       robertolocatelli81-dev/evidence-record-cleanroom-verifier `2bdc3ae` on the complete object
       the harness builds from `evi-resource-sha256-with-full-resource-rejects` (its
       `evidence_root` carried), changing one member of the entry:
       1. `content_kind: full_resource` with a malformed non-null `resource_sha256` →
          `resource_sha256_present_for_full_resource` and `resource_sha256_not_lowercase_hex64`;
       2. an invalid `content_kind` with a well-formed `resource_sha256` →
          `content_kind_absent_or_invalid_when_pinned` only (the dependent check is suppressed);
       3. an invalid `content_kind` with a malformed `resource_sha256` →
          `content_kind_absent_or_invalid_when_pinned` and `resource_sha256_not_lowercase_hex64`;
       4. `full_resource` with `resource_sha256: null` → no condition; the step goes on to (b)
          and (d).
       The same account reported that babyblueviper1's checker at `3a7e6dc` gives the same four
       sets on the same objects, and offered to contribute the complete-object vector for case 1
       and the candidate-bytes cases.
     - Joe Krausz's reply (https://github.com/x402-foundation/tsc/issues/4#issuecomment-6030823657,
       2026-10-07): the contributions are welcome for review toward -04 / rev 10, separate from
       rev 9's bytes and pin; the filed -03 text is unchanged, and agreement on the clarification
       is not presented as removing the ambiguity from the filed wording.
   - What -04 should do: explicit text for the presence rule in §5.4.1(a).
   - What rev 10 should do: complete-object vectors (not fragments) for the four combinations
     above, each with its exact expected condition set. The malformed-`content_kind` control
     (case 2) uses a well-formed `resource_sha256`, so that it isolates suppression of the
     dependent check; case 3 is the separate vector where both members are malformed.
   - Sources: https://github.com/x402-foundation/tsc/issues/4#issuecomment-6023275339 (the
     question), #issuecomment-6024083056 (the proposed clarification),
     #issuecomment-6025142483 (babyblueviper1's change), #issuecomment-6027722937 (the
     confirmation and the four condition sets), #issuecomment-6030823657 (the reply).
2. **Resolution vectors with actual candidate content bytes (raised by robertolocatelli81-dev,
   tsc#4, 2026-10-06).**
   - The gap: `evi-step-resolves-affirmatively` and `evi-resolve-all-counts-absent-accepted` carry
     `content_matches: true`, not content bytes, so they do not exercise the digest comparison of
     §5.4.1(d). The account's harness takes the held digest from the vector, so a one-byte change to
     `snippet_sha256` on the first of them was not caught. Only `evi-content-mismatch-unknown`
     exercises the comparison. These two vectors should not be cited as coverage of hashing
     candidate content bytes.
   - What rev 10 should do: positive and negative vectors that carry the candidate content bytes
     themselves: a matching case (the bytes hash to the pinned `snippet_sha256`; the step resolves
     `resolved` with `content_matches`) and a changed-byte control (one byte differs; `content_differs`).
     Rev 9's existing vectors and bytes are preserved; new vectors are appended.
   - Sources: #issuecomment-6023275339 (the note), #issuecomment-6024083056 (the agreement).
3. **Eight proposed rev 10 vectors contributed by robertolocatelli81-dev (tsc#4, 2026-10-07; PR #11).**
   - The set: `evidence-pinning-rev10-proposed/proposed_vectors_presence_rule_candidate_bytes.json` at
     robertolocatelli81-dev/evidence-record-cleanroom-verifier `250c19d`
     (`250c19d03efb9934fcfc05965f1705f9fe8b96cc`), file sha256
     `d33638d9704a301c0387d92c6556190667a61e65e7d4d7142d9e0fae07350573`, offered under CC0 1.0 with
     its generator (`build.py`), runner (`run_vectors.py`), notice and frozen results, and opened as
     PR #11 of this repository (`fixtures/contrib/robertolocatelli81-dev-rev10-proposed/`, head
     `986068a`) at Joe Krausz's request (tsc#4, issuecomment-6039263779). The vector file, `build.py`
     and `run_vectors.py` in the PR are the same git blobs as at `250c19d`.
   - What it covers. Vectors 1–4 are the four complete-object combinations of item 1 above: vector 1
     (`evi-resource-sha256-malformed-with-full-resource-reports-both-rejects`) encodes the proposed
     presence-rule clarification, and the filed -03 wording stays ambiguous on that case; vector 2
     keeps `resource_sha256` well-formed so it isolates suppression of the dependent check. Vectors
     5–6 are the candidate-bytes matching case and changed-byte control of item 2; the bytes are
     carried as a fixture input (`input.verifier_holds_bytes_hex`, next to `input.evidence_set`, not a
     receipt field). Vectors 7–8 test -03 Section 5.3.2 as filed: a trailing `"\n"` in
     `snippet_sha256` (`snippet_sha256_not_lowercase_hex64`) or in `retrieved_at`
     (`retrieved_at_not_canonical_form`), with `evidence_root` recomputed over the members as
     carried, so a checker that accepts the value does not stop on the root either. The two cases
     come from babyblueviper1/preaction-governance-conformance#12 and babyblueviper1's proposal on
     tsc#4 (issuecomment-6034322483).
   - Reported by the contributor (Python 3.9.25, 3.11.2, 3.13.15): 8/8 with the account's
     `evidence-pinning-rev9/es_check_filed.py` at `250c19d` and 8/8 with babyblueviper1's
     `tools/evidence_set_check.py` at `bcf6592`; the pre-fix control, the same checker at `5c72428`,
     6/8, failing exactly vectors 7 and 8 (7 ends `unknown`, 8 ends `resolved`). Tetsurohhori
     reported the same three results on Python 3.10.12 and 3.11.15 (issuecomment-6038753338).
   - Rerun here, 2026-10-07 (Python 3.14.7, macOS; the two checkers taken from their repositories at
     the commits named): `SHA256SUMS` all OK; `build.py --check` byte-identical; `run_vectors.py`
     8/8 and 8/8; the control at `5c72428` 6/8, failing exactly vectors 7 and 8; the `--json` output
     equal to the frozen `results/` files apart from the interpreter version; every vector's
     `evidence_root` recomputed with `root()` of
     `fixtures/evidence-pinning-fixture-crosscheck-rev9.mjs`, 8/8. The limits the contributor states
     stand: both checkers were aligned on the tsc#4 thread, and vectors 7 and 8 were written after
     the `bcf6592` fix, so agreement between the two checkers is not evidence about the filed text.
   - Unchanged: rev 9's bytes (`fixtures/evidence-pinning-fixtures-v2-rev9.json`, sha256
     `3c5f4bf42d5e60c4e424d9a301f1efbfdffba642f2f7b80b2cec1727e0873724`), the `0dffb77` pin and the
     filed -03 text. The proposed vectors are not part of a released corpus.
   - What rev 10 should do: after review, take the eight vectors into the rev 10 corpus through the
     generator with attribution members, as rev 9 did for `contrib/babyblueviper1-open-issue-3/`,
     keeping vector 1 marked as the proposed clarification until -04 carries the text.
   - Sources: PR #11 (https://github.com/TKCollective/tanilo-receipt-spec/pull/11); tsc#4
     #issuecomment-6030823657 (the request for complete-object and candidate-bytes vectors),
     #issuecomment-6034322483 (the trailing-newline cases), #issuecomment-6038753338 (Tetsurohhori's
     reruns), #issuecomment-6039263779 (the request to open the PR).

## For -04, carried from the thread (already noted elsewhere)

- Section 10: record the rev 9 results reported on tsc#4 (babyblueviper1 47/47 at `8a7599f`
  against `0dffb77`; Tetsurohhori's reruns; robertolocatelli81-dev's second implementation at
  `2bdc3ae`, 47/47 outcome and named condition, 44/47 exact condition sets, with the report's disclosures).
  Details: `fixtures/evidence-pinning-fixture-README-rev9.md`, "Reported runs".

## Related work for -04

- Cite two execution-receipt drafts as complementary, not overlapping. Both record a tool call
  after it happened; this draft's receipt records the verification state of the premise before the
  action (the claim checked, the evidence pinned, the result signed). A -04 Related Work paragraph
  should say that each covers a different step and claim nothing about the other's.
  - AER-1, "A Portable Execution Receipt for AI Agent Tool Calls", `draft-zambo-aer1` (B. Zambo,
    Independent Submission, Informational). Revision -01 is dated 26 September 2026; the datatracker
    lists -12, dated 5 October 2026, as current on 2026-10-07. One tool call as a portable,
    independently checkable receipt: execution identity, time, the canonical bytes behind the output
    commitment, tool and caller scope, a provenance class, a stable public URL.
  - XAIP Receipts, "Signed Execution Receipts for AI Agent Tool Calls",
    `draft-xkumakichi-xaip-receipts-03` (xkumakichi, Independent Submission, Informational,
    2 July 2026). A signed per-call record (who acted, who delegated, which tool, outcome, duration,
    input and output identifiers) with Ed25519 over a JCS-canonicalized payload, optional caller
    co-signature over the same payload, and DIDs for identities.
