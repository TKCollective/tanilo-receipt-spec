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

## For -04, carried from the thread (already noted elsewhere)

- Section 10: record the rev 9 results reported on tsc#4 (babyblueviper1 47/47 at `8a7599f`
  against `0dffb77`; Tetsurohhori's reruns; robertolocatelli81-dev's second implementation at
  `2bdc3ae`, 47/47 outcome and named condition, 44/47 exact condition sets, with the report's disclosures).
  Details: `fixtures/evidence-pinning-fixture-README-rev9.md`, "Reported runs".
