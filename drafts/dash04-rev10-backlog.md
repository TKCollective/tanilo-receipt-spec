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
     check; the presence exemption names only `*_present_when_*` and `*_absent_when_*`. His checker
     reports both conditions. No rev 9 vector covers the case.
   - Proposed clarification (Joe Krausz, tsc#4, 2026-10-06, for review): the condition tests
     non-null presence, independently of the digest's form. With a valid `content_kind:
     full_resource` and a malformed non-null `resource_sha256`, both conditions are reported
     (`resource_sha256_present_for_full_resource` and `resource_sha256_not_lowercase_hex64`). A
     malformed `content_kind` still suppresses the dependent check.
   - Status on the thread: babyblueviper1 changed his checker to report both at `c64b41d`
     (2026-10-06), matching the proposed clarification and robertolocatelli81-dev's checker.
     Whether the reading is settled for the text awaits robertolocatelli81-dev's answer to the
     question put to him.
   - What -04 should do: explicit text for the presence rule in §5.4.1(a).
   - What rev 10 should do: a complete-object vector (not a fragment) with `content_kind:
     full_resource` and a malformed non-null `resource_sha256`, with the exact expected condition
     set stated; and a control with a malformed `content_kind`, where only the `content_kind`
     condition is expected.
   - Sources: https://github.com/x402-foundation/tsc/issues/4#issuecomment-6023275339 (the
     question), #issuecomment-6024083056 (the proposed clarification),
     #issuecomment-6025142483 (babyblueviper1's change).
2. **Resolution vectors with actual candidate content bytes (raised by robertolocatelli81-dev,
   tsc#4, 2026-10-06).**
   - The gap: `evi-step-resolves-affirmatively` and `evi-resolve-all-counts-absent-accepted` carry
     `content_matches: true`, not content bytes, so they do not exercise the digest comparison of
     §5.4.1(d). His harness takes the held digest from the vector, so a one-byte change to
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
  `2bdc3ae`, 47/47 outcome and named condition, 44/47 exact condition sets, with his disclosures).
  Details: `fixtures/evidence-pinning-fixture-README-rev9.md`, "Reported runs".
