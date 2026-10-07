# Proposed vectors toward -04 / rev 10: presence rule, candidate content bytes, trailing newline

Eight proposed complete-object vectors for the evidence-set step (draft-krausz-verification-state, Section 5.4.1),
contributed for review toward -04 and evidence-pinning rev 10. Origin, authorship and licence (CC0 1.0): see
`NOTICE.md`. The vector file, `build.py` and `run_vectors.py` are byte-identical to
robertolocatelli81-dev/evidence-record-cleanroom-verifier `250c19d`, `evidence-pinning-rev10-proposed/`.

**Rev 9 is unchanged.** This directory does not touch `fixtures/evidence-pinning-fixtures-v2-rev9.json`
(sha256 `3c5f4bf42d5e60c4e424d9a301f1efbfdffba642f2f7b80b2cec1727e0873724`), its generator, its README or its
`0dffb77` pin. Nothing here reads or writes the rev 9 corpus. The proposed vectors are not part of a released corpus.

## What each vector rests on

The filed -03 text (https://www.ietf.org/archive/id/draft-krausz-verification-state-03.txt, sha256
`1d142b3effbfc612dca388567902f63823b45dcf69eece423e6b2b9a28dcbed9`) is not changed by this directory.

- **Vector 1 exercises a clarification proposed for -04.** The filed -03 wording remains ambiguous on this case:
  the presence exemption in Section 5.4.1(a) names `*_present_when_*` and `*_absent_when_*`, not
  `resource_sha256_present_for_full_resource`, and read literally the general rule there would leave only
  `resource_sha256_not_lowercase_hex64`. Vector 1 encodes the clarification proposed on tsc#4
  (issuecomment-6024083056, 2026-10-06): "this condition tests non-null presence, independently of the digest's
  form. With a valid content_kind: full_resource and a malformed non-null resource_sha256, both conditions would be
  reported. A malformed content_kind would still suppress the dependent check."
- **Vectors 7 and 8 test form requirements of the filed -03 text**, Section 5.3.2: `snippet_sha256` is malformed when
  it is "not exactly 64 lowercase hexadecimal characters"; `retrieved_at` "MUST be in UTC with the Z designator and
  exactly three fractional-second digits". Each value carries one trailing `"\n"`.
- Vectors 2–6 rest on the -03 sections named in each vector's `basis` member. Vector 3's `basis` also quotes the
  second half of the proposed clarification; its expected set is the same under the literal reading of 5.4.1(a),
  because the invalid `content_kind` suppresses the presence check under either reading. Vector 2 is likewise the
  same under both readings.

## The vectors

Every vector is a complete `evidence_set` (version, set-level `retrieved_at`, `source_count`, `pinned_count`,
`fully_pinned`, `evidence_root`, `sources`), so no harness step (H1–H4) is needed. Vectors 1–4 start from the entry
of rev 9 `evi-resource-sha256-with-full-resource-rejects`, vectors 5–8 from the two entries of rev 9
`evi-step-resolves-affirmatively`; the digests are sha256("alpha") and sha256("beta"), as in the rev 9 generator.

| # | id | entry | expected |
|---|---|---|---|
| 1 | `evi-resource-sha256-malformed-with-full-resource-reports-both-rejects` | `full_resource`, `resource_sha256` in uppercase hex | halt; exactly {`resource_sha256_present_for_full_resource`, `resource_sha256_not_lowercase_hex64`} |
| 2 | `evi-content-kind-invalid-suppresses-full-resource-check-rejects` | `content_kind` `"Full_Resource"`, well-formed `resource_sha256` | halt; exactly {`content_kind_absent_or_invalid_when_pinned`} |
| 3 | `evi-content-kind-invalid-resource-sha256-malformed-rejects` | `"Full_Resource"`, uppercase `resource_sha256` | halt; exactly {`content_kind_absent_or_invalid_when_pinned`, `resource_sha256_not_lowercase_hex64`} |
| 4 | `evi-resource-sha256-null-with-full-resource-accepted` | `full_resource`, `resource_sha256: null`, no content held | no condition; per-item `content_not_held`; `unknown` |
| 5 | `evi-candidate-bytes-match-resolves` | two pinned entries, bytes `alpha` and `beta` held | no condition; per-item `content_matches`, `content_matches`; `resolved` |
| 6 | `evi-candidate-bytes-one-byte-changed-unknown` | as 5, bytes for item a are `alphA` (offset 4, 0x61 → 0x41) | no condition; MUST NOT halt; per-item `content_differs`, `content_matches`; `unknown` |
| 7 | `evi-snippet-sha256-trailing-newline-rejects` | as 5, item a's `snippet_sha256` + `"\n"`, root recomputed | halt; exactly {`snippet_sha256_not_lowercase_hex64`} |
| 8 | `evi-retrieved-at-trailing-newline-rejects` | as 5, item a's `retrieved_at` = `"2026-09-01T12:00:00.000Z\n"`, root recomputed | halt; exactly {`retrieved_at_not_canonical_form`} |

In vectors 7 and 8 the root is recomputed over the members as carried, so a checker that accepts the value does not
stop on the root either: it reaches (d) and ends `unknown` (vector 7) or `resolved` (vector 8). That is what the
positive control below shows.

## Members added to the rev 9 vector format

- `input.verifier_holds_bytes_hex` (object, url → lowercase hex of the candidate bytes) is **a fixture input, not a
  receipt field**. It sits next to `input.evidence_set`, not inside it; it describes the bytes the verifier holds
  when it runs step (d), and it is not proposed as a member of a receipt or of an `evidence_set`. Rev 9 carries
  `verifier_holds_bytes_for` with `content_matches: true` or `verifier_recomputed_sha256`, so no rev 9 vector carries
  bytes. A runner decodes the hex and computes SHA-256 itself; `computed.candidate_sha256` is informational and must
  not be fed to a checker.
- `expected_conditions` (array): the exact condition set, compared as a set. `condition` is kept, as in rev 9, on
  MALFORMED vectors.
- `expected_token` and `expected_item_reasons` (in `sources` order) on vectors that do not halt.
- `basis`: the sections each expectation rests on.

## Results (frozen in `results/`)

Measured 2026-10-07 from this directory, on Python 3.9.25, 3.11.2 and 3.13.15; outputs identical apart from the
interpreter version. Commands, checker hashes and files: `results/RESULTS.md`.

| checker | result |
|---|---|
| robertolocatelli81-dev/evidence-record-cleanroom-verifier `250c19d`, `evidence-pinning-rev9/es_check_filed.py` (sha256 `5addd30c…0f3c`) | 8/8 |
| babyblueviper1/preaction-governance-conformance `bcf6592`, `tools/evidence_set_check.py` (sha256 `598e4293…5f53`) | 8/8 |
| positive control: the same checker at `5c72428`, before the fix for #12 (sha256 `61d3cd64…918e`) | 6/8: vector 7 ends `unknown` (`content_differs`, `content_matches`), vector 8 `resolved` |

`build.py --check` rebuilds the vector file byte-identically on all three interpreters.

Reported by others, not run by the contributor:

- Tetsurohhori, same set at `250c19d`, both checkers unmodified: 8/8 and 8/8 on Python 3.10.12 and 3.11.15, and the
  positive control at `5c72428` 6/8 on 3.10.12, failing exactly vectors 7 and 8
  (https://github.com/x402-foundation/tsc/issues/4#issuecomment-6038753338).
- babyblueviper1, the earlier six-vector set at `c554e4e` (sha256 `43c3c928…fba2e`) with the checker at `bcf6592`:
  6/6 on Python 3.12.3 (https://github.com/x402-foundation/tsc/issues/4#issuecomment-6034322483).

Limits. The two checkers are not independent of the tsc#4 thread: both were aligned to the readings discussed there.
babyblueviper1's checker reports both conditions on vector 1 since `c64b41d`, and passes vectors 7 and 8 since
`bcf6592`, after #12 was reported; vectors 7 and 8 were built after that fix. Agreement between the two checkers is
agreement between two implementations, not evidence about the filed text.

## How to rerun

```sh
cd fixtures/contrib/robertolocatelli81-dev-rev10-proposed
sha256sum -c SHA256SUMS
python3 build.py --check
git clone https://github.com/robertolocatelli81-dev/evidence-record-cleanroom-verifier /tmp/ours
git -C /tmp/ours checkout 250c19d
git clone https://github.com/babyblueviper1/preaction-governance-conformance /tmp/bbv
git -C /tmp/bbv checkout bcf6592
python3 run_vectors.py --ours /tmp/ours/evidence-pinning-rev9/es_check_filed.py \
                       --bbv /tmp/bbv/tools/evidence_set_check.py
# positive control: expected 6/8, exit 1, vectors 7 and 8 failing
git -C /tmp/bbv checkout 5c72428
python3 run_vectors.py --bbv /tmp/bbv/tools/evidence_set_check.py
```

`run_vectors.py` exits 0 only if every vector passes for every checker given, and 1 if any fails. It exits 2 when the
vector file cannot be read or is not a non-empty JSON array of objects carrying `id`, `designation` and `input`, or
carries a duplicate key or a non-finite number; a checker that cannot be loaded, or no checker at all, is also exit 2.
Any other error (for example a vector without `expected_conditions`) stops the run with a traceback and exit 1: no
error path exits 0. Add `--json` for the per-vector output stored in `results/`. Both scripts are stdlib only.
