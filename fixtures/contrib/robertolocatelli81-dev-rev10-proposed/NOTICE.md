# Contributed vectors: proposed rev 10 set (presence rule, candidate content bytes, trailing newline)

The files in this directory were written by **robertolocatelli81-dev** (Noûs, an AI agent operating under a
revocable mandate from Roberto Locatelli, who reviews and is accountable for them) and are contributed for review
toward draft-krausz-verification-state-04 / evidence-pinning rev 10, as requested on x402-foundation/tsc issue #4
(https://github.com/x402-foundation/tsc/issues/4#issuecomment-6030823657 and
https://github.com/x402-foundation/tsc/issues/4#issuecomment-6039263779, both 2026-10-07).

Three files are copied unmodified from `robertolocatelli81-dev/evidence-record-cleanroom-verifier`, commit
`250c19d`, folder `evidence-pinning-rev10-proposed/`
(https://github.com/robertolocatelli81-dev/evidence-record-cleanroom-verifier/tree/250c19d/evidence-pinning-rev10-proposed):

- `proposed_vectors_presence_rule_candidate_bytes.json` — the eight proposed vectors
  (sha256 `d33638d9704a301c0387d92c6556190667a61e65e7d4d7142d9e0fae07350573`);
- `build.py` — the deterministic generator of that file (stdlib only; `--check` rebuilds it and compares bytes);
- `run_vectors.py` — a control runner that runs the vectors against one or more checkers.

`README.md` and this `NOTICE.md` were rewritten for this repository; `results/` and `SHA256SUMS` are new.

Vectors 7 and 8 encode the two cases of babyblueviper1/preaction-governance-conformance#12, in the form
babyblueviper1 proposed on x402-foundation/tsc#4
(https://github.com/x402-foundation/tsc/issues/4#issuecomment-6034322483).

**Licence: CC0 1.0 Universal (public-domain dedication)** for every file in this directory.
CC0 text: https://creativecommons.org/publicdomain/zero/1.0/legalcode
The rest of this repository keeps its own licence.

Status. These are proposed vectors. They are not part of a released corpus, they are separate from rev 9 (the rev 9
corpus, its bytes and its `0dffb77` pin are unchanged), and adding or reviewing this directory does not change the
filed -03 text. The results in `results/` are the contributor's reported results, produced with the contributor's
own checker (`evidence-pinning-rev9/es_check_filed.py` of the repository above) and with babyblueviper1's
(`tools/evidence_set_check.py` at `bcf6592`, and at `5c72428` as the positive control). They are not results of this
repository's tooling.
