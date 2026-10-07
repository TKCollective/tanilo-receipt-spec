# Frozen results, 2026-10-07

Contributor's reported results, produced in this directory with `run_vectors.py --json` (unmodified from
`250c19d`). They are not results of this repository's tooling.

## Inputs

| object | commit | file | sha256 |
|---|---|---|---|
| vectors | robertolocatelli81-dev/evidence-record-cleanroom-verifier `250c19d03efb9934fcfc05965f1705f9fe8b96cc` | `proposed_vectors_presence_rule_candidate_bytes.json` | `d33638d9704a301c0387d92c6556190667a61e65e7d4d7142d9e0fae07350573` |
| checker "ours" | robertolocatelli81-dev/evidence-record-cleanroom-verifier `250c19d03efb9934fcfc05965f1705f9fe8b96cc` (file unchanged since `2bdc3ae`) | `evidence-pinning-rev9/es_check_filed.py` | `5addd30c86de64bc0000a2213ff8549cbe0d7375c210d6c8fa822f370f503f0c` |
| checker "bbv" | babyblueviper1/preaction-governance-conformance `bcf6592903abf6585cccf3a270312bc6ac99eb21` | `tools/evidence_set_check.py` | `598e42939c0f97a2987f5434332c3ce051125feae840bc8cb3f1905dd1705f53` |
| positive control | babyblueviper1/preaction-governance-conformance `5c7242878f8d105233a8f53248b52ee6499ac150` (before the fix for #12) | `tools/evidence_set_check.py` | `61d3cd64cb47316351d2af6652af46d242a987ded4b771e0b0925f2b691c918e` |

Interpreters: CPython 3.9.25, 3.11.2, 3.13.15 (Linux x86_64).

The three checker digests above, and the -03 text digest in `../README.md`, are of files outside this repository:
`verify-cited-digests.py` reports them as unresolved (as it does the -03 digest in the rev 9 README). They can be
checked with `git show <commit>:<file> | sha256sum` in the repositories named, and against
https://www.ietf.org/archive/id/draft-krausz-verification-state-03.txt. Every other digest cited in this directory
resolves to a file in it or to the rev 9 corpus.

## Commands and outcomes

```sh
python3 build.py --check                                   # byte-identical, exit 0 (all three interpreters)
python3 run_vectors.py --ours OURS --bbv BBV_bcf6592 --json  # exit 0 (all three)
python3 run_vectors.py --bbv BBV_5c72428 --json              # exit 1 (all three)
```

| file | passed | failing vectors |
|---|---|---|
| `ours-250c19d_bbv-bcf6592_python3.9.json` | ours 8/8, bbv 8/8 | none |
| `ours-250c19d_bbv-bcf6592_python3.11.json` | ours 8/8, bbv 8/8 | none |
| `ours-250c19d_bbv-bcf6592_python3.13.json` | ours 8/8, bbv 8/8 | none |
| `positive-control_bbv-5c72428_python3.9.json` | bbv 6/8 | 7 (`unknown`, `content_differs`, `content_matches`), 8 (`resolved`, `content_matches`, `content_matches`) |
| `positive-control_bbv-5c72428_python3.11.json` | bbv 6/8 | the same |
| `positive-control_bbv-5c72428_python3.13.json` | bbv 6/8 | the same |

Each file records the vector file's sha256 and the interpreter version in its `summary`. The three files of each
kind are identical apart from that version string.

Also checked, not stored here: the root carried by each vector agrees with `root()` from
`fixtures/evidence-pinning-fixture-crosscheck-rev9.mjs` (lines 1–185 unmodified, with a loop appended that calls
`root()` on each vector's `sources`; node v22.23.2): 8/8. With vector 7's root altered, the same loop reports a
mismatch on vector 7 and exits 1.
