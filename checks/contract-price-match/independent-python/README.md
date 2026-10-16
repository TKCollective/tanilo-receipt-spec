# contract-price-match/v0.1: an independent Python implementation

A second implementation of the rule in this folder, contributed by
[invinoveritas](https://invinoveritas.dev).

It was written from the rule text: this folder's README and
[tanilo.io/docs/contract-price-check](https://tanilo.io/docs/contract-price-check).
It was not written from `contract-price.js`. It uses the Python standard library only,
with no network, no clock and no randomness.

| File | What it is |
|---|---|
| `cpm.py` | The rule (`recompute`), the input schema check (`validate`) and RFC 8785 canonical JSON (`sha`). |
| `run_vectors.py` | Runs `cpm.py` against `../contract-price.vectors.json` and exits 0 only when every compared field agrees. |
| `RESULTS.txt` | The recorded output of `run_vectors.py`. |
| `LICENSE`, `NOTICE` | Apache License 2.0. |

## Run it

Needs Python 3.9 or later. Tested with Python 3.12.3.

```bash
python3 run_vectors.py
```

## What was tested

- Repository revision: `2596aa9` (main, 2026-10-16).
- Rule: `contract-price-match/v0.1`.
- Vectors: `contract-price.vectors.json`, SHA-256
  `7d73d07f0bcfe5dee348a30ac4a308b1eb1cb6d0bb5bf2192d6e6c378426a338`. This matches `SHA256SUMS`.
- `node contract-price.test.mjs` on the same checkout, Node 22.23.3: 82 cases, 547 assertions passed, 0 failed.

## Results

```
cases 82: state+reason 59/59, invalid member 23/23, digests 149/149
ALL AGREE
```

What is compared for each case:

- **Schema-invalid cases (23).** `validate` refuses the input and names the same member as the stored result.
- **All other cases (59).** `state` and `reason`, plus the digests the evidence carries:
  `offer_sha256`, `terms_sha256`, and the matched term's `term_sha256` when there is one.

What is not compared: the rest of the evidence object, meaning the `steps`, the
`expected` and `offered` blocks, and the reason texts.

## Scope

Agreement on these vectors means two implementations reach the same result from the
same supplied inputs. It does not show that any supplied terms are genuine, complete
or approved.
