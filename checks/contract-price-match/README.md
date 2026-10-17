# Contract price check: the rule, its tests and its vectors

`contract_price_match` is a check type of Tanilo's `POST /v1/verify-facts`. It
answers one question: **does this offer match the terms the caller supplied?** More
exactly: does the offer's unit price equal the price in the one applicable term. No model is involved.

This folder holds the rule as the service runs it, so that anyone can replay a
check: same input, same rule, same result.

| File | What it is |
|---|---|
| `contract-price.js` | The rule, `contract-price-match/v0.1`. Pure: no network, no clock, no randomness. |
| `contract-price-jcs.js` | Canonical JSON (RFC 8785) for the values the rule hashes. |
| `contract-price.test.mjs` | The test suite: 97 cases, including the USD 2.00 against USD 1.00 example and 15 boundary cases (see the record at the end). |
| `contract-price.vectors.json` | Each case as an input and the exact result. Use it to check another implementation. |
| `SHA256SUMS` | SHA-256 of the four files above. |
| `LICENSE`, `NOTICE` | Apache License 2.0 and its notice, for the code and this README. |
| `LICENSE-vectors-CC0-1.0.txt` | CC0 1.0, for the vectors. |

## Run it

Needs Node and nothing else. Tested with Node 24.

```bash
node contract-price.test.mjs
```

It exits 0 only when every case passes and every stored vector equals what the
rule gives.

## Replay a check

Take the offer and the terms you sent, and call the rule:

```js
import { evaluateContractPrice } from "./contract-price.js";

const result = evaluateContractPrice({ offer, terms });
console.log(result.state, result.reason, result.evidence);
```

Compare `result.evidence` with the `evidence` of the `contract_price_match`
entry in the receipt's signed payload. They are equal when the input and the
rule are the same. The receipt also carries `offer_sha256` and `terms_sha256`,
so you can first confirm that the offer and terms you hold are the ones that
were checked.

Checking the receipt's signature is a separate step, done with
[`tanilo-receipt-verify`](https://pypi.org/project/tanilo-receipt-verify/). A
valid signature shows which key signed the receipt. It does not show that the
supplied terms were genuine.

## Three results

- `verified`: the offer's unit price equals the applicable term's price.
- `contradicted`: it differs, above or below. Expected, offered and the
  difference are recorded.
- `indeterminate`: the applicable price could not be established. A reason says
  why: `no_applicable_term`, `effective_interval_unresolved`,
  `precedence_unresolved`, `currency_mismatch`, `unit_mismatch` or
  `tier_selection_unresolved`. This is not a finding that the price is wrong.

Input that does not satisfy the schema gets no result at all. The rule returns
`{ invalid: true, path, message }`, and the service answers 422 without a
receipt. That is different from `indeterminate`, which records that the check
ran on valid input but could not establish an applicable price.

The service returns a result as a signed receipt when signing succeeds.

## The rule in order

The first step that cannot continue decides the reason. Later steps are not run.

1. **Scope.** Keep terms with the offer's seller whose product list contains the offer's product. Exact strings. None: `no_applicable_term`.
2. **Effective at the offer time.** `effective_from` ≤ `offered_at` < `effective_to`. The end is excluded. None: `effective_interval_unresolved`.
3. **Declared precedence.** A term is set aside when another term of the same agreement, itself in effect at the offer time, names its version in `supersedes`.
4. **Exactly one term.** More than one left: `precedence_unresolved`. Currency and unit are not used to choose between terms.
5. **Currency** of that term equals the offer's. Otherwise `currency_mismatch`. No conversion.
6. **Unit** of that term equals the offer's. Otherwise `unit_mismatch`. No conversion.
7. **Price for the quantity.** One price, or the tier where `min_quantity` ≤ quantity < `max_quantity`. No tier, or more than one: `tier_selection_unresolved`. The tier's unit price applies to the whole quantity.
8. **Compare** by exact decimal value. `"1"` equals `"1.00"`. No tolerance, no rounding.

Details that decide edge cases:

- **Amounts and quantities** are decimal strings: up to 18 digits, then optionally a point and 1 to 8 digits. The same limits apply to every amount and quantity: the offer's `unit_price` and `quantity`, a term's `price_per_unit`, and a tier's `min_quantity`, `max_quantity` and `price_per_unit`. No leading zeros: `"01.00"` is invalid; a value below 1 starts with a single `0`, as in `"0.50"`. A point must have digits on both sides: `"1."` and `".50"` are invalid. Input outside these forms is refused (no result), not rounded or re-read.
- **Times** are UTC and end in `Z`, with seconds and optionally 1 to 3 fractional digits. They are compared to the millisecond. A time with an explicit offset such as `+02:00` is unsupported by this Z-only schema. A leap second (`:60`) is invalid, as is any time that does not exist on the calendar.
- **`product_scope.skus`** must be a non-empty array of distinct product identifiers. An empty list and a repeated identifier are both invalid input (no result), not a scope that matches nothing.
- **`supersedes`** is a single string: the `version` of one term of the same `agreement_id`. A term can replace one version, not several. A term may not name its own version (invalid input). `supersedes: null` is treated as absent, exactly as if the member were left out. It has effect only while the superseding term is itself in effect at the offer time. When a superseding term has ended, the term it replaced applies again if it is still in effect. Precedence is not carried across a term that is not in effect: if version 3 replaces version 2 and version 2 replaced version 1, and version 2 has ended, versions 1 and 3 are both left and the result is `precedence_unresolved`.
- **Two terms whose dates do not both contain the offer time never compete.** Nothing replaces anything in that case; only the term in effect is considered.
- **`terms_sha256`** is the SHA-256 of the canonical JSON of the `terms` array in the order supplied. Member order inside an object does not matter; the order of the array does. **`offer_sha256`** and each **`term_sha256`** are over the canonical JSON of that object.

## What this does not establish

The terms are supplied by the caller. The check does not establish that they
are genuine, complete, validly executed or approved by anyone.

The caller translates an agreement into this model: one price per unit, or
prices selected by quantity. The check cannot detect pricing that the input
leaves out, such as a discount that was never mentioned. Fields it does not
support are refused when sent; pricing that is simply omitted may be
undetectable.

It makes no unit or currency conversion, applies no rounding, and calculates no
tax. A `verified` result does not authorize a payment.

## Versions

A change to what the rule returns for any input gets a new rule identifier.
The identifier in a receipt (`evidence.rule_id`) tells you which rule to
replay. This folder holds `contract-price-match/v0.1`.

Documentation: https://tanilo.io/docs/contract-price-check

## Record

**2026-10-17.** The 82-case result recorded by the independent Python implementation in `independent-python/` (run at repository revision `2596aa9`, vectors SHA-256 `7d73d07f…a338`: all 82 agree) stands as the historical measurement; that folder's `RESULTS.txt` and README are unchanged. Cases `cpm-083` to `cpm-097` were added on this date. They are the fifteen single-field changes from `cpm-001` listed by that implementation's author (babyblueviper1, in the discussion of pull request #12), with expected results produced by `contract-price.js`; the rule itself is unchanged and keeps the identifier `contract-price-match/v0.1`. Run against both implementations at `f3d24c9`, eleven of the fifteen agreed and four differed; in each of the four the published rule keeps its behaviour and the README above now states it explicitly:

| Case | Input | `contract-price.js` | Python implementation (at `f3d24c9`) |
|---|---|---|---|
| `cpm-083` | `unit_price` `"01.00"` | invalid `offer.unit_price` (no leading zeros) | verified |
| `cpm-092` | `product_scope.skus` `[]` | invalid `terms[0].product_scope.skus` (must be non-empty) | indeterminate `no_applicable_term` |
| `cpm-093` | the same sku listed twice | invalid `terms[0].product_scope.skus` (no duplicates) | verified |
| `cpm-095` | `unit_price` with thirty fractional digits | invalid `offer.unit_price` (at most 8 fractional digits) | verified |

The other readings the list raised are also now written down: `"1."` and `".50"` invalid, a leap second invalid, self-supersession invalid, `supersedes: null` treated as absent. `cpm.py` would need the digit limits, the leading-zero rule and the non-empty, distinct `skus` rule to agree on all 97; until then `independent-python/run_vectors.py` reports those four cases.

## Licence

This folder is licensed separately from the rest of this repository.

| Files | Licence |
|---|---|
| `contract-price.js`, `contract-price-jcs.js`, `contract-price.test.mjs`, `README.md` | Apache License 2.0. See `LICENSE` and `NOTICE`. Copyright 2026 TK Collective LLC. |
| `contract-price.vectors.json` | CC0 1.0 Universal. See `LICENSE-vectors-CC0-1.0.txt`. Use the vectors without restriction. |

The rest of this repository stays under its own licence (see the `LICENSE` file at the repository root).
