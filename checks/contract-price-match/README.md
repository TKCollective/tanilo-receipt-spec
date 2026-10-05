# Contract price check: the rule, its tests and its vectors

`contract_price_match` is a check type of Tanilo's `POST /v1/verify-facts`. It
answers one question: **does the unit price in an offer match the price in the
applicable term, among the terms the caller supplied?** No model is involved.

This folder holds the rule as the service runs it, so that anyone can replay a
check: same input, same rule, same result.

| File | What it is |
|---|---|
| `contract-price.js` | The rule, `contract-price-match/v0.1`. Pure: no network, no clock, no randomness. |
| `contract-price-jcs.js` | Canonical JSON (RFC 8785) for the values the rule hashes. |
| `contract-price.test.mjs` | The test suite: 69 cases, including the USD 2.00 against USD 1.00 example. |
| `contract-price.vectors.json` | Each case as an input and the exact result. Use it to check another implementation. |
| `SHA256SUMS` | SHA-256 of the four files above. |

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

Input that cannot be read as declared gets no result at all. The rule returns
`{ invalid: true, path, message }`, and the service answers 422 without a
receipt.

## The rule in order

1. **Scope.** Keep terms with the offer's seller whose product list contains the offer's product. Exact strings.
2. **Effective at the offer time.** `effective_from` ≤ `offered_at` < `effective_to`. The end is excluded.
3. **Declared precedence.** A term is set aside when another in-effect term of the same agreement names its version in `supersedes`. Never inferred from version numbers or dates.
4. **Currency**, then 5. **unit.** Exact match, no conversion.
6. **Exactly one term** must remain.
7. **Price for the quantity.** One price, or the tier where `min_quantity` ≤ quantity < `max_quantity`.
8. **Compare** by exact decimal value. `"1"` equals `"1.00"`. No tolerance, no rounding.

Amounts and quantities are decimal strings. Times are UTC and end in `Z`.

## What this does not establish

The terms are supplied by the caller. The check does not establish that they
are genuine, complete, validly executed or approved by anyone. It makes no unit
or currency conversion, applies no rounding, and calculates no tax. A
`verified` result does not authorize a payment.

## Versions

A change to what the rule returns for any input gets a new rule identifier.
The identifier in a receipt (`evidence.rule_id`) tells you which rule to
replay. This folder holds `contract-price-match/v0.1`.

Documentation: https://tanilo.io/docs/contract-price-check

Licensed under the MIT License, as the rest of this repository.
