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
| `contract-price.test.mjs` | The test suite: 82 cases, including the USD 2.00 against USD 1.00 example. |
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

- **Amounts and quantities** are decimal strings: up to 18 digits, then optionally a point and 1 to 8 digits.
- **Times** are UTC and end in `Z`, with seconds and optionally 1 to 3 fractional digits. They are compared to the millisecond.
- **`supersedes`** is a string: the `version` of a term of the same `agreement_id`. It has effect only while the superseding term is itself in effect at the offer time. When a superseding term has ended, the term it replaced applies again if it is still in effect. Precedence is not carried across a term that is not in effect: if version 3 replaces version 2 and version 2 replaced version 1, and version 2 has ended, versions 1 and 3 are both left and the result is `precedence_unresolved`.
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

Licensed under the MIT License, as the rest of this repository.
