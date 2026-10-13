# Spend cap check: the rule, its tests and its vectors

`spend_cap` is a check type of Tanilo's `POST /v1/verify-facts`. It answers one
question: **does the total of this offer fit within the remaining cap the caller
supplied?** The total is the offer's unit price times its quantity, by exact
decimal arithmetic. No model is involved.

This folder holds the rule as the service runs it, so that anyone can replay a
check: same input, same published rule version, same result.

| File | What it is |
|---|---|
| `spend-cap.js` | The rule, `spend-cap/v0.1`. Pure: no network, no clock, no randomness. |
| `contract-price-jcs.js` | Canonical JSON (RFC 8785) for the values the rule hashes (shared with the contract price check, byte-identical). |
| `spend-cap.test.mjs` | The test suite, including the exactly-at-cap and one-cent-over cases. |
| `spend-cap.vectors.json` | Each case as an input and the exact result. Use it to check another implementation. |
| `SHA256SUMS` | SHA-256 of the four files above. |
| `LICENSE`, `NOTICE` | Apache License 2.0 and its notice, for the code and this README. |
| `LICENSE-vectors-CC0-1.0.txt` | CC0 1.0, for the vectors. |

## Run it

Needs Node and nothing else. Tested with Node 24.

```bash
node spend-cap.test.mjs
```

It exits 0 only when every case passes and every stored vector equals what the
rule gives.

## Replay a check

Rerun the original input using the published rule version named by
`evidence.rule_id` in the receipt, then compare the resulting evidence with the
evidence inside the signed receipt:

```js
import { evaluateSpendCap } from "./spend-cap.js";

const result = evaluateSpendCap({ offer, cap });
console.log(result.state, result.reason, result.evidence);
```

Compare `result.evidence` with the `evidence` of the `spend_cap` entry in the
receipt's signed payload. They are equal when the input and the rule version are
the same. The receipt also carries `offer_sha256` and `cap_sha256`, so you can
first confirm that the offer and cap you hold are the ones that were checked.

Checking the receipt's signature is a separate step, done with
[`tanilo-receipt-verify`](https://pypi.org/project/tanilo-receipt-verify/).
Verify the receipt's signature against a key set you have authenticated as
Tanilo's (published at https://tanilo.io/.well-known/jwks.json). A valid
signature establishes that the signed content verifies under the selected key
and has not been altered. It does not establish that the supplied cap is
authentic, approved or current, or that the purchase is authorized.

## Input

```
offer: { unit_price, currency, quantity?, offered_at?, seller?, sku? }
cap:   { amount, currency, scope, already_spent?, period?: { from, to }, cap_id? }
```

`input`, `offer`, `cap` and any supplied `period` must be objects. Unknown
members are rejected at each of those levels.

`offer.unit_price`, `offer.currency`, `cap.amount`, `cap.currency` and
`cap.scope` are required.

`scope` is `per_purchase` (the cap applies to this offer alone) or `per_period`
(the cap applies to a period, and `already_spent` counts what the period has
already consumed). With `per_purchase`, non-null values of `already_spent` and
`period` are rejected as schema-invalid. Explicit `null` values are treated as
absent.

Amounts and quantities must be decimal strings matching
`^(0|[1-9][0-9]{0,17})(\.[0-9]{1,8})?$`. Signs, leading zeros other than the
single zero before a decimal point, whitespace, exponents, symbols and
separators are rejected. Amounts may be zero; quantity must be greater than
zero and may be fractional.

Currency values must contain exactly three uppercase ASCII letters. The rule
compares these strings; it does not validate them against a currency registry.

Timestamps must use `YYYY-MM-DDTHH:mm:ssZ`, optionally with 1–3
fractional-second digits before `Z`, and must represent a valid calendar date
and time. Explicit offsets, including `+00:00`, and leap seconds are rejected.
This rule version accepts timestamp years from `0100` through `9999`.

When supplied and non-null, `seller`, `sku` and `cap_id` must be non-empty
strings of at most 200 UTF-16 code units, with no leading or trailing
whitespace.

Optional fields accept `null` as absence. For `per_period`, absent or null
`already_spent` defaults to `"0"` and may exceed `amount`. An absent or null
quantity produces `quantity_missing` if evaluation reaches that step.

## Three results

- `verified`: the offer's total is less than or equal to the remaining cap.
- `contradicted`: the total exceeds the remaining cap. The total, the remaining
  cap and the excess are recorded.
- `indeterminate`: the comparison could not be made. A reason says why:
  `currency_mismatch`, `quantity_missing`, `period_bounds_missing`,
  `offer_time_missing` or `offer_outside_period`. This is not a finding that the
  offer exceeds the cap.

A contradicted result has reason `cap_exceeded`; a verified result has reason
`null`. The rule returns the reason in `reason`. In the API check result,
contradicted reasons appear in `failure_reason` and indeterminate reasons appear
in `indeterminate_reason`.

`cap_already_exhausted` is true only on a contradicted result when the computed remaining cap is zero or below. This means the supplied inputs leave no positive allowance before including this offer; it does not establish that any spending actually occurred. It is false otherwise. For indeterminate results, false does not establish that budget remains.

Schema-invalid input gets no result at all. The rule returns
`{ invalid: true, path, message }`. At the service, schema-invalid input
receives HTTP 422 `claim_not_deterministic` and no receipt. Rule-validation
errors identify the offending member and include spend-cap help and an example.
Requests rejected earlier because required input objects are missing may use a
different error shape.

A valid-input indeterminate result records that the check ran but could not
complete the comparison. It receives a signed receipt only when signing
succeeds. With no signing key, the service returns HTTP 503 with
`status: "not_signed"` and unsigned check results.

## The rule in order

The complete input is validated before evaluation begins. Schema-invalid input
is rejected before any of the five rule steps runs. For valid input, evaluation
stops at the first step that cannot continue. Later steps are not run.

1. **Currency.** `offer.currency` equals `cap.currency`. Otherwise
   `currency_mismatch`. No conversion.
2. **Quantity.** `offer.quantity` is present. Otherwise `quantity_missing`.
3. **Total.** `unit_price` × `quantity`, exact. A product of two values with up
   to 8 fraction digits has up to 16; nothing is rounded. Recorded as
   `offer_total`.
4. **Remaining cap.**
   - `per_purchase`: remaining = `amount`.
   - `per_period`: an absent or null `period` produces `period_bounds_missing`.
     If a period object is supplied, both `from` and `to` must be valid
     timestamps, with `to` strictly later than `from`; otherwise the input is
     schema-invalid. An absent or null `offer.offered_at` produces
     `offer_time_missing`. An offer time outside `from` ≤ `offered_at` < `to`
     produces `offer_outside_period`. Otherwise, remaining = `amount` −
     `already_spent`.
   These indeterminate reasons remain subject to earlier evaluation steps
   succeeding.
5. **Compare.** total ≤ remaining → `verified`. Otherwise `contradicted` with
   `excess` = total − remaining. `"1"` equals `"1.00"`. No tolerance, no rounding.

The rule does not enforce currency-specific minor units. Products and
differences may have up to 16 fractional digits, including fractions of a cent.
Output amounts have at least two fractional digits; no rounding is applied.

**`offer_sha256`** and **`cap_sha256`** are over the canonical JSON of each object
as supplied; member order does not matter.

## What this does not establish

The cap and `already_spent` are caller-supplied. This check does not establish
that the cap is authentic, approved or applicable to this purchase, or that
`already_spent` is complete or current. It does not authenticate the supplied
offer time or establish that the offer is still current. It does not retrieve
budget balances, maintain a running balance or reserve funds: it keeps no state
between calls and does not record this offer against the cap.

Each call evaluates only the supplied snapshot. Repeated or concurrent calls can
each return `verified` against the same remaining amount. This check does not
reserve funds, update spending or prevent combined purchases from exceeding a
cap.

`seller`, `sku` and `cap_id` are recorded and included in the input hashes.
They are not used to determine whether the cap applies to this seller, item or
account.

The signed payload includes the supplied offer and cap, including optional
identifiers. Signing does not encrypt this information; sharing the receipt
exposes its payload to the recipient.

It makes no currency conversion, applies no rounding or tolerance, and
calculates no tax. It does not judge whether the purchase is sensible. A
`verified` result does not authorize a payment.

## Versions

A change to what the rule returns for any input gets a new rule identifier.
The identifier in a receipt (`evidence.rule_id`) tells you which rule to
replay. This folder holds `spend-cap/v0.1`.

Documentation: https://tanilo.io/docs/spend-cap-check (not yet published)

## Licence

This folder is licensed separately from the rest of this repository.

| Files | Licence |
|---|---|
| `spend-cap.js`, `contract-price-jcs.js`, `spend-cap.test.mjs`, `README.md` | Apache License 2.0. See `LICENSE` and `NOTICE`. Copyright 2026 TK Collective LLC. |
| `spend-cap.vectors.json` | CC0 1.0 Universal. See `LICENSE-vectors-CC0-1.0.txt`. Use the vectors without restriction. |

The rest of this repository stays under its own licence (see the `LICENSE` file at the repository root).
