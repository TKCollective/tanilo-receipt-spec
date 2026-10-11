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

Take the offer and the cap you sent, and call the rule:

```js
import { evaluateSpendCap } from "./spend-cap.js";

const result = evaluateSpendCap({ offer, cap });
console.log(result.state, result.reason, result.evidence);
```

Compare `result.evidence` with the `evidence` of the `spend_cap` entry in the
receipt's signed payload. They are equal when the input and the rule are the
same. The receipt also carries `offer_sha256` and `cap_sha256`, so you can first
confirm that the offer and cap you hold are the ones that were checked.

Checking the receipt's signature is a separate step, done with
[`tanilo-receipt-verify`](https://pypi.org/project/tanilo-receipt-verify/) against
a key set you have authenticated as Tanilo's (published at
https://tanilo.io/.well-known/jwks.json). A valid signature shows which key signed the receipt. It does not show that the
supplied cap was genuine.

## Input

```
offer: { unit_price, currency, quantity?, offered_at?, seller?, sku? }
cap:   { amount, currency, scope, already_spent?, period?: { from, to }, cap_id? }
```

- `scope` is `per_purchase` (the cap applies to this offer alone) or `per_period`
  (the cap applies to a period, and `already_spent` counts what the period has
  already consumed).
- Amounts and quantities are decimal strings: up to 18 digits, then optionally a
  point and 1 to 8 digits. No sign, no symbol, no separators.
- Times are UTC and end in `Z`, with seconds and optionally 1 to 3 fractional
  digits.
- Objects are closed: a member not listed here is refused, so nothing the caller
  sends is silently ignored. With `per_purchase`, `already_spent` and `period`
  are refused for the same reason.
- `quantity` may be absent. The check then cannot compute a total and records
  that as an indeterminate result, rather than refusing the request.

## Three results

- `verified`: the offer's total is less than or equal to the remaining cap.
- `contradicted`: the total exceeds the remaining cap. The total, the remaining
  cap and the excess are recorded. When the cap was already exhausted before this
  offer (remaining below zero), `cap_already_exhausted` is `true`.
- `indeterminate`: the comparison could not be made. A reason says why:
  `currency_mismatch`, `quantity_missing`, `period_bounds_missing`,
  `offer_time_missing` or `offer_outside_period`. This is not a finding that the
  offer exceeds the cap.

Input that does not satisfy the schema gets no result at all. The rule returns
`{ invalid: true, path, message }`, and the service answers 422 without a
receipt.

The service returns a result as a signed receipt when signing succeeds.

## The rule in order

The first step that cannot continue decides the reason. Later steps are not run.

1. **Currency.** `offer.currency` equals `cap.currency`. Otherwise
   `currency_mismatch`. No conversion.
2. **Quantity.** `offer.quantity` is present. Otherwise `quantity_missing`.
3. **Total.** `unit_price` × `quantity`, exact. A product of two values with up
   to 8 fraction digits has up to 16; nothing is rounded. Recorded as
   `offer_total`.
4. **Remaining cap.**
   - `per_purchase`: remaining = `amount`.
   - `per_period`: `period.from` and `period.to` must be present, otherwise
     `period_bounds_missing`; `offer.offered_at` must be present, otherwise
     `offer_time_missing`; `from` ≤ `offered_at` < `to` (end exclusive), otherwise
     `offer_outside_period`. Remaining = `amount` − `already_spent`
     (`already_spent` defaults to `"0"` and may exceed `amount`).
5. **Compare.** total ≤ remaining → `verified`. Otherwise `contradicted` with
   `excess` = total − remaining. `"1"` equals `"1.00"`. No tolerance, no rounding.

**`offer_sha256`** and **`cap_sha256`** are over the canonical JSON of each object
as supplied; member order does not matter.

## What this does not establish

The cap and `already_spent` are supplied by the caller; this check does not
retrieve or track budgets. It does not establish that this is the right cap,
that it was approved, or that `already_spent` is complete or current. It is not a
ledger: it keeps no state between calls and does not record this offer against
the cap.

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
