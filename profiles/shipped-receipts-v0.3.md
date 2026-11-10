# Shipped receipt shapes under `verification.v0.3+composed`

**Status: descriptive.** This page records what the reference implementation emits, so that a receiver and an implementer can work from the same description. It describes the deployment at API commit `ed63fc06` (deployed 2026-10-28). It adds no new requirement, and it does not change any receipt already issued. Points that are not yet decided are listed under [Open questions](#open-questions); none of them is settled by this page.

Two receipt shapes share one envelope. Both are JWS general serializations of an RFC 8785 canonical JSON payload, signed by the same key, and both verify with [`tanilo-receipt-verify`](https://pypi.org/project/tanilo-receipt-verify/) against the same published key set.

| shape | issued by | specified in |
|---|---|---|
| Judgment receipt | `POST /evaluate` | [README, Receipt envelope](../README.md#receipt-envelope) and [Decision mapping](../README.md#decision-mapping) |
| Deterministic-check receipt | `POST /v1/verify-facts` | this page, below |

## Protected header (both shapes)

| member | value |
|---|---|
| `alg` | `EdDSA` |
| `kid` | the signing key's id; since 2026-10-02 `tanilo-2026-10-ed25519-7d885da9` |
| `typ` | `application/vnd.verification.v0.3+composed+jws` |
| `role` | `evaluated` on receipts signed since 2026-10-02; absent on older receipts |

Verify the signature over the protected header bytes exactly as received. Those bytes are not RFC 8785 canonical; only the payload is.

## Deterministic-check receipt (`/v1/verify-facts`)

A worked example with its decoded payload is [`examples/interop/aer1/`](../examples/interop/aer1/) (`receipt.jws.json`, signed 2026-10-08).

### Payload members

The payload carries exactly these members:

| member | value |
|---|---|
| `agent_id` | the caller's `agent_id` as sent. When the caller sends none: `urn:tanilo:verify-facts:anonymous`, or `did:ao:verify-facts:anonymous` on receipts signed before 2026-10-13T00:07:22.431Z. It is not authenticated |
| `check_mode` | `deterministic` |
| `check_results` | one entry per requested check, in request order (1 to 20); see below |
| `check_types_applied` | the distinct check types in `check_results`, sorted |
| `envelope_kind` | `verification.v0.3+composed` |
| `receipt_version` | `0.3.0-composed` |
| `signature_meta` | `{ "jwks_url": "https://tanilo.io/.well-known/jwks.json" }` (`agentoracle_jwks_url` on receipts signed before 2026-10-02) |
| `subject` | the caller's `subject` object as sent. `subject.claim_hash` must be present, or the request gets HTTP 400 and no receipt. The service does not check its format or recompute it. Any other member the caller puts in `subject` is signed as sent |
| `timestamp`, `timestamp_ms` | the signing instant: RFC 3339 UTC with three fractional digits, and the same instant in milliseconds |
| `v_gate` | see below |

It does **not** carry `composed_decision`, `composed_decision_rule`, `subject.skill_hash` (unless the caller sends one), `v_verdict`, `v_confidence`, `v_gate_threshold` or `v_recommendation`. Those belong to the judgment receipt.

### `v_gate`

| member | value |
|---|---|
| `verdict` | `act` when every entry in `check_results` passed (`outcome: pass`); otherwise `halt` |
| `confidence` | `1` |
| `v_adversarial_result` | `n/a` |
| `deterministic_mapping_id` | the check catalog revision in force: `tanilo-deterministic-v0.3-2026-10-10` since 2026-10-10 (earlier: `tanilo-deterministic-v0.2-2026-10-04`, `agentoracle-deterministic-v0.1-2026-08-06`) |
| `mapping_id`, `mapping_hash` | the **judgment-mode** mapping document in force at signing (`tanilo-v0.3-2026-10-13`, or `agentoracle-v0.3-2026-05-30` before the 13 October cutover). They do not identify the check catalog |
| `issuer` | `tanilo.io` |
| `signed_at` | equal to `timestamp` |

### `check_results[]`

The check types fall into two groups.

**Two-outcome checks:** `signature_verification`, `hash_comparison`, `registry_lookup`, `regex_match`, `timestamp_validation`, `json_schema_conformance`.

| member | value |
|---|---|
| `check_type` | one of the six |
| `outcome` | `pass` or `fail` |
| `recommendation` | a fixed sentence for that check type and outcome |
| `evidence` | present on `pass` |
| `failure_reason`, `failure_detail` | present on `fail`; `failure_detail` only when there is one |

These entries carry **no `state` member**.

**Three-state checks:** `contract_price_match`, `spend_cap`. Their rules, tests and vectors are in [`checks/contract-price-match/`](../checks/contract-price-match/) and [`checks/spend-cap/`](../checks/spend-cap/).

| member | value |
|---|---|
| `check_type` | `contract_price_match` or `spend_cap` |
| `state` | `verified`, `contradicted` or `indeterminate` |
| `outcome` | `pass` (verified), `fail` (contradicted) or `indeterminate` (indeterminate) |
| `recommendation` | a fixed sentence for that check type and state |
| `evidence` | present in every state |
| `failure_reason` | present when `contradicted` |
| `indeterminate_reason` | present when `indeterminate` |

An `indeterminate` result halts the gate. It records that the check ran on valid input and could not establish a result; it is not a finding that the price is wrong or the cap exceeded.

### When no receipt is issued

| response | cause |
|---|---|
| HTTP 400 | `checks` missing, empty or longer than 20; `subject.claim_hash` missing |
| HTTP 422 `claim_not_deterministic` | an unknown check type, missing inputs, schema-invalid input, or a check that could not be executed as declared (for example a registry that could not be reached). There is no fallback to a model |
| HTTP 503 `not_signed` | the service holds no seed for the selected signing key. The checks ran, and their results are returned unsigned |

### What a receiver can recompute

- **The gate:** `v_gate.verdict` from `check_results`. It is `act` only if every entry has `outcome: pass`.
- **The canonical bytes:** RFC 8785 over the payload, and its SHA-256.
- **The three-state checks:** the result itself, by replaying the rule on the offer, terms or cap the caller kept. The receipt carries their digests in `evidence`.

As with every receipt, a valid signature shows which key signed. It does not show that caller-supplied inputs were genuine, and it does not authorize an action.

## State vocabularies in use

| where | values |
|---|---|
| deterministic receipt, `check_results[].state` (three-state checks only) | `verified`, `contradicted`, `indeterminate` |
| deterministic receipt, `check_results[].outcome` | `pass`, `fail`, and `indeterminate` for the three-state checks |
| judgment receipt, `v_gate.v_verdict` | `supported`, `refuted`, `unverifiable`, `unknown` (the domain of draft -01) |
| draft-krausz-verification-state-03, `v_verdict` | `verified`, `contradicted`, `indeterminate`, `not_evaluated`, one-for-one in that order with the -01 values |
| gate, every shape | `act`, `halt` |

No shipped receipt emits `not_evaluated`. No shipped receipt emits the -03 values in `v_verdict`.

## Open questions

These are not decided. Nothing on this page should be read as settling them.

1. **-03 vocabulary in judgment receipts.** Whether, and when, judgment receipts move `v_verdict` from the -01 values to the -03 values. Draft -03 §5.2 defers renaming the claim itself to `v_state`.
2. **A `state` member for every check.** Whether the six two-outcome check types gain one, and with which values.
3. **Composition fields in deterministic receipts.** Whether deterministic receipts should carry `composed_decision` and `composed_decision_rule`. Today the conjunction over checks is expressed only by `v_gate.verdict`.
4. **Content address for the check catalog.** `deterministic_mapping_id` has no published content hash. `v_gate.mapping_hash` in these receipts refers to the judgment mapping, not to the check catalog.
5. **Members outside these tables.** No shipped receipt carries other top-level members. Nothing yet says how a receiver should treat an unrecognized member, or whether a separately signed object (for example an authorization disposition, or a reference to an earlier receipt) has a place in this envelope. That discussion is in [tanilo-ietf-id issue #1](https://github.com/TKCollective/tanilo-ietf-id/issues/1).
6. **More than one signature.** Deterministic receipts carry one signature. The README's verification procedure requires every present signature to verify. A policy for co-signed deterministic receipts is not defined.
7. **`subject` contents.** Only `subject.claim_hash` is required, and it is not recomputed. Whether other members may appear, and whether `claim_hash` should be recomputable from the checks, is not settled.
