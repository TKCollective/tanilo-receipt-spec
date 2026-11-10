# Shipped receipt shapes under `verification.v0.3+composed`

**Status: descriptive.** This page records what the reference implementation emits, so that a receiver and an implementer can work from the same description. It describes the deployment at API commit `ed63fc06` (deployed 2026-10-28), and notes where earlier receipts differ. It adds no new requirement, and it does not change any receipt already issued. Points that are not yet decided are listed under [Open questions](#open-questions); none of them is settled by this page.

Two receipt shapes share one envelope. Both are JWS general serializations whose payload is the base64url encoding of RFC 8785 canonical JSON. At any one time the same key signs both shapes, and both verify with [`tanilo-receipt-verify`](https://pypi.org/project/tanilo-receipt-verify/) against the same published key set.

| shape | issued by | specified in | published fixture |
|---|---|---|---|
| Judgment receipt | `POST /evaluate` | [README, Receipt envelope](../README.md#receipt-envelope) and [Decision mapping](../README.md#decision-mapping) | [`examples/live-receipts/evaluate-demo-2026-10-02.json`](../examples/live-receipts/evaluate-demo-2026-10-02.json) |
| Deterministic-check receipt | `POST /v1/verify-facts` | this page, below | [`examples/interop/aer1/receipt.jws.json`](../examples/interop/aer1/receipt.jws.json) |

At API commit `ed63fc06` the judgment builder also emits two optional top-level members, `sources` and `sources_used` (each an array, empty when absent), which the published judgment fixture carries. Judgment receipts carry `composed_decision` under `composed_decision_rule` `AND_PRESENT`. In receipts from the reference implementation `v_gate` is the only sibling block, so `composed_decision` equals `v_gate.verdict`. The recompute is step 4 of the [README's verification procedure](../README.md#verification-procedure).

## Protected header (both shapes)

| member | value |
|---|---|
| `alg` | `EdDSA` |
| `kid` | `tanilo-2026-10-ed25519-7d885da9` on receipts signed after the signing-key cutover on 2 October 2026 (UTC); `ao-composed-2026-06-ed25519-c3abfce3` on receipts signed before it. Tell receipts apart by `kid`, not by date |
| `typ` | `application/vnd.verification.v0.3+composed+jws` |
| `role` | `evaluated` on receipts signed with `tanilo-2026-10-ed25519-7d885da9`; absent on receipts signed with `ao-composed-2026-06-ed25519-c3abfce3` |

**Signature check.** For each entry in `signatures[]`, the JWS signing input is the ASCII bytes of the received `protected` string, a literal `.`, and the received `payload` string ([RFC 7515 §5.2](https://datatracker.ietf.org/doc/html/rfc7515#section-5.2)). Use both encoded strings exactly as received; do not decode and re-encode either one. Verify against a key set you trust for the issuer you expect. `signature_meta` names where the issuer publishes its keys, but a URL named inside a receipt does not make that key set trustworthy.

**Payload digest check.** Recomputing the RFC 8785 digest is a separate check: base64url-decode the received `payload` string, parse it, canonicalize it per RFC 8785, and take the SHA-256. In receipts from the reference implementation the decoded payload bytes are already the RFC 8785 bytes, so this equals the SHA-256 of the decoded bytes. The protected header is not RFC 8785 canonical, and its bytes are not part of this digest. See [README, Verification procedure](../README.md#verification-procedure).

## Deterministic-check receipt (`/v1/verify-facts`)

The published example, with its decoded payload, is [`examples/interop/aer1/`](../examples/interop/aer1/). It was signed on 2026-10-08 with `tanilo-2026-10-ed25519-7d885da9`, before the 13 October mapping cutover. It therefore carries `v_gate.mapping_id` `agentoracle-v0.3-2026-05-30`, `v_gate.deterministic_mapping_id` `tanilo-deterministic-v0.2-2026-10-04` and `agent_id` `did:ao:verify-facts:anonymous`.

### Payload members

At API commit `ed63fc06` the deterministic builder emits exactly these payload members:

| member | value |
|---|---|
| `agent_id` | the caller's `agent_id` as sent, not authenticated. When the caller sends none, or a falsy value (empty string, `null`, `0`, `false`): `urn:tanilo:verify-facts:anonymous`. Receipts from the builder before the 13 October 2026 (UTC) mapping cutover carry `did:ao:verify-facts:anonymous` instead; the identifier changed in the same deployment as `v_gate.mapping_id`, so a receipt with `agentoracle-v0.3-2026-05-30` carries the older identifier |
| `check_mode` | `deterministic` |
| `check_results` | one entry per requested check, in request order, 1 to 20 entries; see below. A request with no checks or more than 20 gets HTTP 400 and no receipt |
| `check_types_applied` | the distinct check types in `check_results`, sorted |
| `envelope_kind` | `verification.v0.3+composed` |
| `receipt_version` | `0.3.0-composed` |
| `signature_meta` | `{ "jwks_url": "https://tanilo.io/.well-known/jwks.json" }` on receipts signed with `tanilo-2026-10-ed25519-7d885da9`; `{ "agentoracle_jwks_url": "https://agentoracle.co/.well-known/jwks.json" }` on receipts signed with `ao-composed-2026-06-ed25519-c3abfce3` |
| `subject` | the caller's `subject` object as sent. `subject.claim_hash` must be present and not falsy (empty string, `null`, `0`, `false`), or the request gets HTTP 400 and no receipt. The service does not check its format or recompute it. Any other member the caller puts in `subject` is signed as sent |
| `timestamp`, `timestamp_ms` | the signing instant: RFC 3339 UTC with three fractional digits, and the same instant in milliseconds |
| `v_gate` | see below |

It does **not** carry `composed_decision`, `composed_decision_rule`, `sources`, `sources_used`, `subject.skill_hash` (unless the caller sends one), `v_gate.v_verdict`, `v_gate.v_confidence`, `v_gate.v_gate_threshold` or `v_gate.v_recommendation`. Those belong to the judgment receipt.

### `v_gate`

| member | value |
|---|---|
| `verdict` | `act` when `check_results` has 1 to 20 entries and every entry has `outcome: pass`; otherwise `halt`. The service never signs an empty `check_results`. A receiver must reject an empty array rather than read it as `act` |
| `confidence` | `1` |
| `v_adversarial_result` | `n/a` |
| `deterministic_mapping_id` | the check catalog revision in force at signing: `tanilo-deterministic-v0.3-2026-10-10` at API commit `ed63fc06`. Earlier receipts carry `tanilo-deterministic-v0.2-2026-10-04` or `agentoracle-deterministic-v0.1-2026-08-06`. The date in an identifier names the revision, not the day it was deployed |
| `mapping_id`, `mapping_hash` | the **judgment-mode** mapping document in force at signing: `tanilo-v0.3-2026-10-13` from the 13 October 2026 (UTC) mapping cutover, `agentoracle-v0.3-2026-05-30` before it. They do not identify the check catalog |
| `issuer` | `tanilo.io` on receipts signed with `tanilo-2026-10-ed25519-7d885da9`; `agentoracle.co` on receipts signed with `ao-composed-2026-06-ed25519-c3abfce3` |
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

In the order the service applies them at API commit `ed63fc06`:

| response | cause |
|---|---|
| HTTP 400 | the request body is not valid JSON |
| HTTP 429 `rate_limited` | the per-network hourly limit for this route, or for GitHub registry lookups, is exhausted |
| HTTP 400 `missing_or_invalid_checks`, `too_many_checks` | `checks` is not a non-empty array, or has more than 20 entries |
| HTTP 422 `claim_not_deterministic` (with `unresolvable`) | before any check runs: an unknown check type, or a check missing one of its required input members |
| HTTP 422 `claim_not_deterministic` (with `unexecutable`) | after the checks run: a check could not be executed as declared. The reasons are `missing_inputs`, `invalid_input` (schema-invalid input to a three-state check), `unsupported_algorithm`, `invalid_jwk`, `unsupported_registry`, `invalid_pattern`, `pattern_too_long`, `pattern_rejected`, `value_too_long`, `invalid_timestamp`, `invalid_bound`, `unsupported_schema_keywords`, `verify_error`, `registry_unreachable` and `registry_error`. There is no fallback to a model |
| HTTP 400 `missing_subject_claim_hash` | `subject.claim_hash` missing or falsy. This is checked after the checks have run |
| HTTP 503 `not_signed` | the service holds no seed for the selected signing key. The checks ran, and their results are returned unsigned |
| HTTP 500 | an internal error. The response carries a reference and no results |

### What a receiver can recompute

- **The gate:** `v_gate.verdict` from `check_results`. Given 1 to 20 entries, it is `act` only if every entry has `outcome: pass`. An empty or missing `check_results` is malformed.
- **The canonical digest:** RFC 8785 over the decoded payload, and its SHA-256.
- **Individual checks:** see the next section. Most need the caller's original inputs.

### Replaying a check

A receipt records each check's `evidence`; it does not always record the check's inputs. At API commit `ed63fc06`:

| check type | `evidence` records | replaying the check needs |
|---|---|---|
| `spend_cap` | the offer and the cap in full, their digests, the computed total and remaining cap, and each rule step (every state) | nothing beyond the receipt |
| `timestamp_validation` | the timestamp and the bounds, normalized (on `pass`) | nothing beyond the receipt, on `pass` |
| `contract_price_match` | the offer in full and its digest; the terms only by digest (`terms_sha256`, and a digest per term named in the rule steps) (every state) | the original terms, which must match `terms_sha256` |
| `hash_comparison` | the algorithm, the computed digest and the content length (on `pass`) | the original content |
| `regex_match` | the pattern, the flags, and a digest and length of the value (on `pass`) | the original value |
| `json_schema_conformance` | digests of the schema and the document, and the keywords applied (on `pass`) | the original schema and document |
| `signature_verification` | the algorithm, the `kid`, a digest of the signing input and the signature length (on `pass`) | the original signing input, signature and public key |
| `registry_lookup` | the registry, the identifier, the observed metadata, a digest of the response read and the time it was read (on `pass`) | cannot be replayed exactly: a new lookup reads the registry as it is now |

A failed two-outcome check carries no `evidence`, only `failure_reason` and, when there is one, `failure_detail`. Replaying it needs the original inputs. In every case the replayed result can be compared with `outcome` (and `state`), but the inputs remain the caller's: the receipt does not show they were genuine.

`tanilo-receipt-verify==0.2.4` returning `valid` means every signature verified against the key sets you passed in, and that the canonical digest matched `canonical_sha256` when the envelope carried one. It does not recompute the gate from `check_results`.

As with every receipt, a valid signature shows which key signed. It does not show that caller-supplied inputs were genuine, and it does not authorize an action.

## State vocabularies in use

| where | values |
|---|---|
| deterministic receipt, `check_results[].state` (three-state checks only) | `verified`, `contradicted`, `indeterminate` |
| deterministic receipt, `check_results[].outcome` | `pass`, `fail`, and `indeterminate` for the three-state checks |
| judgment receipt, `v_gate.v_verdict` | `supported`, `refuted`, `unverifiable`, `unknown` (the domain of draft -01) |
| draft-krausz-verification-state-03, the `v_verdict` claim | `verified`, `contradicted`, `indeterminate`, `not_evaluated`, one-for-one in that order with the -01 values |
| gate, every shape: `v_gate.verdict`, and `composed_decision` in judgment receipts | `act`, `halt` |

At API commit `ed63fc06` neither builder emits `not_evaluated`, and the judgment builder accepts only the -01 values for `v_gate.v_verdict`. The two published fixtures agree.

## Open questions

These are not decided. Nothing on this page should be read as settling them.

1. **-03 vocabulary in judgment receipts.** Whether, and when, judgment receipts move `v_gate.v_verdict` from the -01 values to the -03 values. Draft -03 §5.2 defers renaming the claim itself to `v_state`.
2. **A `state` member for every check.** Whether the six two-outcome check types gain one, and with which values.
3. **Composition fields in deterministic receipts.** Whether deterministic receipts should carry `composed_decision` and `composed_decision_rule`. Today the conjunction over checks is expressed only by `v_gate.verdict`.
4. **Content address for the check catalog.** `v_gate.deterministic_mapping_id` has no published content hash. `v_gate.mapping_hash` in these receipts refers to the judgment mapping, not to the check catalog.
5. **Members outside these tables.** At API commit `ed63fc06` the deterministic builder emits no top-level members beyond those listed above. Judgment receipts also carry `sources` and `sources_used`. Nothing yet says how a receiver should treat an unrecognized member, whether such a member counts as a sibling block under `AND_PRESENT`, or whether a separately signed object (for example an authorization disposition, or a reference to an earlier receipt) has a place in this envelope. That discussion is in [tanilo-ietf-id issue #1](https://github.com/TKCollective/tanilo-ietf-id/issues/1).
6. **More than one signature.** Deterministic receipts carry one signature. The README's verification procedure requires every present signature to verify. A policy for co-signed deterministic receipts is not defined.
7. **`subject` contents.** Only `subject.claim_hash` is required, and it is not recomputed. Whether other members may appear, and whether `claim_hash` should be recomputable from the checks, is not settled.
