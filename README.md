# Verification Receipt Format

A signed, offline-verifiable receipt recording **what was checked before an agent acted**, so a gate can refuse to proceed and a later examiner can recompute the decision.

**Version 0.3 — in production use since May 2026 (the issuing service is in free beta).** The v0.3 envelope and its decision mapping (`agentoracle-v0.3-2026-05-30`) have been serving live traffic since May 2026. This document is normative for v0.3. Extension work for v0.4 is an open draft and is **not** normative — see [Extension draft](#extension-draft-v04).

| | |
|---|---|
| Envelope | `verification.v0.3+composed` |
| Canonicalization | JCS ([RFC 8785](https://datatracker.ietf.org/doc/html/rfc8785)) |
| Signature | Ed25519 over JWS ([RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)), `alg: EdDSA` |
| Multi-issuer | Yes — `signatures[]` accepts additional co-signers over identical canonical bytes |
| IETF draft | [`draft-krausz-verification-state-03`](https://datatracker.ietf.org/doc/draft-krausz-verification-state) (filed 2026-10-01; working repo [`tanilo-ietf-id`](https://github.com/TKCollective/tanilo-ietf-id)) |
| Independent implementations | 1 byte-identical, built from this spec text alone — see [Implementations](#implementations) |
| Conformance vectors | Published — see [Conformance](#conformance) |

---

## Verify a receipt yourself

You do not need to contact any verifier's service to check a receipt. Install the verifier and run it against the canonical bytes:

```bash
pip install tanilo-receipt-verify
```

```python
import json, urllib.request
from tanilo_receipt_verify import verify

# A real receipt from this repository, issued by /evaluate on 2026-10-02.
envelope = json.load(open("examples/live-receipts/evaluate-demo-2026-10-02.json"))

# The key set. New receipts name this URL in the payload's `signature_meta.jwks_url`.
jwks_url = "https://tanilo.io/.well-known/jwks.json"
jwks = json.load(urllib.request.urlopen(jwks_url))

result = verify(envelope, jwks_by_issuer={jwks_url: jwks})

if result.status == "valid":
    print("signature valid — canonical:", result.canonical_sha256)
```

Run from the root of this repository, this prints
`signature valid — canonical: sha256-baac7b814e66e90d729a51d7337fa3ea24d57daf623d8d545a0778f838447aff`.

**`jwks_by_issuer` is required to reach a verdict.** `result.status` is one of `"valid"`,
`"invalid"` or `"indeterminate"`. Called as `verify(envelope)` with no key material on a signed
envelope, the verifier returns `"indeterminate"`, not `"valid"`: the canonical bytes recomputed,
but no signature was checked. Branch on `result.status`.

The verifier recomputes JCS canonical bytes from the payload and checks each signature against the JWKS you supply. It does not fetch JWKS for you. **It does not call the issuing service.** The key set is published at `https://tanilo.io/.well-known/jwks.json`; the same set is served at `https://api.tanilo.io/.well-known/jwks.json` and `https://agentoracle.co/.well-known/jwks.json`. Receipts issued since 2026-10-02 name the key set URL in `signature_meta.jwks_url`; older receipts name it in `signature_meta.agentoracle_jwks_url`.

A valid signature shows which key signed these bytes. It does not show that the claim is true — see the next section.

To confirm the canonical bytes independently, canonicalize the `payload` object with any RFC 8785 implementation and SHA-256 the result. It must equal `canonical_sha256`.

---

## What a receipt proves, and what it does not

This section is normative for how implementers describe the format, and it is the most important section in this document.

**A receipt proves:**

1. **Issuance** — a specific key, resolvable from published JWKS, committed to this exact content.
2. **Integrity** — the content has not been altered since signing; any change breaks the canonical hash and every signature over it.
3. **Non-repudiation** — a valid signature under a key whose issuance paths are documented binds the issuer to having signed this determination; it does not by itself show how the evaluation was carried out, or that the claim is true. This holds for keys whose issuance paths are documented, and only as far as that documentation goes. For one key, a signature alone does not establish that the issuer made the determination: `ao-composed-2026-06-ed25519-c3abfce3` also signed caller-supplied bytes from 2026-06-23 until 2026-08-28. See the [incident record](https://tanilo.io/incidents/2026-08-25-canned-verdicts) and the [trust page](https://tanilo.io/trust). Receipts issued since 2026-10-02 are signed by `tanilo-2026-10-ed25519-7d885da9`, a key generated on 2026-09-30 that first signed on 2026-10-02 (see the key-continuity statement at [tanilo.io/.well-known/key-continuity.json](https://tanilo.io/.well-known/key-continuity.json)) and carry `role: evaluated` in the protected header, an issuance-path role stating that the issuer evaluated the claim itself.
4. **Recomputability** — the receipt carries the decision inputs and the identifier and hash of the ruleset applied, so a third party can re-derive the decision rather than accept it.

**A receipt does not prove the verified claim is true.**

A signature establishes who issued a determination, not whether that determination is correct. For any check requiring judgement, a receipt is a **non-repudiable commitment to an opinion**, not evidence the opinion is right. An issuer with a valid key can sign a receipt over any content, including content it never actually verified.

Three properties narrow that gap. None closes it:

- **Deterministic checks.** Where a check is mechanically re-runnable from the receipt's own inputs, "trust the issuer" is replaced by "re-run the check." A deterministic verification mode with six such check types and no model in the trust chain ships in the reference implementation.
- **Multi-issuer composition.** `signatures[]` accepts co-signers over identical canonical bytes, so a consumer need not trust any single issuer. The reference implementation and one independent implementation, built from this spec text alone, produce byte-identical canonical bytes.
- **Non-evaluation is a first-class state.** The format distinguishes *"checked and could not establish"* from *"did not check."* An issuer that skipped a check cannot represent the result as a pass — see [Decision mapping](#decision-mapping).

Consumers requiring a truth guarantee rather than an accountability guarantee should treat receipts as **evidence about process**, and apply their own policy on top.

---

## Terminology

| Term | Meaning |
|---|---|
| **claim verifier** | Any service that evaluates a claim and issues a receipt in this format. The format is not specific to any one implementation. |
| **issuer** | The signing party. One receipt may carry several. |
| **consumer** | The party verifying a receipt and applying policy to it. |
| **gate** | The decision point that consumes a receipt and permits or refuses an action. |
| **examiner** | A party reviewing a receipt after the fact, without access to the issuer's runtime. |

This document uses generic terms throughout. Implementation names appear only under [Implementations](#implementations).

---

## Receipt envelope

The receipt is a JWS with a JCS-canonicalized JSON payload. Additional serializations (COSE) are out of scope for v0.3.

### JWS header

The protected header of a receipt issued on 2026-10-02 ([`examples/live-receipts/evaluate-demo-2026-10-02.json`](examples/live-receipts/evaluate-demo-2026-10-02.json)):

```json
{
  "alg": "EdDSA",
  "kid": "tanilo-2026-10-ed25519-7d885da9",
  "typ": "application/vnd.verification.v0.3+composed+jws",
  "role": "evaluated"
}
```

| Field | Required | Notes |
|---|---|---|
| `alg` | yes | `EdDSA` (Ed25519) |
| `kid` | yes | Resolves via the issuer's published JWKS |
| `typ` | yes | `application/vnd.verification.v0.3+composed+jws` |
| `role` | no | Issuance-path role. `evaluated` on receipts the reference implementation has issued since 2026-10-02. Not part of the v0.3 envelope as first published; a header without it is still a v0.3 header. |

Historical: until 2026-10-02 the reference implementation signed with `kid` `ao-composed-2026-06-ed25519-c3abfce3` and the header carried no `role`. That key is retired; its public key stays in the published set so receipts already issued can still be checked. See [What a receipt proves](#what-a-receipt-proves-and-what-it-does-not) for what a signature under it does and does not establish.

### Payload

Historical example, in the shape issued in June 2026. Receipts issued since 2026-10-02 carry `"signature_meta": {"jwks_url": "https://tanilo.io/.well-known/jwks.json"}` and `"issuer": "tanilo.io"` in `v_gate`.

```json
{
  "composed_decision": "act",
  "composed_decision_rule": "AND_PRESENT",
  "envelope_kind": "verification.v0.3+composed",
  "receipt_version": "0.3.0-composed",
  "signature_meta": {
    "agentoracle_jwks_url": "https://agentoracle.co/.well-known/jwks.json"
  },
  "subject": {
    "claim_hash": "sha256-9b1c6...",
    "skill_hash": "sha256-3b1f2d8e..."
  },
  "timestamp": "2026-06-30T13:28:18.674Z",
  "timestamp_ms": 1782826098674,
  "v_gate": {
    "confidence": 0.87,
    "issuer": "agentoracle.co",
    "mapping_hash": "sha256-3b1f2d8e...",
    "mapping_id": "agentoracle-v0.3-2026-05-30",
    "signed_at": "2026-06-30T13:28:18.674Z",
    "v_adversarial_result": "resilient",
    "v_confidence": 0.87,
    "v_gate_threshold": 0.7,
    "v_recommendation": "confident_supported",
    "v_verdict": "supported",
    "verdict": "act"
  }
}
```

| Field | Required | Notes |
|---|---|---|
| `envelope_kind` | yes | Fixed `verification.v0.3+composed` |
| `receipt_version` | yes | Fixed `0.3.0-composed` |
| `composed_decision` | yes | `act` or `halt`. Result of `composed_decision_rule` over all present sibling blocks. |
| `composed_decision_rule` | yes | `AND_PRESENT` — every present sibling must permit; a single `halt` collapses the composition |
| `subject.claim_hash` | yes | SHA-256 of the claim text. The binding object; claim text is never required in the receipt |
| `subject.skill_hash` | yes | SHA-256 of the ruleset document that reduced signals to a verdict |
| `timestamp` / `timestamp_ms` | yes | RFC 3339 UTC with exactly 3 fractional digits, and its integer form. Derived from one source so identical inputs yield byte-identical canonical bytes |
| `v_gate` | yes | The verification decision block — see below |
| `signature_meta` | yes | JWKS URLs for the signers, so a consumer can resolve keys without out-of-band configuration. `jwks_url` on receipts issued since 2026-10-02; `agentoracle_jwks_url` on older ones |

Sibling blocks other than `v_gate` (for example an independent skill or screening block from a different issuer) MAY be present. `composed_decision` is computed over all of them.

### `v_gate`

| Field | Required | Notes |
|---|---|---|
| `v_verdict` | yes | `supported` · `refuted` · `unverifiable` · `unknown` |
| `v_adversarial_result` | yes | `resilient` · `vulnerable` · `not_checked` |
| `v_confidence` | yes | Float in `[0,1]` |
| `v_gate_threshold` | yes | Decision threshold **from the mapping, not from the request.** See note below |
| `v_recommendation` | yes | Derived — see [Decision mapping](#decision-mapping) |
| `verdict` | yes | `act` or `halt`, derived from `v_recommendation` by the gate map |
| `mapping_id` | yes | Identifier of the ruleset applied |
| `mapping_hash` | yes | SHA-256 of the ruleset bytes. Content-addressing: fetch by hash, hash the bytes, confirm they match |
| `issuer` | yes | Issuing authority for this block |
| `signed_at` | yes | Must equal envelope `timestamp` for a single-issuer receipt |

**`v_gate_threshold` is a property of the mapping and is not caller-tunable.** A request may carry its own advisory threshold for presentation purposes, but that value MUST NOT be written into the receipt. Echoing a caller-supplied threshold would let a consumer obtain a signed receipt asserting a permissive gate threshold it did not actually pass.

---

## Decision mapping

`v_recommendation` is derived by applying the mapping's rules in order. This table is normative for `agentoracle-v0.3-2026-05-30`:

| # | `v_verdict` | `v_adversarial_result` | confidence | `v_recommendation` |
|---|---|---|---|---|
| 5 | `refuted` | any | any | `refuted` |
| 6 | `unverifiable` or `unknown` | any | any | `unverifiable` |
| 1 | `supported` | `resilient` | ≥ threshold | `confident_supported` |
| 2 | `supported` | `not_checked` | ≥ threshold | `un_probed_not_cleared` |
| 3 | `supported` | `vulnerable` | any | `vulnerable_supported` |
| 4 | `supported` | `resilient` or `not_checked` | < threshold | `weak_supported` |
| 7 | — | — | — | `error` (unreachable fallback) |

**Gate map: `confident_supported` → `act`. Every other recommendation → `halt`.**

Two consequences worth stating explicitly, because both have been misread:

- **`supported` alongside `not_checked` is a legitimate state and it does not pass.** It derives `un_probed_not_cleared` and halts. It is distinct from `unverifiable`: one records that no adversarial attempt was made, the other that an attempt was made and failed. **Implementations MUST NOT collapse these into a single state.** An examiner needs the difference.
- **A receipt reaching rule 7 is malformed.** `error` indicates the inputs were not a valid combination; treat it as a verification failure, not a halt.

### Guardrails on signing

An implementation MUST refuse to sign rather than emit a malformed receipt. At minimum:

- `v_verdict` and `v_adversarial_result` outside their enumerations MUST throw.
- `v_confidence` outside `[0,1]`, or non-finite, MUST throw.
- `mapping_hash` that is not a 64-character lowercase hex SHA-256 MUST throw.
- An evaluation with **zero evaluated members** MUST NOT produce a receipt at all. A verifier that could not evaluate anything must report unavailability, not sign an envelope over an empty determination.

---

## Verification procedure

A consumer MUST perform, in order:

1. **Resolve keys.** Fetch JWKS from the URL in `signature_meta`. Locate each `kid`.
2. **Recompute canonical bytes.** Canonicalize `payload` per RFC 8785. SHA-256 it. Compare to `canonical_sha256` if the transport supplies one.
3. **Verify every signature** in `signatures[]` over those bytes. A receipt is valid only if every signature present verifies.
4. **Re-derive the decision.** Apply the mapping identified by `mapping_id` to `v_verdict`, `v_adversarial_result`, and `v_confidence`. Confirm the derived `v_recommendation` and `verdict` match what the receipt asserts. **A mismatch means the receipt is internally inconsistent and MUST be rejected**, even when signatures verify.
5. **Apply local policy.** Signature validity is not authorization. A consumer decides which recommendations it accepts.

Step 4 is what makes the receipt recomputable rather than merely authentic. Skipping it reduces the format to a signed assertion.

---

## Conformance

Conformance is validated against a published fixture set, with byte-identical recomputation confirmed between the reference implementation and one independent implementation. Fixtures: [`agentoracle-v1` conformance set](https://github.com/giskard09/argentum-core/tree/main/examples/conformance/agentoracle-v1), merged 2026-06-17.

`action_ref` derivation follows the canonical JCS + SHA-256 construction in [`draft-giskard-aeoess-action-ref`](https://github.com/giskard09/draft-giskard-aeoess-action-ref) over four preimage fields — `agent_id`, `action_type`, `scope`, `timestamp` (RFC 3339 UTC, exactly 3 fractional digits).

`verification.v0.3` is the first candidate profile entry in the ERC-8210 Receipt Profile Registry ([entry merged 2026-06-23](https://github.com/wangbin9953/erc8210-aap/pull/4)). Registry status `candidate` means a single live issuer with a second independent implementation not yet recorded by the registry maintainer.

A vector set covering the decision mapping — including a required-reject vector for a receipt that reports a pass while a member reads `not_checked` — is maintained alongside this spec at [`conformance/`](conformance/). Run it with `node conformance/check.mjs`.

The `leaf-screen-halt` reject vector for `delegation-chain-ref-v1` (a payment-authority chain cannot anchor a PII-screen halt as its leaf) is mirrored byte-for-byte from [giskard09/argentum-core PR #27](https://github.com/giskard09/argentum-core/pull/27) at [`examples/conformance/delegation-chain-ref/leaf-screen-halt/`](examples/conformance/delegation-chain-ref/leaf-screen-halt/); the upstream commit, file hashes and Apache-2.0 notice are in [`examples/conformance/delegation-chain-ref/NOTICE.md`](examples/conformance/delegation-chain-ref/NOTICE.md). Run it with `python verify.py` from that directory; expected `1/1 passed`.

---

## Standards position

The `verification.*` constraint family is specified in [`draft-krausz-verification-state-03`](https://datatracker.ietf.org/doc/draft-krausz-verification-state) (filed 2026-10-01), *"The verification.\* Constraint Family: Pre-Action Fail-Closed …"*. It is an individual Internet-Draft, a work in progress, and uses generic terminology throughout; its working repository is [`tanilo-ietf-id`](https://github.com/TKCollective/tanilo-ietf-id). This document is its implementation-facing companion.

**The verdict vocabulary differs between this envelope and -03.** The v0.3 envelope specified here carries `v_verdict` as one of `supported`, `refuted`, `unverifiable`, `unknown`, the raw verdict domain of -01. -03 replaces that domain with a four-state vocabulary, `verified`, `contradicted`, `indeterminate` and `not_evaluated`, together with a reason-code mechanism. Its Section 6.1 restates the decision table against the four states, one-for-one in declaration order, and leaves the recommendation and gate vocabulary unchanged. Receipts in the v0.3 envelope use the four values in this document. Nothing here should be read as a claim that the v0.3 envelope carries -03's vocabulary.

**Why a sibling family rather than an existing constraint namespace.** Environment-state constraint families evaluate boolean predicates with oracle-fixed semantics and a single uniform TTL, and gating against them is trivial. Claim verification is probabilistic, its threshold belongs to the consumer's policy rather than the oracle, and its freshness is not one-dimensional — a signing key can rotate without invalidating prior determinations, and underlying evidence can age without invalidating the verifier's calibration. Folding a probabilistic predicate into a boolean family loses exactly the distinctions a gate needs.

Confidence is carried as a sidecar property rather than a peer claim, aligning with the [W3C VC Confidence Method](https://www.w3.org/TR/vc-confidence-method/) working draft.

> **Note, 2026-08.** Earlier revisions of this document positioned the family against a public Mastercard Verifiable Intent repository. That repository no longer resolves publicly, so the comparison above is stated structurally rather than as a reference to a specific external artifact.

---

## Implementations

The format is not specific to any implementation. Known implementations:

| Implementation | Status | Notes |
|---|---|---|
| **Tanilo** (formerly AgentOracle) | Live, in free beta | Reference implementation. Pre-action claim verification, live in free beta at `api.tanilo.io` and `agentoracle.co`. Self-serve accounts are not open. x402 pay-per-call is not available. A deterministic verification mode with no model in the trust chain is live. JWKS at [`tanilo.io/.well-known/jwks.json`](https://tanilo.io/.well-known/jwks.json); the same set is served at `api.tanilo.io` and `agentoracle.co` |
| **AgentTrust** | Independent | Built from this spec text without access to the reference code. Produces **byte-identical** canonical bytes on the shared fixture set. Co-signs composed envelopes |

An offline verifier is published on PyPI: [`tanilo-receipt-verify`](https://pypi.org/project/tanilo-receipt-verify/). It runs without contacting any issuer.

The reference implementation is a provider under the [Mycelium provider protocol](https://github.com/giskard09/argentum-core/blob/main/docs/mycelium-provider-protocol.md). When composed with a post-action attestation flow, a returned trail identifier can be carried at envelope level as a sibling pointer to `v_gate`.

---

## Extension draft (v0.4)

**Not normative. Do not implement against this section.** v0.4 is an open draft under discussion; v0.3 is the shipped and normative version. Open items include a signed, ordered session history across a multi-step run (an append-only transparency log rather than per-claim receipts alone), a COSE binding for embedded consumers, and a first-class `not_evaluated` value in the verdict enumeration so that non-evaluation need not route through `unknown`.

Discussion happens in issues and pull requests on this repository. Extension proposals are tracked as additive changes; a change to the decision mapping requires a new `mapping_id` and hash, because receipts already in circulation were derived under the prior ruleset.

---

## Corrections record

Corrections are kept permanently. Nothing in this section is removed once entered.

**2026-04-29 — FEVER metrics conflated.** An earlier revision cited two FEVER figures adjacently, implying they were comparable. They were not: they came from different evaluation settings, one with gold evidence supplied to the label classifier and one end-to-end through the retrieval pipeline. Conflating them was our error. Separately, FEVER 1.0 is a public 2018 benchmark and parametric-knowledge contamination on a modern model is a live risk that was not controlled for. Raised by Beenz / [headlessoracle](https://github.com/headlessoracle).

**No FEVER figure is cited in this document, and none should be cited externally,** until a seeded containerized harness is public, recall@5 and recall@10 are reported alongside any headline score, and a contamination-controlled run on a newer held-out benchmark is published side by side.

**2026-08-27 — the FEVER figures are additionally under review for what they measure.** Two different definitions of the same percentage exist across our own repositories, and at most one can be correct. Until that is resolved against the benchmark code, no specific FEVER number is reproduced anywhere in this document.

**2026-08-27 — this document misrepresented the project.** Until this revision, the README described a `v0.1` draft with an `ao_*`-prefixed JWT payload and an ES256 signature, under a status line reading *"EARLY DRAFT … Not yet implemented."* None of that had been accurate for months: v0.3 with the `v_gate` composed envelope and Ed25519 signatures had been in production since May 2026. The document also named the reference implementation in its title, mixing a product with a format specification, and led with the correction notice above rather than with what the format is. Every technical reader who found this repository in that period was given a materially wrong picture. Raised by **Ryosuke Niwa**.


**2026-08-27 — the verification walkthrough in this document failed open.** The Python example called `verify(receipt_json)` with no JWKS map. In that form the verifier checks recompute-invariants only and returns `valid: True` with an empty `signers` list, having verified no signature. This document also stated that the verifier fetches published JWKS; it does not. Anyone who followed the previous text believing they had checked a signature had not. Both statements are corrected in [Verify a receipt yourself](#verify-a-receipt-yourself); the format, the published keys, and the canonical-bytes recomputation were unaffected.

**2026-08-28 — the correction above described a superseded release.** The entry dated 2026-08-27 stated that `verify(receipt_json)` returns `valid: True` with an empty `signers` list. That was the behaviour of version 0.0.1 only. The current release at the time of that entry was 0.1.0, whose three-outcome API returns `status: "indeterminate"` and `valid: None` on a signed envelope called without `jwks_by_issuer`, and populates `indeterminate_reason` explaining that canonicalization recomputed but no key material was supplied. `None` is falsy, so `if result.valid:` on 0.1.0 fails closed. The fail-open path — `valid: True` on an unverified signature — was 0.0.1-only. The 2026-08-27 entry was written from a locally installed 0.0.1 without checking it against PyPI's current release. Both substantive corrections from that entry still stand on 0.1.0: signatures are checked only when `jwks_by_issuer` is supplied, and this document's earlier claim that the verifier fetches published JWKS was false. 0.1.0 documents these behaviours directly.

**2026-10-03 — the implementation row overstated access, and this document referenced a superseded package and draft.** Until this revision the Implementations table described the reference implementation as offering "self-serve and pay-per-call access, on-chain settlement". Self-serve accounts were not open. The only routes that asked for x402 payment were the research routes (`POST /research`, `/deep-research`, `/deep-research/skale`, `/research/batch`), which were retired on <RETIREMENT DATE>. `/evaluate` and `/v1/verify-facts` are free during the beta. The row now states that. This document also pointed readers to the superseded verifier package `agentoracle-receipt-verify` and to `draft-krausz-verification-state-01`. The current package is `tanilo-receipt-verify`, and the current draft is -03, filed 2026-10-01. In the same revision the reference implementation is named Tanilo (formerly AgentOracle), the non-repudiation statement is qualified for `ao-composed-2026-06-ed25519-c3abfce3`, and the header example shows the key in use since 2026-10-02.

---

## Acknowledgements

**Ryosuke Niwa** — for the terminology and framing correction that produced this revision: separate the format specification from the implementation that issues it, and use generic terms such as *claim verifier* throughout. Also for pressing the distinction between authenticity and truth, which is now the [What a receipt proves](#what-a-receipt-proves-and-what-it-does-not) section.

**Beenz / [headlessoracle](https://github.com/headlessoracle)** — for the original architectural objection that a probabilistic verification predicate does not fit a boolean environment-state namespace, and for the sibling-family-with-confidence-as-sidecar shape that followed from it. Also for the FEVER conflation catch above.

**[@giskard09](https://github.com/giskard09)** — for the `action_ref` canonical derivation and the conformance fixture set that made independent byte-identical recomputation checkable.

Acknowledgement is not endorsement. None of the above has reviewed this revision.

---

## Contributing

Issues and pull requests: [this repository](https://github.com/TKCollective/tanilo-receipt-spec/issues).

Particularly wanted:

- **Break it.** The [What a receipt proves](#what-a-receipt-proves-and-what-it-does-not) section is the place to attack. If you can construct a receipt that verifies while asserting something the issuer did not determine, that is the bug worth reporting.
- Independent implementations, especially ones that disagree with the reference on canonical bytes.
- Review of the decision mapping against real gating requirements.

---

## License

Specification text: [CC-BY 4.0](https://creativecommons.org/licenses/by/4.0/). The published offline verifier is MIT.
