# verification.v0.4 — Draft Extension rev-1: Sealed Evidence & Multi-Clock Anchoring

**Status:** DRAFT FOR DISCUSSION, revision 1 — not yet normative. Comments welcome via issues/PRs.
**Extends:** verification.v0.3 (and v0.3+composed). Additive at the canonical-bytes level: a valid v0.3 envelope's bytes are unchanged by this extension (see §6 and §2.1 for the rules that keep that true).
**Author:** Joe Krausz, AgentOracle (TK Collective LLC)
**Date:** 2026-07-29 (rev-1.2; rev-1.1 2026-07-28; rev-1 2026-07-26; original draft 2026-07-24)

**rev-1 changelog.** This revision incorporates the findings of the draft's first hostile review, by **poteshniy (AgentTrust)** — the format's independent second implementer — across three review rounds (PR #5 and follow-ups), plus one determinism point absorbed from an adjacent multi-value discussion by **vstantch**. Findings are credited inline as [P-n] (poteshniy) and [V-1] (vstantch). Every change is listed here; the diff against the original draft is visible on PR #5.

- [P-1] **(blocking)** typ-downgrade closed: check-set selection is content-driven, not issuer-declared (§6)
- [P-2] **(blocking)** canonicalize-as-received made explicit normative text (§2.1)
- [P-3] anchor suppression made detectable: signed `anchor_commitments` (§3.4)
- [P-4] anchoring status gets three-outcome + indeterminate semantics with proof-class clock adjudication (§3.5)
- [P-5] bounded curation named in the text as a chosen bound (§3.4)
- [P-6] snapshot checks split into three outcomes; core verdict offline-deterministic (§2.3)
- [P-7] `anchored_at` demoted to hint; time derives from the proof (§3.1)
- [P-8] `merkle_proof` fully specified: domain separation, sibling positions, odd-node rule (§3.3)
- [P-9] per-type offline-verifiability profiles stated (§3.2)
- [P-10] absent-vs-null: MUST omit, never null (§5.1)
- [P-11] smaller items: `target_sha256` cites v0.3 `envelope_hash`; hash-after-decompression pinned; `ref` uniqueness MUST; completeness signal added (§2.2, §2.4, §3.1)
- [V-1] `evidence_seals` ordering pinned (lexicographic by `ref`); v0.3 `evidence` ordering becomes a forward-looking SHOULD (§2.5)
- [P-12] `test-clock` conformance domain added so shortfall/skewed-clock vectors are deterministic and offline (§3.1, §7.1) — resolution of the implementer's vector-construction question, rev-1.1
- [P-13..18] six baseline under-determinations pinned (composed `evidence` array required with seals; string-entry form; `envelope_kind`/`receipt_version` values; top-level placement; snapshot-less seals accept-valid) — found by the independent implementer deriving the accept baseline from the field tables alone (§2.2, §2.6, §6), rev-1.2


**rev-2 changelog (2026-08-06).** `layer_trace` field group added per receipt-spec#7 consensus (§4). [Y-1] layer-boundary definition and [Y-2] chain-to-input correction credited to @yun520-1 (HeartFlow); production `src/gate.js` surfaced both. [Y-3] divergence diagnostics (§4.3) credited to @yun520-1; production `src/core/verifier-grant.js` surfaced it.

---

## 1. Motivation

verification.v0.3 makes the *record* tamper-evident: canonical bytes (RFC 8785), Ed25519 JWS (RFC 7515/8037), published JWKS (RFC 7517), offline verification. Two gaps remain between a v0.3 receipt and the strongest evidence artifact the same primitives can support:

1. **Evidence drift.** A receipt binds a *reference* to the evidence consulted, but the referenced content can change or disappear after signing. "We checked source X" weakens over time because X is mutable. An examiner years later cannot confirm what X said at verification time.

2. **Single-clock precedence.** Optional on-chain anchoring proves a record existed before a block timestamp — one clock, one trust domain. Different examiners trust different clocks: a DeFi counterparty trusts an EVM chain; a court or regulator trusts an RFC 3161 timestamping authority; a neutrality-maximalist trusts Bitcoin. One clock forces the examiner into one trust domain.

v0.4 closes both gaps with two additive field groups: **sealed evidence** and **multi-clock anchors**. A third concern — that additions must never weaken v0.3 verification — is addressed by two rules this revision makes explicit: content-driven check-set selection (§6) and canonicalization of the payload exactly as received (§2.1).

## 2. Sealed Evidence

### 2.1 Canonicalization of received payloads [P-2]

Verifiers MUST canonicalize the payload **exactly as received**. Tolerance of unrecognized members (§5.2) applies to *semantic processing only* — it MUST NOT cause a verifier to reconstruct, filter, or re-serialize the payload before canonicalization or signature verification. Signature verification operates over the canonical form of the received bytes; a verifier that strips unknown fields and then canonicalizes will compute different bytes and MUST be considered non-conformant. (This rule is what makes the extension additive at the bytes level: a v0.3 verifier meeting v0.4 fields — or a v0.4 verifier meeting a future v0.5 field such as a populated `fetch_attestation` — verifies the same bytes the issuer signed.)

### 2.2 The `evidence_seals` array

In composed profiles, a payload carrying `evidence_seals` MUST also carry a top-level `evidence` array: the set of evidence references the seals correspond to and that `seals_complete` is evaluated against. Each entry of `evidence` is a string (URI or other identifier); each seal's `ref` MUST match an entry byte-exactly. Emitters SHOULD order `evidence` lexicographically by byte-wise UTF-8 comparison (mirroring §2.5); verifiers MUST NOT reject on `evidence` ordering. The v0.3 non-composed `evidence.snippets` object is a distinct legacy surface and is unchanged by this extension.

A v0.4 payload MAY include `evidence_seals`, an array of seal objects, one per evidence item consulted. Each seal object contains:

| Field | Req | Description |
|---|---|---|
| `ref` | MUST | The evidence reference exactly as it appears in the v0.3 `evidence` set. Every entry in `evidence_seals` MUST correspond to an entry in `evidence`. `ref` values MUST be unique within `evidence_seals` [P-11]. |
| `content_sha256` | MUST | Lowercase hex SHA-256 of the retrieved evidence bytes (§2.4). |
| `retrieved_at` | MUST | RFC 3339 UTC timestamp of retrieval. |
| `media_type` | MUST | MIME type of the hashed representation. |
| `content_length` | SHOULD | Byte length of the hashed representation. |
| `snapshot_ref` | MAY | Content-addressed locator of an archived copy (WACZ path, IPFS CID, or HTTPS archive URL). Raw snapshots MUST hash to `content_sha256`; container formats MUST include the member path (e.g. `wacz:archive.wacz!data/pages/p1.html`). |
| `fetch_attestation` | MAY | Reserved for a future extension: a third-party proof that the content was served by the origin. Structure unspecified in v0.4; verifiers MUST ignore unrecognized members *semantically* while §2.1 governs the bytes. |

A payload containing `evidence_seals` SHOULD also contain `seals_complete` (boolean): `true` asserts every item in `evidence` has a corresponding seal [P-11]. Verifiers MUST treat `seals_complete: true` with a missing seal as `evidence_seal_incomplete` (reject).

### 2.3 Verification semantics — three outcomes, offline-deterministic core [P-6]

Seal verification produces two separable results:

**Core (offline, deterministic — part of envelope PASS/FAIL):**
- An `evidence_seals` entry whose `ref` is absent from `evidence` → `evidence_seal_unmatched` (reject).
- `seals_complete: true` with an unsealed evidence item → `evidence_seal_incomplete` (reject).
- Malformed seal objects (missing MUST fields) → reject.
The core verdict MUST be computable with no network access and MUST NOT change based on network state.

**Extended (snapshot resolution — reported separately, never mutates the core verdict):** for each seal with a `snapshot_ref`, the extended check yields exactly one of:
- `verified` — snapshot retrieved and hashes to `content_sha256`;
- `contradicted` — snapshot retrieved and does NOT hash to `content_sha256`;
- `could_not_check` — snapshot unretrievable (archive offline, resolver unavailable).

Verifiers MUST report extended results per seal and MUST NOT fold `could_not_check` into either other outcome. A deployment policy MAY treat `contradicted` as disqualifying; the *format-level* core verdict does not, because a core verdict that depends on network reachability is not deterministic [P-6]. Conformance vectors for the extended class ship with a defined resolvability parameter so they reproduce offline.

### 2.4 What is hashed [P-11]

`content_sha256` is computed over the response body **after transfer decoding and after content decoding** (i.e., after reversing any `Content-Encoding` such as `gzip` or `br`), before any rendering, extraction, or normalization. Transfer-Encoding artifacts (chunking) never appear in the hashed bytes. For dynamic pages, the seal attests to the decoded bytes the fetch received at `retrieved_at` — no more, no less.

### 2.5 Ordering [V-1]

Entries in `evidence_seals` MUST be ordered lexicographically by `ref` (byte-wise comparison of the UTF-8 encoding). Two honest emitters sealing the same evidence set therefore produce identical canonical bytes — the same determinism class as absent-vs-null (§5.1).

The v0.3 `evidence` array's ordering was not pinned by v0.3 and this revision does not retroactively pin it: v0.4 emitters SHOULD order `evidence` lexicographically, and verifiers MUST NOT reject an envelope for `evidence` ordering. (A retroactive MUST would render existing conformant v0.3 emitters non-conformant — the wrong side of the additivity promise. Credit for surfacing the one-level-up question: [P] round 3.)

### 2.6 What sealing does and does not prove

A seal proves the issuer committed, at signing time, to specific evidence bytes with a specific hash. With a resolvable snapshot, an examiner can read exactly what the verifier read. Sealing does **not** by itself prove the bytes genuinely originated from the referenced origin (that is `fetch_attestation`'s future work), and does not make the evidence true. State precisely what is proven, and no more. A seal without a `snapshot_ref` is accept-valid: its `content_sha256` is a commitment that becomes independently checkable when a snapshot or refetch matches.

## 3. Multi-Clock Anchors

### 3.1 The `anchors` array

A v0.4 envelope MAY carry `anchors`, an array of anchor objects **outside** the signed payload (anchoring necessarily happens after signing). Each anchor binds the envelope's canonical hash — or a Merkle root committing to it — to an external clock. Fields:

| Field | Req | Description |
|---|---|---|
| `type` | MUST | One of `evm-tx`, `ots` (OpenTimestamps), `rfc3161`, `test-clock` (conformance only — see §7.1), or a collision-resistant custom string. |
| `target_sha256` | MUST | The canonical envelope hash this anchor commits to — the same value as v0.3's `envelope_hash` (sha256 over the canonical payload bytes) [P-11]. |
| `merkle_proof` | MAY | If the anchor commits to a batch root: an inclusion proof per §3.3 plus `merkle_root`. |
| `anchor_data` | MUST | Type-specific proof: for `evm-tx`, chain ID + tx hash; for `ots`, the base64 OTS proof; for `rfc3161`, the base64 DER TimeStampToken. |
| `anchored_at` | MAY | Advisory hint only [P-7]. Verifiers MUST derive the anchor's clock reading from `anchor_data` itself (block header time, OTS-attested Bitcoin block time, TST `genTime`) and MUST ignore `anchored_at` for any adjudication; a mismatch between hint and proof SHOULD be reported as a warning. |

### 3.2 Anchor verification and offline profiles [P-9]

Each anchor verifies **independently**; anchors are additive evidence, never a quorum. For `evm-tx`, the transaction data MUST contain `target_sha256` or the recomputed `merkle_root` (requires chain access: RPC). For `ots`, the proof MUST verify per the OpenTimestamps protocol (offline against a local Bitcoin header set; obtaining current headers requires network). For `rfc3161`, the TimeStampToken MUST verify per RFC 3161 over `target_sha256` (or `merkle_root`) against the TSA certificate chain (fully offline given the chain). These offline profiles are properties of the clock domains, stated here so deployments choose with eyes open.

Precedence claims take the form: *this envelope's hash existed at or before clock C's reading T* — per clock, never aggregated into a single "true time."

### 3.3 Merkle inclusion proofs — full construction [P-8]

Batching MUST use the following construction (RFC 6962-compatible):
- Leaf hash: `H(0x00 || leaf_data)` where `leaf_data` is the 32-byte `target_sha256` and `H` is SHA-256.
- Interior node: `H(0x01 || left || right)`. The `0x00`/`0x01` domain separation prevents leaf/interior second-preimage confusion.
- Odd node at any level: promoted unchanged to the next level (no self-pairing).
- `merkle_proof` is an ordered array, leaf-to-root, of objects `{"sibling": <hex>, "position": "left"|"right"}` — position states which side the *sibling* occupies in the concatenation.
- Verifiers MUST recompute from `target_sha256` through the proof and require equality with `merkle_root`; `merkle_root` (not the leaf) is what appears in `anchor_data`'s external commitment.

### 3.4 Signed anchor commitments [P-3, P-5]

A hash over the *final* anchor set cannot live inside the signed payload — anchoring post-dates signing. What CAN be signed is intent. A v0.4 payload MAY include `anchor_commitments`:

| Field | Req | Description |
|---|---|---|
| `expected_types` | MUST | Array of anchor `type` values the issuer commits to obtaining. |
| `min_count` | MUST | Minimum number of verified anchors, drawn from `expected_types`, that satisfy the commitment. |
| `anchor_by` | MUST | RFC 3339 UTC deadline by which the commitment is to be met. Mandatory whenever `anchor_commitments` is present — a commitment without a deadline gives suppression a permanent alibi ("not anchored *yet*"). |

Because the commitment is inside the signed payload, a presenter cannot remove or weaken it. **Bounded curation is a chosen bound, stated plainly [P-5]:** with `expected_types: [evm-tx, ots, rfc3161]` and `min_count: 2`, the presenter still selects *which* two verified anchors to present. Issuers wanting zero curation set `min_count` equal to the number of expected types. Substitution across envelopes was never possible (`target_sha256` binds every anchor to this envelope); the exposure was suppression, and commitments make suppression detectable — with teeth defined in §3.5.

### 3.5 Anchoring status — adjudication without a trusted wall-clock [P-4]

When `anchor_commitments` is present, verifiers MUST report exactly one machine-readable anchoring status. **"Now" must itself be proof-class:** adjudication uses only anchor-domain time evidence, never the verifier's local clock.

- **`meets_commitment`** — at least `min_count` verified anchors, of types in `expected_types`, whose *own proof-derived clock readings* are ≤ `anchor_by`. Clock-free in the trust sense, but not count-blind: anchors whose proof-derived readings are *after* `anchor_by` remain valid precedence evidence individually — they cannot retroactively satisfy a deadline they missed; the late window is exactly what the commitment exists to bound.
- **`short_of_commitment`** — the verified-in-time count is below `min_count`, AND at least one verified time proof exists whose reading is ≥ `anchor_by`. That proof may be an anchor already on the envelope, or a **verifier-obtained current proof from a committed domain** (a fresh RFC 3161 token over any value, or a current Bitcoin header via OTS) — which is how total suppression past deadline remains convictable by an examiner who trusts no local clock.
- **`not_yet_anchored`** — zero (or below-minimum) verified anchors, and at least one verified time proof shows a reading strictly < `anchor_by` (the deadline demonstrably has not passed in that clock domain).
- **`indeterminate_pending`** — none of the above is provable from available proof-class evidence. This is an honest named state and MUST NOT be defaulted into either `not_yet_anchored` or `short_of_commitment`.

The verifier's wall-clock MAY be reported as advisory context and MUST NOT move the machine-readable status. Anchoring status is reported alongside — never folded into — core envelope validity: a signature-valid envelope short of its commitment is precisely the state that must be visible as itself. Conformance vectors will include the skewed-verifier-clock case (commitment past `anchor_by`, zero anchors, adversarial local time) [P, round 3].

## 4. Layer Trace [Y-1, Y-2]

The v0.3 payload attests a single composed decision (verdict, confidence, threshold, adversarial_result), but not the sequence of per-layer decisions that produced it. Two failure classes go undetected without per-layer provenance: (i) a "valid receipt, wrong decision" case where a well-formed signature covers an output produced by the wrong rule firing on the wrong premise, and (ii) post-hoc audit of "which layer refused what" when a claim halts.

v0.4 adds `layer_trace` as an optional array in the signed payload, attesting each in-pipeline decision layer as its own object.

### 4.1 The `layer_trace` array

A v0.4 payload MAY include `layer_trace`, an array of per-layer objects. Each object contains:

| Field | Req | Description |
|---|---|---|
| `layer` | MUST | Layer identifier (e.g. `scope-check`, `discriminate`). Unique within the array. |
| `action` | MUST | Layer verdict (e.g. `pass`, `verify`, `rewrite`). |
| `mode` | MUST | One of `recomputable` or `signed`. See §4.2. |
| `score`, `issues`, `dimensions_hit`, `reason` | MAY | Layer-specific detail; verifiers MUST ignore unrecognized members semantically per §5.2. |

**Order.** Emitters MUST place `layer_trace` entries in execution order. Verifiers MUST NOT reject on ordering divergence but MAY report a warning; the trace is not itself the chain (see §4.4).

### 4.2 Modes: `recomputable` vs `signed`

Every entry declares one mode:

- **`recomputable`** — the layer is a pure function of declared inputs (input text + prior layer findings) and produces the same output on rerun. A verifier can rerun the layer against the input and confirm the recorded action byte-for-byte. This is strictly stronger than signature-check for the layer's own claim: rerun proves the current rules produce this verdict, not merely that some rules were once signed. Requires no external judge in the layer's decision path.
- **`signed`** — the layer output is covered by the envelope signature but cannot be independently recomputed (external judge, LLM, human review). Verifiers rely on the signature to attest that the output was sealed at issue.

The two modes MAY appear in the same trace, keyed per layer, and MUST NOT be mixed within a single layer entry.

### 4.3 Compose, don't compete

A verifier reading `layer_trace` performs two independent checks that must agree: **rerun** proves the `recomputable` layers produce the observed verdict, and **signature** proves the verdict was sealed at issue. Divergence between them is itself a detectable failure class ("rerun disagrees with sealed"), which neither mode catches alone. Verifiers MUST NOT fold this divergence into core envelope validity — signature verification remains authoritative for byte-integrity — but SHOULD report it as a distinct status.

**What divergence indicates [Y-3].** A rerun/sealed split is not only detectable but diagnostic: it narrows the cause to post-hoc tampering (the sealed bytes no longer match what the declared rules produce) or runtime drift (the rules themselves moved since issuance). Verifiers SHOULD report which layers diverged, since the set of diverging layers is what distinguishes the two. Credit: @yun520-1 (HeartFlow); the integrity chain in production `src/core/verifier-grant.js` is the motivating implementation.

### 4.4 Chain-to-input, not per-layer [Y-2]

`layer_trace` does NOT chain per-layer `prev_hash` values. Per-layer chaining is brittle to pipeline evolution: a new layer inserted mid-pipeline invalidates every downstream hash, punishing exactly the evolution the pipeline should tolerate. Emitters and verifiers MUST NOT rely on per-layer prev_hash to validate the trace. The input-to-verdict binding is instead the composed decision's canonical bytes — which the envelope signature already covers — and layers order but do not hash-link.

**Layer boundary [Y-1].** A layer for `layer_trace` purposes is a single unit that: (i) receives one input structure (text + prior findings), (ii) produces one action decision with typed fields, and (iii) is either fully deterministic or fully external — never split. Implementations MAY span multiple skills or modules within one layer boundary, but MUST NOT split a single decision across layers.

### 4.5 Absence semantics

`layer_trace` follows three-state semantics, distinct from the general absent-vs-null rule of §5.1:

- **Absent** — no assertion. Interpreted as "issuer emits pre-trace envelopes" (a v0.3 issuer or a v0.4 issuer opting out); v0.3 verifiers already tolerate this per unrecognized-members rules.
- **`null`** — positive assertion: "this issuer runs no layered pipeline." A v0.4 issuer explicitly emitting `null` distinguishes "no trace exists to attest" from "trace was stripped." **This is the sole exception to §5.1's "MUST omit, never null" rule**; the value-bearing null carries semantic meaning specific to this field. Verifiers MUST NOT reject `layer_trace: null` as `null_field_present`.
- **Array** — trace present; verifiers apply §4.1–§4.4.

Stripping detection remains at the JWS layer: `layer_trace` sits inside the signed payload, so any post-sign edit — including turning an array into `null` or removing the field — breaks the canonical hash and fails signature verification.

## 5. Encoding rules

### 5.1 Absent versus null [P-10]

Optional fields that are not asserted MUST be **omitted**, never set to `null`. A v0.4 field present with value `null` is malformed (reject). This is the same rule v0.3 composed envelopes enforce, and byte-identical cross-implementation parity depends on it.

### 5.2 Unrecognized members

Verifiers MUST ignore unrecognized members for semantic purposes — subject to §2.1: ignoring is semantic only and never alters canonicalization input or signature verification bytes.

## 6. Version declaration and check-set selection [P-1]

`typ` declares the profile: envelopes using v0.4 fields MUST declare `application/vnd.verification.v0.4+jws` (or `+composed+jws`).

Check-set selection is **content-driven**: verifiers MUST apply the v0.4 checks of §2–§5 whenever any v0.4 field group (`evidence_seals`, `seals_complete`, `anchor_commitments`, `anchors`, `layer_trace`) is present — regardless of the declared `typ`. A v0.3-declared envelope carrying v0.4 fields MUST additionally be rejected as `typ_field_mismatch`: the mandatory checks of this extension are not issuer-selectable, and a declared-down envelope is treating them as opt-in. (The reject vector for this case is contributed by the independent implementer — same shape as at-r01.)

Payloads using v0.4 fields MUST declare `envelope_kind` `verification.v0.4+composed` (composed profile) and `receipt_version` `0.4.0-composed`; a disagreement between `envelope_kind` and the declared typ is rejected as `typ_field_mismatch`. All v0.4 field groups (`evidence`, `evidence_seals`, `seals_complete`, `anchor_commitments`, `layer_trace`) and the `anchors` array position per §3.1 are payload/envelope top-level members.

## 7. Conformance (vector classes for rev-1)

### 7.1 The `test-clock` conformance domain

Deterministic conformance vectors for §3.5's adjudication require a time proof
whose reading is fixed forever — which no real clock domain can provide (TSA
tokens age, certificate chains expire, chain state moves). The spec therefore
reserves one honest fiction, declared as such:

- `type: "test-clock"` — reserved for conformance vectors only.
- `anchor_data` is `{"reading": "<RFC 3339 UTC>"}`; the proof-derived clock
  reading (§3.1, §3.5) is that declared value, verbatim.
- Verifiers MUST accept `test-clock` as a valid clock domain only when
  operating in an explicitly enabled conformance mode, and MUST reject any
  envelope carrying a `test-clock` anchor in production verification
  (reject code: `test_clock_in_production`).
- `anchor_commitments.expected_types` MAY include `test-clock` in vectors;
  a commitment naming `test-clock` outside conformance mode is likewise a
  production reject.

This gives the shortfall and skewed-clock vector classes stable bytes and
fully offline reproduction: the vector declares `anchor_by`, commits to the
`test-clock` domain, and adjudicates against a declared reading — identical
results in any year, on any machine. A non-normative companion vector using a
genuine RFC 3161 token (real TSA, real `genTime`) accompanies the suite as a
sanity check that the same adjudication path holds against real cryptographic
time; it is marked time-pinned and expires with its certificate chain, and is
not part of the normative reject set.

**Accept:** sealed set matching evidence (ordered per §2.5) · `seals_complete` satisfied · single anchor of each type · batched anchor with valid §3.3 inclusion proof · commitment met within `anchor_by` (proof-derived readings).
**Reject:** `typ_field_mismatch` (typ-downgrade) · `evidence_seal_unmatched` · `evidence_seal_incomplete` · `null_field_present` (null-instead-of-absent, §5.1) · `evidence_seals_out_of_order` (§2.5 violation) · inclusion proof recomputing to wrong root · rfc3161 token over wrong hash.
**Extended/status:** snapshot `verified` / `contradicted` / `could_not_check` (with resolvability parameter) · `meets_commitment` / `short_of_commitment` / `not_yet_anchored` / `indeterminate_pending` · commitment shortfall past deadline · skewed-verifier-clock case.

Commitment-shortfall and skewed-verifier-clock cases are STATUS-domain conformance: core validity holds and adjudication proceeds per §3.5 vocabulary — verifiers MUST NOT fold anchoring status into core reject.
The reject set for typ-downgrade, null-vs-absent, seal ordering, commitment shortfall, and the skewed-clock case is produced independently by the second implementer with byte-identical Node output, alongside the reference Python vectors — two parties, one byte-level truth, before this text goes normative.

## 8. Compatibility & rollout

v0.3 verifiers ignore unknown fields semantically and continue to PASS valid v0.3 envelopes; §2.1 guarantees they verify the same bytes. v0.4-aware verifiers add the checks above under §6's content-driven rule. Reference implementations (Node + Python, byte-identical output) accompany the normative revision, per the project's standing conformance discipline.

---

*rev-1 exists because the draft was hostile-read before it was believed. Findings credited above; the diff is the argument. Further hostile readings welcome — that remains the point.*
