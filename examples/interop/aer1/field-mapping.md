# Field mapping: Tanilo receipt to AER-1 evidence reference

The AER-1 evidence reference for a Tanilo receipt carries three Tanilo values. This table says where each comes from in the Tanilo receipt and how a verifier recomputes or checks it. Definitions from draft-krausz-verification-state-03 and this repository's README ("Recompute canonical bytes": canonicalize `payload` per RFC 8785, SHA-256 it, compare to `canonical_sha256`).

| AER-1 member | Value for this receipt | Where it comes from | How a verifier checks it |
|---|---|---|---|
| `canonical_sha256` | `sha256-eaf9cdf889c088da4c5969fd179f07bed28b44d55fde9461e3f0fe8ccd439038` | The API response's top-level `canonical_sha256`; derived, not signed: it is the SHA-256 of the RFC 8785 canonical form of the JWS `payload` | base64url-decode `payload`; parse; serialize per RFC 8785 (keys sorted by UTF-16 code units, no whitespace, literal UTF-8); SHA-256 the UTF-8 bytes; lowercase hex; prefix `sha256-`. `tanilo-receipt-verify` returns it as `VerifyResult.canonical_sha256`. The exact bytes are in `payload.canonical.bin`; `shasum -a 256 payload.canonical.bin` prints the hex above |
| `url` | `https://raw.githubusercontent.com/TKCollective/tanilo-receipt-spec/9e88d972c0ce6bdf63d509c883d532b5438a25b0/examples/interop/aer1/receipt.jws.json` | This repository, pinned to the commit that added the file, so the bytes cannot change behind the URL | Fetch; recompute `canonical_sha256` as above and compare. The file's own SHA-256 is `d4b41548ec040a60445d1e424db76f2abc24a493b6279309ef9fd284de01b785`; it covers the file bytes, which is a different thing from the canonical hash |
| `kid` | `tanilo-2026-10-ed25519-7d885da9` | The JWS protected header (`{"alg":"EdDSA","kid":…,"typ":"application/vnd.verification.v0.3+composed+jws","role":"evaluated"}`); the API response also repeats it at top level | Look the `kid` up in https://tanilo.io/.well-known/jwks.json (Ed25519, `kty: OKP`), verify the JWS signature over `protected.payload`. A match shows which key signed; associating that key with Tanilo requires a key set you have authenticated |

Members an AER-1 verifier may also want, all inside the signed payload (`payload.decoded.json`):

| Member | Value | Meaning |
|---|---|---|
| `timestamp` | `2026-10-08T04:29:07.072Z` | The issuer's own statement of issue time; not independently established. The anchor, once available, gives an upper bound |
| `v_gate.verdict` | `halt` | Gate decision for the whole receipt |
| `check_results[0].state` | `contradicted` | The three-state result of the contract price check |
| `check_results[0].evidence.offer_sha256`, `terms_sha256`, `matched_term.term_sha256` | see payload | Digests over the offer, the supplied terms and the term used |
| `subject.claim_hash` | `sha256-…` of a claim text that is not stored | The claim this check was attached to; only its hash is in the receipt |

What a match on all three values establishes: the AER-1 receipt refers to exactly this signed payload, and the payload was signed by the holder of the key published under that `kid`. What it does not establish: that the supplied term is genuine or in force, that the claim is true, or that anything acted on the result.
