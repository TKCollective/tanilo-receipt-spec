# AgentOracle Receipt Verification — Working Examples

End-to-end verifying examples for the receipt format described in the parent
[README](../README.md). Both examples fetch the live JWKS from the production
endpoint and verify a real detached JWS against a real payload.

**Live JWKS endpoint:** https://agentoracle.co/.well-known/jwks.json

## What's in this directory

| File | Purpose |
| --- | --- |
| `sample_payload.json` | Example `claim + evidence + confidence` payload — the canonical content the signature commits to |
| `sample_receipt_attached_jws.json` | Flattened JWS (attached payload) — used by the verifying examples for cross-language byte stability |
| `sample_receipt_detached_jws.json` | Flattened JWS (detached) — for reference; matches the production wire format |
| `verify_node.mjs` | Node.js verifier using [`jose`](https://github.com/panva/jose) |
| `verify_python.py` | Python verifier using [`joserfc`](https://github.com/authlib/joserfc) (EdDSA-supported; python-jose does not yet support EdDSA — [issue 319](https://github.com/mpdavis/python-jose/issues/319)) |
| `package.json` | Node deps (jose) |
| `requirements.txt` | Python deps (joserfc, requests) |

## Run the Node verifier

```bash
cd examples
npm install
node verify_node.mjs
```

Expected output:

```
=== VERIFIED OK ===
  algorithm:                EdDSA
  key id (kid):             ao-receipt-2026-04-ed25519-f2753b7c
  content type:             application/json
  receipt type:             application/vnd.agentoracle.receipt+jws
  jwks source:              https://agentoracle.co/.well-known/jwks.json
  ...
```

## Run the Python verifier

```bash
cd examples
pip install -r requirements.txt
python verify_python.py
```

Same expected output under `joserfc`.

> **Note on Python library choice:** `python-jose` is the historically popular
> JOSE library for Python but does not implement EdDSA / Ed25519
> ([issue 319](https://github.com/mpdavis/python-jose/issues/319), open since 2023).
> `joserfc` (Authlib) is RFC 7515 / 7517 / 8037-compliant and supports the
> full algorithm set. PyJWT also supports EdDSA via its OKP algorithm if a
> JWT-style API is preferred.

## Attached vs. detached

The production wire format is **detached** JWS (RFC 7797, `b64=false` flow) —
the receipt body transports the payload separately from the signature to
minimize header size on every `/evaluate` response. The signing input follows
RFC 7797 §3 exactly:

```
BASE64URL(UTF8(JWS Protected Header)) || '.' || JWS Payload
```

— with the payload transported as raw octets (no base64 wrapping), which is
what the `"b64": false` header + `"crit": ["b64"]` marker together declare.
The payload bytes are **RFC 8785 (JCS)** canonicalized before signing so that
two independent implementations sign over byte-identical input.

The verifying examples here come in two languages and two forms:

| Script | Form | Key |
|---|---|---|
| `verify_node.mjs`         | Attached (flattened JWS) | Production `ao-receipt-2026-04-ed25519-*` in the live JWKS |
| `verify_python.py`        | Attached (flattened JWS) | Production `ao-receipt-2026-04-ed25519-*` in the live JWKS |
| `verify_detached_node.mjs` | Detached (RFC 7797 `b64=false`) | Fixture-suite `ao-fixture-detached-rfc7797-2026-07-*` — see below |
| `verify_detached_python.py`| Detached (RFC 7797 `b64=false`) | Fixture-suite `ao-fixture-detached-rfc7797-2026-07-*` — see below |

## What you're seeing here

1. **The public key is live.** `GET https://agentoracle.co/.well-known/jwks.json`
   returns an RFC 7517 JWK Set with four Ed25519 keys — one legacy receipt
   signer, two composed-envelope signers (site + gateway), and one
   fixture-suite key for the detached sample. All four are clearly labeled by
   `kid`.
2. **The attached sample was signed with a production key.**
   `sample_receipt_attached_jws.json` was signed with the matching private
   half of `ao-receipt-2026-04-ed25519-f2753b7c`; that private half lives only
   in the issuer environment and is never in this repo.
3. **The detached sample was signed with a fixture-suite key, published in
   the JWKS, stated plainly — not a production key.**
   `sample_receipt_detached_jws.json` is signed with the fixture kid
   `ao-fixture-detached-rfc7797-2026-07-*`. Its keypair — both public and
   private halves — is committed to this repo at `jwks-fixture-detached.json`
   because reproducibility is the whole point of a fixture: any implementer
   can run `generate_detached_fixture.py` and get byte-identical output to
   the committed fixture, or `verify_detached_python.py` / `.mjs` and confirm
   the committed bytes verify. No production key is ever exposed by this
   design; production kids are in the same JWKS but their private halves are
   not published.
4. **Standard libraries verify the attached form.** Both `jose` (Node, 9k+
   GitHub stars) and `joserfc` (Python, Authlib) verify cleanly with no
   custom parsing.
5. **The detached verifiers are minimal and dependency-only-on-stdlib
   (`cryptography` for Ed25519 in Python; only `node:crypto` in Node) so a
   stranger can read the whole recomputation contract in ~50 lines.**

## Ed25519 input guard

`ed25519_guard.py` is a byte-identical copy of `tanilo_receipt_verify/ed25519_guard.py` from
[`tanilo-receipt-verify` 0.2.1](https://pypi.org/project/tanilo-receipt-verify/0.2.1/)
(sha256 `2fb65a919a4aecf83d1345b319de2a984fe8c8e0b5d198433093343a0b3243e3`).
`ed25519_guard.mjs` is its JavaScript port, written to apply the same decoding, checks and
reason codes; on 53 shared key and signature pairs it returns the same reason as the Python
file.

Before the library runs, the public key must decode per RFC 8032 section 5.1.3 (including:
x = 0 with the sign bit set is invalid), be canonically encoded (y < p) and not be a small-order
point (order 1, 2, 4 or 8, in any encoding); the signature's R must decode and not be
small-order; S must satisfy 0 <= S < L (section 5.1.7). The guard returns a rejection reason,
or no reason when these input checks pass; passing the guard does not establish that the
signature is valid.

Under normal RFC 8032 signing, small-order R is negligibly unlikely but not impossible. Version
0.2.1 intentionally rejects equation-valid signatures with small-order R, including ones a key
holder constructs deliberately.

Not checked: a mixed-order key or R (a point outside the prime-order subgroup that is not
itself small-order; Taming case 3). RFC 8032 does not require blanket rejection of mixed-order
points. Passing the guard leaves signature verification to the library; in our recorded run, it
accepted case 3 and rejected cases 4 and 5.

The guard is called by `verify_detached_node.mjs`, `verify_detached_python.py`, and by
`verify.mjs` and `verify.py` under `v0.3-composed/` and `v0.4-composed/`. `verify_node.mjs`
(jose) and `verify_python.py` (joserfc) do not call it; they rely on their library.

```bash
node --test examples/ed25519_guard.test.mjs
```

## Questions / PRs

Open an issue on this repo or join the
[Coinbase Developer Discord #x402 thread](https://discord.gg/cdp).
