# AER-1 interop, Tanilo half

A worked example for the AER-1 interop ([Brennan Zambo's half](https://gitlab.com/rambozambodotdev/zambo/-/tree/main/aer1-interop/tanilo)): one real Tanilo receipt that an AER-1 execution receipt can reference by evidence reference, with everything needed to verify it offline.

## The receipt

One `POST https://api.tanilo.io/v1/verify-facts` made on 2026-10-08 at 04:47 UTC (`request.json`, the body as sent; the offer's `offered_at` is 04:42:34Z, five minutes before the request). It asked for a `contract_price_match` check: an offer of USD 2.00 per call for `api.weather.v1` from `seller.example`, against one caller-supplied term, agreement `MSA-2026-014` version 1, priced at USD 1.00 per call. The result is `contradicted` (`offer_is: above_term_price`, `difference_per_unit: 1.00`), and the receipt is signed with `tanilo-2026-10-ed25519-7d885da9`.

| | |
|---|---|
| Receipt (JWS object only) | `receipt.jws.json`, file SHA-256 `3feb5a4fee5c2d4719c53c144ce143b2b76b3f96903d43f45dec01d4ad8cebd8` |
| Pinned raw URL | https://raw.githubusercontent.com/TKCollective/tanilo-receipt-spec/e1206d1a54ae23d7e0f6fed55cd85ca7149275e2/examples/interop/aer1/receipt.jws.json |
| `canonical_sha256` | `sha256-ca2fb84597076f9c8fac2d957a05bf21a11bd741e519879ff09ba78fd2305325` |
| `kid` | `tanilo-2026-10-ed25519-7d885da9` (Ed25519, in https://tanilo.io/.well-known/jwks.json) |
| Issued (payload `timestamp`) | `2026-10-08T04:47:35.336Z` |
| Added in commit | `e1206d1a54ae23d7e0f6fed55cd85ca7149275e2` |

Also here: `response.json` (the full response, of which the receipt is the `jws` member), `payload.decoded.json` (the signed payload, decoded and pretty-printed; the canonical form is not this file, see below), `payload.canonical.bin` (the exact RFC 8785 bytes that `canonical_sha256` is the SHA-256 of, 3,655 bytes), `jwks-tanilo-io-2026-10-08.json` (Tanilo's published key set as fetched on 2026-10-08, public keys only), `field-mapping.md` (the AER-1 evidence-reference members and how to recompute each), and `test_aer1_interop.py`.

## What the receipt records, and what it does not

It records the offer in full, digests of the offer and supplied terms, selected attributes and the digest of the matched term, the comparison amounts, the rule applied and the outcome. Retain request.json to replay the check against the complete supplied terms. A valid signature shows which key signed those bytes and that they have not changed since.

It does not show that the premise was true. The terms are supplied by the caller (`terms_source: caller_supplied`) and are not authenticated: nothing here shows the agreement exists, was signed by anyone, or is the one in force. The receipt says which supplied term it used and why. The claim text behind `subject.claim_hash` is not stored; only its hash is in the receipt. It also does not show that any tool call acted on the result; that is the AER-1 receipt's half.

## Verify the signature offline

Needs Python 3 and the published verifier, version 0.2.0 or later.

```
python3 -m pip install tanilo-receipt-verify==0.2.0
curl -sS -o receipt.json https://raw.githubusercontent.com/TKCollective/tanilo-receipt-spec/e1206d1a54ae23d7e0f6fed55cd85ca7149275e2/examples/interop/aer1/receipt.jws.json
curl -sS -o jwks.json https://tanilo.io/.well-known/jwks.json
python3 -c "import json; from tanilo_receipt_verify import verify; r = verify(json.load(open('receipt.json')), jwks_by_issuer={'https://tanilo.io/.well-known/jwks.json': json.load(open('jwks.json'))}, jwks_is_complete=True); print(r.status, r.canonical_sha256, [s['kid'] for s in r.signers])"
```

Expected output:

```
valid sha256-ca2fb84597076f9c8fac2d957a05bf21a11bd741e519879ff09ba78fd2305325 ['tanilo-2026-10-ed25519-7d885da9']
```

Downloading the key set from tanilo.io is a convenience, not authentication of it; associating the key with the issuer needs a key set you have authenticated as Tanilo's. `jwks_is_complete=True` tells the verifier that this key set is the whole trust list, so an unknown `kid` is refused rather than left unevaluated.

## Recompute canonical_sha256

`canonical_sha256` is `"sha256-"` followed by the lowercase hex SHA-256 of the UTF-8 bytes of the RFC 8785 (JCS) canonical form of the signed payload. The JWS protected header and the signature are not covered. Steps:

1. Take `payload` from the JWS object and base64url-decode it (no padding) to a JSON text.
2. Parse it, then serialize it per RFC 8785: object members sorted by UTF-16 code units, no whitespace, strings escaped as JSON.stringify does, literal UTF-8.
3. SHA-256 the UTF-8 bytes of that string; prefix the lowercase hex digest with `sha256-`.

`test_aer1_interop.py` does this with a canonicalizer written from the RFC, independent of the verifier, and checks the result against the value above; it also runs the signature check and asserts the receipt's content. Run `python3 test_aer1_interop.py` in this directory (needs `tanilo-receipt-verify`); no network.

## The anchor proof

Signed receipt hashes are queued for anchoring on GOAT Network and batched about once a day (no interval is guaranteed, and not every receipt is guaranteed a proof; see https://tanilo.io/docs/anchoring). This receipt was issued at 04:47 UTC on 2026-10-08, after that day's batch, so its proof is expected after the next run. Fetch and check it with the same package:

```
curl -sS https://api.tanilo.io/v1/anchor/proof/sha256-ca2fb84597076f9c8fac2d957a05bf21a11bd741e519879ff09ba78fd2305325 -o proof.json
python3 -c "
import json; from tanilo_receipt_verify import verify, verify_anchor, evm_contract_lookup
r = verify(json.load(open('receipt.json')), jwks_by_issuer={'https://tanilo.io/.well-known/jwks.json': json.load(open('jwks.json'))})
assert r.status == 'valid'
d = json.load(open('proof.json'))
assert 'proof' in d, 'no proof yet: ' + str(d.get('status', d))
proof = d['proof']
lookup = evm_contract_lookup('https://rpc.goat.network', trusted_contracts=['0xddCC4eb18b39a520b874046b91b748B5E8cE7C54'], chain_id=2345)
a = verify_anchor(r.canonical_sha256, proof, {'evm-contract': lookup}); print(a.status, a.anchored_at)"
```

At this check, no proof was available. A later scheduled run may include the hash, but inclusion is not guaranteed. Run the following verification command only after the endpoint returns a proof. Report the verifier's actual status; anchored requires both a valid inclusion path and a successful trusted lookup. An anchor shows the receipt's canonical payload existed by that block's timestamp; it does not show when the receipt was signed or that its claim is true. Pass the hash your verifier recomputed, never the proof's own `leaf`.

## The AER-1 half

Brennan's current fixture illustrates the proposed evidence-reference shape. The values below are supplied for an updated example; end-to-end binding and execution have not yet been verified. Brennan Zambo's AER-1 receipt and its evidence-reference shape are at https://gitlab.com/rambozambodotdev/zambo/-/tree/main/aer1-interop/tanilo. The three values the AER-1 receipt carries for this receipt are the `canonical_sha256`, the pinned raw URL and the `kid` in the table above; `field-mapping.md` says where each comes from and how a verifier of the AER-1 receipt recomputes them. The evidence-reference object itself (`type`, `url`, `kid`, `relationship`, `description`) is AER-1's; Tanilo's specification defines `canonical_sha256` and `kid`, not that object.
