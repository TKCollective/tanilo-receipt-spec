# Live receipts

Receipts issued by the production service, kept here so published links can point to a fixed commit containing the exact bytes. Each file is the `receipt.jws` object (the JWS envelope) from one response, nothing else. The signed payload carries a claim hash, not the claim text.

## evaluate-demo-2026-09-30.json

| Field | Value |
|---|---|
| Issued (payload `timestamp` / `v_gate.signed_at`) | `2026-09-30T02:37:01.475Z` |
| Signing key (`kid`) | `ao-composed-2026-06-ed25519-c3abfce3` |
| Canonical SHA-256 (RFC 8785 bytes of the payload) | `sha256-608f91ecf5f397dc1e02ed6dd1924288bb466dcff918c310f6abf29c91d308c9` |
| File SHA-256 | `4fd391e6dcd6844f12f0f94ea0a050ee7a52b851804ebcc41a914b31e1c2abb8` |
| Added in commit | `0f3b0cd8db5bb33c55aa73c1229c8398be96a37e` |

**How it was produced.** One `POST https://agentoracle.co/evaluate` with the body `{"content": "Paris is the capital of France."}`, made on 30 September 2026. According to the operator's capture record, the response reported `meta.cache_hit: false` and `meta.receipt_status: "signed"`, so the receipt comes from a fresh evaluation, not from the cache; those fields are not part of the retained envelope. Only the response's `receipt.jws` object was saved, as this file. The issue time above is the payload's own timestamp, not the requester's clock.

**Verify it offline.** The signature is checked against the published JWKS with no call to the service. Fetch the key set once, then verify:

```
pip install tanilo-receipt-verify==0.2.4
curl -s https://raw.githubusercontent.com/TKCollective/tanilo-receipt-spec/0f3b0cd8db5bb33c55aa73c1229c8398be96a37e/examples/live-receipts/evaluate-demo-2026-09-30.json -o receipt.json
curl -s https://agentoracle.co/.well-known/jwks.json -o jwks.json
python3 -c "import json; from tanilo_receipt_verify import verify; r=verify(json.load(open('receipt.json')), jwks_by_issuer={'https://agentoracle.co/.well-known/jwks.json': json.load(open('jwks.json'))}); print(r.status, r.canonical_sha256)"
```

Expected output:

```
valid sha256-608f91ecf5f397dc1e02ed6dd1924288bb466dcff918c310f6abf29c91d308c9
```

The file hash can be checked with `shasum -a 256 receipt.json`, which should print the file SHA-256 above.

**What the signature does and does not show.** A valid signature under `ao-composed-2026-06-ed25519-c3abfce3` proves the payload bytes have not changed since they were signed and that the signature verifies under this published public key. It does not, on its own, prove the service issued the payload: from 23 June to 28 August 2026 the same key also signed bytes supplied by callers through routes that have since been closed, and a forged payload could carry any timestamp. A matching entry in the internal claim-fingerprint store can corroborate issuance; that check is run on request. See https://tanilo.io/incidents/2026-08-25-canned-verdicts.

## key-continuity-2026-10-02.json

The key-continuity statement issued at the signing-key cutover of 2 October 2026: one JWS General Serialization payload listing every published key with its status, signed twice — by the retiring key and by the new key — so a reader can check that the publisher of the old key is the publisher of the new one. Saved as the full response object: `jws`, `canonical_sha256`, `canonical_bytes_length`, `signers`.

| Field | Value |
|---|---|
| `statement_kind` | `tanilo.key-continuity.v1` |
| `issued_at` (payload) | `2026-10-02T03:03:46.220Z` |
| Signers (`kid`, in order) | `ao-composed-2026-06-ed25519-c3abfce3` (retired as of 2026-10-02), `tanilo-2026-10-ed25519-7d885da9` (current) |
| Keys listed (status) | `tanilo-2026-10-ed25519-7d885da9` current · `ao-composed-2026-06-ed25519-c3abfce3` retired · `ao-composed-2026-07-ed25519-3d44ba27` retired · `ao-receipt-2026-04-ed25519-f2753b7c` legacy · `ao-fixture-detached-rfc7797-2026-07-ed25519-0f8bf2a5` fixture |
| Canonical SHA-256 (RFC 8785 bytes of the payload) | `sha256-5c82cef917110df3a76b567252941cb55ef4aae00e57a33b052a4979178730f4` (1628 bytes) |
| File SHA-256 | `2d3027f6ebecfa2c8b922080c239a7ea3a54e529eecdfa3325760f685ddc6b99` |
| Added in commit | `6de1afb` |
| Also served at | `https://tanilo.io/.well-known/key-continuity.json` |

**What it does and does not show.** Both signatures verify against the published key set, so the holder of the retiring key and the holder of the new key signed the same statement at `issued_at`. As the statement's own text says, it does not establish the issuance time, service origin or evaluation provenance of any older signed payload.

**Verify it offline.** Both signatures are plain Ed25519 over the JWS signing input (`protected || "." || payload`); the keys are the entries with the two `kid`s in the published JWKS. With Python and the `cryptography` package:

```
curl -s https://agentoracle.co/.well-known/jwks.json -o jwks.json
python3 - <<'PY'
import json, base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
b = lambda x: base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
d = json.load(open("key-continuity-2026-10-02.json")); jws = d["jws"]
keys = {k["kid"]: k for k in json.load(open("jwks.json"))["keys"]}
for s in jws["signatures"]:
    kid = json.loads(b(s["protected"]))["kid"]
    Ed25519PublicKey.from_public_bytes(b(keys[kid]["x"])).verify(b(s["signature"]), (s["protected"] + "." + jws["payload"]).encode())
    print("valid", kid)
PY
```

## evaluate-demo-2026-10-02.json

| Field | Value |
|---|---|
| Issued (payload `timestamp` / `v_gate.signed_at`) | `2026-10-02T02:47:45.524Z` |
| Signing key (`kid`) | `tanilo-2026-10-ed25519-7d885da9`, protected header `role: evaluated` |
| Canonical SHA-256 (RFC 8785 bytes of the payload) | `sha256-baac7b814e66e90d729a51d7337fa3ea24d57daf623d8d545a0778f838447aff` |
| File SHA-256 | `08d76b029dbaddc3591e4fe59e9452454111687d2ca2d9bd16977b16ea432fcd` |
| Added in commit | `6de1afb` |

**How it was produced.** One `POST https://agentoracle.co/evaluate` with the body `{"content": "Paris is the capital of France."}`, made on 2 October 2026 immediately after the signing-key cutover: the first `/evaluate` receipt signed by the Tanilo key. The response reported `meta.cache_hit: false` and `meta.receipt_status: "signed"`; an identical call made directly afterwards was answered from the cache with the same receipt (`meta.receipt_replayed: true`). Only the response's `receipt.jws` object was saved, as this file. The issue time above is the payload's own timestamp, not the requester's clock.

**Verify it offline.** The receipt's `signature_meta.jwks_url` is `https://tanilo.io/.well-known/jwks.json`; the same key set is served at `https://api.tanilo.io/.well-known/jwks.json` and `https://agentoracle.co/.well-known/jwks.json`.

```
pip install tanilo-receipt-verify==0.2.4
curl -s https://tanilo.io/.well-known/jwks.json -o jwks.json
python3 -c "import json; from tanilo_receipt_verify import verify; r=verify(json.load(open('evaluate-demo-2026-10-02.json')), jwks_by_issuer={'https://tanilo.io/.well-known/jwks.json': json.load(open('jwks.json'))}); print(r.status, r.canonical_sha256)"
```

Expected output:

```
valid sha256-baac7b814e66e90d729a51d7337fa3ea24d57daf623d8d545a0778f838447aff
```

**What the signature does and does not show.** A valid signature under `tanilo-2026-10-ed25519-7d885da9` shows the payload bytes have not changed since signing and that the signature verifies under this published public key. This key has only ever signed payloads the service evaluated itself (its JWKS entry carries `role: evaluated`); it has never signed caller-supplied bytes. The signature does not independently prove how the checks ran, and it says nothing about whether the claim is true.
