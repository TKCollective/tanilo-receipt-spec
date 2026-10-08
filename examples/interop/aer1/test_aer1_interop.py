"""Offline check of the AER-1 interop receipt (examples/interop/aer1/).

Recomputes canonical_sha256 from the saved JWS payload (base64url-decode, RFC 8785
canonicalize, SHA-256, lowercase hex, "sha256-" prefix) with an independent
canonicalizer written here from the RFC, and verifies the Ed25519 signature against
the saved copy of tanilo.io/.well-known/jwks.json with tanilo-receipt-verify 0.2.0.
No network. Run: python3 test_aer1_interop.py  (or pytest).
"""
import base64, hashlib, json, pathlib, sys

HERE = pathlib.Path(__file__).resolve().parent
JWKS_URL = "https://tanilo.io/.well-known/jwks.json"
EXPECTED_SHA = "sha256-eaf9cdf889c088da4c5969fd179f07bed28b44d55fde9461e3f0fe8ccd439038"
EXPECTED_KID = "tanilo-2026-10-ed25519-7d885da9"


def b64url_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jcs(v):
    """RFC 8785 for the value types this payload uses: objects, arrays, strings,
    integers, booleans, null. Keys sorted by UTF-16 code units; no whitespace;
    strings escaped as JSON.stringify does. Floats are refused on purpose."""
    if v is None: return "null"
    if v is True: return "true"
    if v is False: return "false"
    if isinstance(v, int) and not isinstance(v, bool): return str(v)
    if isinstance(v, float): raise TypeError("float in payload; RFC 8785 number formatting not implemented here")
    if isinstance(v, str): return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list): return "[" + ",".join(jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + jcs(v[k]) for k in keys) + "}"
    raise TypeError(type(v))


def test_canonical_sha256_recomputes():
    jws = json.loads((HERE / "receipt.jws.json").read_text())
    payload = json.loads(b64url_decode(jws["payload"]).decode("utf-8"))
    got = "sha256-" + hashlib.sha256(jcs(payload).encode("utf-8")).hexdigest()
    assert got == EXPECTED_SHA, got
    assert json.loads((HERE / "response.json").read_text())["canonical_sha256"] == EXPECTED_SHA
    assert json.loads((HERE / "payload.decoded.json").read_text()) == payload
    canonical = (HERE / "payload.canonical.bin").read_bytes()
    assert canonical == jcs(payload).encode("utf-8")
    assert "sha256-" + hashlib.sha256(canonical).hexdigest() == EXPECTED_SHA


def test_signature_verifies_offline_with_tanilo_receipt_verify():
    from tanilo_receipt_verify import verify, __version__
    assert tuple(int(x) for x in __version__.split(".")[:2]) >= (0, 2), __version__
    jws = json.loads((HERE / "receipt.jws.json").read_text())
    jwks = json.loads((HERE / "jwks-tanilo-io-2026-10-08.json").read_text())
    r = verify(jws, jwks_by_issuer={JWKS_URL: jwks}, jwks_is_complete=True)
    assert r.status == "valid", (r.status, r.errors, r.indeterminate_reason)
    assert r.canonical_sha256 == EXPECTED_SHA
    assert [s["kid"] for s in r.signers] == [EXPECTED_KID]


def test_result_is_contradicted_offer_above_term():
    payload = json.loads((HERE / "payload.decoded.json").read_text())
    (cr,) = payload["check_results"]
    assert cr["check_type"] == "contract_price_match" and cr["state"] == "contradicted"
    ev = cr["evidence"]
    assert ev["offered"]["unit_price"] == "2.00" and ev["expected"]["price_per_unit"] == "1.00"
    assert ev["offer_is"] == "above_term_price" and ev["difference_per_unit"] == "1.00"
    assert ev["terms_source"] == "caller_supplied" and ev["matched_term"]["agreement_id"] == "MSA-2026-014"


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn(); print("PASS", name)
