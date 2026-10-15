"""verify_detached_python.py — Verifies the detached RFC 7797 sample fixture.

The detached form is what production wire actually uses: the signature travels
in the receipt header/envelope, the payload travels beside it. This script
demonstrates the recomputation contract in ~40 lines of stdlib + cryptography:

  1. Load payload from `sample_payload.json`.
  2. JCS-canonicalize (RFC 8785) the payload — this is what the SIGNING INPUT
     covers, not `json.dumps` insertion order (April's silent-failure mode).
  3. Load the fixture kid's public key from the site JWKS (or the local
     fixture JWKS if the JWKS URL is unreachable).
  4. Construct the RFC 7797 signing input for b64=false:
        BASE64URL(UTF8(protected_header)) || '.' || payload_bytes
  5. Verify the signature.

The fixture kid is 'ao-fixture-detached-rfc7797-2026-07-*'. It is a fixture
key, publicly stated as such (see README §Attached vs detached), and its
private half is committed to this repo in `jwks-fixture-detached.json` so any
implementer can regenerate the bytes deterministically.

Usage:
    pip install cryptography requests
    python3 verify_detached_python.py
"""
from __future__ import annotations
import base64, hashlib, json, sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ed25519_guard import check_ed25519  # noqa: E402  (small-order guard, see ./ed25519_guard.py)

HERE = Path(__file__).parent


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ---- RFC 8785 JCS canonicalizer ----
_ESC = {'"':'\\"','\\':'\\\\','\b':'\\b','\f':'\\f','\n':'\\n','\r':'\\r','\t':'\\t'}
def _jcs_string(s: str) -> str:
    out = ['"']
    for ch in s:
        if ch in _ESC:
            out.append(_ESC[ch])
        elif ord(ch) < 0x20:
            out.append('\\u%04x' % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _jcs_number(x):
    if isinstance(x, bool):
        raise TypeError
    if isinstance(x, int):
        return str(x)
    if x != x or x in (float("inf"), float("-inf")):
        raise ValueError
    if x == int(x) and abs(x) < 1e21:
        return str(int(x))
    r = repr(x)
    assert float(r) == x and "e" not in r
    return r


def jcs(o):
    if o is None: return "null"
    if o is True: return "true"
    if o is False: return "false"
    if isinstance(o, str): return _jcs_string(o)
    if isinstance(o, (int, float)): return _jcs_number(o)
    if isinstance(o, list): return "[" + ",".join(jcs(v) for v in o) + "]"
    if isinstance(o, dict):
        items = sorted(o.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(_jcs_string(k) + ":" + jcs(v) for k, v in items) + "}"
    raise TypeError


def main() -> None:
    payload_obj = json.loads((HERE / "sample_payload.json").read_text())
    payload_bytes = jcs(payload_obj).encode()

    detached = json.loads((HERE / "sample_receipt_detached_jws.json").read_text())
    header = json.loads(b64u_dec(detached["protected"]))
    assert header["b64"] is False, "expected RFC 7797 b64:false header"
    assert "b64" in header["crit"], "expected b64 in crit"
    assert header["alg"] == "EdDSA"

    # Load fixture public key (from local repo; the same kid is also live at
    # https://agentoracle.co/.well-known/jwks.json for over-the-wire verifiers).
    local_jwks = json.loads((HERE / "jwks-fixture-detached.json").read_text())
    keys = local_jwks.get("public_only", {}).get("keys") or local_jwks["keys"]
    pub_jwk = next(k for k in keys if k["kid"] == header["kid"])
    pk = Ed25519PublicKey.from_public_bytes(b64u_dec(pub_jwk["x"]))
    # Small-order key or R, non-canonical encoding, S >= L, mixed-order key or R: rejected before the library verifies the signature.
    guard = check_ed25519(b64u_dec(pub_jwk["x"]), b64u_dec(detached["signature"]))
    if guard is not None:
        raise SystemExit(f"=== DETACHED VERIFICATION FAILED ===\n{guard}")

    signing_input = detached["protected"].encode("ascii") + b"." + payload_bytes
    pk.verify(b64u_dec(detached["signature"]), signing_input)

    print("=== DETACHED FIXTURE VERIFIED (RFC 7797 b64=false, JCS-canonical) ===")
    print(f"  kid:                        {header['kid']}")
    print(f"  alg:                        {header['alg']}")
    print(f"  b64:                        {header['b64']}")
    print(f"  crit:                       {header['crit']}")
    print(f"  cty:                        {header.get('cty')}")
    print(f"  payload JCS bytes:          {len(payload_bytes)}")
    print(f"  signing input bytes:        {len(signing_input)}")
    print(f"  payload sha256:             {hashlib.sha256(payload_bytes).hexdigest()}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"=== DETACHED VERIFICATION FAILED: {exc!r} ===", file=sys.stderr)
        sys.exit(1)
