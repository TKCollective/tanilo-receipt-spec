#!/usr/bin/env python3
"""Build v04-accept-001 — deterministic composition + cross-check against Pote's hand-signed AT leg.

INPUT: Pote's b64u payload string (whitespace-stripped) as first arg or via stdin.

CONTRACT (Claude 2026-07-30, executing parked_tasks/v04_accept_001_signing.md):
  1. base64url-decode input → assert sha256 begins '0664f60e' and length == 1823
  2. Confirm JCS-canonical byte-identity (parse + re-canonicalize, must match input)
  3. Derive AO + AT Ed25519 keys from the fixture-suite seed convention
     (`agentoracle-receipt-spec::v0.3-composed::{label}` — same as v0.3-composed build_fixtures.py)
  4. Sign AO leg with kid `ao-fixture-v0.3-composed-2026-06`, typ v0.4+composed+jws
  5. Sign AT leg deterministically with the same convention (kid `at-fixture-v0.3-composed-2026-06`)
  6. CROSS-CHECK: Pote's AT signature MUST byte-match the deterministic AT signature we produced.
     If any single-byte divergence: HALT + report (per parked-task rule 4).
     Pote's signature: fWTMae9shEBnV_EqWSCSzFfHXxRPfj3bnIyEcCp_sctOzkOL5yQXiEpLRtcfW1dK4qbn13svlDGwkB4jXM6xCg
  7. Compose General JWS JSON (payload_b64, signatures = [AO, AT] — AO first, same order as v0.3 fixtures)
  8. Write examples/v0.4/v04-accept-001.json
  9. Print composed envelope sha256 + vectors.json entry for manual paste
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HERE = Path(__file__).parent
SPEC_ROOT = HERE.parent.parent

# ---- constants pinned by Claude 2026-07-30 memo ----
EXPECTED_PAYLOAD_SHA256_PREFIX = "0664f60e"
EXPECTED_PAYLOAD_LEN = 1823
POTE_AT_SIGNATURE_B64 = "fWTMae9shEBnV_EqWSCSzFfHXxRPfj3bnIyEcCp_sctOzkOL5yQXiEpLRtcfW1dK4qbn13svlDGwkB4jXM6xCg"

AO_KID = "ao-fixture-v0.3-composed-2026-06"
AT_KID = "at-fixture-v0.3-composed-2026-06"
JWS_TYP = "application/vnd.verification.v0.4+composed+jws"

# ---- byte primitives ----
def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def b64u_json(obj: Any) -> str:
    """Protected header: compact JSON, no whitespace. Header is NOT JCS — it's the
    encoder's responsibility to produce identical bytes if recomputed. Must match
    v0.3 build_fixtures.py's exact form: json.dumps(sort_keys=False, separators=(',',':')).
    """
    return b64u(json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))

# ---- RFC 8785 JCS (mirror of v0.3-composed/build_fixtures.py) ----
def _jcs_string(s: str) -> str:
    out = ['"']
    for ch in s:
        cp = ord(ch)
        if ch == '"': out.append('\\"')
        elif ch == "\\": out.append("\\\\")
        elif ch == "\b": out.append("\\b")
        elif ch == "\f": out.append("\\f")
        elif ch == "\n": out.append("\\n")
        elif ch == "\r": out.append("\\r")
        elif ch == "\t": out.append("\\t")
        elif cp < 0x20: out.append(f"\\u{cp:04x}")
        else: out.append(ch)
    out.append('"'); return "".join(out)

def _jcs_number(n) -> str:
    if isinstance(n, bool): raise TypeError
    if isinstance(n, int): return str(n)
    if not isinstance(n, float): raise TypeError(f"unsupported number: {type(n)}")
    if n != n or n in (float("inf"), float("-inf")): raise ValueError
    if n == 0: return "0"
    return repr(n)

def jcs(v: Any) -> str:
    if v is True: return "true"
    if v is False: return "false"
    if v is None: return "null"
    if isinstance(v, str): return _jcs_string(v)
    if isinstance(v, (int, float)): return _jcs_number(v)
    if isinstance(v, list): return "[" + ",".join(jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v.keys(), key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(_jcs_string(k) + ":" + jcs(v[k]) for k in keys) + "}"
    raise TypeError(f"unsupported JCS type: {type(v)}")

# ---- key derivation (same as v0.3-composed/build_fixtures.py) ----
def derive_ed25519(label: str) -> Ed25519PrivateKey:
    seed = hashlib.sha256(f"agentoracle-receipt-spec::v0.3-composed::{label}".encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def main(payload_b64_raw: str) -> None:
    # Whitespace-stripped, as Claude specified
    payload_b64 = "".join(payload_b64_raw.split())

    # ---- Step 1: decode + verify digest + length ----
    payload_bytes = b64u_dec(payload_b64)
    digest = hashlib.sha256(payload_bytes).hexdigest()
    print(f"  payload length:     {len(payload_bytes)} bytes  (expect {EXPECTED_PAYLOAD_LEN})")
    print(f"  payload sha256:     {digest}")
    if len(payload_bytes) != EXPECTED_PAYLOAD_LEN:
        print(f"  ✗ FINDING: length mismatch"); sys.exit(2)
    if not digest.startswith(EXPECTED_PAYLOAD_SHA256_PREFIX):
        print(f"  ✗ FINDING: sha256 does not begin '{EXPECTED_PAYLOAD_SHA256_PREFIX}'"); sys.exit(2)
    print(f"  ✓ digest+length match Claude's memo")

    # ---- Step 2: JCS canonicalization round-trip ----
    payload_obj = json.loads(payload_bytes.decode("utf-8"))
    recanonicalized = jcs(payload_obj).encode("utf-8")
    if recanonicalized != payload_bytes:
        print(f"  ✗ FINDING: payload is NOT JCS-canonical (input {len(payload_bytes)} bytes, recanonicalized {len(recanonicalized)} bytes)")
        # Show the first differing byte
        for i, (a, b) in enumerate(zip(payload_bytes, recanonicalized)):
            if a != b:
                print(f"    first diff at byte {i}: input=0x{a:02x} recanon=0x{b:02x}")
                print(f"    ...input context:    {payload_bytes[max(0,i-20):i+20]!r}")
                print(f"    ...recanon context:  {recanonicalized[max(0,i-20):i+20]!r}")
                break
        sys.exit(2)
    print(f"  ✓ JCS round-trip byte-identical")

    # ---- Step 3-4: derive keys, sign AO leg ----
    ao_sk = derive_ed25519("agentoracle-issuer-v1")
    at_sk = derive_ed25519("agenttrust-issuer-v1")
    ao_pub_b64 = b64u(ao_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    at_pub_b64 = b64u(at_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    assert ao_pub_b64 == "pB-ci4MJkokSrVh9U3DaEWUMaveXlcz8mv7gbhar_rA", "AO public key drift"
    assert at_pub_b64 == "J_FsTYGoR2-STAkta-3UgbWLSou84Xi4oOSd-SY9bfE", "AT public key drift"
    print(f"  ✓ AO + AT fixture public keys match published JWKS")

    protected_ao = {"alg": "EdDSA", "kid": AO_KID, "typ": JWS_TYP}
    protected_at = {"alg": "EdDSA", "kid": AT_KID, "typ": JWS_TYP}
    protected_ao_b64 = b64u_json(protected_ao)
    protected_at_b64 = b64u_json(protected_at)

    signing_input_ao = (protected_ao_b64 + "." + payload_b64).encode("ascii")
    signing_input_at = (protected_at_b64 + "." + payload_b64).encode("ascii")

    ao_sig = ao_sk.sign(signing_input_ao)
    at_sig = at_sk.sign(signing_input_at)
    ao_sig_b64 = b64u(ao_sig)
    at_sig_b64 = b64u(at_sig)
    print(f"  AO signature:       {ao_sig_b64}")
    print(f"  AT signature:       {at_sig_b64}")

    # ---- Step 5: CROSS-CHECK against Pote's hand-signed AT ----
    if at_sig_b64 != POTE_AT_SIGNATURE_B64:
        print(f"\n  ✗ FINDING: deterministic AT signature does not byte-match Pote's hand-signed value.")
        print(f"    deterministic: {at_sig_b64}")
        print(f"    pote's:        {POTE_AT_SIGNATURE_B64}")
        print(f"    HALT per parked-task rule 4. Do not push.")
        sys.exit(3)
    print(f"  ✓ CROSS-CHECK PASSES: deterministic AT signature byte-matches Pote's hand-signed AT leg")

    # ---- Step 6: compose General JWS JSON ----
    composed = {
        "payload": payload_b64,
        "signatures": [
            {"protected": protected_ao_b64, "signature": ao_sig_b64},
            {"protected": protected_at_b64, "signature": at_sig_b64},
        ],
    }
    composed_json = json.dumps(composed, indent=2, ensure_ascii=False) + "\n"
    composed_bytes = composed_json.encode("utf-8")
    composed_sha = hashlib.sha256(composed_bytes).hexdigest()

    out_path = HERE / "v04-accept-001.json"
    out_path.write_text(composed_json, encoding="utf-8")
    print(f"\n  ✓ wrote {out_path}")
    print(f"    envelope size:  {len(composed_bytes)} bytes")
    print(f"    envelope sha256: {composed_sha}")

    # ---- Step 7: vectors.json entry (print for manual paste into new v0.4 vectors.json) ----
    canonical_hash = "sha256-" + digest
    entry = {
        "id": "v04-accept-001",
        "description": "First v0.4 accept vector — ratified baseline from PR #5 discussion; AO+AT composed envelope with v0.4 fields per rev-1.2 pins (P-13..18). AT leg hand-signed by @poteshniy from AgentTrust; byte-matched deterministically by build_fixtures via the fixture-suite seed convention.",
        "envelope_file": "v04-accept-001.json",
        "expected_canonical_sha256": canonical_hash,
        "signer_kids": [AO_KID, AT_KID],
        "envelope_kind": payload_obj.get("envelope_kind"),
        "receipt_version": payload_obj.get("receipt_version"),
    }
    print(f"\n  vectors.json v04-accept-001 entry:")
    print(json.dumps(entry, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    if len(sys.argv) > 1:
        payload_input = sys.argv[1]
    else:
        payload_input = sys.stdin.read()
    if not payload_input.strip():
        print("USAGE: build_accept_001.py '<payload_b64>' OR pipe b64 via stdin", file=sys.stderr)
        sys.exit(1)
    main(payload_input)
