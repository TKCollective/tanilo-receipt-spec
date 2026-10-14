"""
verify_python.py — End-to-end verification of an AgentOracle receipt using a
modern JOSE library that supports EdDSA / Ed25519.

We use `joserfc` (https://github.com/authlib/joserfc) instead of `python-jose`
because python-jose does not currently support EdDSA — see
https://github.com/mpdavis/python-jose/issues/319. `joserfc` is RFC 7515 / 7517 /
8037-compliant and supports the full set of JOSE algorithms including EdDSA.

Requirements:
    pip install joserfc requests

Usage:
    cd examples
    pip install -r requirements.txt
    python verify_python.py

Expected output: "VERIFIED OK" (exit code 0).
If signature / kid / algorithm does not match the live JWKS, raises and exits 1.
"""

from __future__ import annotations

import base64
import json
import sys
import warnings
from pathlib import Path

# joserfc emits an advisory warning that RFC 9864 prefers the "Ed25519"
# algorithm identifier over "EdDSA". EdDSA remains supported under RFC 7518
# and RFC 8037; the newer identifier is not yet widely deployed in JOSE
# libraries. Identifier migration is on our roadmap. Silenced for clean
# example output; does not affect verification correctness.
try:
    from joserfc.errors import SecurityWarning as _JoseSecurityWarning
    warnings.filterwarnings("ignore", category=_JoseSecurityWarning)
except Exception:
    warnings.filterwarnings("ignore", category=UserWarning)

import requests
from joserfc import jws as joserfc_jws
from joserfc.jwk import KeySet

JWKS_URL = "https://tanilo.io/.well-known/jwks.json"
HERE = Path(__file__).parent


def main() -> None:
    # Load attached flattened JWS — payload is inside `payload`, base64url-encoded.
    attached = json.loads((HERE / "sample_receipt_attached_jws.json").read_text())

    # Fetch live JWKS.
    resp = requests.get(JWKS_URL, timeout=10)
    resp.raise_for_status()
    jwks_doc = resp.json()
    key_set = KeySet.import_key_set(jwks_doc)

    # Reconstruct compact JWS form: <protected>.<payload>.<signature>
    compact = f"{attached['protected']}.{attached['payload']}.{attached['signature']}"

    # Inspect protected header for reporting.
    proto_header = json.loads(
        base64.urlsafe_b64decode(_pad_b64(attached["protected"])).decode("utf-8")
    )

    # Verify.
    result = joserfc_jws.deserialize_compact(
        compact, key_set, algorithms=["EdDSA"]
    )
    verified = json.loads(result.payload)
    cal = verified["confidence"]["calibration_anchor"]

    print("=== VERIFIED OK ===")
    print(f"  algorithm:                {proto_header['alg']}")
    print(f"  key id (kid):             {proto_header['kid']}")
    print(f"  content type:             {proto_header.get('cty')}")
    print(f"  receipt type:             {proto_header.get('typ')}")
    print(f"  jwks source:              {JWKS_URL}")
    print()
    print("--- Verified payload ---")
    print(f"  evaluation_id:            {verified['evaluation_id']}")
    print(f"  claim_text:               {verified['subject']['claim_text']}")
    print(f"  confidence.score:         {verified['confidence']['score']}")
    print(f"  confidence.scope:         {verified['confidence']['scope']}")
    print(f"  calibration.dataset:      {cal['dataset']}")
    print(f"  calibration.provisional:  {cal['provisional']}")
    print(f"  signature.valid_until:    {verified['signature_meta']['valid_until']}")
    print(f"  calibration.valid_until:  {verified['confidence']['valid_until']}")
    print(f"  evidence.valid_until:     {verified['evidence']['valid_until']}")


def _pad_b64(s: str) -> str:
    """Add base64url padding so urlsafe_b64decode is happy."""
    return s + "=" * (-len(s) % 4)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        print("=== VERIFICATION FAILED ===", file=sys.stderr)
        print(repr(exc), file=sys.stderr)
        sys.exit(1)
