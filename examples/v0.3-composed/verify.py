#!/usr/bin/env python3
"""Conformance verifier for verification.v0.3+composed (Phase 1, 2-signer JWS).

Independent recomputation of verify.mjs. Stdlib + `cryptography` only. A pass on
this verifier cross-checks the Node implementation against a second language
runtime — canonical bytes, AND_PRESENT composition, and Ed25519 signatures must
all agree byte-identically.

Vector-level checks mirror verify.mjs exactly:

  Accept vectors:
    1. JCS-canonicalize the payload object. SHA-256 must match expected.
    2. Recompute composed_decision under AND_PRESENT. Must equal signed.
    3. mycelium_trail_id is absent or a string — never null.
    4. Every JWS general-serialization signature must verify against the
       issuer JWKS matched by kid.

  Reject vectors:
    - comp-r01: at least one signature MUST fail
    - comp-r02: mycelium_trail_id === null MUST be flagged
    - comp-r03: composed_decision MUST disagree with AND_PRESENT recompute
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ed25519_guard import check_ed25519  # noqa: E402  (small-order guard, see ../ed25519_guard.py)

HERE = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# RFC 8785 JCS — scoped to the composed-envelope payload domain
# ---------------------------------------------------------------------------


def _jcs_string(s: str) -> str:
    # JSON.stringify-equivalent: escapes per RFC 8259 §7. json.dumps with the
    # default settings produces the same byte sequence for the strings used in
    # this domain (ASCII labels, hex digests, ISO timestamps, UUIDs).
    return json.dumps(s, ensure_ascii=False, separators=(",", ":"))


def _jcs_number(n: float | int) -> str:
    if isinstance(n, bool):
        raise TypeError("bools must be handled before numbers")
    if isinstance(n, float):
        if n != n or n in (float("inf"), float("-inf")):
            raise ValueError("JCS forbids non-finite numbers")
        if n.is_integer():
            return str(int(n))
        # ECMAScript Number.prototype.toString (RFC 8785 §3.2.2.3) and Python's
        # repr produce identical output for IEEE-754 double values in the
        # domain used here (confidence scores, integer ms timestamps). Both
        # emit the shortest round-tripping decimal representation.
        return repr(n)
    return str(int(n))


def jcs(value: Any) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    if isinstance(value, str):
        return _jcs_string(value)
    if isinstance(value, (int, float)):
        return _jcs_number(value)
    if isinstance(value, list):
        return "[" + ",".join(jcs(v) for v in value) + "]"
    if isinstance(value, dict):
        # UTF-16 code-unit ordering. For the ASCII keys in this suite, that's
        # identical to Python's default sort.
        keys = sorted(value.keys(), key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(_jcs_string(k) + ":" + jcs(value[k]) for k in keys) + "}"
    raise TypeError(f"unsupported JCS type: {type(value).__name__}")


# ---------------------------------------------------------------------------
# base64url + JWK helpers
# ---------------------------------------------------------------------------


def b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def load_jwks(filename: str) -> dict[str, Ed25519PublicKey]:
    data = json.loads((HERE / filename).read_text())
    by_kid: dict[str, Ed25519PublicKey] = {}
    for jwk in data["keys"]:
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
            raise ValueError(f"unexpected JWK shape for kid={jwk.get('kid')}")
        x = b64u_decode(jwk["x"])
        by_kid[jwk["kid"]] = Ed25519PublicKey.from_public_bytes(x)
    return by_kid


# ---------------------------------------------------------------------------
# Composition rule (AND_PRESENT)
# ---------------------------------------------------------------------------


def recompose_decision(payload: dict) -> str:
    verdicts: list[str] = []
    if payload.get("v_gate"):
        verdicts.append(payload["v_gate"]["verdict"])
    if payload.get("v_gate_skill"):
        verdicts.append(payload["v_gate_skill"]["verdict"])
    if payload.get("screen_ref"):
        verdicts.append(payload["screen_ref"]["verdict"])
    if not verdicts:
        return "halt"  # empty composition fails closed
    return "act" if all(v == "act" for v in verdicts) else "halt"


# ---------------------------------------------------------------------------
# Verify one composed envelope
# ---------------------------------------------------------------------------


def verify_one(
    payload: dict,
    jws: dict,
    jwks_by_issuer: dict[str, dict[str, Ed25519PublicKey]],
    expected_canonical_sha256: str | None = None,
) -> dict:
    # 1. mycelium_trail_id null check
    if "mycelium_trail_id" in payload and payload["mycelium_trail_id"] is None:
        return {"ok": False, "reason": "mycelium_trail_id_is_null"}

    # 2. JCS canonicalize + SHA-256
    canonical = jcs(payload).encode("utf-8")
    sha = "sha256-" + hashlib.sha256(canonical).hexdigest()
    if expected_canonical_sha256 and sha != expected_canonical_sha256:
        return {
            "ok": False,
            "reason": "canonical_sha256_mismatch",
            "computed": sha,
            "expected": expected_canonical_sha256,
        }

    # 3. Composed decision recompute under AND_PRESENT
    composed = recompose_decision(payload)
    if payload.get("composed_decision") != composed:
        return {
            "ok": False,
            "reason": "composed_decision_rule_violated",
            "signed": payload.get("composed_decision"),
            "recomputed": composed,
        }

    # 3b. screen_ref content-address recompute (Phase 2). Present iff the key
    # carries a non-null value. Recompute action_ref from the four-field preimage
    # rather than trusting the emitted hash. This binds the screening decision
    # recorded in `scope` (verdict class + entity set); the act/halt composition
    # verdict is bound by the signatures and the AND_PRESENT recompute above.
    # Presence/type tests are kept byte-for-byte identical to verify.mjs so the
    # two runtimes never disagree on a malformed screen_ref.
    if payload.get("screen_ref") is not None:
        screen_ref = payload["screen_ref"]
        screen = screen_ref.get("screen") if isinstance(screen_ref, dict) else None
        if not isinstance(screen, dict):
            return {"ok": False, "reason": "screen_ref_missing_preimage"}
        recomputed = hashlib.sha256(jcs(screen).encode("utf-8")).hexdigest()
        if recomputed != screen_ref.get("action_ref"):
            return {
                "ok": False,
                "reason": "screen_ref_action_ref_mismatch",
                "computed": recomputed,
                "claimed": screen_ref.get("action_ref"),
            }

    # 4. Verify every JWS signature
    payload_b64 = jws["payload"]
    payload_bytes = b64u_decode(payload_b64)
    if payload_bytes != canonical:
        return {"ok": False, "reason": "jws_payload_mismatch_canonical"}

    for sig_entry in jws["signatures"]:
        protected_json = json.loads(b64u_decode(sig_entry["protected"]).decode("utf-8"))
        kid = protected_json.get("kid")
        if not kid:
            return {"ok": False, "reason": "jws_missing_kid"}
        if protected_json.get("alg") != "EdDSA":
            return {
                "ok": False,
                "reason": "jws_alg_not_EdDSA",
                "alg": protected_json.get("alg"),
            }

        pub_key: Ed25519PublicKey | None = None
        issuer: str | None = None
        for issuer_name, by_kid in jwks_by_issuer.items():
            if kid in by_kid:
                pub_key = by_kid[kid]
                issuer = issuer_name
                break
        if pub_key is None:
            return {"ok": False, "reason": "jws_kid_not_found_in_any_jwks", "kid": kid}

        signing_input = (sig_entry["protected"] + "." + payload_b64).encode("ascii")
        sig_bytes = b64u_decode(sig_entry["signature"])
        # Small-order key or R, non-canonical encoding, S >= L: rejected before
        # the library is asked; a failed verification with its reason.
        guard = check_ed25519(pub_key.public_bytes(Encoding.Raw, PublicFormat.Raw), sig_bytes)
        if guard is not None:
            return {"ok": False, "reason": "signature_invalid", "guard": guard, "kid": kid, "issuer": issuer}
        try:
            pub_key.verify(sig_bytes, signing_input)
        except InvalidSignature:
            return {
                "ok": False,
                "reason": "signature_invalid",
                "kid": kid,
                "issuer": issuer,
            }

    return {"ok": True}


# ---------------------------------------------------------------------------
# Run the suite
# ---------------------------------------------------------------------------


def main() -> int:
    suite = json.loads((HERE / "vectors.json").read_text())
    jwks_by_issuer: dict[str, dict[str, Ed25519PublicKey]] = {}
    for issuer in suite["issuers"]:
        jwks_by_issuer[issuer["issuer"]] = load_jwks(issuer["jwks_file"])

    failures: list[str] = []
    accepted_ok = 0
    rejected_ok = 0

    for v in suite["accept_vectors"]:
        payload = json.loads((HERE / v["payload_file"]).read_text())
        jws = json.loads((HERE / v["jws_file"]).read_text())
        result = verify_one(
            payload,
            jws,
            jwks_by_issuer,
            expected_canonical_sha256=v["expected_canonical_sha256"],
        )
        if not result["ok"]:
            failures.append(
                f"{v['id']}: accept vector failed verification — {json.dumps(result)}"
            )
            continue
        accepted_ok += 1

    for v in suite["reject_vectors"]:
        payload = json.loads((HERE / v["payload_file"]).read_text())
        jws = json.loads((HERE / v["jws_file"]).read_text())
        result = verify_one(payload, jws, jwks_by_issuer)
        if result["ok"]:
            failures.append(
                f"{v['id']}: reject vector incorrectly PASSED — must have failed for {v['expected_failure']}"
            )
            continue
        if result["reason"] != v["expected_failure"]:
            failures.append(
                f"{v['id']}: reject vector failed for wrong reason — "
                f"expected {v['expected_failure']}, got {result['reason']}"
            )
            continue
        rejected_ok += 1

    total = len(suite["accept_vectors"]) + len(suite["reject_vectors"])
    if failures:
        print(f"FAIL: {len(failures)} failure(s) across {total} vectors\n")
        for f in failures:
            print(f"- {f}")
        return 1
    print(
        f"PASS: {total} vectors ({accepted_ok} accept verified end-to-end, "
        f"{rejected_ok} reject correctly refused)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
