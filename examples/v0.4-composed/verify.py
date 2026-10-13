#!/usr/bin/env python3
"""Conformance verifier for verification.v0.4+composed (Phase 3, 4-signer JWS).

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

    5. delegation_chain_ref, when present, must satisfy the four
       delegation-chain-ref-v1 invariants and its own content address.

  Reject vectors:
    - comp-r05: a hop widens scope relative to its parent
    - comp-r06: chain continuity is broken between adjacent hops
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
    if payload.get("delegation_chain_ref"):
        verdicts.append(payload["delegation_chain_ref"]["verdict"])
    if not verdicts:
        return "halt"  # empty composition fails closed
    return "act" if all(v == "act" for v in verdicts) else "halt"


# ---------------------------------------------------------------------------
# delegation-chain-ref-v1 (Phase 3)
# ---------------------------------------------------------------------------
# Derivations and invariants are taken unmodified from giskard09/argentum-core
# at 16e140a (docs/spec/delegation-chain-ref.md, examples/conformance/
# delegation-chain-ref/verify.py). Nothing is renamed and nothing is added to
# any action_ref preimage: delegation_chain_ref is envelope-only.


def action_ref_v1(preimage: dict) -> str:
    """action-ref-v1: lowercase-hex SHA-256 of the JCS canonical 4-field preimage."""
    return hashlib.sha256(jcs(preimage).encode("utf-8")).hexdigest()


def scope_is_narrower_or_equal(parent_scope: str, child_scope: str) -> bool:
    """True if child_scope is equal to or a strict sub-namespace of parent_scope.

    Namespace separator is ':'. A parent ending in ':*' matches any child under
    the prefix before the star. Ported from the argentum-core reference at
    16e140a so both runtimes apply the identical rule.
    """
    if parent_scope == child_scope:
        return True
    if parent_scope.endswith(":*"):
        prefix = parent_scope[:-2]
        return child_scope == prefix or child_scope.startswith(prefix + ":")
    return child_scope.startswith(parent_scope + ":")


def check_delegation_chain(block: dict) -> dict | None:
    """Return a failure dict, or None when every invariant holds.

    Checks run in the argentum-core order: content address, chain continuity,
    root anchoring, leaf anchoring, monotonic scope narrowing. Presence and type
    tests are kept byte-for-byte identical to verify.mjs so the two runtimes
    never disagree on a malformed block.
    """
    if not isinstance(block, dict):
        return {"ok": False, "reason": "delegation_chain_ref_missing_chain"}
    chain = block.get("chain")
    if not isinstance(chain, dict):
        return {"ok": False, "reason": "delegation_chain_ref_missing_chain"}
    hops = chain.get("hops")
    if not isinstance(hops, list) or len(hops) < 2:
        return {"ok": False, "reason": "delegation_chain_ref_hops_too_short"}
    leaf_preimage = block.get("leaf_preimage")
    if not isinstance(leaf_preimage, dict):
        return {"ok": False, "reason": "delegation_chain_ref_missing_leaf_preimage"}

    # 0. content address over the chain artifact
    recomputed = hashlib.sha256(jcs(chain).encode("utf-8")).hexdigest()
    if recomputed != block.get("delegation_chain_ref"):
        return {
            "ok": False,
            "reason": "delegation_chain_ref_mismatch",
            "computed": recomputed,
            "claimed": block.get("delegation_chain_ref"),
        }

    # 1. chain continuity
    for i in range(len(hops) - 1):
        if hops[i]["delegatee"] != hops[i + 1]["delegator"]:
            return {
                "ok": False,
                "reason": "delegation_chain_ref_chain_break",
                "hop": i,
                "delegatee": hops[i]["delegatee"],
                "next_delegator": hops[i + 1]["delegator"],
            }

    # 2. root anchoring
    if chain.get("root_delegator") != hops[0]["delegator"]:
        return {
            "ok": False,
            "reason": "delegation_chain_ref_root_anchor_mismatch",
            "root_delegator": chain.get("root_delegator"),
            "hop0_delegator": hops[0]["delegator"],
        }

    # 3. leaf anchoring, both parts
    computed_leaf = action_ref_v1(leaf_preimage)
    if computed_leaf != chain.get("leaf_action_ref"):
        return {
            "ok": False,
            "reason": "delegation_chain_ref_leaf_anchor_mismatch",
            "computed": computed_leaf,
            "claimed": chain.get("leaf_action_ref"),
        }
    if leaf_preimage.get("scope") != hops[-1]["scope"]:
        return {
            "ok": False,
            "reason": "delegation_chain_ref_scope_mismatch_at_leaf",
            "leaf_scope": leaf_preimage.get("scope"),
            "last_hop_scope": hops[-1]["scope"],
        }

    # 4. monotonic scope narrowing
    for i in range(1, len(hops)):
        parent = hops[i - 1]["scope"]
        child = hops[i]["scope"]
        if not scope_is_narrower_or_equal(parent, child):
            return {
                "ok": False,
                "reason": "delegation_chain_ref_scope_widening",
                "hop": i,
                "parent_scope": parent,
                "child_scope": child,
            }

    return None


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

    # 3c. delegation_chain_ref invariants (Phase 3). Present iff the key carries
    # a non-null value. The chain artifact and the leaf preimage travel with the
    # block so the verifier recomputes the chain ref and the leaf action_ref
    # rather than trusting either. This binds authority provenance; it says
    # nothing about action identity, and delegation_chain_ref never enters an
    # action_ref preimage.
    if payload.get("delegation_chain_ref") is not None:
        chain_failure = check_delegation_chain(payload["delegation_chain_ref"])
        if chain_failure is not None:
            return chain_failure

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
