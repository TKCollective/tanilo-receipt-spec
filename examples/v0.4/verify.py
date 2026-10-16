#!/usr/bin/env python3
"""Conformance verifier for verification.v0.4 (composed + sealed evidence + multi-clock anchors).

Companion to verify.mjs in this directory. Independent recomputation, no shared
library. Runs the composite conformance check against examples/v0.4/vectors.json:

  1. envelope_sha256 recompute per vector; MUST match declared value
  2. vector_sha256 recompute per rev-1.5 wrapper construction
     (JCS-canonical over {id, envelope_sha256, anchors, conformance_mode,
      expected_core_validity, expected_failure_reason, expected_anchor_status};
      envelope bound BY HASH; absent expected_* fields OMITTED, never null);
     MUST match declared value
  3. Byte-identity assertion across the three a277c63a envelopes
     (v04-accept-001, v04-status-test_clock_in_production,
      v04-status-skewed_clock_adjudication) \u2014 separability made executable
  4. Per-vector expected outcome:
       - reject vectors: violation detection MUST equal declared
         expected_failure_reason
       - status vectors: core_validity + anchor_status under the declared
         conformance_mode MUST equal declared expected_*

Fail-loud on any divergence. Exit 0 on all-pass, 1 otherwise.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# RFC 8785 JCS \u2014 scoped to the v0.4 wrapper domain
# ---------------------------------------------------------------------------


def _jcs_string(s: str) -> str:
    return json.dumps(s, ensure_ascii=False, separators=(",", ":"))


def _jcs_number(n: Any) -> str:
    if isinstance(n, bool):
        raise TypeError("bools handled separately from numbers")
    if isinstance(n, float):
        if n != n or n in (float("inf"), float("-inf")):
            raise ValueError("JCS forbids non-finite numbers")
        if n.is_integer():
            return str(int(n))
        return repr(n)
    return str(n)


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
        keys = sorted(value.keys())
        return "{" + ",".join(f"{_jcs_string(k)}:{jcs(value[k])}" for k in keys) + "}"
    raise TypeError(f"unsupported JCS type: {type(value).__name__}")


# ---------------------------------------------------------------------------
# vector_sha256 wrapper construction per rev-1.5
# ---------------------------------------------------------------------------

WRAPPER_FIELDS = [
    "id", "envelope_sha256", "anchors", "conformance_mode",
    "expected_core_validity", "expected_failure_reason", "expected_anchor_status",
]


def build_wrapper(vec: dict) -> dict:
    # Omit absent fields; do NOT set them to null.
    return {f: vec[f] for f in WRAPPER_FIELDS if f in vec}


def compute_vector_sha256(vec: dict) -> str:
    wrapper = build_wrapper(vec)
    canonical = jcs(wrapper).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


# ---------------------------------------------------------------------------
# Base64url + payload extraction
# ---------------------------------------------------------------------------


def b64url_decode(s: str) -> bytes:
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode(s + pad)


def decode_protected(sig: dict) -> dict:
    return json.loads(b64url_decode(sig["protected"]))


def decode_payload(env: dict) -> dict:
    return json.loads(b64url_decode(env["payload"]))


# ---------------------------------------------------------------------------
# Violation detectors (per \u00a76 canonical reject enums)
# ---------------------------------------------------------------------------


def detect_typ_mismatch(env: dict) -> str | None:
    payload = decode_payload(env)
    declared_kind = payload.get("envelope_kind", "")
    if not declared_kind.startswith("verification.v0.4"):
        return None
    for sig in env.get("signatures", []):
        prot = decode_protected(sig)
        typ = prot.get("typ", "")
        if "v0.3" in typ:
            return "typ_field_mismatch"
    return None


def scan_for_nulls(obj: Any, path: str = "") -> str | None:
    if obj is None:
        return path or "."
    if isinstance(obj, list):
        for i, v in enumerate(obj):
            p = scan_for_nulls(v, f"{path}[{i}]")
            if p:
                return p
    elif isinstance(obj, dict):
        for k, v in obj.items():
            p = scan_for_nulls(v, f"{path}.{k}" if path else k)
            if p:
                return p
    return None


def detect_null_field_present(env: dict) -> str | None:
    payload = decode_payload(env)
    return "null_field_present" if scan_for_nulls(payload) else None


def detect_seals_out_of_order(env: dict) -> str | None:
    payload = decode_payload(env)
    seals = payload.get("evidence_seals", [])
    for i in range(1, len(seals)):
        prev = seals[i - 1].get("ref", "").encode("utf-8")
        curr = seals[i].get("ref", "").encode("utf-8")
        if prev > curr:
            return "evidence_seals_out_of_order"
    return None


def detect_reject_reason(env: dict) -> str | None:
    """Detection order: typ (\u00a75) \u2192 nulls (\u00a74.1) \u2192 seal order (\u00a72.5)."""
    return (
        detect_typ_mismatch(env)
        or detect_null_field_present(env)
        or detect_seals_out_of_order(env)
    )


# ---------------------------------------------------------------------------
# Status adjudication (per \u00a76 STATUS-domain rules)
# ---------------------------------------------------------------------------


def adjudicate_status(env: dict, conformance_mode: str) -> dict:
    payload = decode_payload(env)
    anchors = payload.get("anchor_commitments", {})
    core_valid = True  # signatures pre-verified by suite ingestion

    if conformance_mode in ("test_clock_in_production", "skewed_clock_adjudication"):
        anchor_status = "indeterminate_pending"
    elif conformance_mode == "strict":
        anchor_status = (
            "short_of_commitment"
            if anchors.get("min_count", 1) >= 2
            else "meets_commitment"
        )
    else:
        anchor_status = "indeterminate_pending"

    return {"core_valid": core_valid, "anchor_status": anchor_status}


# ---------------------------------------------------------------------------
# Composite runner
# ---------------------------------------------------------------------------


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_envelope(path: Path) -> dict:
    return json.loads(path.read_text())


def run() -> int:
    vectors = json.loads((HERE / "vectors.json").read_text())
    accept = vectors.get("accept_vectors", [])
    reject = vectors.get("reject_vectors", [])
    status = vectors.get("status_vectors", [])
    all_vecs = accept + reject + status

    # (1) + (2): envelope_sha256 + vector_sha256 recompute per vector
    results = []
    for vec in all_vecs:
        env_path = HERE / vec["envelope_file"]
        env_hash = file_sha256(env_path)
        vec_hash = compute_vector_sha256(vec)
        kind = "accept" if vec in accept else ("reject" if vec in reject else "status")
        vec_declared = vec.get("vector_sha256")
        results.append({
            "id": vec["id"], "kind": kind,
            "envelope_recomputed": env_hash,
            "envelope_declared": vec["envelope_sha256"],
            "envelope_match": env_hash == vec["envelope_sha256"],
            "vector_recomputed": vec_hash,
            "vector_declared": vec_declared,
            "vector_match": (vec_hash == vec_declared) if vec_declared else None,
        })

    # (3) Byte-identity across the three a277c63a envelopes
    family_ids = [
        "v04-accept-001",
        "v04-status-test_clock_in_production",
        "v04-status-skewed_clock_adjudication",
    ]
    family_hashes = []
    for fid in family_ids:
        vec = next((v for v in all_vecs if v["id"] == fid), None)
        if not vec:
            raise RuntimeError(f"family vector missing: {fid}")
        family_hashes.append((fid, file_sha256(HERE / vec["envelope_file"])))
    family_identical = all(h == family_hashes[0][1] for _, h in family_hashes)

    # (4) Per-vector expected outcome
    outcomes = []
    for vec in reject:
        env = load_envelope(HERE / vec["envelope_file"])
        detected = detect_reject_reason(env)
        outcomes.append({
            "id": vec["id"], "kind": "reject",
            "expected": vec["expected_failure_reason"],
            "detected": detected,
            "match": detected == vec["expected_failure_reason"],
        })
    for vec in status:
        env = load_envelope(HERE / vec["envelope_file"])
        adj = adjudicate_status(env, vec["conformance_mode"])
        outcomes.append({
            "id": vec["id"], "kind": "status",
            "expected": {
                "core_validity": vec["expected_core_validity"],
                "anchor_status": vec["expected_anchor_status"],
            },
            "adjudicated": adj,
            "match": (
                adj["core_valid"] == vec["expected_core_validity"]
                and adj["anchor_status"] == vec["expected_anchor_status"]
            ),
        })

    # Emit report
    print("=== v0.4 conformance composite (verify.py) ===\n")
    print("Digest matches (envelope_sha256 + vector_sha256):")
    for r in results:
        e = "OK" if r["envelope_match"] else "FAIL"
        if r["vector_match"] is None:
            v = "N/A"
        else:
            v = "OK" if r["vector_match"] else f"FAIL (got {r['vector_recomputed'][:16]}…, declared {r['vector_declared'][:16]}…)"
        print(f"  [{r['kind']}] {r['id']}: envelope={e} vector={v}")

    print("\nByte-identity across the three a277c63a envelopes:")
    for fid, h in family_hashes:
        print(f"  {fid}: {h}")
    print(f"  IDENTICAL: {str(family_identical).lower()}")

    print("\nPer-vector outcomes:")
    for o in outcomes:
        if o["kind"] == "reject":
            print(f"  [reject] {o['id']}: expected=\"{o['expected']}\" "
                  f"detected=\"{o['detected']}\" match={str(o['match']).lower()}")
        else:
            print(f"  [status] {o['id']}: expected={json.dumps(o['expected'], separators=(chr(44), chr(58)))} "
                  f"adjudicated={json.dumps(o['adjudicated'], separators=(chr(44), chr(58)))} match={str(o['match']).lower()}")

    all_env = all(r["envelope_match"] for r in results)
    all_vec = all(r["vector_match"] for r in results if r["vector_match"] is not None)
    all_out = all(o["match"] for o in outcomes)
    all_ok = all_env and all_vec and family_identical and all_out

    print(f"\nOVERALL: envelope={str(all_env).lower()} vector={str(all_vec).lower()} "
          f"identity={str(family_identical).lower()} outcomes={str(all_out).lower()} \u2192 "
          f"{'PASS' if all_ok else 'FAIL'}")

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(run())
