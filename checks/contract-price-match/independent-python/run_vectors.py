#!/usr/bin/env python3
"""Run the independent Python implementation (cpm.py) against contract-price.vectors.json.

For every case it compares, against the stored result:
  * schema-invalid cases: that validate() refuses the input and names the same member;
  * all other cases: state and reason, and the three digests the evidence carries
    (offer_sha256, terms_sha256, and the matched term's term_sha256 when there is one).
It does NOT reproduce the rest of the evidence object (steps, expected/offered blocks, texts).

    python3 run_vectors.py [path/to/contract-price.vectors.json]

Exits 0 only when every compared field agrees.
"""
import hashlib, json, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cpm  # noqa: E402

path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "contract-price.vectors.json")
raw = open(path, "rb").read()
d = json.loads(raw)
assert d["rule_id"] == cpm.RULE_ID, d["rule_id"]

cases = d["cases"]
state_ok = invalid_ok = dig_ok = dig_n = 0
bad = []
for c in cases:
    res, inp = c["result"], c["input"]
    if res.get("invalid"):
        got = cpm.validate(inp)
        if got == res["member"]:
            invalid_ok += 1
        else:
            bad.append((c["id"], "invalid member", res["member"], got))
        continue
    member = cpm.validate(inp)
    if member:
        bad.append((c["id"], "refused a valid case", None, member))
        continue
    got = cpm.recompute(inp)
    if got == (res["state"], res.get("reason")):
        state_ok += 1
    else:
        bad.append((c["id"], "state/reason", (res["state"], res.get("reason")), got))
    ev = res.get("evidence") or {}
    pairs = [("offer_sha256", inp["offer"]), ("terms_sha256", inp["terms"])]
    mt = ev.get("matched_term")
    if mt and mt.get("term_sha256"):
        t = next(t for t in inp["terms"] if t["agreement_id"] == mt["agreement_id"] and t["version"] == mt["version"])
        pairs.append(("term_sha256", t))
    for k, v in pairs:
        if k in ev or k == "term_sha256":
            want = ev[k] if k in ev else mt["term_sha256"]
            dig_n += 1
            if cpm.sha(v) == want:
                dig_ok += 1
            else:
                bad.append((c["id"], k, want, cpm.sha(v)))

n_inv = sum(1 for c in cases if c["result"].get("invalid"))
print(f"rule {d['rule_id']}; vectors sha256 {hashlib.sha256(raw).hexdigest()}")
print(f"cases {len(cases)}: state+reason {state_ok}/{len(cases) - n_inv}, invalid member {invalid_ok}/{n_inv}, digests {dig_ok}/{dig_n}")
for b in bad:
    print("DISAGREE", b)
print("ALL AGREE" if not bad else f"{len(bad)} disagreement(s)")
sys.exit(0 if not bad else 1)
