"""contract-price-match/v0.1 -- an independent Python implementation.

Written by invinoveritas (https://invinoveritas.dev) from the published RULE TEXT
(the README of this folder and the docs at tanilo.io/docs/contract-price-check),
not from contract-price.js. Pure: standard library only, no network, no clock,
no randomness. Licensed under the Apache License 2.0 (see LICENSE in this folder).

    validate(input) -> the first invalid member path, or None
    recompute(input) -> (state, reason)   # state: verified | contradicted | indeterminate
    sha(value)       -> "sha256-" + hex SHA-256 of the RFC 8785 canonical JSON
"""
import hashlib, json, re
from datetime import datetime
from decimal import Decimal

RULE_ID = "contract-price-match/v0.1"


# ---------------------------------------------------------------- RFC 8785 (JCS) for the JSON this rule uses (strings, objects, arrays)
def jcs(v):
    if isinstance(v, dict):
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + jcs(v[k]) for k in sorted(v, key=lambda s: s.encode("utf-16-be"))) + "}"
    if isinstance(v, list):
        return "[" + ",".join(jcs(x) for x in v) + "]"
    if v is None or isinstance(v, bool):
        return json.dumps(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, int):
        return str(v)
    raise ValueError(f"JCS: unsupported value {v!r} (this rule's inputs are strings only)")


def sha(v):
    return "sha256-" + hashlib.sha256(jcs(v).encode()).hexdigest()


# ---------------------------------------------------------------- the rule, from the published text (8 steps, first failing step decides)
def _t(s):
    return datetime.strptime(s.replace("Z", "+0000"), "%Y-%m-%dT%H:%M:%S.%f%z" if "." in s else "%Y-%m-%dT%H:%M:%S%z")


_DEC = re.compile(r"^\d+(\.\d+)?$")                       # no sign, separator or exponent
_CUR = re.compile(r"^[A-Z]{3}$")
_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$")
_OFFER = {"unit_price", "currency", "unit", "quantity", "seller", "sku", "offered_at"}
_TERM_REQ = {"agreement_id", "version", "seller", "product_scope", "currency", "unit", "effective_from"}
_TERM_OPT = {"price_per_unit", "tiers", "effective_to", "supersedes"}


def _ts_ok(s):
    if not isinstance(s, str) or not _TS.match(s):
        return False
    try:
        _t(s); return True
    except ValueError:                                      # impossible calendar date
        return False


def validate(inp):
    """Schema check from the published rule text. -> the first invalid member path, or None. Unknown members are refused."""
    if not isinstance(inp.get("terms"), list):
        return "terms"
    o = inp.get("offer")
    if not isinstance(o, dict):
        return "offer"
    for k in o:
        if k not in _OFFER:
            return f"offer.{k}"
    for k in ("unit_price", "currency", "unit", "quantity", "seller", "sku", "offered_at"):
        v = o.get(k)
        if not isinstance(v, str) or v == "":
            return f"offer.{k}"
    if not _DEC.match(o["unit_price"]):
        return "offer.unit_price"
    if not _DEC.match(o["quantity"]) or Decimal(o["quantity"]) <= 0:
        return "offer.quantity"
    if not _CUR.match(o["currency"]):
        return "offer.currency"
    if not _ts_ok(o["offered_at"]):
        return "offer.offered_at"
    seen = set()
    for i, t in enumerate(inp["terms"]):
        p = f"terms[{i}]"
        if not isinstance(t, dict):
            return p
        for k in t:
            if k not in _TERM_REQ | _TERM_OPT:
                return f"{p}.{k}"
        for k in _TERM_REQ:
            if k not in t:
                return f"{p}.{k}"
        if ("price_per_unit" in t) == ("tiers" in t):
            return p                                        # exactly one of price_per_unit / tiers
        if "price_per_unit" in t and not (isinstance(t["price_per_unit"], str) and _DEC.match(t["price_per_unit"])):
            return f"{p}.price_per_unit"
        if "tiers" in t:
            for j, x in enumerate(t["tiers"]):
                for k in ("min_quantity", "price_per_unit"):
                    if not (isinstance(x.get(k), str) and _DEC.match(x[k])):
                        return f"{p}.tiers[{j}].{k}"
                if "max_quantity" in x and not (isinstance(x["max_quantity"], str) and _DEC.match(x["max_quantity"])
                                                and Decimal(x["max_quantity"]) > Decimal(x["min_quantity"])):
                    return f"{p}.tiers[{j}].max_quantity"
        if not _CUR.match(str(t["currency"])):
            return f"{p}.currency"
        if not _ts_ok(t["effective_from"]):
            return f"{p}.effective_from"
        if "effective_to" in t and (not _ts_ok(t["effective_to"]) or _t(t["effective_to"]) <= _t(t["effective_from"])):
            return f"{p}.effective_to"
        if (t["agreement_id"], t["version"]) in seen:
            return p                                        # same agreement version twice
        seen.add((t["agreement_id"], t["version"]))
    by = {(t["agreement_id"], t["version"]): t for t in inp["terms"]}
    for i, t in enumerate(inp["terms"]):                    # supersedes chains must not loop back
        cur, hops = t, 0
        while cur.get("supersedes") is not None and hops <= len(by):
            nxt = by.get((cur["agreement_id"], cur["supersedes"]))
            if nxt is None:
                break
            if nxt is t:
                return f"terms[{i}].supersedes"
            cur, hops = nxt, hops + 1
    return None


def recompute(inp):
    """-> (state, reason). state in verified | contradicted | indeterminate."""
    o, terms = inp["offer"], inp["terms"]
    t_off = _t(o["offered_at"])
    # 1 scope: seller + sku
    s = [t for t in terms if t["seller"] == o["seller"] and o["sku"] in t["product_scope"]["skus"]]
    if not s:
        return "indeterminate", "no_applicable_term"
    # 2 effective at offer time: effective_from <= offered_at < effective_to (no end = open)
    s = [t for t in s if _t(t["effective_from"]) <= t_off and ("effective_to" not in t or t_off < _t(t["effective_to"]))]
    if not s:
        return "indeterminate", "effective_interval_unresolved"
    # 3 declared precedence: drop a term another in-effect term of the SAME agreement declares it supersedes
    sup = {(t["agreement_id"], t["supersedes"]) for t in s if t.get("supersedes") is not None}
    s = [t for t in s if (t["agreement_id"], t["version"]) not in sup]
    # 4 exactly one
    if len(s) != 1:
        return "indeterminate", "precedence_unresolved"
    t = s[0]
    # 5 currency, 6 unit
    if t["currency"] != o["currency"]:
        return "indeterminate", "currency_mismatch"
    if t["unit"] != o["unit"]:
        return "indeterminate", "unit_mismatch"
    # 7 price for the quantity
    q = Decimal(o["quantity"])
    if "price_per_unit" in t:
        price = Decimal(t["price_per_unit"])
    else:
        m = [x for x in t["tiers"] if Decimal(x["min_quantity"]) <= q and ("max_quantity" not in x or q < Decimal(x["max_quantity"]))]
        if len(m) != 1:
            return "indeterminate", "tier_selection_unresolved"
        price = Decimal(m[0]["price_per_unit"])
    # 8 exact decimal compare
    return ("verified", None) if Decimal(o["unit_price"]) == price else ("contradicted", "price_mismatch")
