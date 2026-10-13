#!/usr/bin/env python3
"""Vector -> requirement mapping for the receipt-verify registry (methodology v0.4.5 §2.7).

Reads the vector manifests at the corpus snapshot commit (git show, not the
working tree), attaches the
per-vector mapping judgments recorded below, derives the reverse view
(requirement -> vectors) from the forward view, checks every count against the
manifests, and writes mapping.json. Run from the repository root:

    python3 mappings/receipt-verify-registry/generate_mapping.py

Coverage vocabulary (per vector x requirement):
  covered      the assertion is executed by a checker published with the corpus
               (examples/*/verify.mjs|verify.py, conformance/check.mjs,
               fixtures/evidence-pinning-fixture-crosscheck-rev8.mjs) against
               the shipped file.
  partial      the expectation is declared in the manifest and exercised only by
               the generator that emitted it, or by an external run, or the
               published checker exercises part of the requirement.
  not covered  no executed assertion exists for the requirement.
Coverage is recorded only where an assertion is actually checked; a vector that
merely contains a field is not coverage of the rule about that field.
"""
import hashlib, json, os, subprocess, sys
from collections import OrderedDict
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from normative_audit import extract as extract_normative, extract_outside, extract_structural

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mapping.json")
SNAPSHOT = "cbba94b7576cf2aec08c70aeb2899fdfa4d35c66"

def snapshot_bytes(rel, commit=SNAPSHOT):
    """The file's bytes at the corpus snapshot commit, via git show. Never the working tree."""
    r = subprocess.run(["git", "show", f"{commit}:{rel}"], cwd=ROOT, capture_output=True)
    if r.returncode != 0:
        raise SystemExit(f"git show {commit}:{rel} failed: {r.stderr.decode().strip()}")
    return r.stdout

def load(rel):
    data = snapshot_bytes(rel)
    return json.loads(data), hashlib.sha256(data).hexdigest()

HERE = os.path.dirname(os.path.abspath(__file__))
CITED = OrderedDict([
    ("D01", OrderedDict([("path", "mappings/receipt-verify-registry/cited/draft-krausz-verification-state-01.txt"), ("url", "https://www.ietf.org/archive/id/draft-krausz-verification-state-01.txt"), ("fetched", "2026-10-01")])),
    ("MAP", OrderedDict([("path", "mappings/receipt-verify-registry/cited/agentoracle-v0.3-2026-05-30.json"), ("url", "https://agentoracle.co/mappings/agentoracle-v0.3-2026-05-30.json"), ("fetched", "2026-10-01")])),
])
def cited_sha256(key):
    with open(os.path.join(ROOT, CITED[key]["path"]), "rb") as f: return hashlib.sha256(f.read()).hexdigest()

# ── requirement registries ──────────────────────────────────────────
# Identifiers are stable strings a reader can resolve in the cited text.
DOCS = OrderedDict()
DOCS["D01"] = {
    "title": "draft-krausz-verification-state-01 (filed 2026-06-12)",
    "url": "https://www.ietf.org/archive/id/draft-krausz-verification-state-01.txt",
    "sha256": "22c5ce262bdf4e63ef538a308e7a8455e93c4143b9e1726b7b64720615d516db",
    "pinned_by": "examples/v0.3-composed/vectors.json spec + README; examples/v0.4-composed/vectors.json spec + README (both name -01)",
    "scope": "sections 3-7, 9 and 10: every sentence carrying MUST, MUST NOT, SHALL, SHALL NOT, SHOULD, SHOULD NOT, REQUIRED or RECOMMENDED (normative_audit.sentences), and the requirement-bearing items that are not such sentences: the typ item of §4.1, the numbered steps of §4.3 and the rows of Table 2 in §5.1 (normative_audit.structural_sources). Statements carrying only MAY or OPTIONAL are outside the audit; the six in these sections are listed in normative_audit.outside_audit",
    "requirements": OrderedDict([
        ("D01-3.2-conjunction", "§3.2: multiple verification.* constraints combine with AND; all MUST resolve to act for the action to proceed"),
        ("D01-3.2-env-ordering", "§3.2: environment.* constraints MUST short-circuit before verification.* constraints"),
        ("D01-4.1-jws", "§4.1: receipts MUST be JWS; a relying party MUST accept compact and JSON (flattened) serializations"),
        ("D01-4.1-alg", "§4.1: a conforming implementation MUST accept both EdDSA and ES256"),
        ("D01-4.1-iana-alg", "§4.1: other algorithms are optional and SHOULD follow the IANA JOSE Algorithms registry (overlaps D01-4.1-alg: the accepted set is EdDSA and ES256 plus registry-listed options)"),
        ("D01-4.1-kid", "§4.1: kid MUST resolve to a key in the issuer's published JWKS"),
        ("D01-4.1-typ", "§4.1: typ is verification-receipt+jws"),
        ("D01-4.2-v_verdict", "§4.2: v_verdict REQUIRED, one of supported | refuted | unverifiable | unknown"),
        ("D01-4.2-v_confidence", "§4.2: v_confidence REQUIRED, float in [0, 1]"),
        ("D01-4.2-v_adversarial_result", "§4.2: v_adversarial_result REQUIRED, one of resilient | vulnerable | not_checked"),
        ("D01-4.2-v_recommendation", "§4.2: v_recommendation REQUIRED, derived deterministically from the canonical input under the named mapping"),
        ("D01-4.2-v_gate", "§4.2: v_gate REQUIRED, act | halt, derived from v_recommendation under the named mapping"),
        ("D01-4.2-v_gate_mapping", "§4.2: v_gate_mapping REQUIRED; mapping documents are immutable after publication"),
        ("D01-4.2-v_gate_mapping_hash", "§4.2: v_gate_mapping_hash REQUIRED; absence is a malformed-receipt condition and MUST halt"),
        ("D01-4.2-jwt-claims", "§4.2: iss, iat, exp REQUIRED; sub RECOMMENDED; nbf OPTIONAL"),
        ("D01-4.3-sequence", "§4.3: a relying party MUST execute the eight-step sequence and treat any failure as malformed with gate decision halt"),
        ("D01-4.3-1-signature", "§4.3 step 1: verify the JWS signature against the issuer's published JWKS"),
        ("D01-4.3-2-mapping-digest", "§4.3 step 2: fetch the named mapping document; its SHA-256 MUST match v_gate_mapping_hash; receipts without the hash are malformed"),
        ("D01-4.3-3-recompute-recommendation", "§4.3 step 3: recompute candidate_recommendation from (v_verdict, v_confidence, v_adversarial_result) using the mapping's rules and threshold"),
        ("D01-4.3-4-confirm-recommendation", "§4.3 step 4: confirm candidate_recommendation == v_recommendation"),
        ("D01-4.3-5-compute-gate", "§4.3 step 5: compute candidate_gate = mapping(v_recommendation)"),
        ("D01-4.3-6-confirm-gate", "§4.3 step 6: confirm candidate_gate == v_gate"),
        ("D01-4.3-7-time", "§4.3 step 7: verify exp/nbf against current time subject to clock tolerance"),
        ("D01-4.3-8-mismatch-halts", "§4.3 step 8: any mismatch -> malformed; gate decision = halt"),
        ("D01-4.4-v_claim", "§4.4: the verified claim MUST be bound via v_claim (text, or hash REQUIRED when text is omitted)"),
        ("D01-4.5-mapping-hash-present", "§4.5: v_gate_mapping_hash MUST be present in all conforming receipts"),
        ("D01-4.6-old-mapping-verifiable", "§4.6: a receipt issued under an older mapping MUST remain verifiable as correct under that mapping"),
        ("D01-4.6-mapping-immutable", "§4.6: publishers MUST treat published mappings as immutable; new rules ship under new identifiers; errata MAY be appended to a published mapping's metadata but the normative rule tables MUST NOT change after first publication"),
        ("D01-5.1-table-shape", "§5.1: the binary act/halt shape derived from the canonical recommendation MUST be preserved"),
        ("D01-5.1-row-1", "§5.1 Table 2 row 1: supported, >= threshold, resilient -> confident_supported -> act"),
        ("D01-5.1-row-2", "§5.1 Table 2 row 2: supported, >= threshold, not_checked -> un_probed_not_cleared -> halt"),
        ("D01-5.1-row-3", "§5.1 Table 2 row 3: supported, any, vulnerable -> vulnerable_supported -> halt"),
        ("D01-5.1-row-4", "§5.1 Table 2 row 4: supported, < threshold, resilient or not_checked -> weak_supported -> halt"),
        ("D01-5.1-row-5", "§5.1 Table 2 row 5: refuted -> refuted -> halt"),
        ("D01-5.1-row-6", "§5.1 Table 2 row 6: unverifiable or unknown -> unverifiable -> halt"),
        ("D01-5.1-row-7", "§5.1 Table 2 row 7: error condition -> error -> halt"),
        ("D01-5.2-threshold-from-mapping", "§5.2: the threshold is recovered from the named mapping; two receipts under one mapping ID MUST gate against the same threshold"),
        ("D01-5.2-uncertainty-halts", "§5.2: un-probed adversarial state is not equivalent to resilient; uncertainty MUST halt (un_probed_not_cleared)"),
        ("D01-5.2-no-foreign-threshold", "§5.2: relying parties MUST NOT treat a receipt as conformant under a mapping with a different threshold than that mapping states"),
        ("D01-5.3-fail-closed", "§5.3: missing, malformed, expired, signature-invalid or unresolvable-mapping receipts MUST be treated as halt; implementations MUST NOT default to act"),
        ("D01-6.1-reject-expired", "§6.1 Table 3, signature axis: the verifier MUST reject expired signatures (overlaps D01-4.3-7-time, D01-6.2-stale-signature, D01-9.2-replay and the 'expired' case of D01-5.3-fail-closed)"),
        ("D01-6.2-stale-signature", "§6.2: a stale signature makes the receipt invalid; relying party MUST treat as halt (overlaps D01-6.1-reject-expired)"),
        ("D01-6.2-stale-calibration", "§6.2: stale calibration SHOULD be re-evaluated; issuers SHOULD publish recalibration cadence"),
        ("D01-6.2-stale-evidence", "§6.2: stale evidence SHOULD be re-evaluated and MUST NOT be honored as a gate signal for new actions"),
        ("D01-7.1-publish-anchors", "§7.1: verifier issuers MUST publish calibration anchors (the listed items)"),
        ("D01-7.1-harness", "§7.1: verifier issuers SHOULD publish a reference reproduction harness under a permissive license"),
        ("D01-7.2-cadence", "§7.2: issuers SHOULD publish a recalibration cadence; v_calibration.valid_until SHOULD reflect it"),
        ("D01-7.2-surface-stale", "§7.2: relying parties consuming receipts with stale calibration SHOULD log and surface the staleness rather than silently accept"),
        ("D01-9.1-ordering-holds", "§9.1: the §3.2 ordering MUST hold when composed with environment.* (overlaps D01-3.2-env-ordering)"),
        ("D01-9.1-no-mask-env-halt", "§9.1: a verification.* ACT outcome MUST NOT mask an environment.* HALT outcome; an environment.* halt is final regardless of the verification.* state (overlaps D01-3.2-env-ordering, D01-9.1-ordering-holds)"),
        ("D01-9.1-env-terminal-first", "§9.1: implementations MUST evaluate environment.* to its terminal state before evaluating any verification.* constraint, and a verification.* state SHALL NOT be reached if environment.* has already halted (overlaps D01-3.2-env-ordering)"),
        ("D01-9.2-key-rotation", "§9.2: issuers MUST rotate JWKS keys on a published cadence; RPs MUST honor key revocation lists where published"),
        ("D01-9.2-replay", "§9.2: RPs MUST verify iat and exp against current time"),
        ("D01-9.2-sample-harness", "§9.2 (confidence inflation): RPs SHOULD periodically sample receipts against the issuer's published harness"),
        ("D01-9.2-downgrade", "§9.2: a relying party MUST NOT accept a v0.3-spec receipt against a v0.4-spec gate"),
        ("D01-9.2-mapping-tampering", "§9.2: receipts MUST bind to a content-addressed mapping; mapping documents MUST be hosted with a stable, independently verifiable digest; verifier implementations MUST verify the fetched document's SHA-256 against v_gate_mapping_hash before use and a mismatch MUST halt (the same check as D01-4.3-2-mapping-digest)"),
        ("D01-9.2-unverifiable-mapping-hash-malformed", "§9.2: a relying party that cannot independently verify the mapping document's hash MUST treat the receipt as malformed (overlaps the 'mapping ID cannot be resolved' case of D01-5.3-fail-closed and D01-4.3-2-mapping-digest)"),
        ("D01-10-well-known-jwks", "§10: verification issuers using HTTPS SHOULD publish their JWKS at /.well-known/jwks.json per RFC 7517 §4.7 conventions"),
    ]),
    "requirement_notes": OrderedDict([
        ("D01-4.1-typ", "Finding 1 (Michael Msebenzi, review of b1da800): the v0.3 fixtures use typ application/vnd.verification.v0.3+composed+jws and the v0.4 fixtures (all 12 protected headers) use application/vnd.verification.v0.4+composed+jws; neither matches -01 §4.1 (verification-receipt+jws). No published checker asserts typ, so the requirement is not covered, and the corpus as shipped would not satisfy it."),
    ]),
}
# ── normative audit of -01 §§3-7, 9, 10: every MUST/SHOULD/SHALL/REQUIRED/RECOMMENDED
# sentence extracted from the cited bytes (normative_audit.py) is assigned here,
# keyed by (section, first 48 characters). An unassigned sentence stops generation.
AUDIT_ASSIGN = [
    ("3.2", "All constraints MUST resolve to act", ["D01-3.2-conjunction"]),
    ("3.2", "Ordering with environment.*:* environment.* constr", ["D01-3.2-env-ordering"]),
    ("4.1", "Verification receipts MUST be issued as JSON Web S", ["D01-4.1-jws"]),
    ("4.1", "A relying party MUST accept both serializations.", ["D01-4.1-jws"]),
    ("4.1", "alg: A conforming implementation MUST accept both", ["D01-4.1-alg"]),
    ("4.1", "Other algorithms are optional and SHOULD follow th", ["D01-4.1-iana-alg"]),
    ("4.1", "kid: MUST resolve to a key in the issuer's publish", ["D01-4.1-kid"]),
    ("4.2", "v_verdict (string, REQUIRED)", ["D01-4.2-v_verdict"]),
    ("4.2", "v_confidence (number, REQUIRED)", ["D01-4.2-v_confidence"]),
    ("4.2", "v_adversarial_result (string, REQUIRED)", ["D01-4.2-v_adversarial_result"]),
    ("4.2", "v_recommendation (string, REQUIRED)", ["D01-4.2-v_recommendation"]),
    ("4.2", "v_gate (string, REQUIRED)", ["D01-4.2-v_gate"]),
    ("4.2", "v_gate_mapping (string, REQUIRED)", ["D01-4.2-v_gate_mapping"]),
    ("4.2", "v_gate_mapping_hash (string, REQUIRED)", ["D01-4.2-v_gate_mapping_hash"]),
    ("4.2", "MUST be present in every receipt.", ["D01-4.2-v_gate_mapping_hash", "D01-4.5-mapping-hash-present"]),
    ("4.2", "Receipts MUST bind to a content-addressed mapping;", ["D01-4.2-v_gate_mapping_hash", "D01-9.2-mapping-tampering"]),
    ("4.2", "iss (REQUIRED), sub (RECOMMENDED), iat (REQUIRED)", ["D01-4.2-jwt-claims"]),
    ("4.3", "A relying party verifying a receipt MUST execute t", ["D01-4.3-sequence", "D01-4.3-8-mismatch-halts"]),
    ("4.3", "MUST verify the SHA-256 digest of the fetched docu", ["D01-4.3-2-mapping-digest"]),
    ("4.4", "The verified claim MUST be bound to the receipt vi", ["D01-4.4-v_claim"]),
    ("4.4", "\"v_claim\": {", ["D01-4.4-v_claim"]),
    ("4.5", "This field MUST be present in all conforming recei", ["D01-4.5-mapping-hash-present"]),
    ("4.6", "MUST remain verifiable as _correct-under-v0.3.0_", ["D01-4.6-old-mapping-verifiable"]),
    ("4.6", "Mapping document publishers MUST treat published m", ["D01-4.6-mapping-immutable"]),
    ("4.6", "Errata (typographical corrections only) MAY be app", ["D01-4.6-mapping-immutable"]),
    ("5.1", "Future mappings MAY tighten or extend this table;", ["D01-5.1-table-shape"]),
    ("5.2", "This ensures that the threshold is auditable, vers", ["D01-5.2-threshold-from-mapping"]),
    ("5.2", "Per the fail- closed property, uncertainty MUST ha", ["D01-5.2-uncertainty-halts"]),
    ("5.2", "They MUST NOT treat a receipt as conformant under", ["D01-5.2-no-foreign-threshold"]),
    ("5.3", "If a receipt is missing, malformed, expired, signa", ["D01-5.3-fail-closed"]),
    ("5.3", "Implementations MUST NOT default to act under any", ["D01-5.3-fail-closed"]),
    ("6.1", "Signature | exp | Key rotation; verifier MUST reje", ["D01-6.1-reject-expired"]),
    ("6.2", "Stale signature* --- Receipt is invalid; relying p", ["D01-6.2-stale-signature"]),
    ("6.2", "Stale calibration* --- Receipt SHOULD be re-evalua", ["D01-6.2-stale-calibration"]),
    ("6.2", "Verifier issuers SHOULD publish recalibration cade", ["D01-6.2-stale-calibration", "D01-7.2-cadence"]),
    ("6.2", "Stale evidence* --- Receipt SHOULD be re-evaluated", ["D01-6.2-stale-evidence"]),
    ("6.2", "MAY be honored for retrospective audit purposes", ["D01-6.2-stale-evidence"]),
    ("7.1", "Verifier issuers MUST publish:", ["D01-7.1-publish-anchors"]),
    ("7.1", "Verifier issuers SHOULD publish a reference reprod", ["D01-7.1-harness"]),
    ("7.2", "Verifier issuers SHOULD publish a recalibration ca", ["D01-7.2-cadence"]),
    ("7.2", "The v_calibration.valid_until field in receipts SH", ["D01-7.2-cadence"]),
    ("7.2", "Relying parties consuming receipts with stale cali", ["D01-7.2-surface-stale"]),
    ("9.1", "When verification.* composes alongside environment", ["D01-9.1-ordering-holds"]),
    ("9.1", "A verification.* ACT outcome MUST NOT mask an envi", ["D01-9.1-no-mask-env-halt"]),
    ("9.1", "Implementations MUST evaluate environment.* to its", ["D01-9.1-env-terminal-first"]),
    ("9.2", "Key compromise.* Verifier issuers MUST rotate JWKS", ["D01-9.2-key-rotation"]),
    ("9.2", "RPs MUST honor key revocation lists where publishe", ["D01-9.2-key-rotation"]),
    ("9.2", "RPs MUST verify both against current time, subject", ["D01-9.2-replay"]),
    ("9.2", "RPs SHOULD periodically sample receipts against th", ["D01-9.2-sample-harness"]),
    ("9.2", "Downgrade attacks.* A future relying party MUST NO", ["D01-9.2-downgrade"]),
    ("9.2", "Mapping document tampering.* Receipts MUST bind to", ["D01-9.2-mapping-tampering", "D01-4.2-v_gate_mapping_hash"]),
    ("9.2", "Mapping documents MUST be hosted such that the SHA", ["D01-9.2-mapping-tampering"]),
    ("9.2", "Verifier implementations MUST verify the SHA-256 d", ["D01-9.2-mapping-tampering", "D01-4.3-2-mapping-digest"]),
    ("9.2", "A relying party that cannot independently verify t", ["D01-9.2-unverifiable-mapping-hash-malformed"]),
    ("10", "Well-known URI:* Verification issuers using HTTPS", ["D01-10-well-known-jwks"]),
]
# The requirement-bearing items of -01 that are not keyword sentences, keyed by
# (section, locator) as normative_audit.extract_structural reports them. Each names the
# one registry row that stands for it. An item with no entry here, or an entry with no
# item in the text, stops generation.
STRUCT_ASSIGN = OrderedDict([
    (("4.1", "typ"), "D01-4.1-typ"),
    (("4.3", "step 1"), "D01-4.3-1-signature"),
    (("4.3", "step 2"), "D01-4.3-2-mapping-digest"),
    (("4.3", "step 3"), "D01-4.3-3-recompute-recommendation"),
    (("4.3", "step 4"), "D01-4.3-4-confirm-recommendation"),
    (("4.3", "step 5"), "D01-4.3-5-compute-gate"),
    (("4.3", "step 6"), "D01-4.3-6-confirm-gate"),
    (("4.3", "step 7"), "D01-4.3-7-time"),
    (("4.3", "step 8"), "D01-4.3-8-mismatch-halts"),
] + [(("5.1", f"Table 2 row {n}"), f"D01-5.1-row-{n}") for n in range(1, 8)])
def build_structural(text, reqs):
    items = extract_structural(text)
    keys = [(sec, loc) for _, sec, loc, _ in items]
    if keys != list(STRUCT_ASSIGN):
        raise SystemExit("structural sources: the text's items %r differ from STRUCT_ASSIGN %r" % (keys, list(STRUCT_ASSIGN)))
    out = []
    for n, (kind, sec, loc, txt) in enumerate(items, 1):
        rid = STRUCT_ASSIGN[(sec, loc)]; assert rid in reqs, rid
        out.append(OrderedDict([("n", n), ("kind", kind), ("section", sec), ("locator", loc), ("text", txt), ("requirement", rid)]))
    return out

def build_audit(text, reqs):
    sentences = extract_normative(text)
    out, unassigned, seen = [], [], set()
    for n, (sec, sent) in enumerate(sentences, 1):
        matches = [(i, ids) for i, (asec, pre, ids) in enumerate(AUDIT_ASSIGN) if asec == sec and sent.startswith(pre)]
        if len(matches) != 1: unassigned.append(f"[{sec}] {sent} (matches: {len(matches)})"); ids = None
        else:
            seen.add(matches[0][0]); ids = matches[0][1]
            for i in ids: assert i in reqs, i
        out.append(OrderedDict([("n", n), ("section", sec), ("text", sent), ("requirements", ids or [])]))
    stale = [AUDIT_ASSIGN[i][:2] for i in range(len(AUDIT_ASSIGN)) if i not in seen]
    if unassigned or stale:
        raise SystemExit("normative audit: unassigned sentences: %r; stale table keys: %r" % (unassigned, stale))
    return out

DOCS["RMT"] = {
    "title": "tanilo-receipt-spec README, section 'Mycelium Trails'",
    "url": "https://github.com/TKCollective/tanilo-receipt-spec/blob/196df22b255e7173d4eb6b20e833cc4e8ae6d35d/README.md#mycelium-trails",
    "commit": "196df22b255e7173d4eb6b20e833cc4e8ae6d35d",
    "pinned_by": "not pinned by the manifests (they cite ../../README.md unversioned); revision used is recorded here",
    "scope": "the three paragraphs of the section only",
    "requirements": OrderedDict([
        ("RMT-action-ref", "action_ref is computed per draft-giskard-aeoess-action-ref over agent_id, action_type, scope, timestamp (RFC 3339 UTC, exactly 3 fractional digits)"),
        ("RMT-trail-sibling", "a returned mycelium_trail_id can be carried at the envelope level as a sibling pointer to v_gate (the composed-envelope spec it defers to is described as forthcoming)"),
    ]),
}
DOCS["MAP"] = {
    "title": "mapping document agentoracle-v0.3-2026-05-30 (recommendation_rules, gate_map, threshold)",
    "url": "https://agentoracle.co/mappings/agentoracle-v0.3-2026-05-30.json",
    "sha256": "0a78263976790df6e76cd9f3f441bf5a3b5c3a82e346b5aca43e49626881d7b0",
    "pinned_by": "conformance/vectors-rule2.json mapping_id; the document is content-addressed (D01 §4.2) and the digest above is the one every composed fixture carries as v_gate_mapping_hash",
    "scope": "recommendation_rules 1-7, gate_map, threshold",
    "requirements": OrderedDict([
        ("MAP-rule-1", "rule 1: supported, >= threshold, resilient -> confident_supported"),
        ("MAP-rule-2", "rule 2: supported, >= threshold, not_checked -> un_probed_not_cleared"),
        ("MAP-rule-3", "rule 3: supported, any, vulnerable -> vulnerable_supported"),
        ("MAP-rule-4", "rule 4: supported, < threshold, resilient or not_checked -> weak_supported"),
        ("MAP-rule-5", "rule 5: refuted -> refuted"),
        ("MAP-rule-6", "rule 6: unverifiable or unknown -> unverifiable"),
        ("MAP-rule-7", "rule 7: error condition -> error"),
        ("MAP-gate_map", "gate_map: only confident_supported -> act; every other recommendation -> halt"),
        ("MAP-threshold", "threshold: v_confidence >= 0.7; the threshold lives in the mapping, not in receipts"),
    ]),
}
DOCS["EP"] = {
    "title": "evidence-pinning section for draft -02 (review draft + amendments), as pinned by the rev8 fixture header",
    "texts": OrderedDict([
        ("review-draft", {"path": "drafts/evidence-pinning-02-review-draft.md", "sha256": "9832156998ceb35f25d08c5be2d4d7c314477b25045f4499e07f3c5e501f5096", "pinned_by": "fixture header spec_bases.review_draft_sha256"}),
        ("rev5", {"path": "drafts/evidence-pinning-02-amendments-rev5-2026-09-06.md", "sha256": "1f901fd7d56fcfe9f858446e5b685b540b5904d6abcfb4b2509e1eb675aa1e51", "pinned_by": "spec_bases.rev5_sha256"}),
        ("rev6", {"path": "drafts/evidence-pinning-02-amendments-rev6-2026-09-08.md", "sha256": "d62ded37dcf63f541e5b670b0cc0f7876e04a182064eb06a32af0037effaf026", "pinned_by": "spec_bases.rev6_sha256"}),
        ("rev7", {"path": "drafts/evidence-pinning-02-amendments-rev7-2026-09-09.md", "sha256": "6b13f6fc35d745c2642edcb52a2754f7cd43340ded3248b5d1ba70a431d6c037", "pinned_by": "spec_bases.rev7_sha256"}),
        ("rev8", {"path": "drafts/evidence-pinning-02-amendments-rev8-2026-09-17.md", "sha256": "6a1ca7844396055e4a2b76dd925cc623f0e530885c50b16f747b51e6a0aaecad", "pinned_by": "spec_bases.rev8_sha256"}),
        ("rev2", {"path": "drafts/evidence-pinning-02-amendments-rev2-2026-09-04.md", "sha256": None, "pinned_by": "NOT pinned by the fixture header; revision used is the file at the snapshot commit (digest filled at generation)"}),
        ("rev4", {"path": "drafts/evidence-pinning-02-amendments-rev4-2026-09-06.md", "sha256": None, "pinned_by": "NOT pinned by the fixture header; revision used is the file at the snapshot commit (digest filled at generation)"}),
    ]),
    "scope": "the evidence-pinning section only (review draft §4.1 evidence_set, §4.1.1, §4.1.2, the §4.3 step, §5; the normative findings of the amendments that change that section). Not the rest of -02.",
    "requirements": OrderedDict([
        ("EP-4.1-members", "review draft §4.1: an evidence_set, when present, MUST be an object with evidence_set_version, retrieved_at, source_count, pinned_count (<= source_count), fully_pinned, evidence_root, sources"),
        ("EP-4.1-fully_pinned-stated", "review draft §4.1: fully_pinned is stated, not derived; an issuer MUST NOT omit it when some items are unpinned; partial pinning is an honest state"),
        ("EP-4.1.1-entry-members", "review draft §4.1.1 as amended (rev2 §3): each sources entry carries url, snippet_sha256 (or null), retrieved_at, pinned, and content_kind when pinned"),
        ("EP-4.1.1-digest-as-received", "review draft §4.1.1 as amended (rev4 Finding 16): snippet_sha256 is computed over the retrieved content exactly as received, the octet sequence as it arrived, with no transcoding, trimming, whitespace collapsing, case folding or Unicode normalization; there is no character-encoding step, the digest is over bytes, not text"),
        ("EP-4.1.1-url-bytes", "rev2 §3: the url carried in an entry MUST be the URI bytes used for retrieval, without normalization"),
        ("EP-4.1.1-possession", "rev2 §3 (possession rule): an issuer MUST pin every item for which it received content bytes; every pinned: false entry MUST carry an unpinned_reason from the stated domain; an item outside that domain or without a reason is malformed"),
        ("EP-4.1.1-content_kind", "rev2 §3 / rev6 Finding 30: content_kind MUST be present and one of the defined values when pinned; on an unpinned entry it MUST be absent or null (equivalent)"),
        ("EP-4.1.1-full_resource", "rev4 Finding 19 / rev8 Finding 42: a full_resource entry does not carry resource_sha256 (the rule ranges over every entry)"),
        ("EP-4.1.1-pinned-boolean", "rev8 Finding 40: pinned is REQUIRED on every entry and MUST be exactly true or false; anything else halts"),
        ("EP-4.1.2-leaf", "review draft §4.1.2 as amended (rev2 Finding 1, rev4 Finding 15a, prefix ao-evidence-leaf-v2): the leaf preimage binds url, snippet_sha256, content_kind and retrieved_at with 0x00 separators"),
        ("EP-4.1.2-node", "review draft §4.1.2 / rev6 Finding 27: interior node = SHA-256(prefix || 0x00 || left || 0x00 || right) over the raw 32-octet children"),
        ("EP-4.1.2-odd-promotion", "review draft §4.1.2 / rev6 Finding 28: an odd final entry is promoted unchanged, never duplicated; termination stated"),
        ("EP-4.1.2-canonical-order", "review draft §4.1.2 as amended (rev4 Finding 15c): leaves sort ascending by the four-term key url, snippet_sha256, content_kind, retrieved_at, bytewise over UTF-8"),
        ("EP-4.1.2-domain-separation", "review draft §4.1.2: distinct leaf and node prefixes; a leaf hash can never be reinterpreted as a node"),
        ("EP-4.1.2-empty-root-null", "review draft §4.1.2 / rev8 Finding 43: when pinned_count is zero evidence_root MUST be null; a non-null root with zero pinned entries, or a null root with pinned entries, is malformed"),
        ("EP-4.1.2-no-identical-entries", "rev5 Finding 24a as amended by rev8 Finding 35: two entries in sources are one retrieval recorded twice when they are identical in url and retrieved_at and, where both are pinned, also identical in snippet_sha256 and content_kind; the rule ranges over every entry, pinned and unpinned alike; malformed, gate decision halt (duplicate_bound_tuple)"),
        ("EP-4.1.2-no-identical-entries-mixed-pair", "rev8 Finding 35, stated consequence: a pinned entry and an unpinned entry sharing url and retrieved_at are also one retrieval recorded twice and the set halts. rev8 records that no vector in that revision covers this mixed pair"),
        ("EP-4.1.2-retrieved_at-form", "rev6 Finding 32 / rev8 Finding 37: retrieved_at MUST be RFC 3339 UTC with Z and exactly three fractional digits; the rule ranges over every entry"),
        ("EP-4.1-set-retrieved_at-least", "rev8 Finding 36: the set-level retrieved_at MUST equal the bytewise-least retrieved_at among all entries"),
        ("EP-4.3-a-counts", "review draft §4.3 (a) as amended (rev5 24d, rev8 Findings 41, 44): pinned_count, source_count and fully_pinned MUST be consistent with the entries; absent declared counts derive from the entries and MUST NOT halt for want of them"),
        ("EP-4.3-a-snippet-required", "rev8 Finding 46: step (a) MUST halt on a pinned entry whose snippet_sha256 is absent or null, and MUST NOT let it reach leaf or root construction"),
        ("EP-4.3-b-root-recompute", "review draft §4.3 (b): a non-null evidence_root is recomputed from sources; a mismatch is malformed and halts"),
        ("EP-4.3-c-partial-unknown", "§4.3 (c) as restated by rev2 §5: when fully_pinned is false the step resolves unknown, and the receipt MUST NOT be treated as malformed on that account"),
        ("EP-4.3-d-content-item-unknown", "§4.3 (d) as amended (rev2 §5, rev4 Finding 17, rev8 Finding 45): a content mismatch, or content not held, resolves unknown for that item with a per-item reason (content_differs | content_not_held) and MUST NOT halt"),
        ("EP-4.3-e-absent-unknown", "§4.3 (e) (review draft (d)): a receipt carrying no evidence_set resolves unknown for the step and MUST NOT fail it"),
        ("EP-4.3-f-declared-partial-not-invalid", "rev2 §5 step (f): a properly declared partial evidence set is not invalid and the receipt is not malformed; an implementation MUST NOT treat an unknown resolution under (c) as a malformed-receipt condition"),
        ("EP-4.3-g-distinct-category", "rev2 §5 step (g): a verifier MUST treat an unknown resolution under (c) as a distinct category and MUST NOT present it as a weaker form of a satisfied offline-recompute claim; a verifier that reports, displays, summarises or forwards an outcome MUST carry the distinction"),
        ("EP-4.1.2-root-inside-signed-payload", "rev2 §5 (Finding 4, Q2): evidence_root MUST be inside the signed payload, without exception"),
        ("EP-4.3-resolved-token", "rev6 Finding 29: the affirmative step resolution is the token resolved; an implementation MUST emit resolved or unknown and no other value"),
        ("EP-4.3-diagnostic-naming", "rev6 Finding 31: when more than one condition is violated the implementation halts on the first in section order and names it; a vector injecting more than one condition MUST state which"),
        ("EP-4.3-empty-set", "rev4 Finding 20: an evidence_set whose sources names no entries is malformed (evidence_set_names_no_sources)"),
        ("EP-4.3-condition-identifiers", "rev7 Finding 33 / rev8 Finding 38: MALFORMED outcomes are reported with a condition identifier from the registry; superseded identifiers are published as such and fail the build"),
        ("EP-5-non-establishment", "review draft §5: a pinned evidence set establishes nothing about truth, sufficiency, independence or completeness of retrieval; implementations SHOULD NOT present it as if it did"),
    ]),
}

EXTERNAL = OrderedDict([
    ("EXT-action-ref-v1", {"title": "action-ref-v1 (giskard09/argentum-core docs/spec/action-ref.md)", "pinned": "commit 16dbc92 (v0.3 and v0.4 manifests)", "note": "third-party text; out of the in-scope document set"}),
    ("EXT-delegation-chain-ref-v1", {"title": "delegation-chain-ref-v1 (giskard09/argentum-core docs/spec/delegation-chain-ref.md)", "pinned": "commit 16e140a (v0.4 manifest); unpinned in the leaf-screen-halt README", "note": "third-party text; out of the in-scope document set"}),
    ("EXT-signing-trust-ref-v1", {"title": "signing-trust-ref-v1 (giskard09/argentum-core docs/spec/signing-trust-ref.md)", "pinned": "not pinned by the corpus: the manifests name signing-trust-ref-v1 without a commit (16dbc92 is their pin for action-ref.md only). Revision selected by this mapping for reference: 16dbc92", "note": "third-party text; the composed checkers do not assert it"}),
    ("EXT-mycelium-provider-protocol", {"title": "Mycelium Provider protocol (giskard09/argentum-core docs/mycelium-provider-protocol.md)", "pinned": "unpinned (README links main)", "note": "third-party text; comp-r02's null rule cites it and 'the AgentOracle composed envelope spec', which README@196df22b describes as forthcoming"}),
    ("EXT-service-integrity-D1", {"title": "service_integrity.md rule D1 (x402-research-skill standing rules): a zero-member evaluation MUST NOT produce a signed receipt", "pinned": "not a format requirement; operational rule", "note": "d1-no-receipt records it; conformance/check.mjs skips it"}),
])

# ── forward mapping judgments ────────────────────────────────────────
def cov(req, coverage, checker, assertion, note=None):
    d = OrderedDict([("requirement", req), ("coverage", coverage), ("checker", checker), ("assertion", assertion)])
    if note: d["note"] = note
    return d

V03 = "examples/v0.3-composed/verify.mjs (mirrored by verify.py)"
V04 = "examples/v0.4-composed/verify.mjs (mirrored by verify.py)"
COMPOSED_ACCEPT_COMMON = lambda checker: [
    cov("D01-4.3-1-signature", "covered", checker, "every signatures[] entry verifies (Ed25519) against the JWKS matched by kid; signature_invalid otherwise"),
    cov("D01-4.1-kid", "covered", checker, "kid MUST be present and found in some issuer JWKS (jws_missing_kid, jws_kid_not_found_in_any_jwks)"),
    cov("D01-4.1-alg", "partial", checker, "alg MUST be EdDSA (jws_alg_not_EdDSA); ES256 acceptance is not exercised", "the -01 requirement is to accept both; the fixtures sign only EdDSA and the checker rejects anything else"),
    cov("D01-4.1-jws", "partial", checker, "JWS General Serialization envelope is parsed and verified", "only the general (multi-signature) form is exercised; compact and flattened forms are not"),
    cov("D01-3.2-conjunction", "covered", checker, "composed_decision recomputed by AND over every present sibling verdict (v_gate, v_gate_skill, screen_ref, delegation_chain_ref) and compared with the signed value"),
    cov("D01-4.3-sequence", "partial", checker, "any failed check returns ok:false with a reason; the runner fails the vector", "the composed checker executes its own sequence, not the -01 eight-step sequence: steps 2-7 (mapping fetch, recommendation and gate recompute, time) are not executed"),
]
COMPOSED_MYCELIUM = lambda checker: cov("RMT-trail-sibling", "partial", checker, "mycelium_trail_id, when the key is present, MUST NOT be null (absent or string)", "the README says the pointer 'can be carried'; the absent-not-null rule is in EXT-mycelium-provider-protocol and the composed-envelope spec the README defers to")

def composed_vector(v, checker, extra, external, notes=None):
    d = OrderedDict([("id", v["id"]), ("description", v["description"]), ("kind", "accept" if "expected_composed_decision" in v else "reject")])
    if "expected_failure" in v: d["expected_failure"] = v["expected_failure"]
    d["requirements"] = extra
    d["external_requirements"] = external
    if notes: d["notes"] = notes
    return d

def build_v03(manifest):
    out = []
    for v in manifest["accept_vectors"]:
        reqs = COMPOSED_ACCEPT_COMMON(V03)
        ext = []
        if v["mycelium_trail_id_present"]:
            reqs = reqs + [COMPOSED_MYCELIUM(V03)]
        if v["screen_ref_present"]:
            reqs = reqs + [cov("RMT-action-ref", "partial", V03, "executed part: screen_ref.action_ref recomputed as SHA-256(JCS({agent_id, action_type, scope, timestamp})) and compared with the signed value", "the timestamp form (RFC 3339 UTC, exactly 3 fractional digits) and the preimage grammar are not validated")]
            ext.append({"requirement": "EXT-action-ref-v1", "assertion": "screen_ref.action_ref recomputed from the four-field preimage and compared (screen_ref_action_ref_mismatch)"})
        out.append(composed_vector(v, V03, reqs, ext))
    for v in manifest["reject_vectors"]:
        if v["id"] == "comp-r01":
            reqs = [cov("D01-4.3-1-signature", "covered", V03, "a corrupted AgentTrust signature is rejected: signature_invalid"),
                    cov("D01-5.3-fail-closed", "partial", V03, "executed part: one signature-invalid envelope is rejected as a whole", "no gate decision is emitted, and the other §5.3 conditions (missing, expired, unresolvable mapping) are not exercised"),
                    cov("D01-4.3-8-mismatch-halts", "partial", V03, "the envelope is rejected", "the checker reports ok:false; it does not emit a gate decision")]
            ext = []
        elif v["id"] == "comp-r02":
            reqs = [cov("RMT-trail-sibling", "partial", V03, "mycelium_trail_id: null is rejected (mycelium_trail_id_is_null)", "the null prohibition is not stated in README@196df22b; it comes from the Mycelium Provider protocol and the unpublished composed-envelope spec")]
            ext = [{"requirement": "EXT-mycelium-provider-protocol", "assertion": "null pointer rejected"}]
        elif v["id"] == "comp-r03":
            reqs = [cov("D01-3.2-conjunction", "covered", V03, "signed composed_decision act with v_gate halt is rejected on recompute (composed_decision_rule_violated)"),
                    cov("D01-4.3-8-mismatch-halts", "partial", V03, "mismatch between a signed value and its recompute rejects the envelope", "no gate decision is emitted by the checker")]
            ext = []
        elif v["id"] == "comp-r04":
            reqs = [cov("RMT-action-ref", "partial", V03, "executed part: an action_ref that is not the four-field recompute is rejected (screen_ref_action_ref_mismatch)", "hash recompute only; no timestamp-form or preimage-grammar validation")]
            ext = [{"requirement": "EXT-action-ref-v1", "assertion": "screen_ref.action_ref differing from the action-ref-v1 recompute is rejected (screen_ref_action_ref_mismatch)"}]
        out.append(composed_vector(v, V03, reqs, ext))
    return out

def build_v04(manifest):
    out = []
    for v in manifest["accept_vectors"]:
        reqs = COMPOSED_ACCEPT_COMMON(V04) + [cov("RMT-action-ref", "partial", V04, "executed part: screen_ref.action_ref recomputed as SHA-256(JCS(four fields)) and compared", "no timestamp-form or preimage-grammar validation")]
        ext = [{"requirement": "EXT-action-ref-v1", "assertion": "screen_ref.action_ref recomputed and compared"},
               {"requirement": "EXT-delegation-chain-ref-v1", "assertion": "chain content address, continuity, root anchoring, leaf anchoring, leaf scope and monotonic narrowing all checked"}]
        out.append(composed_vector(v, V04, reqs, ext))
    for v in manifest["reject_vectors"]:
        ext = [{"requirement": "EXT-delegation-chain-ref-v1", "assertion": {"comp-r05": "scope widening between hops rejected (delegation_chain_ref_scope_widening)", "comp-r06": "hops[0].delegatee != hops[1].delegator rejected (delegation_chain_ref_chain_break)"}[v["id"]]}]
        d = composed_vector(v, V04, [], ext)
        d["status"] = "deferred"
        d["reason"] = "no in-scope requirement: the decisive rule is third-party (delegation-chain-ref-v1 @16e140a). The published checker executes it (see external_requirements); the requirement text is outside this mapping's document set."
        out.append(d)
    return out

RULE2_CHECK = "conformance/check.mjs (a second, separate derivation of the rule table)"
RULE2_MAP = {
    "rule2-accept": ([("MAP-rule-2", "derivation yields un_probed_not_cleared"), ("MAP-gate_map", "verdict halt"), ("D01-5.1-row-2", "row 2 reproduced"), ("D01-5.2-uncertainty-halts", "not_checked under a supported verdict halts")], "covered"),
    "rule2-reject-act": ([("MAP-gate_map", "verdict MUST NOT be act"), ("D01-5.1-row-2", "row 2 gate"), ("D01-5.2-uncertainty-halts", "un-probed state does not clear")], "covered"),
    "rule2-reject-collapse": ([("MAP-rule-2", "recommendation MUST NOT collapse to unverifiable"), ("D01-5.1-row-2", "row 2 is distinct from row 6")], "covered"),
    "rule1-confident": ([("MAP-rule-1", "confident_supported"), ("MAP-gate_map", "the only path to act"), ("D01-5.1-row-1", "row 1 reproduced")], "covered"),
    "rule4-weak": ([("MAP-rule-4", "weak_supported below threshold"), ("MAP-threshold", "0.5 < 0.7"), ("D01-5.1-row-4", "row 4 reproduced"), ("D01-5.2-threshold-from-mapping", "PARTIAL: the runner compares the manifest's threshold with a hard-coded 0.7; no mapping document is fetched or recovered")], "covered"),
    "rule3-vulnerable": ([("MAP-rule-3", "vulnerable_supported"), ("D01-5.1-row-3", "row 3 reproduced")], "covered"),
    "rule6-unverifiable": ([("MAP-rule-6", "unverifiable"), ("D01-5.1-row-6", "row 6 reproduced")], "covered"),
    "rule5-refuted": ([("MAP-rule-5", "refuted outranks every adversarial state"), ("D01-5.1-row-5", "row 5 reproduced")], "covered"),
    "d1-no-receipt": ([], "not covered"),
}
def build_rule2(manifest):
    out = []
    for v in manifest["vectors"]:
        pairs, coverage = RULE2_MAP[v["id"]]
        d = OrderedDict([("id", v["id"]), ("designation", v["designation"]), ("input", v["input"]),
                         ("expect", v.get("expect")), ("expect_must_not_equal", v.get("expect_must_not_equal"))])
        d["requirements"] = [cov(r, "partial" if a.startswith("PARTIAL: ") else coverage, RULE2_CHECK, a.replace("PARTIAL: ", "executed part: ")) for r, a in pairs]
        d["external_requirements"] = []
        if v["id"] == "d1-no-receipt":
            d["external_requirements"] = [{"requirement": "EXT-service-integrity-D1", "assertion": "not executed: check.mjs skips inputs carrying members_evaluated (service-level, not a derivation)"}]
            d["status"] = "deferred"
            d["reason"] = "service-level rule (EXT-service-integrity-D1), not a format requirement in any in-scope text; conformance/check.mjs skips it. Declared, not run: no published checker executes this vector."
            d["notes"] = ["declared, not run: no published checker executes this vector"]
        out.append(d)
    return out

REV8_CHECK = "fixtures/evidence-pinning-fixture-crosscheck-rev8.mjs"
REV8_GEN = "fixtures/evidence-pinning-fixture-generator-rev8.py (the emitter's own validation; same author, not independent)"
REV8_EXT = "external run: babyblueviper1/preaction-governance-conformance@8e98c0e run_companion_corpus.py against this file (40 of 44 agree; see notes)"
# vector id -> list of (requirement, coverage, checker, assertion)
def rb(req, assertion):  # root-bearing: the cross-check recomputes the root values
    return (req, "covered", REV8_CHECK, assertion)
def mf(req, assertion):  # malformed: condition declared; halting executed by the generator and the external run, not by the published cross-check
    return (req, "partial", REV8_GEN + "; " + REV8_EXT, assertion)
def disc(req, assertion):  # rev8 discriminating vectors: the cross-check executes the rule on the shipped file
    return (req, "covered", REV8_CHECK, assertion)
def prose(req, assertion):  # resolution expectations stated in prose; exercised by the external run only
    return (req, "partial", REV8_EXT, assertion)
REV8_MAP = {
    "evi-root-order-independent": [rb("EP-4.1.2-canonical-order", "identical evidence_root from two input orders (root_1 == root_2 recomputed)")],
    "evi-root-odd-promotion": [rb("EP-4.1.2-odd-promotion", "root equals promote-not-duplicate construction")],
    "evi-node-child-encoding": [rb("EP-4.1.2-node", "root equals normative_root (raw-octet children) and differs from counter_construction_root")],
    "evi-leaf-member-encoding": [rb("EP-4.1.2-leaf", "root equals normative_root and differs from the counter construction")],
    "evi-snippet-change-changes-root": [rb("EP-4.1.2-leaf", "a one-digest change changes the root"), ("EP-4.1.1-digest-as-received", "not covered", REV8_CHECK + " does not execute it", "the checker consumes the supplied snippet_sha256 and never hashes content, so how the digest is computed is not exercised")],
    "evi-url-normalization-changes-root": [rb("EP-4.1.1-url-bytes", "unnormalized url bytes are normative: roots differ"), rb("EP-4.1.2-leaf", "url bound in the leaf")],
    "evi-duplicate-url-distinct-digest": [rb("EP-4.1.2-canonical-order", "two entries sharing a url order deterministically by the four-term key; stable root")],
    "evi-leaf-binds-content-kind": [rb("EP-4.1.2-leaf", "content_kind is bound in the leaf preimage: root differs")],
    "evi-leaf-binds-retrieved-at": [rb("EP-4.1.2-leaf", "retrieved_at is bound in the leaf preimage: root differs")],
    "evi-order-tiebreak-content-kind": [rb("EP-4.1.2-canonical-order", "content_kind tie-break: identical root both ways")],
    "evi-order-tiebreak-retrieved-at": [rb("EP-4.1.2-canonical-order", "retrieved_at tie-break: identical root both ways")],
    "evi-set-retrieved-at-not-earliest-rejects": [mf("EP-4.1-set-retrieved_at-least", "condition set_retrieved_at_not_bytewise_least")],
    "evi-content-kind-absent-when-pinned-rejects": [mf("EP-4.1.1-content_kind", "condition content_kind_absent_when_pinned"), mf("EP-4.3-diagnostic-naming", "diagnostic names the missing member, not a root mismatch")],
    "evi-resource-sha256-with-full-resource-rejects": [mf("EP-4.1.1-full_resource", "condition snippet_digest_present_for_full_resource")],
    "evi-full-resource-digest-on-unpinned-rejects": [mf("EP-4.1.1-full_resource", "the rule ranges over an unpinned entry too (Finding 42)"), mf("EP-4.1.1-pinned-boolean", "the two-state pinned MUST makes the entry's state determinate (Finding 40)")],
    "evi-pinned-absent-rejects": [mf("EP-4.1.1-pinned-boolean", "condition pinned_absent_or_not_boolean (absent)")],
    "evi-pinned-not-boolean-rejects": [mf("EP-4.1.1-pinned-boolean", "condition pinned_absent_or_not_boolean (non-boolean)")],
    "evi-snippet-sha256-absent-when-pinned-rejects": [mf("EP-4.3-a-snippet-required", "condition snippet_sha256_absent_when_pinned; MUST NOT reach leafHash/computeRoot"), mf("EP-4.1.1-entry-members", "snippet_sha256 required on a pinned entry")],
    "evi-empty-set-rejects": [mf("EP-4.3-empty-set", "condition evidence_set_names_no_sources")],
    "evi-duplicate-bound-tuple-rejects": [mf("EP-4.1.2-no-identical-entries", "condition duplicate_bound_tuple")],
    "evi-unpinned-reason-outside-domain-rejects": [mf("EP-4.1.1-possession", "condition unpinned_reason_outside_domain")],
    "evi-unpinned-without-reason-rejects": [mf("EP-4.1.1-possession", "condition unpinned_without_reason")],
    "evi-source-count-mismatch-rejects": [mf("EP-4.3-a-counts", "condition source_count_disagrees_with_sources")],
    "evi-count-inconsistency-rejects": [mf("EP-4.3-a-counts", "condition pinned_count_disagrees_with_pinned_entries")],
    "evi-root-with-zero-pinned-rejects": [mf("EP-4.1.2-empty-root-null", "condition root_present_with_zero_pinned")],
    "evi-nonzero-pinned-null-root-rejects": [mf("EP-4.1.2-empty-root-null", "condition root_null_with_pinned_entries")],
    "evi-fully-pinned-fallback-derives-from-sources-accepted": [prose("EP-4.3-a-counts", "accepted; fully_pinned=false consistent with derived counts (Finding 41)")],
    "evi-root-present-pinned-count-absent-accepted": [prose("EP-4.3-a-counts", "accepted; pinned_count derives to 1 (Finding 43)"), prose("EP-4.1.2-empty-root-null", "a non-null root is consistent with derived pinned_count 1")],
    "evi-resolve-all-counts-absent-accepted": [prose("EP-4.3-a-counts", "step resolves on derived values; MUST NOT halt for want of declared counts (Finding 44)")],
    "evi-root-mismatch-rejects": [mf("EP-4.3-b-root-recompute", "condition root_not_recomputable_from_sources")],
    "evi-empty-root-null": [("EP-4.1.2-empty-root-null", "not covered", REV8_CHECK + " does not execute it", "the vector carries no computed member, so the cross-check's root loop skips it; a non-null root in this vector would still pass. The null expectation is prose only")],
    "evi-absent-unknown": [prose("EP-4.3-e-absent-unknown", "no evidence_set -> unknown; MUST NOT halt")],
    "evi-partial-resolves-unknown": [prose("EP-4.3-c-partial-unknown", "fully_pinned false: step resolves unknown"), prose("EP-4.3-g-distinct-category", "must_not: valid on the offline-recompute claim (the distinction is carried, not collapsed)")],
    "evi-declared-partial-is-not-invalid": [prose("EP-4.3-f-declared-partial-not-invalid", "declared partial set: receipt core-valid, NOT malformed, MUST NOT halt"), prose("EP-4.1-fully_pinned-stated", "the partial state is declared, not concealed")],
    "evi-content-mismatch-unknown": [prose("EP-4.3-d-content-item-unknown", "unknown; per-item reason content_differs")],
    "evi-content-not-held-unknown": [prose("EP-4.3-d-content-item-unknown", "unknown; per-item reason content_not_held")],
    "evi-unpinned-item-reason-content-not-held": [prose("EP-4.3-d-content-item-unknown", "per-item reason content_not_held on the unpinned entry itself (Finding 45)")],
    "evi-step-resolves-affirmatively": [prose("EP-4.3-resolved-token", "step resolves `resolved`, not unknown, not a halt (Finding 29)")],
    "evi-unpinned-members-absent-accepted": [prose("EP-4.1.1-content_kind", "omitted member equivalent to explicit null on an unpinned entry (Finding 30)")],
    "evi-retrieved-at-noncanonical-rejects": [mf("EP-4.1.2-retrieved_at-form", "condition retrieved_at_not_canonical_form")],
    "evi-duplicate-unpinned-entries-rejects": [disc("EP-4.1.2-no-identical-entries", "identity rule halts under the whole-of-sources reading and not under the pinned-only reading (Finding 35)")],
    "evi-unpinned-retrieved-at-noncanonical-rejects": [disc("EP-4.1.2-retrieved_at-form", "a non-canonical value on an unpinned entry is found; none on a pinned entry (Finding 37)")],
    "evi-set-retrieved-at-equals-unpinned-value": [disc("EP-4.1-set-retrieved_at-least", "set retrieved_at equals the least over all entries and not the least over pinned entries (Finding 36)")],
    "evi-set-retrieved-at-above-unpinned-value-rejects": [disc("EP-4.1-set-retrieved_at-least", "set retrieved_at above an unpinned entry's value halts (Finding 36)")],
}
REV8_DISAGREE = ["evi-fully-pinned-fallback-derives-from-sources-accepted", "evi-root-present-pinned-count-absent-accepted", "evi-unpinned-item-reason-content-not-held", "evi-unpinned-members-absent-accepted"]

def build_rev8(manifest):
    out = []
    for v in manifest["vectors"]:
        d = OrderedDict([("id", v["id"]), ("designation", v["designation"]), ("expect", v["expect"])])
        if "condition" in v: d["condition"] = v["condition"]
        d["root_bearing"] = bool(v.get("computed"))
        d["requirements"] = [cov(r, c, ch, a) for (r, c, ch, a) in REV8_MAP[v["id"]]]
        if "condition" in v:
            d["requirements"].append(cov("EP-4.3-condition-identifiers", "partial", REV8_CHECK, "executed part: every MALFORMED vector carries a condition member and none names a superseded identifier (Findings 33, 38)", "the cross-check does not check that a verifier reports the correct condition for the input; an invented condition name would still pass"))
        d["external_requirements"] = []
        if v["id"] in REV8_DISAGREE:
            d["notes"] = ["the external cold-checker run (babyblueviper1, 2026-09-29) disagrees on this vector: it omits snippet_sha256 on an unpinned entry, which -03 §5.3.2 requires present; the corpus side is to be repaired (rev9). Coverage here is as the rev8 text states it."]
        out.append(d)
    return out

def build_leaf(manifest):
    v = manifest["vectors"][0]
    return [OrderedDict([("id", v["id"]), ("expected", v["expected"]), ("failure_mode", v["failure_mode"]),
        ("status", "deferred"),
        ("reason", "the requirement text is third-party: delegation-chain-ref-v1 in giskard09/argentum-core (docs/spec/delegation-chain-ref.md). The leaf-screen-halt README cites it unpinned; the v0.4 manifest pins commit 16e140a. It is not one of the in-scope documents for this mapping."),
        ("assertion_evidence", "examples/conformance/delegation-chain-ref/leaf-screen-halt/verify.py executes continuity, root anchoring, leaf anchoring, leaf scope match and monotonic narrowing; the vector rejects on scope_mismatch_at_leaf"),
        ("external_requirements", [{"requirement": "EXT-delegation-chain-ref-v1", "assertion": "scope_mismatch_at_leaf"}])])]

# ── assembly ────────────────────────────────────────────────────────
def _best(hits):
    if any(h["coverage"] == "covered" for h in hits): return "covered"
    if any(h["coverage"] == "partial" for h in hits): return "partial"
    return "not covered"

def _summary(rows, key="coverage"):
    return OrderedDict([("requirements", len(rows)),
                        ("covered", sum(1 for r in rows.values() if r[key] == "covered")),
                        ("partial", sum(1 for r in rows.values() if r[key] == "partial")),
                        ("not_covered", sum(1 for r in rows.values() if r[key] == "not covered")),
                        ("not_covered_list", [rid for rid, r in rows.items() if r[key] == "not covered"])])

def reverse_view(doc_id, vectors_by_corpus, corpora_in_scope, normative_only=None):
    """normative_only: the subset of corpora_in_scope that is normative; when given,
    every row also carries coverage_excluding_not_normative and the view a second summary."""
    reqs = DOCS[doc_id]["requirements"]
    notes = DOCS[doc_id].get("requirement_notes", {})
    rows = OrderedDict()
    for rid in reqs:
        hits = []
        for corpus, vectors in vectors_by_corpus.items():
            if corpus not in corpora_in_scope: continue
            for v in vectors:
                for r in v.get("requirements", []):
                    if r["requirement"] == rid:
                        hits.append(OrderedDict([("corpus", corpus), ("vector", v["id"]), ("coverage", r["coverage"])]))
        row = OrderedDict([("text", reqs[rid]), ("coverage", _best(hits))])
        if normative_only is not None:
            row["coverage_excluding_not_normative"] = _best([h for h in hits if h["corpus"] in normative_only])
        if rid in notes: row["note"] = notes[rid]
        row["vectors"] = hits
        rows[rid] = row
    view = OrderedDict([("corpora", list(corpora_in_scope)), ("summary", _summary(rows))])
    if normative_only is not None:
        view["summary_excluding_not_normative"] = OrderedDict([("corpora", list(normative_only))] + list(_summary(rows, "coverage_excluding_not_normative").items()))
    view["requirements"] = rows
    return view

def main():
    m03, h03 = load("examples/v0.3-composed/vectors.json")
    m04, h04 = load("examples/v0.4-composed/vectors.json")
    mr2, hr2 = load("conformance/vectors-rule2.json")
    mr8, hr8 = load("fixtures/evidence-pinning-fixtures-v2-rev8.json")
    mlf, hlf = load("examples/conformance/delegation-chain-ref/leaf-screen-halt/vectors.json")
    for key in ("rev2", "rev4"):
        DOCS["EP"]["texts"][key]["sha256"] = hashlib.sha256(snapshot_bytes(DOCS["EP"]["texts"][key]["path"])).hexdigest()
    # pinned-digest checks, against the bytes at the snapshot commit
    for key, t in DOCS["EP"]["texts"].items():
        actual = hashlib.sha256(snapshot_bytes(t["path"])).hexdigest()
        assert actual == t["sha256"], f"{key}: sha256 {actual} != recorded {t['sha256']}"
    # cited texts: the recorded digests are recomputed from the vendored bytes
    for key in ("D01", "MAP"):
        actual = cited_sha256(key)
        assert actual == DOCS[key]["sha256"], f"{key}: cited bytes sha256 {actual} != recorded {DOCS[key]['sha256']}"
        CITED[key]["sha256"] = actual
    assert mr8["header"]["spec_bases"]["review_draft_sha256"] == DOCS["EP"]["texts"]["review-draft"]["sha256"]
    for r in ("5", "6", "7", "8"):
        assert mr8["header"]["spec_bases"][f"rev{r}_sha256"] == DOCS["EP"]["texts"][f"rev{r}"]["sha256"], r

    corpora = OrderedDict()
    corpora["v0.3-composed"] = OrderedDict([("manifest", "examples/v0.3-composed/vectors.json"), ("manifest_sha256", h03), ("normative", True),
        ("requirement_documents", ["D01", "RMT"]), ("external_documents", ["EXT-action-ref-v1", "EXT-signing-trust-ref-v1", "EXT-mycelium-provider-protocol"]),
        ("checkers", ["examples/v0.3-composed/verify.mjs", "examples/v0.3-composed/verify.py"]),
        ("vectors", build_v03(m03))])
    corpora["v0.4-composed"] = OrderedDict([("manifest", "examples/v0.4-composed/vectors.json"), ("manifest_sha256", h04), ("normative", True),
        ("requirement_documents", ["D01", "RMT"]), ("external_documents", ["EXT-action-ref-v1", "EXT-delegation-chain-ref-v1", "EXT-signing-trust-ref-v1"]),
        ("checkers", ["examples/v0.4-composed/verify.mjs", "examples/v0.4-composed/verify.py"]),
        ("vectors", build_v04(m04))])
    corpora["evidence-pinning-rev8"] = OrderedDict([("manifest", "fixtures/evidence-pinning-fixtures-v2-rev8.json"), ("manifest_sha256", hr8), ("normative", True), ("status", "FINAL (rev8)"),
        ("requirement_documents", ["EP"]), ("external_documents", []),
        ("checkers", ["fixtures/evidence-pinning-fixture-crosscheck-rev8.mjs (published, same author as the generator; per its README not a conformance verifier: it checks roots, census and condition identifiers)", "fixtures/evidence-pinning-fixture-generator-rev8.py (emitter validation)", "external: babyblueviper1/preaction-governance-conformance@8e98c0e run_companion_corpus.py"]),
        ("vectors", build_rev8(mr8))])
    corpora["rule2"] = OrderedDict([("manifest", "conformance/vectors-rule2.json"), ("manifest_sha256", hr2), ("normative", False),
        ("label", "NOT NORMATIVE until reviewed and published (the manifest's own $comment)"),
        ("requirement_documents", ["MAP", "D01"]), ("external_documents", ["EXT-service-integrity-D1"]),
        ("checkers", ["conformance/check.mjs"]),
        ("vectors", build_rule2(mr2))])
    corpora["leaf-screen-halt"] = OrderedDict([("manifest", "examples/conformance/delegation-chain-ref/leaf-screen-halt/vectors.json"), ("manifest_sha256", hlf), ("normative", True),
        ("requirement_documents", []), ("external_documents", ["EXT-delegation-chain-ref-v1"]),
        ("checkers", ["examples/conformance/delegation-chain-ref/leaf-screen-halt/verify.py"]),
        ("vectors", build_leaf(mlf))])

    # counts must match the manifests
    expected = {"v0.3-composed": len(m03["accept_vectors"]) + len(m03["reject_vectors"]), "v0.4-composed": len(m04["accept_vectors"]) + len(m04["reject_vectors"]),
                "evidence-pinning-rev8": mr8["header"]["vector_count"], "rule2": len(mr2["vectors"]), "leaf-screen-halt": len(mlf["vectors"])}
    for name, c in corpora.items():
        c["vector_count"] = len(c["vectors"])
        assert c["vector_count"] == expected[name], (name, c["vector_count"], expected[name])
    assert expected["evidence-pinning-rev8"] == len(mr8["vectors"]) == 44

    vectors_by_corpus = OrderedDict((k, c["vectors"]) for k, c in corpora.items())
    reverse = OrderedDict()
    reverse["D01"] = reverse_view("D01", vectors_by_corpus, ["v0.3-composed", "v0.4-composed", "rule2"], normative_only=["v0.3-composed", "v0.4-composed"])
    reverse["D01"]["note"] = "two counts: summary counts every corpus including rule2, which its manifest labels NOT NORMATIVE; summary_excluding_not_normative and each row's coverage_excluding_not_normative count only the normative corpora"
    reverse["RMT"] = reverse_view("RMT", vectors_by_corpus, ["v0.3-composed", "v0.4-composed"])
    reverse["MAP"] = reverse_view("MAP", vectors_by_corpus, ["rule2"], normative_only=[])
    reverse["MAP"]["note"] = "exercised only by the NOT NORMATIVE rule2 set; summary_excluding_not_normative therefore counts no corpus and every row is not covered in it"
    # a view whose scope includes a NOT NORMATIVE corpus must publish the second count
    for doc_id, view in reverse.items():
        has_nn = any(not corpora[c]["normative"] for c in view["corpora"])
        assert has_nn == ("summary_excluding_not_normative" in view), doc_id
        if has_nn: assert view["summary_excluding_not_normative"]["corpora"] == [c for c in view["corpora"] if corpora[c]["normative"]], doc_id
    reverse["EP"] = reverse_view("EP", vectors_by_corpus, ["evidence-pinning-rev8"])
    reverse["EP"]["note"] = "scoped to the evidence-pinning section only, as the fixture header pins it"

    all_req_ids = {rid for d in DOCS.values() for rid in d["requirements"]}
    doc_of = {rid: doc_id for doc_id, d in DOCS.items() for rid in d["requirements"]}
    for cname, c in corpora.items():
        for v in c["vectors"]:
            for r in v.get("requirements", []):
                assert r["requirement"] in all_req_ids, r["requirement"]
                # a vector may link only to documents its own corpus names
                assert doc_of[r["requirement"]] in c["requirement_documents"], (cname, v["id"], r["requirement"])
            for e in v.get("external_requirements", []): assert e["requirement"] in EXTERNAL, e["requirement"]

    doc = OrderedDict()
    doc["$schema"] = "./mapping.schema.json"
    doc["mapping_kind"] = "vector-requirement-mapping"
    doc["methodology"] = OrderedDict([("name", "Agent Receipt Conformance — Grading Methodology"), ("axis", "§2.7 Vector requirement mapping"), ("version", "v0.4.5-draft (§2.7 unchanged from v0.4.1 per its editor)"),
        ("url", "https://github.com/LembaGang/receipt-verify/blob/11d520880d7b3a2647b04d09d84d692c94cc4368/registry/methodology/v0.4.5-draft.md")])
    doc["corpus_snapshot"] = OrderedDict([("repository", "TKCollective/tanilo-receipt-spec"), ("commit", SNAPSHOT)])
    doc["prepared"] = OrderedDict([("by", "Joe Krausz, TK Collective LLC"), ("date", "2026-09-30"), ("revised", "2026-10-06 (mapping-v3, after Michael Msebenzi's re-check of 91e66a7); 2026-10-01 (mapping-v2, after his review of b1da800)"), ("for", "Michael Msebenzi (headlessoracle), receipt-verify registry")])
    doc["cited_texts"] = CITED
    doc["coverage_rule"] = ("Coverage is recorded per vector and requirement only where an assertion is actually executed. "
        "covered: executed by a checker published with the corpus against the shipped file. "
        "partial: declared in the manifest and executed only by the emitter that produced it or by an external run, or the checker exercises part of the requirement. "
        "not covered: no executed assertion. The reverse view takes the best coverage any vector gives a requirement within the corpora it names. "
        "The rev8 cross-check is, in its own README's words, not a conformance verifier: it checks roots, census and condition identifiers, so it can give 'covered' only to root-construction rules and to the four rev8 discriminating vectors.")
    doc["not_counted"] = OrderedDict([
        ("v0.4-branch-vectors", "7 vectors on the unmerged v0.4 branch: not in the snapshot; deferred until merged"),
        ("rev5-rev7-fixtures", "fixtures/evidence-pinning-fixtures-v2-rev5|6|7.json: superseded by rev8; not corpora"),
        ("rev8-known-conflict", "4 rev8 positive fixtures omit snippet_sha256 on unpinned entries, which -03 §5.3.2 requires present; noted per vector; a repaired rev9 is not yet published"),
    ])
    doc["requirement_documents"] = DOCS
    with open(os.path.join(ROOT, CITED["D01"]["path"]), encoding="utf-8") as f: d01_text = f.read()
    audit_rows = build_audit(d01_text, DOCS["D01"]["requirements"])
    doc["external_documents"] = EXTERNAL
    doc["corpora"] = corpora
    doc["totals"] = OrderedDict([("friday_priority", sum(corpora[k]["vector_count"] for k in ("v0.3-composed", "v0.4-composed", "evidence-pinning-rev8"))),
                                 ("also_accounted", corpora["rule2"]["vector_count"] + corpora["leaf-screen-halt"]["vector_count"]),
                                 ("mapped_or_deferred", sum(c["vector_count"] for c in corpora.values()))])
    doc["reverse_view"] = reverse
    # normative audit: every MUST/SHOULD/SHALL/REQUIRED/RECOMMENDED sentence of -01 §§3-7, 9, 10,
    # with the requirement(s) it is mapped to and whether any vector exercises it. Two counts,
    # like the reverse view: over every corpus the D01 view names, and excluding NOT NORMATIVE ones.
    d01_rows = reverse["D01"]["requirements"]
    for row in audit_rows:
        row["exercised"] = any(d01_rows[i]["coverage"] != "not covered" for i in row["requirements"])
        row["exercised_excluding_not_normative"] = any(d01_rows[i]["coverage_excluding_not_normative"] != "not covered" for i in row["requirements"])
    structural = build_structural(d01_text, DOCS["D01"]["requirements"])
    named_by_sentence = {i for row in audit_rows for i in row["requirements"]}
    named_by_structure = {x["requirement"] for x in structural}
    unsourced = [rid for rid in DOCS["D01"]["requirements"] if rid not in named_by_sentence and rid not in named_by_structure]
    assert not unsourced, f"D01 rows with neither an audit sentence nor a structural source: {unsourced}"
    without_sentence = [rid for rid in DOCS["D01"]["requirements"] if rid not in named_by_sentence]
    outside = [OrderedDict([("n", n), ("section", sec), ("text", txt), ("keyword", "MAY" if " MAY " in f" {txt} " else "OPTIONAL")]) for n, (sec, txt) in enumerate(extract_outside(d01_text), 1)]
    nn_scope = reverse["D01"]["summary_excluding_not_normative"]["corpora"]
    doc["normative_audit"] = OrderedDict([
        ("document", "D01"), ("source", CITED["D01"]["path"]), ("sections", ["3", "4", "5", "6", "7", "9", "10"]),
        ("keywords", ["MUST", "MUST NOT", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "REQUIRED", "RECOMMENDED"]),
        ("rule", "every sentence carrying one of the keywords is listed with the requirement identifiers it is mapped to; exercised is true when at least one of those requirements has coverage covered or partial in the reverse view (all corpora), false when every one is not covered (unexercised); exercised_excluding_not_normative is the same test against coverage_excluding_not_normative. A sentence the text breaks across a page is listed whole"),
        ("summary", OrderedDict([("sentences", len(audit_rows)), ("exercised", sum(1 for r in audit_rows if r["exercised"])), ("unexercised", sum(1 for r in audit_rows if not r["exercised"]))])),
        ("summary_excluding_not_normative", OrderedDict([("corpora", list(nn_scope)), ("sentences", len(audit_rows)),
            ("exercised", sum(1 for r in audit_rows if r["exercised_excluding_not_normative"])), ("unexercised", sum(1 for r in audit_rows if not r["exercised_excluding_not_normative"])),
            ("exercised_only_through_not_normative", [r["n"] for r in audit_rows if r["exercised"] and not r["exercised_excluding_not_normative"]])])),
        ("sentences", audit_rows),
        ("structural_sources_rule", "the requirement-bearing items of the same sections that are not keyword sentences: the typ item of §4.1, each numbered step of §4.3 and each body row of Table 2 in §5.1, extracted from the cited bytes, each with the one registry row that stands for it. Every D01 registry row is named by at least one audit sentence or one structural source; rows_without_audit_sentence lists the rows only a structural source names"),
        ("structural_sources", structural),
        ("rows_without_audit_sentence", without_sentence),
        ("outside_audit_rule", "sentences and table rows of the same sections that carry MAY or OPTIONAL and none of the audit keywords. They are outside the audit and are not counted in either summary"),
        ("outside_audit", outside)])
    doc["totals"]["deferred"] = sum(1 for c in corpora.values() for v in c["vectors"] if v.get("status") == "deferred")
    with open(OUT, "w") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False); f.write("\n")
    print("wrote", os.path.relpath(OUT, ROOT))
    for k, c in corpora.items(): print(f"  {k}: {c['vector_count']} vectors")
    for k, r in reverse.items(): print(f"  reverse {k}: {r['summary']}")

if __name__ == "__main__":
    main()
