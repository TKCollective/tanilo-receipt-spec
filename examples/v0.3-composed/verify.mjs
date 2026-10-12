#!/usr/bin/env node
// Conformance verifier for verification.v0.3+composed (Phase 1, 2-signer JWS).
//
// Standalone: Node.js built-ins only (node:crypto, node:fs). A minimal
// RFC 8785 (JCS) serializer is vendored below, scoped to the composed-envelope
// payload domain. Each verifier here is an independent recomputation — not a
// wrapper around any external library — so a pass cross-checks the canonical
// bytes + signatures against a second implementation. The Python sibling
// (verify.py) is a third, in another language.
//
// What this verifies, per accept vector:
//   1. JCS-canonicalize the payload object. Confirm SHA-256 matches expected.
//   2. Recompute composed_decision from the present sibling-pointer verdicts
//      under the AND_PRESENT rule. Confirm match with signed composed_decision.
//   3. Verify EVERY JWS signature against the issuer JWKS (matched by kid).
//   4. Confirm mycelium_trail_id is never null (must be absent or a string).
//
// What this checks, per reject vector:
//   - comp-r01: at least one signature MUST fail verification
//   - comp-r02: payload contains `"mycelium_trail_id": null` — MUST be flagged
//   - comp-r03: composed_decision MUST disagree with the AND_PRESENT recompute

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createHash, createPublicKey, verify as nodeVerify } from 'node:crypto';
import { checkEd25519, rawPublicKeyBytes } from '../ed25519_guard.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------------------
// RFC 8785 JCS — scoped to the composed-envelope payload domain
// ---------------------------------------------------------------------------

const jcsString = (s) => JSON.stringify(s);

const jcsNumber = (n) => {
  if (typeof n !== 'number' || !Number.isFinite(n)) {
    throw new Error(`JCS forbids non-finite numbers, got ${n}`);
  }
  // ECMAScript Number.prototype.toString — exactly what RFC 8785 §3.2.2.3 requires
  return String(n);
};

function jcs(value) {
  if (value === true) return 'true';
  if (value === false) return 'false';
  if (value === null) return 'null';
  if (typeof value === 'string') return jcsString(value);
  if (typeof value === 'number') return jcsNumber(value);
  if (Array.isArray(value)) return '[' + value.map(jcs).join(',') + ']';
  if (typeof value === 'object') {
    // Keys sorted by UTF-16 code units — default JS String comparison
    const keys = Object.keys(value).sort();
    return '{' + keys.map((k) => jcsString(k) + ':' + jcs(value[k])).join(',') + '}';
  }
  throw new Error(`unsupported JCS type: ${typeof value}`);
}

// ---------------------------------------------------------------------------
// Base64url + JWS helpers
// ---------------------------------------------------------------------------

const b64uDecode = (s) => Buffer.from(s, 'base64url');

function publicKeyFromJwk(jwk) {
  // Node 18+ supports JWK directly
  return createPublicKey({ key: jwk, format: 'jwk' });
}

function loadJwks(file) {
  const set = JSON.parse(readFileSync(join(HERE, file), 'utf-8'));
  const byKid = new Map();
  for (const jwk of set.keys) byKid.set(jwk.kid, jwk);
  return byKid;
}

// ---------------------------------------------------------------------------
// Composition rule (AND_PRESENT)
// ---------------------------------------------------------------------------

function recomposeDecision(payload) {
  const verdicts = [];
  if (payload.v_gate) verdicts.push(payload.v_gate.verdict);
  if (payload.v_gate_skill) verdicts.push(payload.v_gate_skill.verdict);
  if (payload.screen_ref) verdicts.push(payload.screen_ref.verdict);
  if (verdicts.length === 0) return 'halt'; // empty composition fails closed
  return verdicts.every((v) => v === 'act') ? 'act' : 'halt';
}

// ---------------------------------------------------------------------------
// Verify one composed envelope
// ---------------------------------------------------------------------------

async function verifyOne(payload, jws, jwksByIssuer, opts = {}) {
  // 1. mycelium_trail_id null check (envelope grammar)
  if ('mycelium_trail_id' in payload && payload.mycelium_trail_id === null) {
    return { ok: false, reason: 'mycelium_trail_id_is_null' };
  }

  // 2. JCS canonicalize + SHA-256
  const canonical = Buffer.from(jcs(payload), 'utf-8');
  const sha = 'sha256-' + createHash('sha256').update(canonical).digest('hex');
  if (opts.expectedCanonicalSha256 && sha !== opts.expectedCanonicalSha256) {
    return { ok: false, reason: 'canonical_sha256_mismatch', computed: sha, expected: opts.expectedCanonicalSha256 };
  }

  // 3. Composed decision recompute under AND_PRESENT
  const composed = recomposeDecision(payload);
  if (payload.composed_decision !== composed) {
    return { ok: false, reason: 'composed_decision_rule_violated', signed: payload.composed_decision, recomputed: composed };
  }

  // 3b. screen_ref content-address recompute (Phase 2). Present iff the key
  // carries a non-null value. Recompute action_ref from the four-field preimage
  // rather than trusting the emitted hash. This binds the screening decision in
  // `scope` (verdict class + entity set); the act/halt composition verdict is
  // bound by the signatures and the AND_PRESENT recompute above. Presence/type
  // tests are kept byte-for-byte identical to verify.py.
  if (payload.screen_ref !== undefined && payload.screen_ref !== null) {
    const screenRef = payload.screen_ref;
    const screen = (typeof screenRef === 'object' && !Array.isArray(screenRef)) ? screenRef.screen : undefined;
    if (typeof screen !== 'object' || screen === null || Array.isArray(screen)) {
      return { ok: false, reason: 'screen_ref_missing_preimage' };
    }
    const recomputed = createHash('sha256').update(Buffer.from(jcs(screen), 'utf-8')).digest('hex');
    if (recomputed !== screenRef.action_ref) {
      return { ok: false, reason: 'screen_ref_action_ref_mismatch', computed: recomputed, claimed: screenRef.action_ref };
    }
  }

  // 4. Verify every signature in the JWS general serialization
  const payloadB64 = jws.payload;
  // Sanity: the b64-decoded payload bytes equal the canonical bytes we just hashed.
  const payloadBytes = b64uDecode(payloadB64);
  if (!payloadBytes.equals(canonical)) {
    return { ok: false, reason: 'jws_payload_mismatch_canonical' };
  }

  for (const sigEntry of jws.signatures) {
    const protectedJson = JSON.parse(b64uDecode(sigEntry.protected).toString('utf-8'));
    const kid = protectedJson.kid;
    if (!kid) return { ok: false, reason: 'jws_missing_kid' };
    if (protectedJson.alg !== 'EdDSA') return { ok: false, reason: 'jws_alg_not_EdDSA', alg: protectedJson.alg };

    // Find the issuer that holds this kid
    let pubKey = null;
    let issuer = null;
    for (const [issuerName, byKid] of jwksByIssuer.entries()) {
      if (byKid.has(kid)) {
        pubKey = publicKeyFromJwk(byKid.get(kid));
        issuer = issuerName;
        break;
      }
    }
    if (!pubKey) return { ok: false, reason: 'jws_kid_not_found_in_any_jwks', kid };

    const signingInput = Buffer.from(sigEntry.protected + '.' + payloadB64, 'ascii');
    const sigBytes = b64uDecode(sigEntry.signature);
    // Small-order key or R, non-canonical encoding, S >= L: rejected before the
    // library is asked (see ../ed25519_guard.mjs); a failed verification with its reason.
    const guard = checkEd25519(rawPublicKeyBytes(pubKey), new Uint8Array(sigBytes));
    if (guard) return { ok: false, reason: 'signature_invalid', guard, kid, issuer };
    const valid = nodeVerify(null, signingInput, pubKey, sigBytes);
    if (!valid) return { ok: false, reason: 'signature_invalid', kid, issuer };
  }

  return { ok: true };
}

// ---------------------------------------------------------------------------
// Run the suite
// ---------------------------------------------------------------------------

async function main() {
  const suite = JSON.parse(readFileSync(join(HERE, 'vectors.json'), 'utf-8'));
  const jwksByIssuer = new Map();
  for (const issuer of suite.issuers) {
    jwksByIssuer.set(issuer.issuer, loadJwks(issuer.jwks_file));
  }

  const failures = [];
  let acceptedOk = 0;
  let rejectedOk = 0;

  for (const v of suite.accept_vectors) {
    const payload = JSON.parse(readFileSync(join(HERE, v.payload_file), 'utf-8'));
    const jws = JSON.parse(readFileSync(join(HERE, v.jws_file), 'utf-8'));
    const result = await verifyOne(payload, jws, jwksByIssuer, { expectedCanonicalSha256: v.expected_canonical_sha256 });
    if (!result.ok) {
      failures.push(`${v.id}: accept vector failed verification — ${JSON.stringify(result)}`);
      continue;
    }
    acceptedOk += 1;
  }

  for (const v of suite.reject_vectors) {
    const payload = JSON.parse(readFileSync(join(HERE, v.payload_file), 'utf-8'));
    const jws = JSON.parse(readFileSync(join(HERE, v.jws_file), 'utf-8'));
    const result = await verifyOne(payload, jws, jwksByIssuer);
    if (result.ok) {
      failures.push(`${v.id}: reject vector incorrectly PASSED — must have failed for ${v.expected_failure}`);
      continue;
    }
    if (result.reason !== v.expected_failure) {
      failures.push(`${v.id}: reject vector failed for wrong reason — expected ${v.expected_failure}, got ${result.reason}`);
      continue;
    }
    rejectedOk += 1;
  }

  const total = suite.accept_vectors.length + suite.reject_vectors.length;
  if (failures.length) {
    console.log(`FAIL: ${failures.length} failure(s) across ${total} vectors\n`);
    for (const f of failures) console.log('- ' + f);
    process.exit(1);
  }
  console.log(`PASS: ${total} vectors (${acceptedOk} accept verified end-to-end, ${rejectedOk} reject correctly refused)`);
}

main().catch((err) => {
  console.error('=== VERIFIER ERROR ===');
  console.error(err.stack || err.message || err);
  process.exit(2);
});
