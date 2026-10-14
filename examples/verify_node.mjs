// verify_node.mjs — End-to-end verification of an AgentOracle receipt using the
// standard `jose` library (https://github.com/panva/jose).
//
// Usage:
//   cd examples
//   npm install jose
//   node verify_node.mjs
//
// Expected output: "VERIFIED OK" (exit code 0).
// If signature / kid / algorithm does not match the live JWKS, throws and exits 1.
//
// ----------------------------------------------------------------------------
// Why the attached (flattened) JWS form is used here:
// The API issues JWS JSON general serialization with an attached payload. This
// script verifies the attached flattened sample so there is zero
// canonicalization ambiguity across languages. The signature covers the exact
// bytes inside the JWS.

import { createRemoteJWKSet, flattenedVerify } from 'jose';
import fs from 'node:fs';

const JWKS_URL = 'https://tanilo.io/.well-known/jwks.json';

async function main() {
  const attachedJws = JSON.parse(fs.readFileSync(
    new URL('./sample_receipt_attached_jws.json', import.meta.url)
  ));

  // Fetch production JWKS — kid in the JWS protected header selects the key.
  const JWKS = createRemoteJWKSet(new URL(JWKS_URL), {
    cacheMaxAge: 300_000,
    cooldownDuration: 30_000,
  });

  const result = await flattenedVerify(attachedJws, JWKS);
  const verified = JSON.parse(new TextDecoder().decode(result.payload));

  console.log('=== VERIFIED OK ===');
  console.log('  algorithm:               ', result.protectedHeader.alg);
  console.log('  key id (kid):            ', result.protectedHeader.kid);
  console.log('  content type:            ', result.protectedHeader.cty);
  console.log('  receipt type:            ', result.protectedHeader.typ);
  console.log('  jwks source:             ', JWKS_URL);
  console.log('');
  console.log('--- Verified payload ---');
  console.log('  evaluation_id:           ', verified.evaluation_id);
  console.log('  claim_text:              ', verified.subject.claim_text);
  console.log('  confidence.score:        ', verified.confidence.score);
  console.log('  confidence.scope:        ', verified.confidence.scope);
  console.log('  calibration.dataset:     ', verified.confidence.calibration_anchor.dataset);
  console.log('  calibration.provisional: ', verified.confidence.calibration_anchor.provisional);
  console.log('  signature.valid_until:   ', verified.signature_meta.valid_until);
  console.log('  calibration.valid_until: ', verified.confidence.valid_until);
  console.log('  evidence.valid_until:    ', verified.evidence.valid_until);
}

main().catch((err) => {
  console.error('=== VERIFICATION FAILED ===');
  console.error(err.message);
  process.exit(1);
});
