// verify_detached_node.mjs — Verifies the detached RFC 7797 sample fixture.
//
// Companion to verify_detached_python.py. See that file's docstring for the
// recomputation contract. This one uses only Node.js built-ins so `npm
// install` isn't required.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createHash, createPublicKey, verify as nodeVerify } from 'node:crypto';
import { checkEd25519, rawPublicKeyBytes } from './ed25519_guard.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));

const b64uDec = (s) =>
  Buffer.from(s + '='.repeat((4 - (s.length % 4)) % 4), 'base64url');

// ---- RFC 8785 JCS ----
const jcsString = (s) => JSON.stringify(s);
const jcsNumber = (n) => {
  if (typeof n !== 'number' || !Number.isFinite(n))
    throw new Error(`JCS forbids non-finite ${n}`);
  return n.toString();
};
const jcs = (o) => {
  if (o === null) return 'null';
  if (o === true) return 'true';
  if (o === false) return 'false';
  if (typeof o === 'string') return jcsString(o);
  if (typeof o === 'number') return jcsNumber(o);
  if (Array.isArray(o)) return '[' + o.map(jcs).join(',') + ']';
  if (typeof o === 'object') {
    const keys = Object.keys(o).sort((a, b) => {
      const ua = Buffer.from(a, 'utf16le').swap16();
      const ub = Buffer.from(b, 'utf16le').swap16();
      return Buffer.compare(ua, ub);
    });
    return '{' + keys.map((k) => jcsString(k) + ':' + jcs(o[k])).join(',') + '}';
  }
  throw new Error(`JCS: unsupported type ${typeof o}`);
};

const payloadObj = JSON.parse(readFileSync(join(HERE, 'sample_payload.json'), 'utf8'));
const payloadBytes = Buffer.from(jcs(payloadObj), 'utf8');

const detached = JSON.parse(readFileSync(join(HERE, 'sample_receipt_detached_jws.json'), 'utf8'));
const header = JSON.parse(b64uDec(detached.protected).toString('utf8'));
if (header.b64 !== false) throw new Error('expected RFC 7797 b64=false');
if (!header.crit?.includes('b64')) throw new Error('expected b64 in crit');
if (header.alg !== 'EdDSA') throw new Error('expected alg=EdDSA');

const localJwks = JSON.parse(readFileSync(join(HERE, 'jwks-fixture-detached.json'), 'utf8'));
const keys = localJwks.public_only?.keys || localJwks.keys;
const pubJwk = keys.find((k) => k.kid === header.kid);
if (!pubJwk) throw new Error(`kid not found: ${header.kid}`);

const publicKey = createPublicKey({ key: { ...pubJwk, d: undefined }, format: 'jwk' });
const signingInput = Buffer.concat([
  Buffer.from(detached.protected, 'ascii'),
  Buffer.from('.', 'ascii'),
  payloadBytes,
]);

// Small-order key or R, non-canonical encoding, S >= L, mixed-order key or R: rejected before the library verifies the signature.
const guard = checkEd25519(rawPublicKeyBytes(publicKey), new Uint8Array(b64uDec(detached.signature)));
if (guard) {
  console.error('=== DETACHED VERIFICATION FAILED ===');
  console.error(guard);
  process.exit(1);
}
const ok = nodeVerify(null, signingInput, publicKey, b64uDec(detached.signature));
if (!ok) {
  console.error('=== DETACHED VERIFICATION FAILED ===');
  process.exit(1);
}

console.log('=== DETACHED FIXTURE VERIFIED (RFC 7797 b64=false, JCS-canonical) ===');
console.log(`  kid:                        ${header.kid}`);
console.log(`  alg:                        ${header.alg}`);
console.log(`  b64:                        ${header.b64}`);
console.log(`  crit:                       ${JSON.stringify(header.crit)}`);
console.log(`  cty:                        ${header.cty}`);
console.log(`  payload JCS bytes:          ${payloadBytes.length}`);
console.log(`  signing input bytes:        ${signingInput.length}`);
console.log(`  payload sha256:             ${createHash('sha256').update(payloadBytes).digest('hex')}`);
