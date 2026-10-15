// ed25519_guard.mjs: Ed25519 input guard (small-order points, non-canonical
// encodings, S range, mixed-order points), run before the library verifies the
// signature.
//
// JavaScript port of tanilo_receipt_verify/ed25519_guard.py as released in
// tanilo-receipt-verify 0.2.3 (tag v0.2.3). ed25519_guard.py beside this
// file is a byte-identical copy of that module. Same decoding, same checks,
// same reason codes; the reason texts are identical too, except the two
// input-type reasons, which name the JavaScript type. Pure BigInt arithmetic,
// no dependency. It never throws: a wrong input type, a wrong length or
// malformed bytes return a reason instead.
//
// From the 0.2.1 module, unchanged, and the 0.2.2 addition after it:
//
//   With the identity public key, the signature R = identity, S = 0 satisfies
//   the verification equation for every message. For other small-order keys,
//   acceptance depends on the verifier's equation and the message. This
//   release rejects all small-order public keys and R values.
//
//   Acceptance of these edge cases varies by library, backend and version. In
//   our measurements, cryptography 50.0.1 (OpenSSL 4.0.2) and Node 18 (OpenSSL
//   3.0.16) accepted Taming cases 0, 1, 2 and 11 and the identity-key
//   signature; Node 24 (OpenSSL 3.5.7) rejected them. This release applies its
//   input restrictions independently of the backend.
//   (Vectors: "Taming the many EdDSAs", Chalkias, Garillot, Nikolaenko 2020;
//   novifinancial/ed25519-speccheck.)
//
//   Rejecting a small-order R is a stricter acceptance policy than the RFC
//   8032 verification equation: an equation-valid signature whose R is a
//   small-order point is refused here. A key holder can construct an
//   equation-valid signature with small-order R deliberately. Small-order R is
//   also possible, with negligible probability, under normal RFC 8032 signing.
//
//   The identity-key behavior was reported by Noûs through
//   @robertolocatelli81-dev in x402-foundation/tsc#4. @babyblueviper1
//   reproduced it and added small-order checks to
//   preaction-governance-conformance at 90b5032. This release adds
//   corresponding input restrictions to Tanilo's verifier.
//
//   Mixed-order points (0.2.2). A mixed-order point is neither small-order nor
//   in the prime-order subgroup: [L]P is not the identity. Whether a signature
//   under a mixed-order key, or with a mixed-order R, verifies depends on
//   whether the verifier uses the cofactorless or the cofactored equation of
//   RFC 8032 section 5.1.7, so two conforming verifiers can disagree. This
//   module refuses both, after every other check. Like the small-order R rule,
//   this is a stricter acceptance policy than the RFC 8032 verification
//   equation: some equation-valid signatures with a mixed-order A or R are
//   refused. It is not a fix for a forgery under an ordinary key.
//
// Checks, before the library verifies the signature:
//   - the public key must decode to a point on the curve (RFC 8032 section
//     5.1.3, including its rule that x = 0 with the sign bit set is invalid),
//     must be canonically encoded (y < p), and must not be a small-order point
//     (order 1, 2, 4 or 8, whatever its encoding);
//   - the signature's R must decode and must not be a small-order point;
//   - the signature's S must satisfy 0 <= S < L (RFC 8032 section 5.1.7);
//   - then, after all of the above: [L]A must be the identity, and [L]R must
//     be the identity, where L, the order of the base point (the prime-order
//     subgroup), is 2^252 + 27742317777372353535851937790883648493 (RFC 8032
//     section 5.1). The point is multiplied by L itself; the scalar is never
//     reduced mod L, which would multiply by zero and pass every point.
//
//   checkEd25519(publicKey: Uint8Array, signature: Uint8Array) -> string | null
//
// Returns null when the pair may go to the library, otherwise a reason that
// starts with one of, in the order they are checked: key_type, key_length,
// key_not_on_curve, small_order_key, noncanonical_key_encoding,
// signature_type, signature_length, r_not_on_curve, small_order_r,
// noncanonical_r_encoding, signature_s_out_of_range, mixed_order_key,
// mixed_order_r.

const P = (1n << 255n) - 19n;
export const L = (1n << 252n) + 27742317777372353535851937790883648493n;   // L, the order of the base point (the prime-order subgroup); RFC 8032 section 5.1
const mod = (a) => ((a % P) + P) % P;
const inv = (x) => modpow(mod(x), P - 2n);
function modpow(b, e) { let r = 1n; b = mod(b); while (e > 0n) { if (e & 1n) r = mod(r * b); b = mod(b * b); e >>= 1n; } return r; }
const D = mod(-121665n * inv(121666n));
const SQRT_M1 = modpow(2n, (P - 1n) / 4n);
export const IDENTITY = [0n, 1n];

function leToBigInt(bytes) { let v = 0n; for (let i = bytes.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(bytes[i]); return v; }

// RFC 8032 section 5.1.3. Returns { point, noncanonical } with point null when
// the bytes do not encode a point on the curve. noncanonical is true for
// y >= p and for x = 0 with the sign bit set (the RFC rejects both; the point
// is still returned so a non-canonical small-order point can be named as such).
export function decodePoint(bytes) {
  if (bytes.length !== 32) return { point: null, noncanonical: false };
  let y = leToBigInt(bytes);
  const sign = y >> 255n;
  y &= (1n << 255n) - 1n;
  let noncanonical = false;
  if (y >= P) { y -= P; noncanonical = true; }
  const y2 = mod(y * y);
  const u = mod(y2 - 1n);
  const v = mod(D * y2 + 1n);
  const x2 = mod(u * inv(v));
  let x = modpow(x2, (P + 3n) / 8n);
  if (mod(x * x - x2) !== 0n) x = mod(x * SQRT_M1);
  if (mod(x * x - x2) !== 0n) return { point: null, noncanonical };
  if (x === 0n) { if (sign === 1n) noncanonical = true; }
  else if ((x & 1n) !== sign) x = P - x;
  return { point: [x, y], noncanonical };
}

export function encodePoint([x, y]) {
  let v = y | ((x & 1n) << 255n);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) { out[i] = Number(v & 255n); v >>= 8n; }
  return out;
}

export function pointAdd([x1, y1], [x2, y2]) {
  const k = mod(D * x1 * x2 * y1 * y2);
  return [mod((x1 * y2 + x2 * y1) * inv(1n + k)), mod((y1 * y2 + x1 * x2) * inv(1n - k))];
}

export function pointMul(k, pt) {
  let result = IDENTITY, addend = pt;
  while (k > 0n) { if (k & 1n) result = pointAdd(result, addend); addend = pointAdd(addend, addend); k >>= 1n; }
  return result;
}

export function isSmallOrder(pt) { const q = pointMul(8n, pt); return q[0] === 0n && q[1] === 1n; }

export function checkPublicKey(raw) {
  if (!(raw instanceof Uint8Array)) return "key_type: expected a Uint8Array";
  if (raw.length !== 32) return `key_length: an Ed25519 public key is 32 bytes, got ${raw.length}`;
  const { point, noncanonical } = decodePoint(raw);
  if (!point) return "key_not_on_curve: the public key bytes do not encode a point on the Ed25519 curve";
  if (isSmallOrder(point)) return "small_order_key: the public key encodes a small-order point (order 1, 2, 4 or 8)" + (noncanonical ? ", in a non-canonical encoding" : "") + "; under such a key a signature can verify for every message, so a valid signature would establish nothing";
  if (noncanonical) return "noncanonical_key_encoding: the public key is not a canonical RFC 8032 encoding (y >= p, or x = 0 with the sign bit set)";
  return null;
}

export function checkSignature(sig) {
  if (!(sig instanceof Uint8Array)) return "signature_type: expected a Uint8Array";
  if (sig.length !== 64) return `signature_length: an Ed25519 signature is 64 bytes, got ${sig.length}`;
  const { point, noncanonical } = decodePoint(sig.subarray(0, 32));
  if (!point) return "r_not_on_curve: the signature's R does not encode a point on the Ed25519 curve";
  if (isSmallOrder(point)) return "small_order_r: the signature's R encodes a small-order point (order 1, 2, 4 or 8)" + (noncanonical ? ", in a non-canonical encoding" : "") + "; this verifier's acceptance policy rejects small-order R values (stricter than the RFC 8032 verification equation)";
  if (noncanonical) return "noncanonical_r_encoding: the signature's R is not a canonical RFC 8032 encoding (y >= p, or x = 0 with the sign bit set)";
  if (leToBigInt(sig.subarray(32)) >= L) return "signature_s_out_of_range: S >= L; RFC 8032 section 5.1.7 requires 0 <= S < L";
  return null;
}

// The scalar for the subgroup check: L, the order of the base point (the prime-order subgroup); RFC 8032 section
// 5.1. Used as it is, never reduced mod L ([L mod L]P = [0]P is the identity for every point, so a reduced scalar
// would pass everything).
export const L_ORDER_SCALAR = (1n << 252n) + 27742317777372353535851937790883648493n;
const D2 = mod(2n * D);

// Extended twisted Edwards addition, a = -1 (Hisil, Wong, Carter, Dawson 2008, "add-2008-hwcd-3").
// Complete for Ed25519 (d is not a square), so it also doubles and handles the identity.
function extAdd([x1, y1, z1, t1], [x2, y2, z2, t2]) {
  const a = mod((y1 - x1) * (y2 - x2)), b = mod((y1 + x1) * (y2 + x2)), c = mod(t1 * D2 * t2), d = mod(z1 * 2n * z2);
  const e = b - a, f = d - c, g = d + c, h = b + a;
  return [mod(e * f), mod(g * h), mod(f * g), mod(e * h)];
}

// True when [k]pt is the identity. k is used exactly as given (no reduction).
export function mulIsIdentity(k, [x, y]) {
  let result = [0n, 1n, 1n, 0n], addend = [x, y, 1n, mod(x * y)];
  while (k > 0n) { if (k & 1n) result = extAdd(result, addend); addend = extAdd(addend, addend); k >>= 1n; }
  return mod(result[0]) === 0n && mod(result[1] - result[2]) === 0n;
}

// True when [L]pt is the identity: pt is in the prime-order subgroup (or is the identity).
export function isTorsionFree(pt) { return mulIsIdentity(L_ORDER_SCALAR, pt); }

// The subgroup checks, for a pair that has passed checkPublicKey and checkSignature: null when [L]A and [L]R are
// both the identity. Never throws.
export function checkMixedOrder(publicKey, signature) {
  try {
    const A = decodePoint(publicKey).point, R = decodePoint(signature.subarray(0, 32)).point;
    if (!A || !R) return null;   // not reached after the earlier checks; those already returned a reason
    if (!isTorsionFree(A)) return "mixed_order_key: the public key is a mixed-order point ([L]A is not the identity: it has a small-order component); whether a signature under it verifies depends on the verifier's equation (cofactored or cofactorless, RFC 8032 section 5.1.7), so this verifier's acceptance policy rejects it (stricter than the RFC 8032 verification equation)";
    if (!isTorsionFree(R)) return "mixed_order_r: the signature's R is a mixed-order point ([L]R is not the identity: it has a small-order component); whether the signature verifies depends on the verifier's equation (cofactored or cofactorless, RFC 8032 section 5.1.7), so this verifier's acceptance policy rejects it (stricter than the RFC 8032 verification equation)";
    return null;
  } catch { return "mixed_order_check_failed: the subgroup check could not run on these bytes"; }
}

// The key is checked first, so a small-order key with a small-order R reports small_order_key. The mixed-order
// checks run last, after every earlier check has passed; a mixed-order key with a mixed-order R reports
// mixed_order_key.
export function checkEd25519(publicKey, signature) { return checkPublicKey(publicKey) || checkSignature(signature) || checkMixedOrder(publicKey, signature); }

// The raw public key bytes of a Node KeyObject (or an OKP JWK): what the guard checks.
// Returns null, never throws, when the input is not an Ed25519 public key; checkPublicKey(null)
// then answers key_type.
export function rawPublicKeyBytes(keyObjectOrJwk) {
  try {
    const jwk = typeof keyObjectOrJwk?.export === "function" ? keyObjectOrJwk.export({ format: "jwk" }) : keyObjectOrJwk;
    if (!jwk || jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") return null;
    return new Uint8Array(Buffer.from(jwk.x, "base64url"));
  } catch { return null; }
}
