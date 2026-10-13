// node --test examples/ed25519_guard.test.mjs
//
// The tests assert only that the guard rejects (or lets through) each input. What the installed
// crypto library itself accepts is printed for information and never asserted: it varies by
// library, backend and version.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createPublicKey, verify as nodeVerify, createHash, generateKeyPairSync, sign as nodeSign } from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { checkEd25519, checkPublicKey, checkSignature, decodePoint, encodePoint, pointMul, isSmallOrder, rawPublicKeyBytes, L, IDENTITY } from "./ed25519_guard.mjs";

const hex = (h) => new Uint8Array(Buffer.from(h, "hex"));
const keyObj = (raw) => createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(raw).toString("base64url") }, format: "jwk" });

const SMALL = [
  "0100000000000000000000000000000000000000000000000000000000000000", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000080",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
];
const SMALL_NONCANONICAL = [
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "0100000000000000000000000000000000000000000000000000000000000080", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
];
// cases.txt, novifinancial/ed25519-speccheck (fetched 2026-10-12): [case, msg, pbk, sig, expected reason]
const TAMING = [
  [0, "8c93255d71dcab10e8f379c26200f3c7bd5f09d9bc3068d3ef4edeb4853022b6", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000", "small_order_key"],
  [1, "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04", "small_order_key"],
  [2, "aebf3f2601a0c8c5d39cc7d8911642f740b78168218da8471772b35f9d35b9ab", "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa8c4bd45aecaca5b24fb97bc10ac27ac8751a7dfe1baff8b953ec9f5833ca260e", "small_order_r"],
  [6, "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40", "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623", "e96f66be976d82e60150baecff9906684aebb1ef181f67a7189ac78ea23b6c0e547f7690a0e2ddcd04d87dbc3490dc19b3b3052f7ff0538cb68afb369ba3a514", "signature_s_out_of_range"],
  [7, "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40", "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623", "8ce5b96c8f26d0ab6c47958c9e68b937104cd36e13c33566acd2fe8d38aa19427e71f98a473474f2f13f06f97c20d58cc3f54b8bd0d272f42b695dd7e89a8c22", "signature_s_out_of_range"],
  [8, "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41", "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03be9678ac102edcd92b0210bb34d7428d12ffc5df5f37e359941266a4e35f0f", "small_order_r"],
  [9, "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41", "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffca8c5b64cd208982aa38d4936621a4775aa233aa0505711d8fdcfdaa943d4908", "small_order_r"],
  [10, "e96b7021eb39c1a163b6da4e3093dcd3f21387da4cc4572be588fafae23c155b", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04", "small_order_key"],
  [11, "39a591f5321bbe07fd5a23dc2f39d025d74526615746727ceefd6e82ae65c06f", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04", "small_order_key"],
];

test("the eight small-order points and their non-canonical encodings are rejected as key and as R", () => {
  for (const h of SMALL) { assert.match(checkPublicKey(hex(h)), /^small_order_key/); assert.match(checkSignature(new Uint8Array([...hex(h), 1, ...new Array(31).fill(0)])), /^small_order_r/); }
  for (const h of SMALL_NONCANONICAL) { assert.match(checkPublicKey(hex(h)), /^small_order_key.*non-canonical/); assert.match(checkSignature(new Uint8Array([...hex(h), 1, ...new Array(31).fill(0)])), /^small_order_r/); }
});

test("RFC 8032 5.1.3: x = 0 with the sign bit set is flagged", () => {
  assert.deepEqual(decodePoint(hex(SMALL[0])), { point: IDENTITY, noncanonical: false });
  assert.deepEqual(decodePoint(hex("0100000000000000000000000000000000000000000000000000000000000080")), { point: IDENTITY, noncanonical: true });
});

test("S at L and above is rejected; S just below L is not, on that ground", () => {
  const r = hex("f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43");
  const le = (v) => { const o = new Uint8Array(32); for (let i = 0; i < 32; i++) { o[i] = Number(v & 255n); v >>= 8n; } return o; };
  assert.equal(checkSignature(new Uint8Array([...r, ...le(L - 1n)])), null);
  assert.match(checkSignature(new Uint8Array([...r, ...le(L)])), /^signature_s_out_of_range/);
});

for (const [c, msg, pbk, sig, expected] of TAMING) {
  test(`Taming case ${c}: ${expected}`, () => {
    console.log(`  node:crypto ${process.version} says ${nodeVerify(null, hex(msg), keyObj(hex(pbk)), hex(sig))} for case ${c}`);
    assert.match(checkEd25519(hex(pbk), hex(sig)), new RegExp("^" + expected));
  });
}

test("the identity key with R = identity, S = 0: whatever the library says, the guard rejects it on any message", () => {
  const identity = hex(SMALL[0]); const idsig = new Uint8Array(64); idsig.set(identity, 0);
  for (const m of ["one message", "a different message"]) {
    const lib = nodeVerify(null, Buffer.from(m), keyObj(identity), idsig);
    console.log(`  node:crypto ${process.version} (OpenSSL ${process.versions.openssl}) says ${lib} for the identity key on "${m}"`);
    assert.match(checkEd25519(identity, idsig), /^small_order_key/);
  }
});

test("a signature that satisfies the verification equation under the published small-order key is rejected by the guard", () => {
  // Taming cases 0/1's key A (order 8). S = 0 and R = -(h mod 8) * A satisfy S*B = R + h*A for our message.
  const rawA = hex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa");
  const { point: A } = decodePoint(rawA); assert.equal(isSmallOrder(A), true);
  const m = Buffer.from("a receipt-shaped message");
  let sig = null;
  for (let k = 0n; k < 8n; k++) {
    const r = encodePoint(pointMul(k, A));
    const h = BigInt("0x" + Buffer.from(createHash("sha512").update(Buffer.concat([Buffer.from(r), Buffer.from(rawA), m])).digest()).reverse().toString("hex")) % L;
    if ((k + h) % 8n === 0n) { sig = new Uint8Array(64); sig.set(r, 0); break; }
  }
  assert.ok(sig);
  console.log(`  node:crypto ${process.version} says ${nodeVerify(null, m, keyObj(rawA), sig)} for that signature`);
  assert.match(checkEd25519(rawA, sig), /^small_order_key/);
});

test("an ordinary key passes the guard", () => {
  const { publicKey } = generateKeyPairSync("ed25519");
  const raw = new Uint8Array(Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url"));
  assert.equal(checkPublicKey(raw), null);
});

// Cases 3, 4 and 5 of the published set have a mixed-order key and R that are not small-order.
// The guard does not check for mixed order (RFC 8032 does not require rejecting it), so it lets
// all three through to the library, which decides them.
const TAMING_NOT_CHECKED = [
  [3, "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79", "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d", "9046a64750444938de19f227bb80485e92b83fdb4b6506c160484c016cc1852f87909e14428a7a1d62e9f22f3d3ad7802db02eb2e688b6c52fcd6648a98bd009"],
  [4, "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c", "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d", "160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed5125ec6bc982a269b723e0668e540911a9a6a58921d6925e434ab10aa7940551a09"],
  [5, "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c", "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d", "21122a84e0b5fca4052f5b1235c80a537878b38f3142356b2c2384ebad4668b7e40bc836dac0f71076f9abe3a53f9c03c1ceeeddb658d0030494ace586687405"],
];
for (const [c, msg, pbk, sig] of TAMING_NOT_CHECKED) {
  test(`Taming case ${c}: mixed-order, not checked by the guard (passes through to the library)`, () => {
    console.log(`  node:crypto ${process.version} says ${nodeVerify(null, hex(msg), keyObj(hex(pbk)), hex(sig))} for case ${c}`);
    assert.equal(checkEd25519(hex(pbk), hex(sig)), null);
  });
}

test("wrong input types are reasons, not exceptions", () => {
  for (const bad of [null, undefined, "0100", 1, [1, 2, 3], {}, 3.5]) {
    assert.equal(checkPublicKey(bad), "key_type: expected a Uint8Array");
    assert.equal(checkSignature(bad), "signature_type: expected a Uint8Array");
    assert.equal(checkEd25519(bad, bad), "key_type: expected a Uint8Array");
  }
  assert.match(checkPublicKey(Buffer.from(SMALL[0], "hex")), /^small_order_key/);   // a Buffer is a Uint8Array
  for (const raw of [new Uint8Array(0), new Uint8Array(31), new Uint8Array(33), new Uint8Array(32).fill(255)]) assert.equal(typeof (checkPublicKey(raw) ?? ""), "string");
  for (const sig of [new Uint8Array(0), new Uint8Array(63), new Uint8Array(65), new Uint8Array(64).fill(255)]) assert.equal(typeof checkSignature(sig), "string");
});

test("rawPublicKeyBytes never throws; a key that is not Ed25519 becomes a key_type reason", () => {
  const ec = generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey;
  for (const bad of [null, undefined, 7, "x", {}, { kty: "OKP", crv: "X25519", x: "AA" }, ec]) {
    assert.equal(rawPublicKeyBytes(bad), null);
    assert.equal(checkEd25519(rawPublicKeyBytes(bad), new Uint8Array(64)), "key_type: expected a Uint8Array");
  }
  const ed = generateKeyPairSync("ed25519").publicKey;
  assert.equal(rawPublicKeyBytes(ed).length, 32);
});

test("ordinary keys and real signatures pass the guard", () => {
  for (let i = 0; i < 25; i++) {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const raw = rawPublicKeyBytes(publicKey); const sig = new Uint8Array(nodeSign(null, Buffer.from("message " + i), privateKey));
    assert.equal(checkEd25519(raw, sig), null);
  }
});

test("the JavaScript port and ed25519_guard.py give the same reason for the same bytes", (t) => {
  const pairs = [];
  const one = new Uint8Array(32); one[0] = 1;
  for (const h of [...SMALL, ...SMALL_NONCANONICAL]) { pairs.push([h, "00".repeat(64)]); pairs.push(["f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43", h + Buffer.from(one).toString("hex")]); }
  for (const [, , pbk, sig] of TAMING) pairs.push([pbk, sig]);
  for (const [, , pbk, sig] of TAMING_NOT_CHECKED) pairs.push([pbk, sig]);
  for (const n of [0, 31, 33]) pairs.push(["ab".repeat(n), "cd".repeat(64)]);
  for (const n of [0, 63, 65]) pairs.push(["f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43", "cd".repeat(n)]);
  pairs.push(["ff".repeat(32), "ff".repeat(64)]);
  for (let i = 0; i < 10; i++) { const { publicKey, privateKey } = generateKeyPairSync("ed25519"); pairs.push([Buffer.from(rawPublicKeyBytes(publicKey)).toString("hex"), nodeSign(null, Buffer.from("m" + i), privateKey).toString("hex")]); }
  const here = fileURLToPath(new URL(".", import.meta.url));
  const py = spawnSync("python3", ["-c", "import sys, json\nsys.path.insert(0, sys.argv[1])\nimport ed25519_guard as g\nprint(json.dumps([g.check_ed25519(bytes.fromhex(k), bytes.fromhex(s)) for k, s in json.load(sys.stdin)]))", here], { input: JSON.stringify(pairs), encoding: "utf8" });
  if (py.error || py.status !== 0) return t.skip("python3 is not available to run ed25519_guard.py: " + (py.error?.message || py.stderr.slice(0, 120)));
  const fromPython = JSON.parse(py.stdout);
  const fromJs = pairs.map(([k, sg]) => checkEd25519(hex(k), hex(sg)));
  assert.equal(fromPython.length, pairs.length);
  let rejected = 0;
  for (let i = 0; i < pairs.length; i++) { assert.equal(fromJs[i], fromPython[i], `pair ${i}: key ${pairs[i][0].slice(0, 16)}…`); if (fromJs[i]) rejected++; }
  console.log(`  ${pairs.length} key/signature pairs compared, identical reasons from both; ${rejected} rejected, ${pairs.length - rejected} passed through`);
});
