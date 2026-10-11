#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 TK Collective LLC
//
// spend-cap.test.mjs — test suite for the spend_cap rule.
//
// Pure: imports the rule and calls it. No server, no network, no clock.
// Every case states the input and the exact result it expects (state, reason,
// and the fields that matter). It also checks the published vectors file
// (spend-cap.vectors.json): every stored result must equal what the rule gives now.
//
// USAGE  node spend-cap.test.mjs                  exit 0 only when every case passes
//        node spend-cap.test.mjs --write-vectors  regenerate spend-cap.vectors.json

import crypto from "node:crypto";
import fs from "node:fs";
import { evaluateSpendCap, SPEND_CAP_RULE_ID, SPEND_CAP_REASONS, SPEND_CAP_EXAMPLE_INPUT } from "./spend-cap.js";
import { jcs } from "./contract-price-jcs.js";

const clone = (x) => JSON.parse(JSON.stringify(x));
const sha = (s) => "sha256-" + crypto.createHash("sha256").update(Buffer.from(s, "utf8")).digest("hex");

// Base offer: USD 1.00 per call, one call, offered on 1 October 2026.
const OFFER = { unit_price: "1.00", currency: "USD", quantity: "1", offered_at: "2026-10-01T12:00:00Z" };
// A per-purchase cap of USD 1.00.
const CAP_P = { amount: "1.00", currency: "USD", scope: "per_purchase" };
// A monthly cap of USD 100.00 for October 2026, of which USD 40.00 is already spent.
const CAP_T = { cap_id: "api-budget-2026-10", amount: "100.00", currency: "USD", scope: "per_period", already_spent: "40.00", period: { from: "2026-10-01T00:00:00Z", to: "2026-11-01T00:00:00Z" } };

const offer = (patch = {}) => { const o = { ...clone(OFFER), ...patch }; for (const k of Object.keys(o)) if (o[k] === undefined) delete o[k]; return o; };
const cap = (patch = {}, base = CAP_P) => { const c = { ...clone(base), ...patch }; for (const k of Object.keys(c)) if (c[k] === undefined) delete c[k]; return c; };

// [name, input, want]. want: { state, reason, total, remaining, excess, exhausted } or { invalid: path }.
const CASES = [
  // ── exactly at the cap ──
  ["at cap: 1.00 x 1 against 1.00", { offer: offer(), cap: cap() }, { state: "verified", total: "1.00", remaining: "1.00" }],
  ["at cap: 0.25 x 4 against 1.00", { offer: offer({ unit_price: "0.25", quantity: "4" }), cap: cap() }, { state: "verified", total: "1.00", remaining: "1.00" }],
  ["at cap: spelling \"1\" equals \"1.00\"", { offer: offer({ unit_price: "1" }), cap: cap({ amount: "1.000" }) }, { state: "verified", total: "1.00", remaining: "1.00" }],
  ["at cap, per period: 60.00 remaining, offer 60.00", { offer: offer({ unit_price: "60.00" }), cap: cap({}, CAP_T) }, { state: "verified", total: "60.00", remaining: "60.00" }],

  // ── one cent over, and smaller ──
  ["one cent over: 1.01 x 1 against 1.00", { offer: offer({ unit_price: "1.01" }), cap: cap() }, { state: "contradicted", reason: "cap_exceeded", total: "1.01", remaining: "1.00", excess: "0.01", exhausted: false }],
  ["one cent over, per period: 60.01 against 60.00 remaining", { offer: offer({ unit_price: "60.01" }), cap: cap({}, CAP_T) }, { state: "contradicted", reason: "cap_exceeded", total: "60.01", remaining: "60.00", excess: "0.01" }],
  ["a hundredth of a cent over: 0.3334 x 3 = 1.0002", { offer: offer({ unit_price: "0.3334", quantity: "3" }), cap: cap() }, { state: "contradicted", reason: "cap_exceeded", total: "1.0002", excess: "0.0002" }],
  ["smallest representable excess", { offer: offer({ unit_price: "1.00000001" }), cap: cap() }, { state: "contradicted", reason: "cap_exceeded", excess: "0.00000001" }],
  ["under by a hundredth of a cent: 0.3333 x 3 = 0.9999", { offer: offer({ unit_price: "0.3333", quantity: "3" }), cap: cap() }, { state: "verified", total: "0.9999", remaining: "1.00" }],

  // ── zero ──
  ["zero price against a zero cap", { offer: offer({ unit_price: "0.00", quantity: "5" }), cap: cap({ amount: "0" }) }, { state: "verified", total: "0.00", remaining: "0.00" }],
  ["zero cap, positive price", { offer: offer({ unit_price: "0.01" }), cap: cap({ amount: "0.00" }) }, { state: "contradicted", reason: "cap_exceeded", total: "0.01", remaining: "0.00", excess: "0.01" }],
  ["zero price against a positive cap", { offer: offer({ unit_price: "0" }), cap: cap() }, { state: "verified", total: "0.00" }],
  ["per period: remaining exactly zero, offer zero", { offer: offer({ unit_price: "0.00" }), cap: cap({ already_spent: "100.00" }, CAP_T) }, { state: "verified", total: "0.00", remaining: "0.00" }],
  ["per period: remaining exactly zero, offer one cent", { offer: offer({ unit_price: "0.01" }), cap: cap({ already_spent: "100.00" }, CAP_T) }, { state: "contradicted", reason: "cap_exceeded", remaining: "0.00", excess: "0.01", exhausted: false }],

  // ── rounding traps: nothing is rounded ──
  ["no float error: 0.10 x 3 against 0.30", { offer: offer({ unit_price: "0.10", quantity: "3" }), cap: cap({ amount: "0.30" }) }, { state: "verified", total: "0.30" }],
  ["no float error: 0.1 x 3 = 0.30 is under a cap of 0.30000001", { offer: offer({ unit_price: "0.1", quantity: "3" }), cap: cap({ amount: "0.30000001" }) }, { state: "verified", total: "0.30", remaining: "0.30000001" }],
  ["16 fraction digits in the total: 0.12345678 x 0.12345678 = 0.0152415765279684, under an 8-digit cap", { offer: offer({ unit_price: "0.12345678", quantity: "0.12345678" }), cap: cap({ amount: "0.01524158" }) }, { state: "verified", total: "0.0152415765279684", remaining: "0.01524158" }],
  ["16 fraction digits in the total, over an 8-digit cap by part of a digit", { offer: offer({ unit_price: "0.12345678", quantity: "0.12345678" }), cap: cap({ amount: "0.01524157" }) }, { state: "contradicted", reason: "cap_exceeded", total: "0.0152415765279684", excess: "0.0000000065279684" }],
  ["large amounts stay exact", { offer: offer({ unit_price: "123456789012345678.12345678", quantity: "1" }), cap: cap({ amount: "123456789012345678.12345678" }) }, { state: "verified" }],
  ["large amounts: one unit over", { offer: offer({ unit_price: "123456789012345678.12345678", quantity: "1" }), cap: cap({ amount: "123456789012345677.12345678" }) }, { state: "contradicted", reason: "cap_exceeded", excess: "1.00" }],
  ["fractional quantity: 2.5 x 0.40 = 1.00", { offer: offer({ unit_price: "0.40", quantity: "2.5" }), cap: cap() }, { state: "verified", total: "1.00" }],
  ["large quantity: 1000000 x 0.000001 = 1.00", { offer: offer({ unit_price: "0.000001", quantity: "1000000" }), cap: cap() }, { state: "verified", total: "1.00" }],

  // ── per period: already_spent and bounds ──
  ["per period: well under", { offer: offer({ unit_price: "10.00" }), cap: cap({}, CAP_T) }, { state: "verified", total: "10.00", remaining: "60.00" }],
  ["per period: already_spent absent defaults to zero", { offer: offer({ unit_price: "100.00" }), cap: cap({ already_spent: undefined }, CAP_T) }, { state: "verified", total: "100.00", remaining: "100.00" }],
  ["per period: cap already exhausted before this offer", { offer: offer({ unit_price: "1.00" }), cap: cap({ already_spent: "120.00" }, CAP_T) }, { state: "contradicted", reason: "cap_exceeded", remaining: "-20.00", excess: "21.00", exhausted: true }],
  ["per period: offer at the period start is inside", { offer: offer({ offered_at: "2026-10-01T00:00:00Z" }), cap: cap({}, CAP_T) }, { state: "verified" }],
  ["per period: offer one millisecond before the end is inside", { offer: offer({ offered_at: "2026-10-31T23:59:59.999Z" }), cap: cap({}, CAP_T) }, { state: "verified" }],
  ["per period: offer at the period end is outside", { offer: offer({ offered_at: "2026-11-01T00:00:00Z" }), cap: cap({}, CAP_T) }, { state: "indeterminate", reason: "offer_outside_period" }],
  ["per period: offer before the period", { offer: offer({ offered_at: "2026-09-30T23:59:59Z" }), cap: cap({}, CAP_T) }, { state: "indeterminate", reason: "offer_outside_period" }],
  ["per period: period bounds missing", { offer: offer(), cap: cap({ period: undefined }, CAP_T) }, { state: "indeterminate", reason: "period_bounds_missing" }],
  ["per period: offer time missing", { offer: offer({ offered_at: undefined }), cap: cap({}, CAP_T) }, { state: "indeterminate", reason: "offer_time_missing" }],
  ["per purchase: offer time is not needed", { offer: offer({ offered_at: undefined }), cap: cap() }, { state: "verified" }],

  // ── mixed currencies, missing quantity ──
  ["currency: offer in EUR, cap in USD", { offer: offer({ currency: "EUR" }), cap: cap() }, { state: "indeterminate", reason: "currency_mismatch" }],
  ["currency: cap in GBP, per period", { offer: offer(), cap: cap({ currency: "GBP" }, CAP_T) }, { state: "indeterminate", reason: "currency_mismatch" }],
  ["quantity missing: no total can be computed", { offer: offer({ quantity: undefined }), cap: cap() }, { state: "indeterminate", reason: "quantity_missing" }],
  ["order: currency differs and quantity missing: currency is reported", { offer: offer({ currency: "EUR", quantity: undefined }), cap: cap() }, { state: "indeterminate", reason: "currency_mismatch" }],
  ["order: quantity missing and offer outside period: quantity is reported", { offer: offer({ quantity: undefined, offered_at: "2026-12-01T00:00:00Z" }), cap: cap({}, CAP_T) }, { state: "indeterminate", reason: "quantity_missing" }],
  ["order: period bounds missing and offer time missing: bounds are reported", { offer: offer({ offered_at: undefined }), cap: cap({ period: undefined }, CAP_T) }, { state: "indeterminate", reason: "period_bounds_missing" }],
  ["optional seller and sku are carried", { offer: offer({ seller: "seller.example", sku: "api.weather.v1" }), cap: cap() }, { state: "verified" }],
  ["cap_id is carried", { offer: offer({ unit_price: "10.00" }), cap: cap({ cap_id: "team-a-october" }, CAP_T) }, { state: "verified" }],

  // ── input that cannot be read as declared: no result at all ──
  ["invalid: price given as a JSON number", { offer: offer({ unit_price: 1.0 }), cap: cap() }, { invalid: "offer.unit_price" }],
  ["invalid: cap amount given as a JSON number", { offer: offer(), cap: cap({ amount: 1 }) }, { invalid: "cap.amount" }],
  ["invalid: negative amount", { offer: offer(), cap: cap({ amount: "-1.00" }) }, { invalid: "cap.amount" }],
  ["invalid: amount with a currency symbol", { offer: offer(), cap: cap({ amount: "$1.00" }) }, { invalid: "cap.amount" }],
  ["invalid: quantity zero", { offer: offer({ quantity: "0" }), cap: cap() }, { invalid: "offer.quantity" }],
  ["invalid: unknown scope", { offer: offer(), cap: cap({ scope: "per_day" }) }, { invalid: "cap.scope" }],
  ["invalid: already_spent with a per-purchase cap", { offer: offer(), cap: cap({ already_spent: "0.50" }) }, { invalid: "cap.already_spent" }],
  ["invalid: period with a per-purchase cap", { offer: offer(), cap: cap({ period: CAP_T.period }) }, { invalid: "cap.period" }],
  ["invalid: period end not after start", { offer: offer(), cap: cap({ period: { from: "2026-10-01T00:00:00Z", to: "2026-10-01T00:00:00Z" } }, CAP_T) }, { invalid: "cap.period.to" }],
  ["invalid: period with only a start", { offer: offer(), cap: cap({ period: { from: "2026-10-01T00:00:00Z" } }, CAP_T) }, { invalid: "cap.period.to" }],
  ["invalid: date without a time", { offer: offer({ offered_at: "2026-10-01" }), cap: cap({}, CAP_T) }, { invalid: "offer.offered_at" }],
  ["invalid: unknown member on the cap (a note)", { offer: offer(), cap: cap({ note: "approved by Sam" }) }, { invalid: "cap.note" }],
  ["invalid: unknown member on the offer", { offer: offer({ discount: "10" }), cap: cap() }, { invalid: "offer.discount" }],
  ["invalid: lower-case currency code", { offer: offer({ currency: "usd" }), cap: cap() }, { invalid: "offer.currency" }],
  ["invalid: cap missing", { offer: offer() }, { invalid: "input.cap" }],
  ["invalid: more than 8 fraction digits", { offer: offer({ unit_price: "1.000000001" }), cap: cap() }, { invalid: "offer.unit_price" }],
];

let pass = 0, fail = 0;
const check = (name, cond, got) => { if (cond) pass++; else { fail++; console.error(`  FAIL: ${name}${got !== undefined ? " — got " + JSON.stringify(got) : ""}`); } };

for (const [name, input, want] of CASES) {
  const r = evaluateSpendCap(clone(input));
  const before = fail;
  if (want.invalid) {
    check(`${name}: rejected as invalid input`, r.invalid === true, r);
    check(`${name}: names the offending member (${want.invalid})`, r.path === want.invalid, r.path);
    check(`${name}: carries no state`, r.state === undefined);
  } else {
    const e = r.evidence || {};
    check(`${name}: state ${want.state}`, r.state === want.state, { state: r.state, reason: r.reason, invalid: r.message });
    check(`${name}: reason ${want.reason ?? "none"}`, (r.reason ?? null) === (want.reason ?? null), r.reason);
    if (want.reason) check(`${name}: reason is in the published list`, want.reason in SPEND_CAP_REASONS);
    if (want.total !== undefined) check(`${name}: total ${want.total}`, e.offer_total === want.total, e.offer_total);
    if (want.remaining !== undefined) check(`${name}: remaining ${want.remaining}`, e.remaining === want.remaining, e.remaining);
    if (want.excess !== undefined) check(`${name}: excess ${want.excess}`, e.excess === want.excess, e.excess);
    if (want.exhausted !== undefined) check(`${name}: cap_already_exhausted ${want.exhausted}`, e.cap_already_exhausted === want.exhausted, e.cap_already_exhausted);
    if (want.state === "verified") check(`${name}: no excess when verified`, e.excess === null && e.cap_already_exhausted === false);
    if (want.state === "indeterminate") check(`${name}: no remaining and no excess when indeterminate`, e.remaining === null && e.excess === null);
    if (want.state === "contradicted") check(`${name}: total, remaining and excess recorded when contradicted`, typeof e.offer_total === "string" && typeof e.remaining === "string" && typeof e.excess === "string");
    check(`${name}: records the rule id`, e.rule_id === SPEND_CAP_RULE_ID);
    check(`${name}: says the cap was supplied by the caller`, e.cap_source === "caller_supplied");
    check(`${name}: records the steps applied`, Array.isArray(e.steps) && e.steps.length >= 1 && e.steps[0].step === "currency");
  }
  console.log(`${before === fail ? "ok  " : "FAIL"}  ${name}`);
}

// ── properties that hold across cases ──
console.log("\nproperties");
{
  const input = { offer: offer({ unit_price: "1.01" }), cap: cap() };
  const a = evaluateSpendCap(clone(input)), b = evaluateSpendCap(clone(input));
  check("same input gives byte-identical output", jcs(a) === jcs(b));
  check("input is not modified", jcs(input) === jcs({ offer: offer({ unit_price: "1.01" }), cap: cap() }));
  check("offer hash is the SHA-256 of the offer's canonical JSON", a.evidence.offer_sha256 === sha(jcs(input.offer)));
  check("cap hash is the SHA-256 of the cap's canonical JSON", a.evidence.cap_sha256 === sha(jcs(input.cap)));
  check("member order inside the cap does not change its hash", evaluateSpendCap({ offer: input.offer, cap: Object.fromEntries(Object.entries(CAP_P).reverse()) }).evidence.cap_sha256 === a.evidence.cap_sha256);
  check("changing the cap changes the cap hash", evaluateSpendCap({ offer: input.offer, cap: cap({ amount: "2.00" }) }).evidence.cap_sha256 !== a.evidence.cap_sha256);
  const steps = a.evidence.steps.map((x) => x.step).join(" > ");
  check("steps run in the published order", steps === "currency > quantity > total > remaining_cap > compare", steps);
  const t = evaluateSpendCap({ offer: offer({ unit_price: "60.01" }), cap: cap({}, CAP_T) });
  check("per-period steps record the period test", t.evidence.steps.some((s) => s.step === "remaining_cap" && s.scope === "per_period" && s.offer_in_period === true), t.evidence.steps);
  const src = ["./spend-cap.js", "./contract-price-jcs.js"].map((f) => fs.readFileSync(new URL(f, import.meta.url), "utf8")).join("\n").replace(/\/\/.*$/gm, "").replace(/"[^"\n]*"|`[^`]*`/g, '""');
  check("the rule's code calls no network, clock, random source or model", !/\bfetch\s*\(|axios|https?:\/\/|Date\.now|new Date\(\)|Math\.random|openai|perplexity|gemma|inference|process\.env|child_process|\bimport\s*\(/i.test(src));
  check("the rule imports only node:crypto and the shared canonical-JSON module", (fs.readFileSync(new URL("./spend-cap.js", import.meta.url), "utf8").match(/^import .*$/gm) || []).join("|") === 'import crypto from "node:crypto";|import { jcs } from "./contract-price-jcs.js";');
}

// ── error messages say what was received and what to send ──
console.log("\nerror messages");
{
  const E = clone(SPEND_CAP_EXAMPLE_INPUT);
  const msg = (i) => evaluateSpendCap(i).message || "";
  check("the built-in example input is valid and contradicted", evaluateSpendCap(clone(E)).state === "contradicted");
  let m = msg({ ...E, cap: { ...E.cap, amount: 25 } });
  check("a JSON number: says it must be in quotes, shows an example, says what it got", /in quotes/.test(m) && /"1\.00"/.test(m) && /got the JSON number 25/.test(m), m);
  m = msg({ ...E, cap: { ...E.cap, scope: "monthly" } });
  check("an unknown scope: names the two scopes and echoes the value", /per_purchase/.test(m) && /per_period/.test(m) && /got the string "monthly"/.test(m), m);
  m = msg({ ...E, cap: { ...E.cap, scope: "per_purchase", already_spent: "1.00", period: undefined } });
  check("already_spent with per_purchase: says it belongs to per_period", /per_period/.test(m), m);
  m = msg({ ...E, cap: { ...E.cap, note: "x" } });
  check("an unknown member: lists the recognised members", /nothing is silently ignored/.test(m) && /already_spent/.test(m), m);
}

// ── published vectors ──
const VECTORS = new URL("./spend-cap.vectors.json", import.meta.url);
const slim = (r) => (r.invalid ? { invalid: true, member: r.path } : r);
const built = { rule_id: SPEND_CAP_RULE_ID, license: "CC0-1.0", note: "Each case is an input and the exact result the rule gives. For input that cannot be read, the result names the member at fault; the message text is not part of the vectors.", cases: CASES.map(([name, input], i) => ({ id: "spc-" + String(i + 1).padStart(3, "0"), name, input, result: slim(evaluateSpendCap(clone(input))) })) };
if (process.argv.includes("--write-vectors")) {
  fs.writeFileSync(VECTORS, JSON.stringify(built, null, 2) + "\n");
  console.log(`\nwrote ${built.cases.length} vectors`);
} else {
  console.log("\npublished vectors");
  let stored = null;
  try { stored = JSON.parse(fs.readFileSync(VECTORS, "utf8")); } catch (e) { check("spend-cap.vectors.json is present and readable", false, String(e.message)); }
  if (stored) {
    check("vectors carry the rule id", stored.rule_id === SPEND_CAP_RULE_ID);
    check(`vectors hold one case per test case (${stored.cases.length})`, stored.cases.length === CASES.length);
    let same = 0; const diff = [];
    for (const c of stored.cases) {
      const now = slim(evaluateSpendCap(clone(c.input)));
      if (jcs(JSON.parse(JSON.stringify(now))) === jcs(c.result)) same++; else diff.push(c.id);
    }
    check(`every stored result equals what the rule gives now (${same}/${stored.cases.length})`, diff.length === 0, diff.slice(0, 5));
  }
}

console.log(`\n${CASES.length} cases, ${pass} assertions passed, ${fail} failed`);
process.exit(fail === 0 && CASES.length >= 40 ? 0 : 1);
