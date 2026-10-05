#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 TK Collective LLC
//
// contract-price.test.mjs — test suite for the contract_price_match rule.
//
// Pure: imports the rule and calls it. No server, no network, no clock.
// Every case states the input change it makes to a base case and the exact
// result it expects (state, reason, and the fields that matter).
//
// It also checks the published vectors file (contract-price.vectors.json):
// every case's stored result must equal what the rule gives now.
//
// USAGE  node contract-price.test.mjs                  exit 0 only when every case passes
//        node contract-price.test.mjs --write-vectors  regenerate contract-price.vectors.json

import crypto from "node:crypto";
import fs from "node:fs";
import { evaluateContractPrice, CONTRACT_PRICE_RULE_ID, CONTRACT_PRICE_REASONS, CONTRACT_PRICE_EXAMPLE_INPUT } from "./contract-price.js";
import { jcs } from "./contract-price-jcs.js";

const clone = (x) => JSON.parse(JSON.stringify(x));
const sha = (s) => "sha256-" + crypto.createHash("sha256").update(Buffer.from(s, "utf8")).digest("hex");

// UC12: the supplied term assigns USD 1.00 per call for this seller and resource.
const OFFER = { unit_price: "1.00", currency: "USD", unit: "call", quantity: "1", seller: "seller.example", sku: "api.weather.v1", offered_at: "2026-10-01T12:00:00Z" };
const FLAT = { agreement_id: "MSA-2026-014", version: "1", seller: "seller.example", product_scope: { skus: ["api.weather.v1"] }, currency: "USD", unit: "call", price_per_unit: "1.00", effective_from: "2026-01-01T00:00:00Z", effective_to: "2027-01-01T00:00:00Z" };
const TIERED = { agreement_id: "SUP-77", version: "1", seller: "seller.example", product_scope: { skus: ["widget-9"] }, currency: "USD", unit: "each", tiers: [
  { min_quantity: "1", max_quantity: "100", price_per_unit: "1.20" },
  { min_quantity: "100", max_quantity: "500", price_per_unit: "1.00" },
  { min_quantity: "500", price_per_unit: "0.80" },
], effective_from: "2026-01-01T00:00:00Z" };
const WOFFER = { unit_price: "1.20", currency: "USD", unit: "each", quantity: "50", seller: "seller.example", sku: "widget-9", offered_at: "2026-10-01T12:00:00Z" };

const offer = (patch = {}) => ({ ...clone(OFFER), ...patch });
const woffer = (patch = {}) => ({ ...clone(WOFFER), ...patch });
const term = (patch = {}, baseTerm = FLAT) => {
  const t = { ...clone(baseTerm), ...patch };
  for (const k of Object.keys(t)) if (t[k] === undefined) delete t[k];
  return t;
};

// Amendment set: v1 open-ended at 1.00; v2 from 1 July at 0.90, declared to supersede v1.
const V1 = term({ effective_to: undefined });
const V2 = term({ version: "2", price_per_unit: "0.90", effective_from: "2026-07-01T00:00:00Z", effective_to: undefined, supersedes: "1" });
const V3 = term({ version: "3", price_per_unit: "0.85", effective_from: "2026-09-01T00:00:00Z", effective_to: undefined, supersedes: "2" });

const CASES = [
  // ── UC12 and plain price comparison ──
  ["UC12-a offer 1.00, term 1.00", { offer: offer(), terms: [FLAT] }, { state: "verified", expected: "1.00", term: ["MSA-2026-014", "1"] }],
  ["UC12-b offer 2.00, term 1.00", { offer: offer({ unit_price: "2.00" }), terms: [FLAT] }, { state: "contradicted", reason: "price_mismatch", expected: "1.00", offered: "2.00", diff: "1.00", dir: "above_term_price" }],
  ["offer below the term price", { offer: offer({ unit_price: "0.90" }), terms: [FLAT] }, { state: "contradicted", reason: "price_mismatch", expected: "1.00", offered: "0.90", diff: "-0.10", dir: "below_term_price" }],
  ["spelling \"1\" equals \"1.00\"", { offer: offer({ unit_price: "1" }), terms: [FLAT] }, { state: "verified", expected: "1.00" }],
  ["spelling \"1.000\" equals \"1.00\"", { offer: offer({ unit_price: "1.000" }), terms: [FLAT] }, { state: "verified" }],
  ["a tenth of a cent is a difference", { offer: offer({ unit_price: "1.001" }), terms: [FLAT] }, { state: "contradicted", reason: "price_mismatch", diff: "0.001", dir: "above_term_price" }],
  ["no float error at 0.30", { offer: offer({ unit_price: "0.30" }), terms: [term({ price_per_unit: "0.30" })] }, { state: "verified", expected: "0.30" }],
  ["smallest representable difference", { offer: offer({ unit_price: "0.30000001" }), terms: [term({ price_per_unit: "0.30" })] }, { state: "contradicted", reason: "price_mismatch", diff: "0.00000001" }],
  ["zero price matches zero price", { offer: offer({ unit_price: "0.00" }), terms: [term({ price_per_unit: "0" })] }, { state: "verified", expected: "0.00" }],
  ["large amounts stay exact", { offer: offer({ unit_price: "123456789012345678.12345678" }), terms: [term({ price_per_unit: "123456789012345678.12345679" })] }, { state: "contradicted", reason: "price_mismatch", diff: "-0.00000001" }],

  // ── quantity tiers (lower bound inclusive, upper bound exclusive) ──
  ["tier: quantity 50 in [1,100)", { offer: woffer(), terms: [TIERED] }, { state: "verified", expected: "1.20", tier: ["1", "100"] }],
  ["tier: quantity 100 sits in [100,500)", { offer: woffer({ quantity: "100", unit_price: "1.00" }), terms: [TIERED] }, { state: "verified", expected: "1.00", tier: ["100", "500"] }],
  ["tier: lower-tier price offered at quantity 100", { offer: woffer({ quantity: "100", unit_price: "1.20" }), terms: [TIERED] }, { state: "contradicted", reason: "price_mismatch", expected: "1.00", offered: "1.20", diff: "0.20" }],
  ["tier: fractional quantity 99.5 in [1,100)", { offer: woffer({ quantity: "99.5" }), terms: [TIERED] }, { state: "verified", expected: "1.20", tier: ["1", "100"] }],
  ["tier: open-ended top tier at 5000", { offer: woffer({ quantity: "5000", unit_price: "0.80" }), terms: [TIERED] }, { state: "verified", expected: "0.80", tier: ["500", null] }],
  ["tier: quantity 500 is the first of the top tier", { offer: woffer({ quantity: "500", unit_price: "1.00" }), terms: [TIERED] }, { state: "contradicted", reason: "price_mismatch", expected: "0.80" }],
  ["tier: gap between tiers", { offer: woffer({ quantity: "150" }), terms: [term({ tiers: [{ min_quantity: "1", max_quantity: "100", price_per_unit: "1.20" }, { min_quantity: "200", price_per_unit: "1.00" }] }, TIERED)] }, { state: "indeterminate", reason: "tier_selection_unresolved", detail: /^gap/ }],
  ["tier: overlapping tiers", { offer: woffer({ quantity: "75" }), terms: [term({ tiers: [{ min_quantity: "1", max_quantity: "100", price_per_unit: "1.20" }, { min_quantity: "50", max_quantity: "200", price_per_unit: "1.00" }] }, TIERED)] }, { state: "indeterminate", reason: "tier_selection_unresolved", detail: /^overlap/ }],
  ["tier: quantity below the first tier", { offer: woffer({ quantity: "0.5" }), terms: [TIERED] }, { state: "indeterminate", reason: "tier_selection_unresolved", detail: /^gap/ }],

  // ── effective dates (start inclusive, end exclusive) ──
  ["dates: offer before the term starts", { offer: offer({ offered_at: "2025-12-31T23:59:59Z" }), terms: [FLAT] }, { state: "indeterminate", reason: "effective_interval_unresolved" }],
  ["dates: offer at the exact start", { offer: offer({ offered_at: "2026-01-01T00:00:00Z" }), terms: [FLAT] }, { state: "verified" }],
  ["dates: offer at the exact end is outside", { offer: offer({ offered_at: "2027-01-01T00:00:00Z" }), terms: [FLAT] }, { state: "indeterminate", reason: "effective_interval_unresolved" }],
  ["dates: one millisecond before the end is inside", { offer: offer({ offered_at: "2026-12-31T23:59:59.999Z" }), terms: [FLAT] }, { state: "verified" }],
  ["dates: open-ended term years later", { offer: offer({ offered_at: "2031-06-01T00:00:00Z" }), terms: [V1] }, { state: "verified" }],
  ["dates: expired term is not used", { offer: offer({ offered_at: "2027-03-01T00:00:00Z" }), terms: [FLAT] }, { state: "indeterminate", reason: "effective_interval_unresolved" }],

  // ── amendments and versions ──
  ["versions: back-to-back dates, offer in the later one", { offer: offer({ unit_price: "0.90", offered_at: "2026-08-01T00:00:00Z" }), terms: [term({ effective_to: "2026-07-01T00:00:00Z" }), term({ version: "2", price_per_unit: "0.90", effective_from: "2026-07-01T00:00:00Z", effective_to: undefined })] }, { state: "verified", expected: "0.90", term: ["MSA-2026-014", "2"] }],
  ["versions: back-to-back dates, offer in the earlier one", { offer: offer({ offered_at: "2026-03-01T00:00:00Z" }), terms: [term({ effective_to: "2026-07-01T00:00:00Z" }), term({ version: "2", price_per_unit: "0.90", effective_from: "2026-07-01T00:00:00Z", effective_to: undefined })] }, { state: "verified", expected: "1.00", term: ["MSA-2026-014", "1"] }],
  ["amendment: declared to supersede, old price offered", { offer: offer({ offered_at: "2026-08-01T00:00:00Z" }), terms: [V1, V2] }, { state: "contradicted", reason: "price_mismatch", expected: "0.90", offered: "1.00", term: ["MSA-2026-014", "2"] }],
  ["amendment: declared to supersede, new price offered", { offer: offer({ unit_price: "0.90", offered_at: "2026-08-01T00:00:00Z" }), terms: [V1, V2] }, { state: "verified", expected: "0.90", term: ["MSA-2026-014", "2"] }],
  ["amendment: offer before the amendment starts uses the original", { offer: offer({ offered_at: "2026-03-01T00:00:00Z" }), terms: [V1, V2] }, { state: "verified", expected: "1.00", term: ["MSA-2026-014", "1"] }],
  ["amendment: two versions in effect, no declared precedence", { offer: offer({ offered_at: "2026-08-01T00:00:00Z" }), terms: [V1, term({ version: "2", price_per_unit: "0.90", effective_from: "2026-07-01T00:00:00Z", effective_to: undefined })] }, { state: "indeterminate", reason: "precedence_unresolved", competing: 2 }],
  ["amendment: chain of three, latest wins by declaration", { offer: offer({ unit_price: "0.85" }), terms: [V1, V2, V3] }, { state: "verified", expected: "0.85", term: ["MSA-2026-014", "3"] }],
  ["amendment: order of the supplied terms does not matter", { offer: offer({ unit_price: "0.85" }), terms: [V3, V1, V2] }, { state: "verified", expected: "0.85", term: ["MSA-2026-014", "3"] }],
  ["amendment: superseding term changes the unit; the old unit is not matched", { offer: offer({ offered_at: "2026-08-01T00:00:00Z" }), terms: [V1, term({ version: "2", unit: "thousand calls", price_per_unit: "900.00", effective_from: "2026-07-01T00:00:00Z", effective_to: undefined, supersedes: "1" })] }, { state: "indeterminate", reason: "unit_mismatch" }],
  ["amendment: the superseding term has ended; the original applies again", { offer: offer(), terms: [V1, term({ version: "2", price_per_unit: "0.90", effective_from: "2026-07-01T00:00:00Z", effective_to: "2026-09-01T00:00:00Z", supersedes: "1" })] }, { state: "verified", expected: "1.00", term: ["MSA-2026-014", "1"] }],
  ["amendment: chain whose middle term has ended is not bridged", { offer: offer({ unit_price: "0.85" }), terms: [V1, term({ version: "2", price_per_unit: "0.90", effective_from: "2026-07-01T00:00:00Z", effective_to: "2026-09-01T00:00:00Z", supersedes: "1" }), V3] }, { state: "indeterminate", reason: "precedence_unresolved", competing: 2 }],
  ["amendment: superseding term is in another currency; the old term is not used", { offer: offer({ offered_at: "2026-08-01T00:00:00Z" }), terms: [V1, term({ version: "2", currency: "EUR", price_per_unit: "0.90", effective_from: "2026-07-01T00:00:00Z", effective_to: undefined, supersedes: "1" })] }, { state: "indeterminate", reason: "currency_mismatch" }],
  ["amendment: supersedes a version that was not supplied", { offer: offer({ unit_price: "0.90", offered_at: "2026-08-01T00:00:00Z" }), terms: [V2] }, { state: "verified", expected: "0.90", term: ["MSA-2026-014", "2"] }],

  // ── overlapping terms across agreements ──
  ["overlap: two agreements cover the product, same price", { offer: offer(), terms: [FLAT, term({ agreement_id: "PO-88" })] }, { state: "indeterminate", reason: "precedence_unresolved", competing: 2 }],
  ["overlap: two agreements cover the product, different prices", { offer: offer(), terms: [FLAT, term({ agreement_id: "PO-88", price_per_unit: "0.95" })] }, { state: "indeterminate", reason: "precedence_unresolved", competing: 2 }],
  ["overlap: supersedes does not reach across agreements", { offer: offer(), terms: [FLAT, term({ agreement_id: "PO-88", supersedes: "1", version: "2" })] }, { state: "indeterminate", reason: "precedence_unresolved", competing: 2 }],
  ["overlap: two agreements, one priced in another unit: unit does not choose between them", { offer: offer(), terms: [FLAT, term({ agreement_id: "PO-88", unit: "thousand calls", price_per_unit: "900.00" })] }, { state: "indeterminate", reason: "precedence_unresolved", competing: 2 }],
  ["overlap: two agreements, one in USD and one in EUR: currency does not choose between them", { offer: offer(), terms: [FLAT, term({ agreement_id: "PO-88", currency: "EUR", price_per_unit: "0.92" })] }, { state: "indeterminate", reason: "precedence_unresolved", competing: 2 }],
  ["overlap: two agreements, both in another currency: still precedence, not currency", { offer: offer(), terms: [term({ currency: "EUR" }), term({ agreement_id: "PO-88", currency: "EUR" })] }, { state: "indeterminate", reason: "precedence_unresolved", competing: 2 }],
  ["overlap: two versions, one in EUR, no declared precedence", { offer: offer({ offered_at: "2026-08-01T00:00:00Z" }), terms: [V1, term({ version: "2", currency: "EUR", price_per_unit: "0.90", effective_from: "2026-07-01T00:00:00Z", effective_to: undefined })] }, { state: "indeterminate", reason: "precedence_unresolved", competing: 2 }],

  // ── unit and currency ──
  ["currency: term in EUR, offer in USD", { offer: offer(), terms: [term({ currency: "EUR" })] }, { state: "indeterminate", reason: "currency_mismatch" }],
  ["unit: term per thousand calls, offer per call", { offer: offer(), terms: [term({ unit: "thousand calls", price_per_unit: "900.00" })] }, { state: "indeterminate", reason: "unit_mismatch" }],
  ["unit: spelling differs only by case", { offer: offer({ unit: "Call" }), terms: [FLAT] }, { state: "indeterminate", reason: "unit_mismatch" }],
  ["currency and unit both differ: currency is reported", { offer: offer(), terms: [term({ currency: "EUR", unit: "thousand calls" })] }, { state: "indeterminate", reason: "currency_mismatch" }],

  // ── which reason is reported when several would apply: the first step that stops ──
  ["order: wrong seller and outside the dates: scope is reported", { offer: offer({ seller: "other.example", offered_at: "2025-06-01T00:00:00Z" }), terms: [FLAT] }, { state: "indeterminate", reason: "no_applicable_term" }],
  ["order: outside the dates and another currency: dates are reported", { offer: offer({ offered_at: "2025-06-01T00:00:00Z" }), terms: [term({ currency: "EUR" })] }, { state: "indeterminate", reason: "effective_interval_unresolved" }],
  ["order: another unit and no matching tier: unit is reported", { offer: woffer({ unit: "case", quantity: "0.5" }), terms: [TIERED] }, { state: "indeterminate", reason: "unit_mismatch" }],

  // ── time precision ──
  ["time: one fractional digit is accepted", { offer: offer({ offered_at: "2026-10-01T12:00:00.5Z" }), terms: [FLAT] }, { state: "verified" }],
  ["time: whole seconds and milliseconds name the same instant", { offer: offer({ offered_at: "2026-01-01T00:00:00.000Z" }), terms: [FLAT] }, { state: "verified" }],

  // ── missing terms ──
  ["missing: no terms supplied", { offer: offer(), terms: [] }, { state: "indeterminate", reason: "no_applicable_term" }],
  ["missing: terms are for another seller", { offer: offer({ seller: "other.example" }), terms: [FLAT] }, { state: "indeterminate", reason: "no_applicable_term" }],
  ["missing: product not in the term's scope", { offer: offer({ sku: "api.maps.v2" }), terms: [FLAT] }, { state: "indeterminate", reason: "no_applicable_term" }],
  ["missing: seller spelling differs only by case", { offer: offer({ seller: "Seller.example" }), terms: [FLAT] }, { state: "indeterminate", reason: "no_applicable_term" }],
  ["scope: term lists several products", { offer: offer(), terms: [term({ product_scope: { skus: ["api.maps.v2", "api.weather.v1"] } })] }, { state: "verified" }],

  // ── input that cannot be read as declared: no result at all ──
  ["invalid: price given as a JSON number", { offer: offer({ unit_price: 1.0 }), terms: [FLAT] }, { invalid: "offer.unit_price" }],
  ["invalid: term price given as a JSON number", { offer: offer(), terms: [term({ price_per_unit: 1 })] }, { invalid: "terms[0].price_per_unit" }],
  ["invalid: date without a time", { offer: offer(), terms: [term({ effective_from: "2026-01-01" })] }, { invalid: "terms[0].effective_from" }],
  ["invalid: local time without Z", { offer: offer({ offered_at: "2026-10-01T12:00:00" }), terms: [FLAT] }, { invalid: "offer.offered_at" }],
  ["invalid: time with an offset instead of Z", { offer: offer({ offered_at: "2026-10-01T12:00:00+02:00" }), terms: [FLAT] }, { invalid: "offer.offered_at" }],
  ["invalid: more than three fractional digits in a time", { offer: offer({ offered_at: "2026-10-01T12:00:00.1234Z" }), terms: [FLAT] }, { invalid: "offer.offered_at" }],
  ["invalid: time without seconds", { offer: offer({ offered_at: "2026-10-01T12:00Z" }), terms: [FLAT] }, { invalid: "offer.offered_at" }],
  ["invalid: impossible calendar date", { offer: offer({ offered_at: "2026-02-30T00:00:00Z" }), terms: [FLAT] }, { invalid: "offer.offered_at" }],
  ["invalid: unknown member on a term (a discount)", { offer: offer(), terms: [term({ discount_percent: "10" })] }, { invalid: "terms[0].discount_percent" }],
  ["invalid: unknown member on the offer", { offer: offer({ note: "rush" }), terms: [FLAT] }, { invalid: "offer.note" }],
  ["invalid: term has both one price and tiers", { offer: offer(), terms: [term({ tiers: TIERED.tiers })] }, { invalid: "terms[0]" }],
  ["invalid: term has neither a price nor tiers", { offer: offer(), terms: [term({ price_per_unit: undefined })] }, { invalid: "terms[0]" }],
  ["invalid: same agreement version twice", { offer: offer(), terms: [FLAT, FLAT] }, { invalid: "terms[1]" }],
  ["invalid: terms that supersede one another", { offer: offer(), terms: [term({ supersedes: "2" }), term({ version: "2", supersedes: "1" })] }, { invalid: "terms[0].supersedes" }],
  ["invalid: negative price", { offer: offer({ unit_price: "-1.00" }), terms: [FLAT] }, { invalid: "offer.unit_price" }],
  ["invalid: price with a thousands separator", { offer: offer({ unit_price: "1,000.00" }), terms: [FLAT] }, { invalid: "offer.unit_price" }],
  ["invalid: price with an exponent", { offer: offer({ unit_price: "1e2" }), terms: [FLAT] }, { invalid: "offer.unit_price" }],
  ["invalid: quantity zero", { offer: offer({ quantity: "0" }), terms: [FLAT] }, { invalid: "offer.quantity" }],
  ["invalid: tier upper bound not above lower bound", { offer: woffer(), terms: [term({ tiers: [{ min_quantity: "100", max_quantity: "100", price_per_unit: "1.00" }] }, TIERED)] }, { invalid: "terms[0].tiers[0].max_quantity" }],
  ["invalid: term ends before it starts", { offer: offer(), terms: [term({ effective_to: "2025-01-01T00:00:00Z" })] }, { invalid: "terms[0].effective_to" }],
  ["invalid: offer without a seller", { offer: (() => { const o = offer(); delete o.seller; return o; })(), terms: [FLAT] }, { invalid: "offer.seller" }],
  ["invalid: lower-case currency code", { offer: offer({ currency: "usd" }), terms: [FLAT] }, { invalid: "offer.currency" }],
  ["invalid: terms is not an array", { offer: offer(), terms: FLAT }, { invalid: "terms" }],
];

let pass = 0, fail = 0;
const check = (name, cond, got) => { if (cond) pass++; else { fail++; console.error(`  FAIL: ${name}${got !== undefined ? " — got " + JSON.stringify(got) : ""}`); } };

for (const [name, input, want] of CASES) {
  const r = evaluateContractPrice(clone(input));
  const before = fail;
  if (want.invalid) {
    check(`${name}: rejected as invalid input`, r.invalid === true, r);
    check(`${name}: names the offending member (${want.invalid})`, r.path === want.invalid, r.path);
    check(`${name}: carries no state`, r.state === undefined);
  } else {
    const e = r.evidence || {};
    check(`${name}: state ${want.state}`, r.state === want.state, { state: r.state, reason: r.reason, invalid: r.message });
    check(`${name}: reason ${want.reason ?? "none"}`, (r.reason ?? null) === (want.reason ?? null), r.reason);
    if (want.reason) check(`${name}: reason is in the published list`, want.reason in CONTRACT_PRICE_REASONS);
    if (want.expected !== undefined) check(`${name}: expected price ${want.expected}`, e.expected?.price_per_unit === want.expected, e.expected);
    if (want.offered !== undefined) check(`${name}: offered price ${want.offered}`, e.offered?.unit_price === want.offered, e.offered);
    if (want.diff !== undefined) check(`${name}: difference ${want.diff}`, e.difference_per_unit === want.diff, e.difference_per_unit);
    if (want.dir !== undefined) check(`${name}: direction ${want.dir}`, e.offer_is === want.dir, e.offer_is);
    if (want.term) check(`${name}: matched term ${want.term.join(" v")}`, e.matched_term?.agreement_id === want.term[0] && e.matched_term?.version === want.term[1], e.matched_term);
    if (want.tier) check(`${name}: tier [${want.tier[0]}, ${want.tier[1]})`, e.matched_term?.tier?.min_quantity === want.tier[0] && e.matched_term?.tier?.max_quantity === want.tier[1], e.matched_term?.tier);
    if (want.detail) check(`${name}: detail ${want.detail}`, want.detail.test(e.detail || ""), e.detail);
    if (want.competing) check(`${name}: lists ${want.competing} competing terms`, e.competing_terms?.length === want.competing, e.competing_terms);
    if (want.state === "indeterminate") check(`${name}: no matched term and no expected price when indeterminate`, e.matched_term === null && e.expected === null);
    if (want.state !== "indeterminate") check(`${name}: matched term and expected price are recorded`, !!e.matched_term && !!e.expected);
    check(`${name}: records the rule id`, e.rule_id === CONTRACT_PRICE_RULE_ID);
    check(`${name}: says the terms were supplied by the caller`, e.terms_source === "caller_supplied");
    check(`${name}: records the steps applied`, Array.isArray(e.steps) && e.steps.length >= 1 && e.steps[0].step === "scope");
  }
  console.log(`${before === fail ? "ok  " : "FAIL"}  ${name}`);
}

// ── properties that hold across cases ──
console.log("\nproperties");
{
  const input = { offer: offer({ unit_price: "2.00" }), terms: [FLAT] };
  const a = evaluateContractPrice(clone(input)), b = evaluateContractPrice(clone(input));
  check("same input gives byte-identical output", jcs(a) === jcs(b));
  check("input is not modified", jcs(input) === jcs({ offer: offer({ unit_price: "2.00" }), terms: [FLAT] }));
  check("matched term hash is the SHA-256 of the term's canonical JSON", a.evidence.matched_term.term_sha256 === sha(jcs(FLAT)), a.evidence.matched_term.term_sha256);
  check("terms hash is the SHA-256 of the supplied terms' canonical JSON", a.evidence.terms_sha256 === sha(jcs([FLAT])));
  check("offer hash is the SHA-256 of the offer's canonical JSON", a.evidence.offer_sha256 === sha(jcs(input.offer)));
  const ab = evaluateContractPrice({ offer: offer({ unit_price: "0.85" }), terms: [V1, V2, V3] }), ba = evaluateContractPrice({ offer: offer({ unit_price: "0.85" }), terms: [V3, V2, V1] });
  check("the terms hash is over the array in the order supplied: reordering changes the hash", ab.evidence.terms_sha256 !== ba.evidence.terms_sha256);
  check("reordering the terms does not change the state or the matched term", ab.state === ba.state && ab.evidence.matched_term.term_sha256 === ba.evidence.matched_term.term_sha256);
  check("member order inside a term does not change its hash", evaluateContractPrice({ offer: input.offer, terms: [Object.fromEntries(Object.entries(FLAT).reverse())] }).evidence.terms_sha256 === a.evidence.terms_sha256);
  const steps = a.evidence.steps.map((x) => x.step).join(" > ");
  check("steps run in the published order", steps === "scope > effective_at_offer_time > declared_precedence > exactly_one_term > currency > unit > price > compare", steps);
  const changed = evaluateContractPrice({ offer: input.offer, terms: [term({ price_per_unit: "1.01" })] });
  check("changing a term changes the terms hash", changed.evidence.terms_sha256 !== a.evidence.terms_sha256);
  const big = Array.from({ length: 200 }, (_, i) => term({ agreement_id: "A-" + i, product_scope: { skus: ["other-" + i] } }));
  check("200 terms are accepted", evaluateContractPrice({ offer: offer(), terms: big }).state === "indeterminate");
  check("201 terms are rejected", evaluateContractPrice({ offer: offer(), terms: [...big, term({ agreement_id: "A-200", product_scope: { skus: ["x"] } })] }).invalid === true);
  const src = ["./contract-price.js", "./contract-price-jcs.js"].map((f) => fs.readFileSync(new URL(f, import.meta.url), "utf8")).join("\n").replace(/\/\/.*$/gm, "").replace(/"[^"\n]*"|`[^`]*`/g, '""');
  check("the rule's code calls no network, clock, random source or model", !/\bfetch\s*\(|axios|https?:\/\/|Date\.now|new Date\(\)|Math\.random|openai|perplexity|gemma|inference|process\.env|child_process|\bimport\s*\(/i.test(src));
  check("the rule imports only node:crypto and its own canonical-JSON module", (fs.readFileSync(new URL("./contract-price.js", import.meta.url), "utf8").match(/^import .*$/gm) || []).join("|") === 'import crypto from "node:crypto";|import { jcs } from "./contract-price-jcs.js";');
}

// ── error messages say what was received and what to send ──
console.log("\nerror messages");
{
  const E = clone(CONTRACT_PRICE_EXAMPLE_INPUT);
  const msg = (i) => evaluateContractPrice(i).message || "";
  check("the built-in example input is valid", evaluateContractPrice(clone(E)).state === "contradicted");
  let m = msg({ ...E, offer: { ...E.offer, unit_price: 2 } });
  check("a JSON number: says it must be in quotes, shows an example, says what it got", /in quotes/.test(m) && /"1\.00"/.test(m) && /got the JSON number 2/.test(m), m);
  m = msg({ ...E, offer: { ...E.offer, unit_price: "$1,000.00" } });
  check("a formatted amount: names the things not allowed and echoes the value", /thousands separator/.test(m) && /currency symbol/.test(m) && /got the string "\$1,000\.00"/.test(m), m);
  m = msg({ ...E, terms: [{ ...E.terms[0], effective_from: "2026-01-01" }] });
  check("a date with no time: shows the form to send", /ending in Z/.test(m) && /"2026-01-01T00:00:00Z"/.test(m) && /got the string "2026-01-01"/.test(m), m);
  m = msg({ ...E, offer: { ...E.offer, offered_at: "2026-10-01T14:00:00+02:00" } });
  check("a time with an offset: says the offset is unsupported by this Z-only schema, and does not say the instant would be guessed", /unsupported by this Z-only schema/.test(m) && /Convert the time to UTC/.test(m) && !/guessed/.test(m) && /got the string "2026-10-01T14:00:00\+02:00"/.test(m), m);
  m = msg({ ...E, offer: { ...E.offer, offered_at: "2026-10-01T14:00:00-0500" } });
  check("an offset written without a colon gets the same message", /unsupported by this Z-only schema/.test(m), m);
  m = msg({ ...E, offer: { ...E.offer, offered_at: "2026-10-01T12:00:00" } });
  check("a time with no Z and no offset still says the instant would have to be guessed", /would have to be guessed/.test(m) && !/Z-only schema/.test(m), m);
  m = msg({ ...E, terms: [{ ...E.terms[0], discount_percent: "10" }] });
  check("an unknown member: lists the recognised members", /nothing is silently ignored/.test(m) && /price_per_unit, tiers/.test(m), m);
  m = msg({ ...E, terms: [{ ...E.terms[0], tiers: [{ min_quantity: "1", price_per_unit: "1.00" }] }] });
  check("both a price and tiers: says exactly one", /carries both/.test(m) && /exactly one/.test(m), m);
  m = msg({ ...E, offer: { ...E.offer, seller: " seller.example" } });
  check("a leading space: says identifiers are exact strings", /exact strings/.test(m), m);
  check("no message echoes more than 40 characters of a value", !msg({ ...E, offer: { ...E.offer, sku: "" } }).includes("x".repeat(41)) && msg({ ...E, offer: { ...E.offer, unit_price: "9".repeat(60) } }).includes("…"));
}

// ── published vectors ──
const VECTORS = new URL("./contract-price.vectors.json", import.meta.url);
const slim = (r) => (r.invalid ? { invalid: true, member: r.path } : r);
const built = { rule_id: CONTRACT_PRICE_RULE_ID, license: "CC0-1.0", note: "Each case is an input and the exact result the rule gives. For input that cannot be read, the result names the member at fault; the message text is not part of the vectors.", cases: CASES.map(([name, input], i) => ({ id: "cpm-" + String(i + 1).padStart(3, "0"), name, input, result: slim(evaluateContractPrice(clone(input))) })) };
if (process.argv.includes("--write-vectors")) {
  fs.writeFileSync(VECTORS, JSON.stringify(built, null, 2) + "\n");
  console.log(`\nwrote ${built.cases.length} vectors`);
} else {
  console.log("\npublished vectors");
  let stored = null;
  try { stored = JSON.parse(fs.readFileSync(VECTORS, "utf8")); } catch (e) { check("contract-price.vectors.json is present and readable", false, String(e.message)); }
  if (stored) {
    check("vectors carry the rule id", stored.rule_id === CONTRACT_PRICE_RULE_ID);
    check(`vectors hold one case per test case (${stored.cases.length})`, stored.cases.length === CASES.length);
    let same = 0; const diff = [];
    for (const [i, c] of stored.cases.entries()) {
      const now = slim(evaluateContractPrice(clone(c.input)));
      if (jcs(JSON.parse(JSON.stringify(now))) === jcs(c.result)) same++; else diff.push(c.id);
    }
    check(`every stored result equals what the rule gives now (${same}/${stored.cases.length})`, diff.length === 0, diff.slice(0, 5));
  }
}

console.log(`\n${CASES.length} cases, ${pass} assertions passed, ${fail} failed`);
process.exit(fail === 0 && CASES.length >= 30 ? 0 : 1);
