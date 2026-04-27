// Smoke-test the browser IIFE bundle by loading it into a V8 VM context
// and calling verifyPDA on Vector A. This proves:
//   1. The bundle parses as an IIFE.
//   2. It exposes a global `AtlVerifier` with `verifyPDA`.
//   3. Vector A (the reference vector) returns passed=true.
//   4. A mutated Vector A returns passed=false with pda_mismatch.
//
// Run manually:
//   pnpm --filter @peptiderx/atl-verifier exec node scripts/smoke-bundle.mjs
//
// The Playwright E2E in tests/e2e/ covers the full browser path; this
// is a cheaper CI guardrail so a broken bundle build fails loudly
// before spinning up Playwright.

import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import { webcrypto } from "node:crypto";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const pkgRoot = resolve(__dirname, "..");
const repoRoot = resolve(pkgRoot, "..", "..", "..");

const bundlePath = join(repoRoot, "web", "vendor", "atl-verifier.iife.js");
const vectorAPath = join(pkgRoot, "tests", "pda-vectors", "vector-a.json");

const bundle = readFileSync(bundlePath, "utf8");
const vectorA = JSON.parse(readFileSync(vectorAPath, "utf8"));

const ctx = {
  console,
  crypto: webcrypto,
  TextEncoder,
  TextDecoder,
  Uint8Array,
  Object,
  Array,
  JSON,
  Math,
  Number,
  String,
  Boolean,
  Error,
  TypeError,
  RangeError,
  SyntaxError,
  Promise,
  Symbol,
  Set,
  Map,
  Reflect,
  structuredClone,
  globalThis: null,
  window: null,
};
ctx.globalThis = ctx;
ctx.window = ctx;
vm.createContext(ctx);

vm.runInContext(bundle, ctx);

if (!ctx.AtlVerifier || typeof ctx.AtlVerifier.verifyPDA !== "function") {
  console.error("FAIL: bundle did not expose AtlVerifier.verifyPDA");
  process.exit(1);
}

const verifyPDA = ctx.AtlVerifier.verifyPDA;

const r1 = await verifyPDA(vectorA);
if (!r1.passed) {
  console.error("FAIL: Vector A did not pass:", r1);
  process.exit(1);
}
console.log("OK: Vector A passed with", Object.keys(r1.verified_fields).length, "verified fields");

// Mutate the published PDA hex (flip one hex nibble to keep it valid hex
// but break the digest equality check) — should fail with pda_mismatch.
const mutated = structuredClone(vectorA);
const last = mutated.pda_hex.slice(-1).toLowerCase();
const flipped = last === "0" ? "1" : "0";
mutated.pda_hex = mutated.pda_hex.slice(0, -1) + flipped;
const r2 = await verifyPDA(mutated);
if (r2.passed) {
  console.error("FAIL: mutated Vector A should not pass");
  process.exit(1);
}
if (!r2.blocked_reasons.includes("pda_mismatch")) {
  console.error("FAIL: mutated Vector A should include pda_mismatch:", r2.blocked_reasons);
  process.exit(1);
}
console.log("OK: mutated Vector A failed with reasons:", r2.blocked_reasons);

console.log(
  `OK: bundle smoke test complete (${(bundle.length / 1024).toFixed(1)} KB)`,
);
