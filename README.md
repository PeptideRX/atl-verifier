# @peptiderx/atl-verifier

> ⚠️ **EXPERIMENTAL · ACTIVE DEVELOPMENT.** This package is published in the open as part of building peptideRx in public. The protocol, schemas, and APIs are not stable. Things will change. Pin exact versions if you depend on it. File issues if something breaks. The cross-language byte-identical property is locked on the three published test vectors — everything else is fair game for revision.

Pure-TypeScript client-side verifier for the Peptide Rx family of
cryptographic commitments. Ships two independent surfaces inside one
package:

1. **ATL commit-reveal + state root verifier** · Chapter 6 of the ATL
   dissertation. Covers the single-endpoint commitment (Section 6.1),
   the multi-endpoint Merkle root (Section 6.2), and the recursive
   state-root replay (Section 6.5).

2. **Peptide Design Attestation (PDA) verifier · V1** · the protocol
   specified in the ATL dissertation appendix. Byte-identical to the
   Python and Rust reference implementations on the three frozen test
   vectors (A, B, C). No native dependencies: Web Crypto SubtleCrypto
   only.

Scope: research use only, nonclinical. No verifier output implies a
clinical claim, human safety, or therapeutic efficacy.

## What it is for

The peptideRx core repository is private. This package is published in
the open so anyone can verify any peptideRx-issued dossier without
trusting the company's servers. Open the verifier in a browser, paste
the published PDAOutput JSON, recompute the cryptographic chain, see
PASS or FAIL.

That is the discipline behind the protocol: **the code that issues a
commitment can stay private, but the code that verifies it cannot.**

## Installation

```bash
pnpm add @peptiderx/atl-verifier
# or
npm install @peptiderx/atl-verifier
```

Node 20+ exposes Web Crypto as `globalThis.crypto`. Older runtimes must
polyfill it; the package throws a clear error if `crypto.subtle` is
absent.

## Quick start: ATL commit-reveal

```ts
import { VerifyCommit, computeStateRoot } from '@peptiderx/atl-verifier';

const ok = await VerifyCommit(
  { endpoint_1: 0.42, endpoint_2: 1.73 },
  'aabbcc...32-byte-salt-hex',
  'f9...the-claimed-commitment-hex',
);
```

See `docs/white-paper/atl-dissertation.md` Chapter 6 for the formal
protocol; see `tests/commit.test.ts` for the exhaustive coverage.

## Quick start: PDA verification

```ts
import { verifyPDA, type PDAOutput } from '@peptiderx/atl-verifier';

const output: PDAOutput = JSON.parse(await readPdaOutputJSON());
const report = await verifyPDA(output);
if (!report.passed) {
  console.error('PDA rejected:', report.blocked_reasons);
}
```

The verifier recomputes every component hash, refolds the final PDA,
checks the TEE attestation signature under the documented simulator key
(or whatever real backend is registered), verifies the claimed public
measurement, and checks nonce freshness against a caller-supplied
seen-nonce set.

### Buyer-audience posture

```ts
const report = await verifyPDA(output, {
  acceptSimulator: false,
  expectedMeasurementHex: '...real-TEE-MRENCLAVE...',
  seenNoncesHex: previouslyAcceptedNonces,
});
```

## Candidate reveal

The PDA binds a Merkle root over per-candidate salted commitments. The
publisher can voluntarily reveal one candidate's full record without
exposing the rest; any third party with the reveal bundle verifies it
against the PDA:

```ts
import { verifyCandidateReveal } from '@peptiderx/atl-verifier';

const ok = await verifyCandidateReveal({
  pdaOutput,
  commitment,               // CandidateCommitment handle
  revealedSequence: 'GIGAVLKVLTT',
  revealedMetadataJSON,     // raw JSON string (preserves -9.0 vs -9 dialect)
  inclusionProof,           // MerkleProof
});
```

The `revealedMetadataJSON` argument is a raw JSON string rather than a
parsed tree because Python's JCS dialect preserves whole-number floats
with their trailing `.0` (`-9.0`, not `-9`). JavaScript's native
`JSON.parse` + `JSON.stringify` round-trip collapses that and breaks
cross-language byte identity. The package's `parsePythonJSON` parser
scans the raw bytes and wraps any token containing a `.` or exponent
marker in a `PyFloatNumber` tag so the canonicalizer can re-emit the
literal verbatim. See `src/pda/canonical-json.ts` for the full dialect
contract.

## Command-line interface

The package installs an `atl-verify-pda` binary that verifies a
published PDAOutput JSON file end-to-end and prints a PASS/FAIL report
with per-field audit flags and machine-readable block reasons.

```bash
# Research audience: accept the V1 simulator.
atl-verify-pda ./vector-a.json

# Buyer audience: refuse the simulator.
atl-verify-pda ./vector-a.json --no-simulator

# Regulatory audience: pin a real TEE measurement and block replayed nonces.
atl-verify-pda ./vector-a.json \
  --measurement <hex64> \
  --nonce <nonce1> --nonce <nonce2>
```

Exit codes: `0` PASS · `1` FAIL · `2` malformed input / unexpected
error.

## The three-language determinism story

The patent-enablement hinge for the PDA protocol is that three
independent implementations in three languages — Python (`pydantic v2`),
Rust (`serde_json` + `sha2`), and TypeScript (Web Crypto + a custom
Python-dialect canonical JSON parser) — converge on the same 32-byte
PDA for the same inputs. Any silent change to the domain separators,
the canonical JSON dialect, the Merkle tag, the odd-level duplication
rule, or the TEE simulator key flips the expected bytes in all three
languages at once.

The frozen vectors:

| Vector | PDA hex                                                              | Shape                                   |
|--------|----------------------------------------------------------------------|-----------------------------------------|
| A      | `28dbab77f560665f9b374b7fb8b5c0dfe8c8ff6582cbd29f773241acfb3a640e`   | 1 candidate                              |
| B      | `4c261a1105a45c55fb0d2eb45d74542b7f70b78b27aa41999cfa444400051594`   | 2 candidates, `-9.0` float edge case     |
| C      | `1bc8afdfee1152521fa1d7a2e9e1019b9d199879ab921f7f5c4874e06d1861f4`   | 3 candidates, odd Merkle duplication     |

Run the full matrix:

```bash
python scripts/cross_lang_pda_parity.py
```

Exits 0 iff Python, Rust, TypeScript vitest, and the TypeScript CLI
all agree on the same 32 bytes for all three vectors.

### Canonical JSON dialect

Strict RFC 8785 JCS mandates that a float equal to a whole number
serialize without a decimal point: `-9.0` becomes `-9`. Python's
`json.dumps` default (and the V1 Python reference) preserves the `.0`:
`-9.0` stays `-9.0`. The Python reference is the byte-level oracle, so
both Rust (`crates/pda`) and TypeScript (this package) match the
Python dialect rather than strict RFC 8785.

The only floats that exercise this edge case are on the
`PeptideCandidate` metadata record (`predicted_affinity_kcal_mol` and
`structure_confidence`). PDA-level inputs (TargetSpec, PipelineManifest,
BiosecurityPolicy, TierDistribution, TEEAttestation) are
integer-and-string-only by schema design, so cross-language PDA
verification stays byte-stable even for callers who never parse the
candidate metadata.

## Package structure

```
sdk/packages/atl-verifier/
├── bin/
│   └── atl-verify-pda.ts           · CLI entrypoint
├── src/
│   ├── canonical-json.ts           · RFC 8785 JCS (ATL dialect)
│   ├── commit.ts                   · VerifyCommit (Section 6.1)
│   ├── constants.ts                · ATL domain separators + state machine
│   ├── hash.ts                     · SHA-256 / hex helpers (Web Crypto)
│   ├── merkle.ts                   · ATL Merkle root
│   ├── state-root.ts               · ATL recursive state root (Section 6.5)
│   ├── index.ts                    · top-level public API
│   └── pda/
│       ├── canonical-json.ts       · Python-dialect JCS (PDA) + parser
│       ├── constants.ts            · PDA domain separators + TEE enum
│       ├── hashing.ts              · SHA-256 + HMAC-SHA256 primitives
│       ├── merkle.ts               · RFC 6962 Merkle (with internal tag)
│       ├── reveal.ts               · commit-reveal verifier
│       ├── types.ts                · PDAOutput, CandidateCommitment, ...
│       ├── verifier.ts             · verifyPDA end-to-end
│       └── index.ts                · PDA public API (`./pda` subpath)
├── tests/
│   ├── canonical-json.test.ts      · ATL dialect
│   ├── commit.test.ts              · ATL commit-reveal
│   ├── merkle.test.ts              · ATL Merkle
│   ├── state-root.test.ts          · ATL state root
│   ├── pda-verifier.test.ts        · PDA verifier (Vec A/B/C + tamper + dialect)
│   └── pda-vectors/
│       ├── generate.py             · regenerate fixtures from the Python ref
│       ├── vector-{a,b,c}.json     · published PDAOutput for each vector
│       └── vector-{a,b,c}.reveal.json · reveal bundles for commit-reveal tests
├── package.json
├── tsconfig.json                   · main library build
├── tsconfig.bin.json               · CLI build (dist/bin/)
└── README.md                       · this file
```

## Tests

```bash
pnpm -C sdk --filter @peptiderx/atl-verifier test
```

Coverage (current head):

| Suite                       | Tests |
|-----------------------------|-------|
| canonical-json.test.ts (ATL) | 12   |
| commit.test.ts              | 20    |
| merkle.test.ts              | 17    |
| state-root.test.ts          | 5     |
| **pda-verifier.test.ts**    | **45** |
| **Total**                   | **99** |

The PDA suite pins:

* Byte-identity for all three vectors (PDA hex, commit root hex,
  simulator signature hex, tier-distribution component hash).
* End-to-end `verifyPDA` PASS on canonical outputs.
* Tamper detection: flipped PDA byte, mutated pipeline manifest,
  mutated biosecurity policy, mutated tier distribution, forged TEE
  measurement, forged TEE signature, replayed nonce.
* Reveal-path verification: per-candidate inclusion proofs for the
  1-leaf, 2-leaf, and 3-leaf trees.
* Merkle primitives: single-leaf identity, two-leaf manual hash,
  odd-count duplication, inclusion-proof round-trip.
* Python-dialect canonical JSON: `-9.0` preservation, `-6.0`/`-6.5`/
  `-7.0`/`0.6`/`0.65`/`0.7` round-trips, integer no-decimal, sort
  order, control-character escapes.
* Posture gates: `acceptSimulator=false`, schema-version mismatch,
  target-spec nonclinical-scope invariant.

## Build

```bash
pnpm -C sdk --filter @peptiderx/atl-verifier build
```

Produces `dist/` (library) and `dist/bin/atl-verify-pda.js` (CLI).

## License

Apache-2.0.
