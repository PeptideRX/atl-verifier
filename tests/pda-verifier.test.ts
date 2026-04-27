import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

import {
  PDA_DIGEST_LEN,
  PDA_DOMAIN_SEPARATOR,
  PDA_SCHEMA_VERSION_V1,
  PDA_SIMULATOR_MEASUREMENT_HEX,
  asPythonFloat,
  canonicalizePythonJSON,
  computeCandidateCommitLeaf,
  computeCandidateMetadataHash,
  computePdaComponentHashes,
  parsePythonJSON,
  pdaGenerateInclusionProof,
  pdaMerkleRoot,
  pdaSha256,
  pdaVerifyInclusionProof,
  recomputePdaHex,
  verifyCandidateReveal,
  verifyPDA,
  type MerkleProof,
  type PDAOutput,
  type PyFloatNumber,
} from '../src/pda/index.js';
import { bytesToHex, hexToBytes } from '../src/hash.js';

const here = dirname(fileURLToPath(import.meta.url));
const vectorsDir = join(here, 'pda-vectors');

function loadVector(label: 'a' | 'b' | 'c'): PDAOutput {
  const p = join(vectorsDir, `vector-${label}.json`);
  return JSON.parse(readFileSync(p, 'utf8')) as PDAOutput;
}

interface RevealCandidate {
  candidate_id: string;
  salt_hex: string;
  sequence: string;
  metadata: Record<string, unknown>;
  leaf_hex: string;
  leaf_index: number;
  inclusion_path: Array<{ sibling_hex: string; side: 'left' | 'right' }>;
  canonical_sequence_hash: string;
  metadata_hash: string;
  candidate_commit_bytes_hex: string;
}

interface RevealBundle {
  candidates: RevealCandidate[];
}

function loadReveal(label: 'a' | 'b' | 'c'): RevealBundle {
  const p = join(vectorsDir, `vector-${label}.reveal.json`);
  return JSON.parse(readFileSync(p, 'utf8')) as RevealBundle;
}

/** Raw metadata JSON for a reveal candidate, pulled directly from the
 * fixture file so whole-number float literals like `-9.0` are preserved
 * verbatim. */
function loadRevealCandidateMetadataJSON(
  label: 'a' | 'b' | 'c',
  index: number,
): string {
  const p = join(vectorsDir, `vector-${label}.reveal.json`);
  const raw = readFileSync(p, 'utf8');
  // Find the i-th "metadata" block in the raw text by walking the
  // candidates in order. The generated fixtures always emit candidates
  // in the same order, so we can find each `"metadata": { ... }` block
  // and snip it out intact.
  const tokens = findMetadataBlocks(raw);
  const block = tokens[index];
  if (!block) throw new Error(`metadata index ${index} not found for vector ${label}`);
  return block;
}

function findMetadataBlocks(src: string): string[] {
  const blocks: string[] = [];
  const needle = '"metadata":';
  let i = 0;
  for (;;) {
    const hit = src.indexOf(needle, i);
    if (hit < 0) break;
    // Skip whitespace to find the opening `{`.
    let j = hit + needle.length;
    while (j < src.length && /\s/.test(src.charAt(j))) j++;
    if (src.charAt(j) !== '{') {
      i = hit + needle.length;
      continue;
    }
    // Brace-balanced scan. Strings and escapes are handled so `}`
    // inside a string literal does not terminate the block.
    let depth = 0;
    let k = j;
    let inString = false;
    let escaped = false;
    for (; k < src.length; k++) {
      const ch = src.charAt(k);
      if (inString) {
        if (escaped) {
          escaped = false;
        } else if (ch === '\\') {
          escaped = true;
        } else if (ch === '"') {
          inString = false;
        }
        continue;
      }
      if (ch === '"') {
        inString = true;
        continue;
      }
      if (ch === '{') depth++;
      else if (ch === '}') {
        depth--;
        if (depth === 0) {
          blocks.push(src.slice(j, k + 1));
          i = k + 1;
          break;
        }
      }
    }
    if (k >= src.length) break;
  }
  return blocks;
}

// -----------------------------------------------------------------------------
// Test constants: frozen byte-level expected values.
// -----------------------------------------------------------------------------

const EXPECTED_VECTOR_A = {
  pda_hex: '28dbab77f560665f9b374b7fb8b5c0dfe8c8ff6582cbd29f773241acfb3a640e',
  commit_root_hex: '4fad4ac8ee6a6f78b8d3617765bcd63379cffabc749a0cd16a83ea5fca7bc5b2',
  signature_hex: '0c73c6ff664e113509088ba57482ab9a57f7216acbbfeb65820db7fedb348325',
  tier_distribution_hash_hex:
    '614e0da9b41d0674729cf1a5864e88fa14cc1ddc86169c883b1344ab6b9edcd8',
};

const EXPECTED_VECTOR_B = {
  pda_hex: '4c261a1105a45c55fb0d2eb45d74542b7f70b78b27aa41999cfa444400051594',
  commit_root_hex: '55fd6d888ed710eb9c101fd66b37de39ee655962a972cde10677a77ad57f7794',
  signature_hex: '4c69669203082a07270d73f8eb222a18b0cee898f9e7fe41e80adb9234f42707',
  tier_distribution_hash_hex:
    'cdff32a774dd372ceb67474446308c287aed7f7c1125057be9c3ef16c1e9354e',
};

const EXPECTED_VECTOR_C = {
  pda_hex: '1bc8afdfee1152521fa1d7a2e9e1019b9d199879ab921f7f5c4874e06d1861f4',
  commit_root_hex: 'a2d80586005d8d0c7628b08656c5acf754a56fa663a51ae3781bed78b2a5f93d',
  signature_hex: '516ef796db40352f732978e4dd35d714e0e88df30d71e3b289562b6ce668b9e3',
  tier_distribution_hash_hex:
    '07e0f7562864d637f805be90b02bee28edcb2a6dfd0c213e1e234711ba276f51',
};

// -----------------------------------------------------------------------------
// Vector tests: 3 hardcoded byte-for-byte pins against Python + Rust.
// -----------------------------------------------------------------------------

describe('PDA Vector A (single candidate, canonical inputs)', () => {
  const output = loadVector('a');

  it('published PDA matches frozen expected bytes', () => {
    expect(output.pda_hex).toBe(EXPECTED_VECTOR_A.pda_hex);
    expect(output.candidate_commit_root_hex).toBe(EXPECTED_VECTOR_A.commit_root_hex);
    expect(output.tee_attestation.signature_hex).toBe(EXPECTED_VECTOR_A.signature_hex);
  });

  it('verifyPDA passes on the canonical output', async () => {
    const r = await verifyPDA(output);
    expect(r.passed).toBe(true);
    expect(r.blocked_reasons).toEqual([]);
    expect(r.verified_fields['pda_matches']).toBe(true);
    expect(r.verified_fields['tee_signature_valid']).toBe(true);
  });

  it('recomputePdaHex yields the byte-identical PDA hex', async () => {
    const recomputed = await recomputePdaHex(output);
    expect(recomputed).toBe(EXPECTED_VECTOR_A.pda_hex);
  });

  it('verifies the single-leaf inclusion proof via candidate reveal', async () => {
    const reveal = loadReveal('a');
    const cand = reveal.candidates[0];
    if (!cand) throw new Error('expected at least one candidate');
    const metadataJSON = loadRevealCandidateMetadataJSON('a', 0);
    const proof: MerkleProof = {
      leaf_index: cand.leaf_index,
      leaf_hash_hex: cand.leaf_hex,
      path: cand.inclusion_path,
    };
    const ok = await verifyCandidateReveal({
      pdaOutput: output,
      commitment: {
        candidate_id: cand.candidate_id,
        salt_hex: cand.salt_hex,
        canonical_sequence_hash: cand.canonical_sequence_hash,
        metadata_hash: cand.metadata_hash,
      },
      revealedSequence: cand.sequence,
      revealedMetadataJSON: metadataJSON,
      inclusionProof: proof,
    });
    expect(ok).toBe(true);
  });

  it('candidate leaf digest matches the Python reference', async () => {
    const reveal = loadReveal('a');
    const cand = reveal.candidates[0];
    if (!cand) throw new Error('expected at least one candidate');
    const metadataJSON = loadRevealCandidateMetadataJSON('a', 0);
    const leaf = await computeCandidateCommitLeaf(
      cand.salt_hex,
      cand.sequence,
      metadataJSON,
    );
    expect(bytesToHex(leaf)).toBe(cand.candidate_commit_bytes_hex);
  });
});

describe('PDA Vector B (two candidates, cyclic whitelist, RGD/LDV motifs)', () => {
  const output = loadVector('b');

  it('published PDA matches frozen expected bytes', () => {
    expect(output.pda_hex).toBe(EXPECTED_VECTOR_B.pda_hex);
    expect(output.candidate_commit_root_hex).toBe(EXPECTED_VECTOR_B.commit_root_hex);
    expect(output.tee_attestation.signature_hex).toBe(EXPECTED_VECTOR_B.signature_hex);
  });

  it('verifyPDA passes on the canonical output', async () => {
    const r = await verifyPDA(output);
    expect(r.passed).toBe(true);
    expect(r.blocked_reasons).toEqual([]);
  });

  it('recomputePdaHex yields the byte-identical PDA hex', async () => {
    const recomputed = await recomputePdaHex(output);
    expect(recomputed).toBe(EXPECTED_VECTOR_B.pda_hex);
  });

  it('verifies both candidates via Merkle inclusion proofs', async () => {
    const reveal = loadReveal('b');
    for (let i = 0; i < reveal.candidates.length; i++) {
      const cand = reveal.candidates[i];
      if (!cand) throw new Error(`missing candidate ${i}`);
      const metadataJSON = loadRevealCandidateMetadataJSON('b', i);
      const proof: MerkleProof = {
        leaf_index: cand.leaf_index,
        leaf_hash_hex: cand.leaf_hex,
        path: cand.inclusion_path,
      };
      const ok = await verifyCandidateReveal({
        pdaOutput: output,
        commitment: {
          candidate_id: cand.candidate_id,
          salt_hex: cand.salt_hex,
          canonical_sequence_hash: cand.canonical_sequence_hash,
          metadata_hash: cand.metadata_hash,
        },
        revealedSequence: cand.sequence,
        revealedMetadataJSON: metadataJSON,
        inclusionProof: proof,
      });
      expect(ok, `candidate ${i}`).toBe(true);
    }
  });

  it('Merkle root recomputation matches the published commit root', async () => {
    const leaves = output.merkle_leaves_hex.map((h) => hexToBytes(h));
    const root = await pdaMerkleRoot(leaves);
    expect(bytesToHex(root)).toBe(EXPECTED_VECTOR_B.commit_root_hex);
  });
});

describe('PDA Vector C (three candidates, odd-count Merkle duplication)', () => {
  const output = loadVector('c');

  it('published PDA matches frozen expected bytes', () => {
    expect(output.pda_hex).toBe(EXPECTED_VECTOR_C.pda_hex);
    expect(output.candidate_commit_root_hex).toBe(EXPECTED_VECTOR_C.commit_root_hex);
    expect(output.tee_attestation.signature_hex).toBe(EXPECTED_VECTOR_C.signature_hex);
  });

  it('verifyPDA passes on the canonical output', async () => {
    const r = await verifyPDA(output);
    expect(r.passed).toBe(true);
    expect(r.blocked_reasons).toEqual([]);
  });

  it('recomputePdaHex yields the byte-identical PDA hex', async () => {
    const recomputed = await recomputePdaHex(output);
    expect(recomputed).toBe(EXPECTED_VECTOR_C.pda_hex);
  });

  it('verifies all three candidates under odd-count Merkle duplication', async () => {
    const reveal = loadReveal('c');
    expect(reveal.candidates.length).toBe(3);
    for (let i = 0; i < reveal.candidates.length; i++) {
      const cand = reveal.candidates[i];
      if (!cand) throw new Error(`missing candidate ${i}`);
      const metadataJSON = loadRevealCandidateMetadataJSON('c', i);
      const proof: MerkleProof = {
        leaf_index: cand.leaf_index,
        leaf_hash_hex: cand.leaf_hex,
        path: cand.inclusion_path,
      };
      const ok = await verifyCandidateReveal({
        pdaOutput: output,
        commitment: {
          candidate_id: cand.candidate_id,
          salt_hex: cand.salt_hex,
          canonical_sequence_hash: cand.canonical_sequence_hash,
          metadata_hash: cand.metadata_hash,
        },
        revealedSequence: cand.sequence,
        revealedMetadataJSON: metadataJSON,
        inclusionProof: proof,
      });
      expect(ok, `candidate ${i}`).toBe(true);
    }
  });

  it('generates proofs that match published inclusion paths', async () => {
    const leaves = output.merkle_leaves_hex.map((h) => hexToBytes(h));
    for (let i = 0; i < leaves.length; i++) {
      const proof = await pdaGenerateInclusionProof(leaves, i);
      const leaf = leaves[i];
      if (!leaf) throw new Error('missing leaf');
      const root = hexToBytes(output.candidate_commit_root_hex);
      const ok = await pdaVerifyInclusionProof(leaf, proof, root);
      expect(ok, `leaf ${i}`).toBe(true);
    }
  });
});

// -----------------------------------------------------------------------------
// Tamper detection.
// -----------------------------------------------------------------------------

describe('Tamper detection', () => {
  it('rejects a PDAOutput with a tampered pipeline_manifest', async () => {
    const output = loadVector('a');
    const tampered: PDAOutput = {
      ...output,
      pipeline_manifest: {
        ...output.pipeline_manifest,
        backbone_model: {
          ...output.pipeline_manifest.backbone_model,
          weights_sha256: '9'.repeat(64),
        },
      },
    };
    const r = await verifyPDA(tampered);
    expect(r.passed).toBe(false);
    expect(r.blocked_reasons).toContain('pda_mismatch');
  });

  it('rejects a PDAOutput with a tampered biosecurity_policy', async () => {
    const output = loadVector('a');
    const tampered: PDAOutput = {
      ...output,
      biosecurity_policy: { ...output.biosecurity_policy, t_pathogen: 99 },
    };
    const r = await verifyPDA(tampered);
    expect(r.passed).toBe(false);
    expect(r.blocked_reasons).toContain('pda_mismatch');
  });

  it('rejects a PDAOutput with a tampered tier_distribution', async () => {
    const output = loadVector('b');
    const tampered: PDAOutput = {
      ...output,
      tier_distribution: {
        green_count: 99,
        amber_count: 0,
        red_count: 0,
        black_count: 0,
        total_count: 99,
      },
    };
    const r = await verifyPDA(tampered);
    expect(r.passed).toBe(false);
    expect(r.blocked_reasons).toContain('pda_mismatch');
  });

  it('rejects a PDAOutput with a forged TEE measurement', async () => {
    const output = loadVector('a');
    const tampered: PDAOutput = {
      ...output,
      tee_attestation: {
        ...output.tee_attestation,
        measurement_hex: 'ff'.repeat(32),
      },
    };
    const r = await verifyPDA(tampered);
    expect(r.passed).toBe(false);
    expect(r.blocked_reasons).toContain('tee_measurement_mismatch');
  });

  it('rejects a PDAOutput whose PDA hex has one flipped byte', async () => {
    const output = loadVector('a');
    const flipped =
      output.pda_hex.slice(0, 2) +
      (output.pda_hex.charAt(2) === 'a' ? 'b' : 'a') +
      output.pda_hex.slice(3);
    const tampered: PDAOutput = { ...output, pda_hex: flipped };
    const r = await verifyPDA(tampered);
    expect(r.passed).toBe(false);
    expect(r.blocked_reasons).toContain('pda_mismatch');
  });

  it('rejects a PDAOutput with a forged TEE signature', async () => {
    const output = loadVector('a');
    const tampered: PDAOutput = {
      ...output,
      tee_attestation: {
        ...output.tee_attestation,
        signature_hex: 'de'.repeat(32),
      },
    };
    const r = await verifyPDA(tampered);
    expect(r.passed).toBe(false);
    expect(r.blocked_reasons).toContain('tee_signature_invalid');
  });

  it('rejects an attestation replayed under seen_nonces', async () => {
    const output = loadVector('a');
    const r = await verifyPDA(output, {
      seenNoncesHex: [output.tee_attestation.nonce_hex],
    });
    expect(r.passed).toBe(false);
    expect(r.blocked_reasons).toContain('tee_nonce_replayed');
  });

  it('rejects the simulator attestation when accept_simulator=false', async () => {
    const output = loadVector('a');
    const r = await verifyPDA(output, { acceptSimulator: false });
    expect(r.passed).toBe(false);
    expect(r.blocked_reasons).toContain('simulator_refused');
  });

  it('rejects a schema_version mismatch', async () => {
    const output = loadVector('a');
    const tampered: PDAOutput = { ...output, schema_version: 2 };
    const r = await verifyPDA(tampered);
    expect(r.passed).toBe(false);
    expect(r.blocked_reasons).toContain('schema_version_mismatch');
  });

  it('rejects a target_spec whose scope string does not match the V1 constant', async () => {
    const output = loadVector('a');
    const tampered: PDAOutput = {
      ...output,
      target_spec: { ...output.target_spec, scope: 'clinical use' },
    };
    const r = await verifyPDA(tampered);
    expect(r.passed).toBe(false);
    expect(r.blocked_reasons).toContain('target_spec_scope_mismatch');
  });
});

// -----------------------------------------------------------------------------
// merkle_leaves_hex shape gates. The verifier MUST reject malformed,
// missing, or empty leaf arrays rather than vacuously passing the
// merkle_leaves_consistent check.
// -----------------------------------------------------------------------------

describe('merkle_leaves_hex shape gates', () => {
  it('rejects a PDAOutput whose merkle_leaves_hex is an empty array', async () => {
    const output = loadVector('a');
    const tampered: PDAOutput = { ...output, merkle_leaves_hex: [] };
    const r = await verifyPDA(tampered);
    expect(r.passed).toBe(false);
    expect(r.blocked_reasons).toContain('merkle_leaves_empty');
    expect(r.verified_fields.merkle_leaves_consistent).toBe(false);
  });

  it('rejects a PDAOutput whose merkle_leaves_hex field is missing entirely', async () => {
    const output = loadVector('a');
    const stripped: Partial<PDAOutput> = { ...output };
    delete (stripped as { merkle_leaves_hex?: unknown }).merkle_leaves_hex;
    const r = await verifyPDA(stripped as PDAOutput);
    expect(r.passed).toBe(false);
    expect(r.blocked_reasons).toContain('merkle_leaves_missing_or_not_array');
    expect(r.verified_fields.merkle_leaves_consistent).toBe(false);
  });

  it('rejects a PDAOutput whose merkle_leaves_hex is not an array', async () => {
    const output = loadVector('a');
    const tampered = {
      ...output,
      merkle_leaves_hex: 'not-an-array',
    } as unknown as PDAOutput;
    const r = await verifyPDA(tampered);
    expect(r.passed).toBe(false);
    expect(r.blocked_reasons).toContain('merkle_leaves_missing_or_not_array');
    expect(r.verified_fields.merkle_leaves_consistent).toBe(false);
  });

  it('rejects a PDAOutput whose merkle_leaves_hex is all zeros', async () => {
    const output = loadVector('a');
    const tampered: PDAOutput = {
      ...output,
      merkle_leaves_hex: ['0'.repeat(64)],
    };
    const r = await verifyPDA(tampered);
    expect(r.passed).toBe(false);
    expect(r.blocked_reasons).toContain('merkle_leaves_inconsistent_with_root');
    expect(r.verified_fields.merkle_leaves_consistent).toBe(false);
  });

  it('rejects a PDAOutput where one leaf has malformed (non-hex) characters', async () => {
    const output = loadVector('b');
    const tampered: PDAOutput = {
      ...output,
      merkle_leaves_hex: [
        output.merkle_leaves_hex[0]!,
        '0g'.padEnd(64, '0'),
      ],
    };
    const r = await verifyPDA(tampered);
    expect(r.passed).toBe(false);
    expect(r.blocked_reasons).toContain('merkle_leaves_inconsistent_with_root');
    expect(r.verified_fields.merkle_leaves_consistent).toBe(false);
  });

  it('rejects a PDAOutput where the leaves are reordered', async () => {
    const output = loadVector('b');
    expect(output.merkle_leaves_hex.length).toBe(2);
    const tampered: PDAOutput = {
      ...output,
      merkle_leaves_hex: [
        output.merkle_leaves_hex[1]!,
        output.merkle_leaves_hex[0]!,
      ],
    };
    const r = await verifyPDA(tampered);
    expect(r.passed).toBe(false);
    expect(r.blocked_reasons).toContain('merkle_leaves_inconsistent_with_root');
    expect(r.verified_fields.merkle_leaves_consistent).toBe(false);
  });
});

// -----------------------------------------------------------------------------
// Merkle primitive sanity.
// -----------------------------------------------------------------------------

describe('Merkle primitives', () => {
  it('single-leaf tree returns the leaf unchanged', async () => {
    const leaf = new Uint8Array(32).fill(0x55);
    const root = await pdaMerkleRoot([leaf]);
    expect(bytesToHex(root)).toBe(bytesToHex(leaf));
  });

  it('two-leaf root matches SHA256(0x01 || left || right)', async () => {
    const left = new Uint8Array(32).fill(0x01);
    const right = new Uint8Array(32).fill(0x02);
    const root = await pdaMerkleRoot([left, right]);
    const manual = await pdaSha256(new Uint8Array([0x01]), left, right);
    expect(bytesToHex(root)).toBe(bytesToHex(manual));
  });

  it('odd leaf count duplicates the final leaf (RFC 6962)', async () => {
    const leaves = [
      new Uint8Array(32).fill(0x01),
      new Uint8Array(32).fill(0x02),
      new Uint8Array(32).fill(0x03),
    ];
    const rootA = await pdaMerkleRoot(leaves);
    const duplicated = [...leaves, new Uint8Array(32).fill(0x03)];
    const rootB = await pdaMerkleRoot(duplicated);
    expect(bytesToHex(rootA)).toBe(bytesToHex(rootB));
  });

  it('a wrong leaf fails the inclusion proof', async () => {
    const leaves = [
      new Uint8Array(32).fill(0x01),
      new Uint8Array(32).fill(0x02),
      new Uint8Array(32).fill(0x03),
      new Uint8Array(32).fill(0x04),
      new Uint8Array(32).fill(0x05),
    ];
    const root = await pdaMerkleRoot(leaves);
    const proof = await pdaGenerateInclusionProof(leaves, 0);
    const bad = new Uint8Array(32).fill(0xff);
    const ok = await pdaVerifyInclusionProof(bad, proof, root);
    expect(ok).toBe(false);
  });
});

// -----------------------------------------------------------------------------
// Canonical JSON dialect: the load-bearing -9.0 edge case.
// -----------------------------------------------------------------------------

describe('Python-dialect canonical JSON', () => {
  it('preserves -9.0 exactly (Python dialect, not strict RFC 8785)', () => {
    const parsed = parsePythonJSON('{"x":-9.0}');
    expect(canonicalizePythonJSON(parsed)).toBe('{"x":-9.0}');
  });

  it('preserves -6.0, -6.5, -7.0 (Vector C float set)', () => {
    const parsed = parsePythonJSON('[-6.0,-6.5,-7.0]');
    expect(canonicalizePythonJSON(parsed)).toBe('[-6.0,-6.5,-7.0]');
  });

  it('preserves 0.6 and 0.65 and 0.7 (shortest-roundtrip non-whole floats)', () => {
    const parsed = parsePythonJSON('[0.6,0.65,0.7]');
    expect(canonicalizePythonJSON(parsed)).toBe('[0.6,0.65,0.7]');
  });

  it('integers emit without a decimal point', () => {
    expect(canonicalizePythonJSON({ n: 42 })).toBe('{"n":42}');
  });

  it('asPythonFloat wraps whole numbers with an explicit .0', () => {
    const v: PyFloatNumber = asPythonFloat(-9);
    expect(v.literal).toBe('-9.0');
    expect(canonicalizePythonJSON({ x: v })).toBe('{"x":-9.0}');
  });

  it('sorts object keys lexicographically', () => {
    const parsed = parsePythonJSON('{"b":1,"a":2,"c":3}');
    expect(canonicalizePythonJSON(parsed)).toBe('{"a":2,"b":1,"c":3}');
  });

  it('escapes \\n and preserves PDB-like embedded newlines', () => {
    const parsed = parsePythonJSON('{"pdb":"HEADER test\\nEND"}');
    expect(canonicalizePythonJSON(parsed)).toBe('{"pdb":"HEADER test\\nEND"}');
  });

  it('rejects NaN and Infinity', () => {
    expect(() => canonicalizePythonJSON(Number.NaN)).toThrow();
    expect(() => canonicalizePythonJSON(Number.POSITIVE_INFINITY)).toThrow();
  });

  it('computeCandidateMetadataHash matches the Python reference on -9.0 payload', async () => {
    // Sourced from the Python reference via generate.py:
    //   vector-b.reveal.json :: candidates[0].metadata_hash for the -9.0
    //   candidate.
    const reveal = loadReveal('b');
    const cand = reveal.candidates[0];
    if (!cand) throw new Error('missing candidate');
    const metadataJSON = loadRevealCandidateMetadataJSON('b', 0);
    const h = await computeCandidateMetadataHash(metadataJSON);
    expect(h).toBe(cand.metadata_hash);
  });
});

// -----------------------------------------------------------------------------
// Domain-separator binding.
// -----------------------------------------------------------------------------

describe('Domain separators', () => {
  it('top-level PDA domain separator is the frozen ASCII constant', () => {
    expect(PDA_DOMAIN_SEPARATOR).toBe('PEPTIDERX_PDA_V1');
    expect(new TextEncoder().encode(PDA_DOMAIN_SEPARATOR).length).toBe(16);
  });

  it('documented simulator measurement matches the hex constant', () => {
    expect(PDA_SIMULATOR_MEASUREMENT_HEX).toBe(
      '5045505449444552582d53494d2d56312d4d4541535552454d454e5400000000',
    );
    expect(PDA_SIMULATOR_MEASUREMENT_HEX.length).toBe(64);
    expect(hexToBytes(PDA_SIMULATOR_MEASUREMENT_HEX).length).toBe(PDA_DIGEST_LEN);
  });

  it('component hashes change when the domain separator changes', async () => {
    const output = loadVector('a');
    const hashes = await computePdaComponentHashes(output);
    expect(hashes.target_spec_hash_hex).not.toBe(hashes.pipeline_manifest_hash_hex);
    expect(hashes.pipeline_manifest_hash_hex).not.toBe(
      hashes.biosecurity_policy_hash_hex,
    );
    expect(hashes.biosecurity_policy_hash_hex).not.toBe(
      hashes.tier_distribution_hash_hex,
    );
    expect(hashes.tier_distribution_hash_hex).not.toBe(
      hashes.tee_attestation_hash_hex,
    );
  });

  it('schema version is v1', () => {
    expect(PDA_SCHEMA_VERSION_V1).toBe(1);
  });

  it('tier_distribution_hash for Vector A is the pinned value', async () => {
    const output = loadVector('a');
    const hashes = await computePdaComponentHashes(output);
    expect(hashes.tier_distribution_hash_hex).toBe(
      EXPECTED_VECTOR_A.tier_distribution_hash_hex,
    );
  });

  it('tier_distribution_hash for Vector B is the pinned value', async () => {
    const output = loadVector('b');
    const hashes = await computePdaComponentHashes(output);
    expect(hashes.tier_distribution_hash_hex).toBe(
      EXPECTED_VECTOR_B.tier_distribution_hash_hex,
    );
  });

  it('tier_distribution_hash for Vector C is the pinned value', async () => {
    const output = loadVector('c');
    const hashes = await computePdaComponentHashes(output);
    expect(hashes.tier_distribution_hash_hex).toBe(
      EXPECTED_VECTOR_C.tier_distribution_hash_hex,
    );
  });
});
