/**
 * Commit-reveal helper for the PDA protocol.
 *
 * A PDA publishes only per-candidate Merkle-leaf digests; the actual
 * sequence and metadata stay inside the producer. A voluntary reveal
 * exposes `(candidate_id, salt, sequence, metadata)` plus an inclusion
 * proof, and any verifier can reconfirm the leaf against the PDA's
 * `candidate_commit_root_hex`. This module is the TypeScript equivalent
 * of `src/peptide_design/pda/verifier.py::verify_candidate_reveal` and
 * `crates/pda/src/verifier.rs::verify_candidate_reveal`.
 *
 * Metadata must be supplied as a raw JSON string so the float dialect
 * is preserved through {@link parsePythonJSON}. Python emits whole-
 * number floats such as `-9.0` with the trailing `.0`; JavaScript's
 * `JSON.parse` + `JSON.stringify` round-trip collapses that to `-9`.
 * See `canonical-json.ts` for the full dialect contract.
 *
 * Scope: research use only, nonclinical.
 */

import { bytesToHex, hexToBytes } from '../hash.js';
import {
  canonicalizePythonJSON,
  parsePythonJSON,
  type PyJsonValue,
} from './canonical-json.js';
import { PDA_DIGEST_LEN, PDA_DOMAIN_CANDIDATE_COMMIT } from './constants.js';
import { parseDigestHex, pdaSha256, pdaTimingSafeEqual } from './hashing.js';
import { pdaVerifyInclusionProof } from './merkle.js';
import type {
  CandidateRevealInput,
  MerkleProof,
  PDAOutput,
  MerklePathEntry,
} from './types.js';

/**
 * Verify a commit-reveal for one candidate.
 *
 * Steps:
 *
 *   1. Canonicalize the revealed metadata with the Python dialect.
 *   2. Check the revealed sequence's SHA-256 matches the
 *      `canonical_sequence_hash` on the commitment.
 *   3. Check the canonicalized metadata's SHA-256 matches the
 *      `metadata_hash` on the commitment.
 *   4. Rebuild the 32-byte leaf
 *      `SHA256(DOMAIN_CANDIDATE_COMMIT || salt || seq || metadata)`.
 *   5. Confirm the leaf equals the claim in the proof's `leaf_hash_hex`.
 *   6. Fold the leaf up through the Merkle proof and compare to the
 *      `candidate_commit_root_hex` on the PDAOutput.
 *
 * Returns `true` iff every step agrees. Any malformed input (bad hex,
 * wrong lengths, unparseable JSON) returns `false` so the PDA verifier
 * can treat reveals uniformly.
 */
export async function verifyCandidateReveal(
  input: CandidateRevealInput,
): Promise<boolean> {
  const {
    pdaOutput,
    commitment,
    revealedSequence,
    revealedMetadataJSON,
    inclusionProof,
  } = input;

  // Step 1 + 3: canonicalize metadata.
  let metadataValue: PyJsonValue;
  try {
    metadataValue = parsePythonJSON(revealedMetadataJSON);
  } catch {
    return false;
  }
  const canonicalMetadata = canonicalizePythonJSON(metadataValue);
  const metadataBytes = new TextEncoder().encode(canonicalMetadata);
  const metadataHash = await pdaSha256(metadataBytes);
  if (bytesToHex(metadataHash) !== commitment.metadata_hash.toLowerCase()) {
    return false;
  }

  // Step 2: sequence hash.
  const sequenceBytes = new TextEncoder().encode(revealedSequence);
  const seqHash = await pdaSha256(sequenceBytes);
  if (bytesToHex(seqHash) !== commitment.canonical_sequence_hash.toLowerCase()) {
    return false;
  }

  // Step 4: rebuild leaf.
  const saltBytes = parseDigestHex(commitment.salt_hex);
  if (!saltBytes) return false;
  const rebuiltLeaf = await pdaSha256(
    PDA_DOMAIN_CANDIDATE_COMMIT,
    saltBytes,
    sequenceBytes,
    metadataBytes,
  );

  // Step 5: leaf equals the one claimed in the proof.
  const claimedLeaf = parseDigestHex(inclusionProof.leaf_hash_hex);
  if (!claimedLeaf || !pdaTimingSafeEqual(rebuiltLeaf, claimedLeaf)) {
    return false;
  }

  // Step 6: fold through the proof.
  const expectedRoot = parseDigestHex(pdaOutput.candidate_commit_root_hex);
  if (!expectedRoot) return false;
  const pathTuples: Array<readonly [Uint8Array, 'left' | 'right']> = [];
  for (const step of inclusionProof.path) {
    const entry = normalizePathEntry(step);
    if (!entry) return false;
    const sibling = parseDigestHex(entry.sibling_hex);
    if (!sibling) return false;
    if (entry.side !== 'left' && entry.side !== 'right') return false;
    pathTuples.push([sibling, entry.side]);
  }
  return pdaVerifyInclusionProof(rebuiltLeaf, pathTuples, expectedRoot);
}

/**
 * Low-level helper exposing the leaf construction used by
 * {@link verifyCandidateReveal}. Returns the 32-byte leaf
 * `SHA256(DOMAIN_CANDIDATE_COMMIT || salt || seq || metadata)`.
 *
 * Useful for consumers that want to build their own reveal bundles in
 * a verifier context. Takes the metadata JSON as a string so the
 * Python float dialect is preserved.
 */
export async function computeCandidateCommitLeaf(
  saltHex: string,
  sequence: string,
  metadataJSON: string,
): Promise<Uint8Array> {
  const salt = parseDigestHex(saltHex);
  if (!salt) {
    throw new Error('computeCandidateCommitLeaf: salt_hex must be 64-char hex');
  }
  const sequenceBytes = new TextEncoder().encode(sequence);
  const parsed = parsePythonJSON(metadataJSON);
  const canonical = canonicalizePythonJSON(parsed);
  const metadataBytes = new TextEncoder().encode(canonical);
  return pdaSha256(PDA_DOMAIN_CANDIDATE_COMMIT, salt, sequenceBytes, metadataBytes);
}

/**
 * Compute the SHA-256 hash of a canonicalized metadata blob. Mirrors
 * the Python producer's `candidate_metadata_hash` helper. Returns the
 * hex digest.
 */
export async function computeCandidateMetadataHash(
  metadataJSON: string,
): Promise<string> {
  const parsed = parsePythonJSON(metadataJSON);
  const canonical = canonicalizePythonJSON(parsed);
  const bytes = new TextEncoder().encode(canonical);
  const digest = await pdaSha256(bytes);
  return bytesToHex(digest);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Accept either the named-field `MerklePathEntry` shape or the raw
 * two-element `[sibling_hex, side]` tuple form that the Python/Rust
 * references emit verbatim over JSON.
 */
function normalizePathEntry(
  entry: MerklePathEntry | [string, 'left' | 'right'] | unknown,
): MerklePathEntry | null {
  if (Array.isArray(entry) && entry.length === 2) {
    const [sibling_hex, side] = entry;
    if (
      typeof sibling_hex === 'string' &&
      (side === 'left' || side === 'right')
    ) {
      return { sibling_hex, side };
    }
    return null;
  }
  if (
    typeof entry === 'object' &&
    entry !== null &&
    typeof (entry as MerklePathEntry).sibling_hex === 'string' &&
    ((entry as MerklePathEntry).side === 'left' ||
      (entry as MerklePathEntry).side === 'right')
  ) {
    return entry as MerklePathEntry;
  }
  return null;
}

// Re-export types so downstream scripts can avoid a second import path.
export type { CandidateRevealInput, MerkleProof, PDAOutput } from './types.js';

// Avoid unused-import lint for hexToBytes in case we need it in tests.
void hexToBytes;
